"""Client-credentials issuance, pilot allowlist, and RS256 signing."""

from __future__ import annotations

import base64
import hashlib
import json
import logging

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from starlette.testclient import TestClient

from mcp_trust_gateway.config import get_financial_allowlist
from mcp_trust_gateway.oauth.keys import SigningConfigError, jwk_thumbprint, validate_signing_config
from mcp_trust_gateway.server import create_app

ISSUER = "https://test.example.com"
AUDIENCE = "https://gateway.a2a-settlement.org"
CLAIMS = "https://a2a-settlement.org/claims"
SECRET = "ate_DoNotLog_9f3c1ab7e2d84c60"
AGENT = "acct-pilot-1"
RFC_N = (
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W"
    "-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
)


@pytest.fixture(scope="module")
def rsa_material(tmp_path_factory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path_factory.mktemp("oauth-keys") / "signing.pem"
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return path, public_pem


@pytest.fixture
def client(rsa_material, monkeypatch):
    path, _public = rsa_material
    monkeypatch.setenv("OAUTH_SIGNING_KEY_FILE", str(path))
    monkeypatch.setenv("OAUTH_ALGORITHM", "RS256")
    monkeypatch.setenv("OAUTH_SIGNING_KEY", "ignored-hmac-secret-not-for-signing-01")
    monkeypatch.setenv("OAUTH_ISSUER", ISSUER)
    monkeypatch.setenv("OAUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("OAUTH_TOKEN_TTL", "3600")
    monkeypatch.setenv("A2A_EXCHANGE_URL", "http://exchange.test")
    monkeypatch.delenv("OAUTH_AUTHORIZE_ENABLED", raising=False)
    monkeypatch.delenv("MCP_TRUST_FINANCIAL_ALLOWLIST", raising=False)
    return TestClient(create_app())


@pytest.fixture
def public_pem(rsa_material):
    return rsa_material[1]


class FakeExchange:
    """In-process exchange. The API key is never copied into a response we make."""

    def __init__(
        self,
        secret: str,
        account_id: str,
        *,
        status: str = "active",
        reputation: float = 0.25,
        balance_mode: str = "ok",
        card_status: int = 200,
        kya: int = 0,
        account_body: dict | None = None,
    ):
        self.secret = secret
        self.account_id = account_id
        self.status = status
        self.reputation = reputation
        self.balance_mode = balance_mode
        self.card_status = card_status
        self.kya = kya
        self.account_body = account_body
        self.paths: list[str] = []
        self.card_authorization: list[str | None] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.path == "/v1/exchange/balance":
            return self._balance(request)
        if request.url.path == f"/v1/accounts/{self.account_id}/card":
            self.card_authorization.append(request.headers.get("authorization"))
            return self._card()
        if request.url.path == f"/api/v1/accounts/{self.account_id}":
            body = self.account_body or {"reputation": self.reputation}
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": "not_found"})

    def _balance(self, request: httpx.Request) -> httpx.Response:
        if self.balance_mode == "down":
            raise httpx.ConnectError("down")
        if self.balance_mode == "unauthorized":
            return httpx.Response(401, json={"echo": self.secret})
        if self.balance_mode == "status_500":
            return httpx.Response(500, json={"echo": self.secret})
        if request.headers.get("authorization") != f"Bearer {self.secret}":
            return httpx.Response(401, json={"echo": self.secret})
        account_id = "someone-else" if self.balance_mode == "mismatch" else self.account_id
        return httpx.Response(200, json={
            "account_id": account_id,
            "bot_name": "pilot-bot",
            "reputation": self.reputation,
            "account_status": self.status,
        })

    def _card(self) -> httpx.Response:
        if self.card_status == 404:
            return httpx.Response(404, json={"error": "not_found"})
        if self.card_status != 200:
            return httpx.Response(self.card_status, json={"echo": self.secret})
        return httpx.Response(200, json={
            "agent_id": self.account_id,
            "kya_level_verified": self.kya,
            "card": {},
        })


def install_exchange(monkeypatch, fake: FakeExchange) -> None:
    transport = httpx.MockTransport(fake.handler)

    def _client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr("mcp_trust_gateway.trust.evaluator.exchange_client", _client)


def assert_secret_hidden(response, caplog, secret: str) -> None:
    assert secret not in response.text
    assert secret not in caplog.text
    for value in response.headers.values():
        assert secret not in value


def _decode(token: str, public_pem: bytes) -> dict:
    return pyjwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
    )


def _b64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _post_token(client: TestClient, how: str, *, scope: str, agent: str = AGENT, secret: str = SECRET):
    body = {
        "grant_type": "client_credentials",
        "client_id": agent,
        "client_secret": secret,
        "scope": scope,
    }
    if how == "json":
        return client.post("/oauth/token", json=body)
    return client.post("/oauth/token", data=body)


class TestClientCredentials:
    @pytest.mark.parametrize("how", ["json", "form"])
    def test_success_contract(self, client, public_pem, monkeypatch, caplog, how):
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", " acct-pilot-1, , other ")
        fake = FakeExchange(SECRET, AGENT, reputation=0.25, kya=0)
        install_exchange(monkeypatch, fake)

        resp = _post_token(client, how, scope="mcp:read mcp:tool:financial")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3600
        assert "mcp:tool:financial" in body["scope"].split()
        token = body["access_token"]
        payload = _decode(token, public_pem)
        assert payload["sub"] == f"agent:{AGENT}"
        assert payload["iss"] == ISSUER
        assert payload["aud"] == AUDIENCE
        assert isinstance(payload["iat"], int)
        assert isinstance(payload["exp"], int)
        assert payload["exp"] - payload["iat"] == 3600
        assert isinstance(payload["jti"], str) and payload["jti"]
        claims = payload[CLAIMS]
        assert claims["agent_id"] == AGENT
        assert type(claims["agent_id"]) is str
        assert claims["org_id"] == ""
        assert type(claims["org_id"]) is str
        trust = claims["trust"]
        assert type(trust["kya_level"]) is int
        assert trust["kya_level"] == 0
        assert trust["reputation"] == pytest.approx(0.25)
        assert 0.0 <= trust["effective_trust"] <= 1.0
        assert trust["effective_trust"] == pytest.approx(0.25)
        assert SECRET not in json.dumps(payload)
        assert_secret_hidden(resp, caplog, SECRET)
        assert fake.card_authorization
        assert all(SECRET not in (item or "") for item in fake.card_authorization)

        jwks = client.get("/.well-known/jwks.json")
        assert jwks.status_code == 200
        jwk = jwks.json()["keys"][0]
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"] == jwk["kid"]
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        numbers = serialization.load_pem_public_key(public_pem).public_numbers()
        assert jwk["n"] == _b64url_uint(numbers.n)
        assert jwk["e"] == _b64url_uint(numbers.e)
        assert jwk["kid"] == jwk_thumbprint({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]})
        meta = client.get("/.well-known/oauth-authorization-server").json()
        assert meta["jwks_uri"].endswith("/.well-known/jwks.json")
        assert "client_credentials" in meta["grant_types_supported"]

    def test_http_basic(self, client, public_pem, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", AGENT)
        fake = FakeExchange(SECRET, AGENT, reputation=0.25, kya=0)
        install_exchange(monkeypatch, fake)
        raw = base64.b64encode(f"{AGENT}:{SECRET}".encode()).decode()
        resp = client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "mcp:tool:financial"},
            headers={"Authorization": f"Basic {raw}"},
        )
        assert resp.status_code == 200, resp.text
        payload = _decode(resp.json()["access_token"], public_pem)
        assert payload["sub"] == f"agent:{AGENT}"
        assert "mcp:tool:financial" in payload["scope"].split()
        assert_secret_hidden(resp, caplog, SECRET)

    def test_card_404_is_kya_zero(self, client, public_pem, monkeypatch):
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", AGENT)
        fake = FakeExchange(SECRET, AGENT, card_status=404, reputation=0.25)
        install_exchange(monkeypatch, fake)
        resp = _post_token(client, "json", scope="mcp:read mcp:tool:financial")
        assert resp.status_code == 200, resp.text
        trust = _decode(resp.json()["access_token"], public_pem)[CLAIMS]["trust"]
        assert trust["kya_level"] == 0
        assert type(trust["kya_level"]) is int

    def test_card_500_fails_closed(self, client, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", AGENT)
        fake = FakeExchange(SECRET, AGENT, card_status=500)
        install_exchange(monkeypatch, fake)
        resp = _post_token(client, "json", scope="mcp:read")
        assert resp.status_code == 503
        assert resp.json()["error"] == "temporarily_unavailable"
        assert "access_token" not in resp.json()
        assert_secret_hidden(resp, caplog, SECRET)

    @pytest.mark.parametrize(
        ("mode", "status", "error"),
        [
            ("unauthorized", 401, "invalid_client"),
            ("mismatch", 401, "invalid_client"),
            ("suspended", 401, "invalid_client"),
            ("down", 503, "temporarily_unavailable"),
            ("status_500", 503, "temporarily_unavailable"),
        ],
    )
    def test_balance_failures(self, client, monkeypatch, caplog, mode, status, error):
        caplog.set_level(logging.DEBUG)
        status_name = "suspended" if mode == "suspended" else "active"
        balance_mode = "ok" if mode == "suspended" else mode
        fake = FakeExchange(
            SECRET,
            AGENT,
            status=status_name,
            balance_mode=balance_mode,
        )
        install_exchange(monkeypatch, fake)
        resp = _post_token(client, "json", scope="mcp:read")
        assert resp.status_code == status, resp.text
        assert resp.json()["error"] == error
        assert "access_token" not in resp.json()
        assert_secret_hidden(resp, caplog, SECRET)
        assert not any(path.endswith("/card") for path in fake.paths)


class TestFinancialAllowlist:
    def test_unlisted_kya3_denied(self, client, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", "acct-pilot-1")
        agent = "acct-kya3"
        fake = FakeExchange(SECRET, agent, kya=3, reputation=0.9)
        install_exchange(monkeypatch, fake)
        resp = _post_token(
            client,
            "json",
            scope="mcp:read mcp:tool:financial",
            agent=agent,
        )
        assert resp.status_code == 403, resp.text
        body = resp.json()
        assert body["error"] == "insufficient_kya_level"
        assert body["reason"] == "not_in_pilot_allowlist"
        assert body["current_kya_level"] == 3
        assert "mcp:tool:financial" in body["denied_scopes"]
        assert "mcp:read" in body["granted_scopes"]
        assert "access_token" not in body
        assert_secret_hidden(resp, caplog, SECRET)

    def test_empty_allowlist_keeps_kya_rules(self, client, public_pem, monkeypatch):
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", " , ")
        low = FakeExchange(SECRET, "acct-low", kya=0, reputation=0.4)
        install_exchange(monkeypatch, low)
        denied = _post_token(client, "json", scope="mcp:tool:financial", agent="acct-low")
        assert denied.status_code == 403, denied.text
        body = denied.json()
        assert body["error"] == "insufficient_kya_level"
        assert "reason" not in body
        assert body["current_kya_level"] == 0

        high = FakeExchange(SECRET, "acct-high", kya=2, reputation=0.4)
        install_exchange(monkeypatch, high)
        allowed = _post_token(client, "json", scope="mcp:tool:financial", agent="acct-high")
        assert allowed.status_code == 200, allowed.text
        payload = _decode(allowed.json()["access_token"], public_pem)
        assert "mcp:tool:financial" in payload["scope"].split()
        assert payload[CLAIMS]["trust"]["kya_level"] == 2


class TestAuthorizeDisabled:
    def test_both_endpoints_reject_code_flow(self, client):
        authorize = client.get("/oauth/authorize", params={
            "response_type": "code",
            "client_id": AGENT,
            "code_challenge": "abc",
            "scope": "mcp:tool:financial",
        })
        assert authorize.status_code == 400
        assert authorize.json()["error"] == "unsupported_response_type"
        assert "client_credentials" in authorize.json()["error_description"]

        token = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": "not-a-code",
            "code_verifier": "not-a-verifier",
        })
        assert token.status_code == 400
        assert token.json()["error"] == "unsupported_grant_type"
        assert "client_credentials" in token.json()["error_description"]

    def test_enabled_code_flow_reads_card(self, client, public_pem, monkeypatch):
        monkeypatch.setenv("OAUTH_AUTHORIZE_ENABLED", "true")
        monkeypatch.delenv("MCP_TRUST_FINANCIAL_ALLOWLIST", raising=False)
        agent = "acct-code-flow"
        fake = FakeExchange(
            SECRET,
            agent,
            reputation=0.66,
            kya=2,
            account_body={"reputation": 0.66, "account_id": agent},
        )
        install_exchange(monkeypatch, fake)
        verifier = "a" * 64
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        issued = client.get("/oauth/authorize", params={
            "response_type": "code",
            "client_id": agent,
            "agent_id": agent,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:tool:financial",
        })
        assert issued.status_code == 200, issued.text
        assert f"/v1/accounts/{agent}/card" in fake.paths
        code = issued.json()["code"]
        traded = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        })
        assert traded.status_code == 200, traded.text
        payload = _decode(traded.json()["access_token"], public_pem)
        assert payload[CLAIMS]["trust"]["kya_level"] == 2
        assert payload[CLAIMS]["trust"]["reputation"] == pytest.approx(0.66)
        assert "mcp:tool:financial" in payload["scope"].split()


class TestSigningConfig:
    def test_rfc7638_thumbprint_vector(self):
        kid = jwk_thumbprint({"kty": "RSA", "n": RFC_N, "e": "AQAB"})
        assert kid == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    def test_hmac_minimum_length(self, monkeypatch):
        monkeypatch.delenv("OAUTH_SIGNING_KEY_FILE", raising=False)
        monkeypatch.setenv("OAUTH_ALGORITHM", "HS256")
        monkeypatch.setenv("OAUTH_SIGNING_KEY", "a" * 31)
        with pytest.raises(SigningConfigError, match="32"):
            validate_signing_config()
        monkeypatch.setenv("OAUTH_SIGNING_KEY", "a" * 32)
        validate_signing_config()

    def test_rejects_algorithm_none(self, monkeypatch):
        monkeypatch.delenv("OAUTH_SIGNING_KEY_FILE", raising=False)
        monkeypatch.setenv("OAUTH_ALGORITHM", "none")
        secret = "n" * 40
        monkeypatch.setenv("OAUTH_SIGNING_KEY", secret)
        with pytest.raises(SigningConfigError, match="none") as exc:
            create_app()
        assert secret not in str(exc.value)

    def test_startup_rejects_mismatched_key(self, monkeypatch):
        monkeypatch.delenv("OAUTH_SIGNING_KEY_FILE", raising=False)
        private = ec.generate_private_key(ec.SECP256R1())
        pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        monkeypatch.setenv("OAUTH_ALGORITHM", "RS256")
        monkeypatch.setenv("OAUTH_SIGNING_KEY", pem)
        with pytest.raises(SigningConfigError, match="RSA") as exc:
            create_app()
        message = str(exc.value)
        assert "BEGIN" not in message
        assert pem.splitlines()[1] not in message

    def test_missing_key_file_does_not_fall_back(self, monkeypatch, tmp_path):
        secret = "fallback-hmac-secret-should-not-appear"
        monkeypatch.setenv("OAUTH_SIGNING_KEY_FILE", str(tmp_path / "missing.pem"))
        monkeypatch.setenv("OAUTH_SIGNING_KEY", secret)
        monkeypatch.setenv("OAUTH_ALGORITHM", "HS256")
        with pytest.raises(SigningConfigError, match="OAUTH_SIGNING_KEY_FILE") as exc:
            validate_signing_config()
        assert secret not in str(exc.value)

    def test_allowlist_parsing(self, monkeypatch):
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", " a, ,b ,")
        assert get_financial_allowlist() == {"a", "b"}
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", "")
        assert get_financial_allowlist() == set()
