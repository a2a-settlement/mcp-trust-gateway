"""Tests for RFC 8693 token exchange with trust decay."""

import time

import pytest
import jwt as pyjwt

from mcp_trust_gateway.oauth.token_exchange import handle_token_exchange

CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"
SIGNING_KEY = "test-secret-key-for-tests-32b-minimum"
ALGORITHM = "HS256"
AUDIENCE = "https://gateway.a2a-settlement.org"


@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.delenv("OAUTH_SIGNING_KEY_FILE", raising=False)
    monkeypatch.delenv("MCP_TRUST_FINANCIAL_ALLOWLIST", raising=False)
    monkeypatch.setenv("OAUTH_ALGORITHM", ALGORITHM)
    monkeypatch.setenv("OAUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("OAUTH_ISSUER", "https://test-issuer.example.com")
    monkeypatch.setenv("MCP_TRUST_DECAY_FACTOR", "0.85")
    monkeypatch.setenv("MCP_TRUST_MAX_DELEGATION_DEPTH", "5")


def _make_parent_token(
    agent_id="parent-agent",
    scopes="mcp:read mcp:tool:invoke mcp:tool:write",
    reputation=0.92,
    kya_level=2,
    transferable=True,
    delegation_chain=None,
    key=None,
    algorithm=None,
) -> str:
    now = int(time.time())
    chain = delegation_chain or [
        {"principal": "user:alice@acme.com", "delegated_at": "2026-01-01T00:00:00Z"}
    ]
    payload = {
        "sub": f"agent:{agent_id}",
        "iss": "https://test-issuer.example.com",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "jti": "parent-jti-001",
        "scope": scopes,
        CLAIMS_NAMESPACE: {
            "agent_id": agent_id,
            "org_id": "org-acme",
            "spending_limits": {
                "per_transaction": 500,
                "per_day": 5000,
            },
            "counterparty_policy": {},
            "delegation": {
                "chain": chain,
                "transferable": transferable,
            },
            "trust": {
                "kya_level": kya_level,
                "reputation": reputation,
                "effective_trust": reputation,
                "delegation_depth": len(chain),
                "decay_factor": 0.85,
            },
        },
    }
    return pyjwt.encode(
        payload,
        SIGNING_KEY if key is None else key,
        algorithm=ALGORITHM if algorithm is None else algorithm,
    )


class TestTokenExchange:
    @pytest.mark.asyncio
    async def test_successful_exchange(self):
        parent_token = _make_parent_token()
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read mcp:tool:invoke",
            "actor_token_agent_id": "child-agent",
        })
        body = resp.body
        import json
        data = json.loads(body)
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "trust_metadata" in data
        meta = data["trust_metadata"]
        assert meta["delegation_depth"] == 2
        assert meta["effective_trust"] < 0.92

    @pytest.mark.asyncio
    async def test_non_transferable_rejected(self):
        parent_token = _make_parent_token(transferable=False)
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        assert data.get("error") == "delegation_not_transferable"

    @pytest.mark.asyncio
    async def test_scope_narrowing(self):
        parent_token = _make_parent_token(scopes="mcp:read mcp:tool:invoke mcp:tool:write")
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        assert "mcp:read" in data["scope"]
        assert "mcp:tool:write" not in data["scope"]

    @pytest.mark.asyncio
    async def test_max_depth_rejected(self, monkeypatch):
        monkeypatch.setenv("MCP_TRUST_MAX_DELEGATION_DEPTH", "2")
        chain = [
            {"principal": "user:a@x.com", "delegated_at": "2026-01-01T00:00:00Z"},
            {"principal": "agent:b", "delegated_at": "2026-01-01T01:00:00Z"},
        ]
        parent_token = _make_parent_token(delegation_chain=chain)
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        assert data.get("error") == "max_delegation_depth"

    @pytest.mark.asyncio
    async def test_spending_limits_reduced(self):
        parent_token = _make_parent_token()
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        child_token = data["access_token"]
        child_payload = pyjwt.decode(
            child_token, SIGNING_KEY, algorithms=[ALGORITHM],
            audience=AUDIENCE,
        )
        child_claims = child_payload[CLAIMS_NAMESPACE]
        child_limits = child_claims["spending_limits"]
        # Spending limits should be reduced from parent's 500/5000
        assert child_limits["per_transaction"] < 500
        assert child_limits["per_day"] < 5000

    @pytest.mark.asyncio
    async def test_invalid_subject_token_type(self):
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "something",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        })
        import json
        data = json.loads(resp.body)
        assert data.get("error") == "invalid_request"


class TestTokenExchangeRS256:
    @pytest.mark.asyncio
    async def test_rs256_round_trip_and_allowlist(self, monkeypatch, tmp_path):
        """Public-key verification, and financial scope cannot be gained or kept
        for an unlisted actor. The actor id is not authenticated.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from mcp_trust_gateway.oauth.keys import jwks_document

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        path = tmp_path / "signing.pem"
        path.write_bytes(private_pem)
        monkeypatch.setenv("OAUTH_SIGNING_KEY_FILE", str(path))
        monkeypatch.setenv("OAUTH_ALGORITHM", "RS256")
        monkeypatch.setenv("MCP_TRUST_FINANCIAL_ALLOWLIST", "listed-agent")

        parent = _make_parent_token(
            scopes="mcp:read mcp:tool:financial",
            kya_level=0,
            reputation=0.4,
            key=private_pem,
            algorithm="RS256",
        )
        listed = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read mcp:tool:financial",
            "actor_token_agent_id": "listed-agent",
        })
        import json
        listed_body = json.loads(listed.body)
        assert listed.status_code == 200, listed_body
        child = pyjwt.decode(
            listed_body["access_token"],
            public_pem,
            algorithms=["RS256"],
            audience=AUDIENCE,
        )
        assert "mcp:tool:financial" in child["scope"].split()
        claims = child[CLAIMS_NAMESPACE]
        assert claims["trust"]["kya_level"] == 0
        assert type(claims["trust"]["kya_level"]) is int
        header = pyjwt.get_unverified_header(listed_body["access_token"])
        jwk = jwks_document()["keys"][0]
        assert header["kid"] == jwk["kid"]
        assert header["alg"] == "RS256"

        denied = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read mcp:tool:financial",
            "actor_token_agent_id": "other-agent",
        })
        denied_body = json.loads(denied.body)
        assert denied.status_code == 403, denied_body
        assert denied_body["error"] == "insufficient_kya_level"
        assert denied_body["reason"] == "not_in_pilot_allowlist"

        narrowed = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "other-agent",
        })
        narrowed_body = json.loads(narrowed.body)
        assert narrowed.status_code == 200, narrowed_body
        assert "mcp:read" in narrowed_body["scope"].split()
        assert "mcp:tool:financial" not in narrowed_body["scope"].split()

        read_only = _make_parent_token(
            scopes="mcp:read",
            kya_level=0,
            key=private_pem,
            algorithm="RS256",
        )
        no_gain = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": read_only,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read mcp:tool:financial",
            "actor_token_agent_id": "listed-agent",
        })
        no_gain_body = json.loads(no_gain.body)
        assert no_gain.status_code == 200, no_gain_body
        assert "mcp:tool:financial" not in no_gain_body["scope"].split()
        assert "mcp:read" in no_gain_body["scope"].split()
