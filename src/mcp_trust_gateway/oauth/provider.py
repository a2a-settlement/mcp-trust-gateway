"""OAuth 2.1 token provider with settlement trust claims.

The production grant is ``client_credentials``: ``client_id`` is the exchange
account id and ``client_secret`` is that bot's ``ate_`` API key. The secret is
used once, on the exchange balance request, and is never stored, logged, or
copied into an error.

``GET /oauth/authorize`` and ``grant_type=authorization_code`` stay available
only when ``OAUTH_AUTHORIZE_ENABLED`` is true. That legacy path does not
check an API key.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from urllib.parse import unquote_plus

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from ..config import (
    get_financial_allowlist,
    get_oauth_audience,
    get_oauth_authorize_enabled,
    get_oauth_issuer,
    get_oauth_token_ttl,
)
from ..trust.evaluator import (
    ExchangeUnavailable,
    authenticate_exchange_api_key,
    fetch_agent_kya_level,
    fetch_agent_reputation,
)
from ..trust.scope_mapper import decide_scopes, kya_denial_body
from ..trust.trust_decay import compute_trust_score
from .keys import SigningConfigError, encode_jwt

logger = logging.getLogger("mcp_trust_gateway.oauth")

CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"

# In-memory stores (production would use Redis/DB)
_auth_codes: dict[str, dict] = {}
_pkce_challenges: dict[str, dict] = {}


def _generate_code() -> str:
    return secrets.token_urlsafe(32)


def _verify_pkce(verifier: str, challenge: str, method: str = "S256") -> bool:
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return computed == challenge
    return verifier == challenge


def _issuer(request: Request) -> str:
    return get_oauth_issuer() or str(request.base_url).rstrip("/")


def mint_access_token(
    *,
    agent_id: str,
    scope: str,
    reputation: float,
    kya_level: int,
    issuer: str,
    org_id: str = "",
) -> tuple[str, int]:
    """Mint the gateway access token used by both token grants.

    ``kya_level`` is the agent's real KYA level. The pilot allowlist can
    change which scopes are granted; it does not change this claim.
    """
    trust = compute_trust_score(reputation, int(kya_level), delegation_depth=0)
    now = int(time.time())
    ttl = get_oauth_token_ttl()
    payload = {
        "sub": f"agent:{agent_id}",
        "iss": issuer,
        "aud": get_oauth_audience(),
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "scope": scope,
        CLAIMS_NAMESPACE: {
            "agent_id": agent_id,
            "org_id": org_id,
            "spending_limits": {},
            "counterparty_policy": {},
            "delegation": {
                "chain": [],
                "transferable": False,
            },
            "trust": trust.summary,
        },
    }
    return encode_jwt(payload), ttl


def _signing_error() -> JSONResponse:
    return JSONResponse(
        {"error": "server_error", "error_description": "Token signing is not configured"},
        status_code=500,
    )


def _invalid_client() -> JSONResponse:
    return JSONResponse(
        {"error": "invalid_client", "error_description": "Client authentication failed"},
        status_code=401,
    )


def _unavailable(description: str) -> JSONResponse:
    return JSONResponse(
        {"error": "temporarily_unavailable", "error_description": description},
        status_code=503,
    )


class _BadClientAuth(Exception):
    """HTTP Basic was present but could not be decoded."""


@dataclass
class _ClientAuth:
    client_id: str
    client_secret: str

    def __repr__(self) -> str:
        return f"_ClientAuth(client_id={self.client_id!r}, client_secret='***')"


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    return ""


def _basic_pair(authorization: str) -> tuple[str, str] | None:
    """Return Basic credentials, or None when the header is not Basic."""
    if not authorization:
        return None
    scheme, _, rest = authorization.partition(" ")
    if scheme.lower() != "basic":
        return None
    token = rest.strip()
    if not token:
        raise _BadClientAuth()
    padded = token + "=" * (-len(token) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except Exception:
        raise _BadClientAuth() from None
    if ":" not in decoded:
        raise _BadClientAuth()
    client_id, client_secret = decoded.split(":", 1)
    return unquote_plus(client_id).strip(), unquote_plus(client_secret)


def _resolve_client_auth(request: Request, body: dict) -> _ClientAuth | JSONResponse:
    """Accept form/JSON client credentials and HTTP Basic.

    When both are present they must agree. A malformed Basic header is
    rejected instead of falling through to the body.
    """
    try:
        basic = _basic_pair(request.headers.get("authorization", ""))
    except _BadClientAuth:
        return _invalid_client()
    body_id = _text(body.get("client_id")).strip()
    body_secret = _text(body.get("client_secret"))
    if basic is None:
        client_id, client_secret = body_id, body_secret
    else:
        basic_id, basic_secret = basic
        if (body_id and body_id != basic_id) or (body_secret and body_secret != basic_secret):
            return _invalid_client()
        client_id, client_secret = basic_id, basic_secret
    if not client_id or any(ch.isspace() for ch in client_id) or not client_secret:
        return _invalid_client()
    return _ClientAuth(client_id, client_secret)


def _requested_scopes(raw: object, *, default: str) -> set[str]:
    if not isinstance(raw, str) or not raw.strip():
        raw = default
    return {part for part in raw.split() if part}


async def authorize_endpoint(request: Request) -> JSONResponse | RedirectResponse:
    """Handle GET /oauth/authorize — legacy Authorization Code + PKCE flow."""
    if not get_oauth_authorize_enabled():
        return JSONResponse(
            {
                "error": "unsupported_response_type",
                "error_description": (
                    "Authorization code grant is disabled. "
                    "Request a token with grant_type=client_credentials."
                ),
            },
            status_code=400,
        )

    params = dict(request.query_params)

    response_type = params.get("response_type", "")
    if response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type", "error_description": "Only 'code' is supported"},
            status_code=400,
        )

    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    scope = params.get("scope", "mcp:read")
    state = params.get("state", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "S256")

    agent_id = params.get("agent_id", client_id)

    if not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "PKCE code_challenge is required"},
            status_code=400,
        )

    reputation = await fetch_agent_reputation(agent_id)
    kya_level = await fetch_agent_kya_level(agent_id)
    if reputation is None:
        reputation = 0.5
    if kya_level is None:
        return _unavailable("KYA lookup failed")

    requested_scopes = _requested_scopes(scope, default="")
    decision = decide_scopes(
        requested_scopes,
        agent_id,
        kya_level,
        get_financial_allowlist(),
    )
    if decision.denied:
        return JSONResponse(
            kya_denial_body(requested_scopes, decision, kya_level),
            status_code=403,
        )
    granted_scopes = set(decision.granted)

    code = _generate_code()
    _auth_codes[code] = {
        "agent_id": agent_id,
        "client_id": client_id,
        "scope": " ".join(sorted(granted_scopes)),
        "redirect_uri": redirect_uri,
        "reputation": reputation,
        "kya_level": kya_level,
        "created_at": time.time(),
    }
    _pkce_challenges[code] = {
        "challenge": code_challenge,
        "method": code_challenge_method,
    }

    if redirect_uri:
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={code}"
        if state:
            location += f"&state={state}"
        return RedirectResponse(location, status_code=302)

    return JSONResponse({
        "code": code,
        "state": state,
        "granted_scopes": sorted(granted_scopes),
    })


async def token_endpoint(request: Request) -> JSONResponse:
    """Handle POST /oauth/token.

    Supports ``client_credentials``, and, when enabled, ``authorization_code``
    with PKCE. Also supports RFC 8693 token exchange.
    """
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Expected JSON body"},
                status_code=400,
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Expected JSON object"},
                status_code=400,
            )
    else:
        try:
            form = await request.form()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Expected form or JSON body"},
                status_code=400,
            )
        body = dict(form)

    grant_type = _text(body.get("grant_type"))

    if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        from .token_exchange import handle_token_exchange
        return await handle_token_exchange(body)

    if grant_type == "client_credentials":
        return await _client_credentials(request, body)

    if grant_type == "authorization_code":
        if not get_oauth_authorize_enabled():
            return JSONResponse(
                {
                    "error": "unsupported_grant_type",
                    "error_description": (
                        "authorization_code is disabled. Use grant_type=client_credentials."
                    ),
                },
                status_code=400,
            )
        return await _authorization_code(request, body)

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def _client_credentials(request: Request, body: dict) -> JSONResponse:
    auth = _resolve_client_auth(request, body)
    if isinstance(auth, JSONResponse):
        return auth
    try:
        principal = await authenticate_exchange_api_key(auth.client_id, auth.client_secret)
    except ExchangeUnavailable:
        return _unavailable("Exchange is unavailable")
    if principal is None:
        return _invalid_client()

    kya_level = await fetch_agent_kya_level(principal.account_id)
    if kya_level is None:
        return _unavailable("KYA lookup failed")

    requested = _requested_scopes(body.get("scope"), default="mcp:read")
    decision = decide_scopes(
        requested,
        principal.account_id,
        kya_level,
        get_financial_allowlist(),
    )
    if decision.denied:
        return JSONResponse(kya_denial_body(requested, decision, kya_level), status_code=403)

    scope_str = " ".join(sorted(decision.granted))
    try:
        token, ttl = mint_access_token(
            agent_id=principal.account_id,
            scope=scope_str,
            reputation=principal.reputation,
            kya_level=kya_level,
            issuer=_issuer(request),
        )
    except SigningConfigError:
        logger.error("token signing is not configured")
        return _signing_error()
    except Exception as exc:
        logger.error("token signing failed: %s", type(exc).__name__)
        return _signing_error()
    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": scope_str,
    })


async def _authorization_code(request: Request, body: dict) -> JSONResponse:
    code = _text(body.get("code"))
    code_verifier = _text(body.get("code_verifier"))

    code_data = _auth_codes.pop(code, None)
    pkce_data = _pkce_challenges.pop(code, None)

    if code_data is None:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired code"},
            status_code=400,
        )

    if time.time() - code_data["created_at"] > 300:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Code expired"},
            status_code=400,
        )

    if pkce_data and code_verifier:
        if not _verify_pkce(code_verifier, pkce_data["challenge"], pkce_data.get("method", "S256")):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )
    elif pkce_data and not code_verifier:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "code_verifier required"},
            status_code=400,
        )

    scope_str = code_data["scope"]
    try:
        token, ttl = mint_access_token(
            agent_id=code_data["agent_id"],
            scope=scope_str,
            reputation=float(code_data["reputation"]),
            kya_level=int(code_data["kya_level"]),
            issuer=_issuer(request),
        )
    except SigningConfigError:
        logger.error("token signing is not configured")
        return _signing_error()
    except Exception as exc:
        logger.error("token signing failed: %s", type(exc).__name__)
        return _signing_error()

    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": scope_str,
    })
