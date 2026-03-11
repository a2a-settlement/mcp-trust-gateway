"""OAuth 2.1 Authorization Code + PKCE provider with settlement trust claims.

Issues tokens enriched with KYA level, EMA reputation, spending limits,
and delegation chains from the A2A Settlement Exchange.
"""

from __future__ import annotations

import hashlib
import base64
import secrets
import time
import uuid
from typing import Optional

import jwt as pyjwt
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from ..config import (
    get_oauth_issuer,
    get_oauth_signing_key,
    get_oauth_algorithm,
    get_oauth_token_ttl,
    get_oauth_audience,
    get_trust_decay_factor,
)
from ..trust.evaluator import fetch_agent_reputation, fetch_agent_kya_level
from ..trust.scope_mapper import (
    KYALevel,
    filter_scopes_by_kya,
    max_kya_for_scopes,
    KYA_LEVEL_NAMES,
)
from ..trust.trust_decay import compute_trust_score

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


async def authorize_endpoint(request: Request) -> JSONResponse:
    """Handle GET /oauth/authorize — initiate Authorization Code + PKCE flow.

    In a full implementation this would render a consent screen or redirect
    to an upstream IdP. For the reference implementation, it accepts
    agent_id + api_key as query params and issues a code directly.
    """
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

    # Fetch trust data from exchange
    reputation = await fetch_agent_reputation(agent_id)
    kya_level = await fetch_agent_kya_level(agent_id)
    if reputation is None:
        reputation = 0.5
    if kya_level is None:
        kya_level = 0

    requested_scopes = set(scope.split())
    granted_scopes = filter_scopes_by_kya(requested_scopes, kya_level)
    max_required = max_kya_for_scopes(requested_scopes)

    if max_required > kya_level:
        denied = requested_scopes - granted_scopes
        return JSONResponse({
            "error": "insufficient_kya_level",
            "error_description": (
                f"Requested scopes require KYA level {KYA_LEVEL_NAMES.get(max_required, str(max_required))}. "
                f"Agent has level {KYA_LEVEL_NAMES.get(kya_level, str(kya_level))}."
            ),
            "denied_scopes": sorted(denied),
            "granted_scopes": sorted(granted_scopes),
            "required_kya_level": max_required,
            "current_kya_level": kya_level,
        }, status_code=403)

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
    """Handle POST /oauth/token — exchange code for access token.

    Supports grant_type=authorization_code (with PKCE) and
    grant_type=urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693).
    """
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type", "")

    if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        from .token_exchange import handle_token_exchange
        return await handle_token_exchange(body)

    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type"},
            status_code=400,
        )

    code = body.get("code", "")
    code_verifier = body.get("code_verifier", "")

    code_data = _auth_codes.pop(code, None)
    pkce_data = _pkce_challenges.pop(code, None)

    if code_data is None:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired code"}, status_code=400)

    # Code expiry (5 minutes)
    if time.time() - code_data["created_at"] > 300:
        return JSONResponse({"error": "invalid_grant", "error_description": "Code expired"}, status_code=400)

    # PKCE verification
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

    agent_id = code_data["agent_id"]
    kya_level = code_data["kya_level"]
    reputation = code_data["reputation"]
    scope_str = code_data["scope"]

    trust = compute_trust_score(reputation, kya_level, delegation_depth=0)

    now = int(time.time())
    ttl = get_oauth_token_ttl()
    jti = str(uuid.uuid4())

    payload = {
        "sub": f"agent:{agent_id}",
        "iss": get_oauth_issuer() or str(request.base_url).rstrip("/"),
        "aud": get_oauth_audience(),
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
        "scope": scope_str,
        CLAIMS_NAMESPACE: {
            "agent_id": agent_id,
            "org_id": "",
            "spending_limits": {},
            "counterparty_policy": {},
            "delegation": {
                "chain": [],
                "transferable": False,
            },
            "trust": trust.summary,
        },
    }

    signing_key = get_oauth_signing_key()
    algorithm = get_oauth_algorithm()

    if not signing_key:
        return JSONResponse(
            {"error": "server_error", "error_description": "OAUTH_SIGNING_KEY not configured"},
            status_code=500,
        )

    token = pyjwt.encode(payload, signing_key, algorithm=algorithm)

    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": scope_str,
    })
