"""RFC 8693 Token Exchange with trust decay.

Implements the urn:ietf:params:oauth:grant-type:token-exchange grant type
extended with EMA-weighted trust decay for multi-hop delegation.

Each exchange:
  - Validates the parent (subject) token
  - Checks the transferable flag
  - Narrows scopes to the intersection of parent and requested
  - Applies trust decay (effective_trust *= decay_factor)
  - Reduces spending limits proportionally
  - Extends the delegation chain

Actor identity is not authenticated. ``actor_token_agent_id`` is copied from
the request body, so this grant only narrows scopes the parent token already
has. It never adds ``mcp:tool:financial`` because the named actor is on the
pilot allowlist. When that allowlist is non-empty, financial scope already on
the parent is kept only if the named actor id is listed; parent KYA is not
enough. An explicit ``scope`` that still includes financial after intersecting
with the parent is rejected with 403 ``insufficient_kya_level`` and
``reason=not_in_pilot_allowlist``. Omitting ``scope`` drops financial for an
unlisted actor and continues with the remaining parent scopes; if that leaves
nothing, the same 403 is returned. A caller who already holds a transferable
parent token that contains financial can keep it by naming an allowlisted id.
That id is not proof the caller controls the listed agent. The child token's
``trust.kya_level`` stays the parent token's KYA; this grant does not re-query
the exchange.
"""

from __future__ import annotations

import logging
import time
import uuid

import jwt as pyjwt
from starlette.responses import JSONResponse

from ..config import (
    get_financial_allowlist,
    get_max_delegation_depth,
    get_oauth_audience,
    get_oauth_issuer,
    get_oauth_token_ttl,
    get_trust_decay_factor,
)
from ..trust.scope_mapper import (
    MCPScope,
    kya_denial_body,
    narrow_delegated_scopes,
)
from ..trust.trust_decay import TrustScore, apply_delegation_decay
from .keys import SigningConfigError, decode_jwt, encode_jwt

logger = logging.getLogger("mcp_trust_gateway.oauth")

CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"


def _decode_parent(token_str: str) -> dict | None:
    """Decode and validate the parent JWT with the verification key.

    HMAC tokens use the shared secret. Asymmetric tokens use the public key
    derived from the configured private key, not the private key itself.
    """
    try:
        return decode_jwt(token_str, audience=get_oauth_audience())
    except pyjwt.InvalidTokenError:
        return None


def _reduce_spending_limits(parent_limits: dict, trust_ratio: float) -> dict:
    """Proportionally reduce spending limits based on trust decay."""
    reduced: dict = {}
    for key in ("per_transaction", "per_session", "per_hour", "per_day"):
        val = parent_limits.get(key)
        if val is not None:
            reduced[key] = round(float(val) * trust_ratio, 2)
    return reduced


async def handle_token_exchange(body: dict) -> JSONResponse:
    """Process an RFC 8693 token exchange request with trust decay."""
    subject_token = body.get("subject_token", "")
    subject_token_type = body.get("subject_token_type", "")
    requested_scope = body.get("scope", "")
    raw_actor = body.get("actor_token_agent_id", "")
    actor_agent_id = raw_actor.strip() if isinstance(raw_actor, str) else ""

    if subject_token_type != "urn:ietf:params:oauth:token-type:jwt":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Only JWT subject tokens are supported"},
            status_code=400,
        )

    if not subject_token:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "subject_token is required"},
            status_code=400,
        )

    parent = _decode_parent(subject_token)
    if parent is None:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired subject token"},
            status_code=400,
        )

    parent_claims = parent.get(CLAIMS_NAMESPACE, {})
    delegation = parent_claims.get("delegation", {})
    trust_data = parent_claims.get("trust", {})

    # Check transferable
    if not delegation.get("transferable", False):
        return JSONResponse(
            {"error": "delegation_not_transferable", "error_description": "Parent token does not allow sub-delegation"},
            status_code=403,
        )

    # Check max delegation depth
    chain = delegation.get("chain", [])
    current_depth = len(chain)
    max_depth = get_max_delegation_depth()
    if current_depth >= max_depth:
        return JSONResponse({
            "error": "max_delegation_depth",
            "error_description": f"Maximum delegation depth ({max_depth}) exceeded",
        }, status_code=403)

    # Narrow scopes. The actor id below is not authenticated; see the module docstring.
    parent_kya = int(trust_data.get("kya_level", 0))
    parent_scopes = {part for part in str(parent.get("scope", "")).split() if part}
    explicit = isinstance(requested_scope, str) and bool(requested_scope.strip())
    if explicit:
        requested_scopes = {part for part in requested_scope.split() if part}
    else:
        requested_scopes = set(parent_scopes)

    child_jti = str(uuid.uuid4())
    child_agent_id = actor_agent_id or f"delegate-{child_jti[:8]}"
    decision = narrow_delegated_scopes(
        parent_scopes,
        requested_scopes,
        actor_id=child_agent_id,
        parent_kya=parent_kya,
        allowlist=get_financial_allowlist(),
    )
    financial_denied = (
        decision.reason == "not_in_pilot_allowlist"
        and MCPScope.TOOL_FINANCIAL in decision.denied
    )
    explicit_financial = explicit and MCPScope.TOOL_FINANCIAL in requested_scopes
    if financial_denied and (explicit_financial or not decision.granted):
        return JSONResponse(
            kya_denial_body(requested_scopes, decision, parent_kya),
            status_code=403,
        )
    child_scopes = set(decision.granted)

    if not child_scopes:
        return JSONResponse(
            {"error": "invalid_scope", "error_description": "No valid scopes after narrowing"},
            status_code=400,
        )

    # Compute trust decay
    parent_trust = TrustScore(
        reputation=float(trust_data.get("reputation", 0.5)),
        kya_level=parent_kya,
        delegation_depth=int(trust_data.get("delegation_depth", 0)),
        decay_factor=float(trust_data.get("decay_factor", get_trust_decay_factor())),
        effective_trust=float(trust_data.get("effective_trust", 0.5)),
    )
    child_trust = apply_delegation_decay(parent_trust)

    # Reduce spending limits
    parent_limits = parent_claims.get("spending_limits", {})
    trust_ratio = child_trust.effective_trust / max(parent_trust.effective_trust, 0.001)
    child_limits = _reduce_spending_limits(parent_limits, trust_ratio)

    # Extend delegation chain
    parent_agent = parent_claims.get("agent_id", parent.get("sub", ""))
    new_link = {
        "principal": f"agent:{parent_agent}" if not parent_agent.startswith("agent:") else parent_agent,
        "delegated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    child_chain = chain + [new_link]

    # Child token cannot sub-delegate unless explicitly granted and KYA is AUDITABLE
    child_transferable = False

    # Build child token
    now = int(time.time())
    parent_exp = parent.get("exp", now + 3600)
    child_ttl = min(get_oauth_token_ttl(), int(parent_exp - now))
    child_ttl = max(child_ttl, 60)
    child_scope_str = " ".join(sorted(child_scopes))

    payload = {
        "sub": f"agent:{child_agent_id}",
        "iss": get_oauth_issuer() or "",
        "aud": get_oauth_audience(),
        "iat": now,
        "exp": now + child_ttl,
        "jti": child_jti,
        "scope": child_scope_str,
        CLAIMS_NAMESPACE: {
            "agent_id": child_agent_id,
            "org_id": parent_claims.get("org_id", ""),
            "spending_limits": child_limits,
            "counterparty_policy": parent_claims.get("counterparty_policy", {}),
            "delegation": {
                "chain": child_chain,
                "transferable": child_transferable,
            },
            "parent_jti": parent.get("jti", ""),
            "trust": child_trust.summary,
        },
    }

    try:
        token = encode_jwt(payload)
    except SigningConfigError:
        logger.error("token signing is not configured")
        return JSONResponse(
            {"error": "server_error", "error_description": "Token signing is not configured"},
            status_code=500,
        )
    except Exception as exc:
        logger.error("token signing failed: %s", type(exc).__name__)
        return JSONResponse(
            {"error": "server_error", "error_description": "Token signing is not configured"},
            status_code=500,
        )

    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": child_ttl,
        "scope": child_scope_str,
        "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "trust_metadata": {
            "effective_trust": round(child_trust.effective_trust, 4),
            "delegation_depth": child_trust.delegation_depth,
            "parent_trust": round(parent_trust.effective_trust, 4),
            "decay_applied": child_trust.decay_factor,
            "scopes_narrowed_from": " ".join(sorted(parent_scopes)),
            "spending_limits_reduced": child_limits != parent_limits,
        },
    })
