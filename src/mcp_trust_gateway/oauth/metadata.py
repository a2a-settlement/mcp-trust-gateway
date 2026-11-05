"""RFC 8414 / RFC 9728 metadata endpoints for the gateway.

Publishes authorization server metadata and protected resource metadata
so MCP clients can discover the gateway's OAuth and trust capabilities.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from ..config import (
    get_exchange_url,
    get_max_delegation_depth,
    get_oauth_authorize_enabled,
    get_oauth_issuer,
    get_trust_decay_factor,
)
from .keys import SigningConfigError, jwks_document
from ..trust.scope_mapper import MCPScope, KYA_LEVEL_NAMES, KYALevel


def _base(request: Request) -> str:
    issuer = get_oauth_issuer()
    if issuer:
        return issuer.rstrip("/")
    return str(request.base_url).rstrip("/")


def _jwks_uri(base: str) -> str | None:
    try:
        document = jwks_document()
    except SigningConfigError:
        return None
    if document is None:
        return None
    return f"{base}/.well-known/jwks.json"


async def authorization_server_metadata(request: Request) -> JSONResponse:
    """GET /.well-known/oauth-authorization-server — RFC 8414."""
    base = _base(request)
    grant_types = [
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ]
    response_types: list[str] = []
    if get_oauth_authorize_enabled():
        grant_types.insert(0, "authorization_code")
        response_types = ["code"]
    body = {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "scopes_supported": [s.value for s in MCPScope] + [
            "settlement:read",
            "settlement:transact",
        ],
        "response_types_supported": response_types,
        "grant_types_supported": grant_types,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_exchange_trust_decay": True,
    }
    jwks_uri = _jwks_uri(base)
    if jwks_uri:
        body["jwks_uri"] = jwks_uri
    return JSONResponse(body)


async def protected_resource_metadata(request: Request) -> JSONResponse:
    """GET /.well-known/oauth-protected-resource — RFC 9728."""
    base = _base(request)
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "scopes_supported": [s.value for s in MCPScope] + [
            "settlement:read",
            "settlement:transact",
        ],
        "bearer_methods_supported": ["header"],
        "trust_extension": {
            "spec_version": "0.1.0",
            "kya_levels": [
                {
                    "level": level.value,
                    "name": KYA_LEVEL_NAMES[level],
                    "description": {
                        KYALevel.SANDBOX: "Unverified identity",
                        KYALevel.ORGANIZATIONAL: "Organization-verified identity",
                        KYALevel.AUDITABLE: "Cryptographically verifiable identity",
                    }[level],
                }
                for level in KYALevel
            ],
            "trust_decay_factor": get_trust_decay_factor(),
            "max_delegation_depth": get_max_delegation_depth(),
            "exchange_url": get_exchange_url(),
            "pre_auth_discovery": "/.well-known/mcp-tools",
        },
    })
