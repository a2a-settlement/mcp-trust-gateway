"""MCP Trust Gateway — Starlette application wiring all components together.

Exposes:
  - OAuth 2.1 endpoints (authorize, token)
  - RFC 8414 / RFC 9728 metadata
  - Pre-auth tool discovery (/.well-known/mcp-tools)
  - MCP JSON-RPC endpoint with trust evaluation (/mcp)
  - Health check
"""

from __future__ import annotations

import json
import logging
import time

import jwt as pyjwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .config import (
    get_oauth_signing_key,
    get_oauth_algorithm,
    get_oauth_audience,
    get_trust_decay_factor,
    get_federation_enabled,
    get_federation_peers,
    get_trust_discount_algorithm,
    get_trust_discount_params,
    get_trust_discount_initial_rho,
    get_health_check_interval,
    get_rho_decay_rate,
)
from .discovery.registry import ToolRegistry
from .discovery.well_known import well_known_mcp_tools
from .oauth.metadata import authorization_server_metadata, protected_resource_metadata
from .oauth.provider import authorize_endpoint, token_endpoint
from .proxy import UpstreamProxy
from .trust.evaluator import TrustEvaluator
from .trust.scope_mapper import (
    requirements_from_annotations,
    default_requirements_for_scope,
    MCPScope,
)
from .trust.trust_decay import compute_trust_score

logger = logging.getLogger("mcp_trust_gateway")

CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"


def _extract_bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def _decode_token(raw: str) -> dict | None:
    signing_key = get_oauth_signing_key()
    algorithm = get_oauth_algorithm()
    audience = get_oauth_audience()
    if not signing_key:
        return None
    try:
        return pyjwt.decode(raw, signing_key, algorithms=[algorithm], audience=audience)
    except pyjwt.InvalidTokenError:
        return None


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "mcp-trust-gateway"})


async def mcp_endpoint(request: Request) -> JSONResponse:
    """Main MCP JSON-RPC endpoint with trust evaluation.

    Handles tools/list and tools/call, evaluating trust before
    proxying to upstream servers.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        }, status_code=400)

    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id", 1)

    evaluator: TrustEvaluator = request.app.state.trust_evaluator
    proxy: UpstreamProxy = request.app.state.upstream_proxy
    registry: ToolRegistry = request.app.state.tool_registry

    # tools/list does not require auth — returns trust-annotated tool list
    if method == "tools/list":
        tools = []
        for tool in registry.tools.values():
            reqs = tool.trust_requirements
            tools.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": {"type": "object"},
                "annotations": {
                    "trust": {
                        "required_kya_level": reqs.required_kya_level,
                        "required_reputation": reqs.required_reputation,
                        "required_scope": reqs.required_scope,
                        "economic_impact": reqs.economic_impact,
                    },
                },
            })
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": tools},
        })

    # All other methods require a valid token
    raw_token = _extract_bearer(request)
    if raw_token is None:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32001,
                "message": "Authentication required",
                "data": {"error_type": "authentication_required"},
            },
        }, status_code=401)

    token_payload = _decode_token(raw_token)
    if token_payload is None:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32001,
                "message": "Invalid or expired token",
                "data": {"error_type": "invalid_token"},
            },
        }, status_code=401)

    claims = token_payload.get(CLAIMS_NAMESPACE, {})
    trust_data = claims.get("trust", {})
    agent_id = claims.get("agent_id", token_payload.get("sub", ""))
    kya_level = int(trust_data.get("kya_level", 0))
    reputation = float(trust_data.get("reputation", 0.5))
    delegation_depth = int(trust_data.get("delegation_depth", 0))

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if not tool_name:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Missing tool name"},
            }, status_code=400)

        # Trust evaluation
        evaluation = await evaluator.evaluate(
            tool_name=tool_name,
            agent_id=agent_id,
            kya_level=kya_level,
            reputation=reputation,
            delegation_depth=delegation_depth,
        )

        if not evaluation.allowed:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32001,
                    "message": "Trust evaluation failed",
                    "data": evaluation.to_denial_data(),
                },
            }, status_code=403)

        # Proxy to upstream
        result = await proxy.proxy_tool_call(tool_name, arguments, req_id)

        # Log the successful evaluation
        logger.info(
            "trust_eval tool=%s agent=%s trust=%.4f allowed=True",
            tool_name, agent_id, evaluation.trust_score.effective_trust,
        )

        return JSONResponse(result)

    # Unknown method
    return JSONResponse({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }, status_code=400)


def create_app() -> Starlette:
    """Build the Starlette application with all routes and shared state."""
    registry = ToolRegistry()
    evaluator = TrustEvaluator()
    proxy = UpstreamProxy(registry)

    routes = [
        Route("/health", health, methods=["GET"]),

        # OAuth 2.1
        Route("/oauth/authorize", authorize_endpoint, methods=["GET"]),
        Route("/oauth/token", token_endpoint, methods=["POST"]),

        # RFC 8414 / RFC 9728 metadata
        Route("/.well-known/oauth-authorization-server", authorization_server_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),

        # Pre-auth tool discovery
        Route("/.well-known/mcp-tools", well_known_mcp_tools, methods=["GET"]),

        # MCP JSON-RPC
        Route("/mcp", mcp_endpoint, methods=["POST"]),
    ]

    # Federation support
    federation_health_monitor = None
    federation_well_known = None
    if get_federation_enabled():
        from .federation import AlgorithmRegistry, FederationHealthMonitor
        from .federation.well_known import FederationWellKnown

        algorithm_registry = AlgorithmRegistry()
        federation_health_monitor = FederationHealthMonitor(
            check_interval_seconds=get_health_check_interval(),
            decay_rate=get_rho_decay_rate(),
        )
        federation_well_known = FederationWellKnown(
            algorithm_id=get_trust_discount_algorithm(),
            initial_rho=get_trust_discount_initial_rho(),
            parameters=get_trust_discount_params(),
        )

        for peer_def in get_federation_peers():
            peer_did = peer_def.get("did", "")
            health_url = peer_def.get("health_url", "")
            if peer_did and health_url:
                federation_health_monitor.add_peer(peer_did, health_url)

        routes.append(
            Route(
                "/.well-known/a2a-trust-policy.json",
                federation_well_known.handle_trust_policy,
                methods=["GET"],
            )
        )

    app = Starlette(routes=routes)
    app.state.tool_registry = registry
    app.state.trust_evaluator = evaluator
    app.state.upstream_proxy = proxy
    app.state.federation_health_monitor = federation_health_monitor
    app.state.federation_well_known = federation_well_known

    @app.on_event("startup")
    async def _startup() -> None:
        await proxy.discover_all_upstream_tools()
        for name, tool in registry.tools.items():
            evaluator.register_tool(name, tool.trust_requirements)
        logger.info(
            "Gateway started: %d servers, %d tools",
            len(registry.servers),
            len(registry.tools),
        )
        if federation_health_monitor and get_federation_enabled():
            await federation_health_monitor.start()
            logger.info(
                "Federation health monitor started: %d peers",
                len(federation_health_monitor.all_peers()),
            )

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        if federation_health_monitor:
            await federation_health_monitor.stop()

    return app
