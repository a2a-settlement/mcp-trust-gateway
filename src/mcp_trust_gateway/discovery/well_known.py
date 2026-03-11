"""Pre-auth tool discovery endpoint — /.well-known/mcp-tools.

Exposes available tools and their trust requirements without requiring
authentication, per SPEC Section 5.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from ..trust.scope_mapper import scope_taxonomy
from .registry import ToolRegistry


async def well_known_mcp_tools(request: Request) -> JSONResponse:
    """Handler for GET /.well-known/mcp-tools."""
    registry: ToolRegistry = request.app.state.tool_registry

    return JSONResponse({
        "gateway": str(request.base_url).rstrip("/"),
        "protocol_version": "2026.1",
        "upstream_servers": registry.get_server_manifest(),
        "tools": registry.get_tool_manifest(),
        "scope_taxonomy": {
            entry["scope"]: {
                "kya_level": entry["kya_level"],
                "description": entry["description"],
            }
            for entry in scope_taxonomy()
        },
    })
