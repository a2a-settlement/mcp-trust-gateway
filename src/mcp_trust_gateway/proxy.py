"""MCP proxy — forwards tool calls to upstream MCP servers through trust evaluation.

Acts as the upstream-facing MCP client. Receives validated, trust-evaluated
requests from the server layer and proxies them to the appropriate
upstream MCP server via HTTP.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .discovery.registry import ToolRegistry

logger = logging.getLogger("mcp_trust_gateway.proxy")


class UpstreamProxy:
    """Forwards MCP JSON-RPC calls to upstream servers."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self._tool_to_server: dict[str, str] = {}

    def resolve_server_url(self, tool_name: str) -> str | None:
        """Look up which upstream server hosts a given tool."""
        tool = self.registry.tools.get(tool_name)
        if tool is None:
            return None
        server = self.registry.servers.get(tool.server_id)
        if server is None:
            return None
        return server.url

    async def proxy_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: int | str = 1,
    ) -> dict:
        """Forward a tools/call to the upstream MCP server.

        Returns the JSON-RPC response dict from the upstream server.
        """
        server_url = self.resolve_server_url(tool_name)
        if server_url is None:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Unknown tool: {tool_name}",
                },
            }

        url = server_url.rstrip("/") + "/mcp"
        jsonrpc_body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    url,
                    json=jsonrpc_body,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    return resp.json()
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32603,
                        "message": f"Upstream returned HTTP {resp.status_code}",
                    },
                }
        except httpx.TimeoutException:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"Upstream server timeout: {server_url}",
                },
            }
        except Exception as exc:
            logger.error("Proxy error for %s: %s", tool_name, exc)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"Proxy error: {exc}",
                },
            }

    async def proxy_tools_list(self, server_id: str) -> list[dict]:
        """Fetch the tools/list from an upstream server."""
        server = self.registry.servers.get(server_id)
        if server is None:
            return []

        url = server.url.rstrip("/") + "/mcp"
        jsonrpc_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=jsonrpc_body)
                if resp.status_code == 200:
                    data = resp.json()
                    result = data.get("result", {})
                    tools = result.get("tools", [])
                    self.registry.register_tools_from_mcp_list(server_id, tools)
                    return tools
        except Exception as exc:
            logger.warning("Failed to list tools from %s: %s", server_id, exc)
        return []

    async def discover_all_upstream_tools(self) -> None:
        """Fetch tools from all registered upstream servers."""
        for server_id in list(self.registry.servers.keys()):
            await self.proxy_tools_list(server_id)
