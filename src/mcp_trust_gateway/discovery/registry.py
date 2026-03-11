"""Exchange directory to tool manifest bridge.

Pulls agent directory and Agent Card data from the settlement exchange
and transforms it into the MCP tool discovery format.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from ..config import get_exchange_url, get_exchange_api_key, get_upstream_servers
from ..trust.scope_mapper import (
    ToolTrustRequirements,
    MCPScope,
    KYA_LEVEL_NAMES,
    requirements_from_annotations,
    default_requirements_for_scope,
)

logger = logging.getLogger("mcp_trust_gateway.discovery")


@dataclass
class UpstreamServer:
    """Registered upstream MCP server."""

    id: str
    url: str
    name: str = ""
    description: str = ""
    agent_card_url: str = ""


@dataclass
class DiscoveredTool:
    """A tool discovered from an upstream MCP server."""

    name: str
    server_id: str
    description: str = ""
    trust_requirements: ToolTrustRequirements = field(
        default_factory=lambda: default_requirements_for_scope(MCPScope.TOOL_INVOKE)
    )

    def to_manifest_entry(self) -> dict:
        reqs = self.trust_requirements
        return {
            "name": self.name,
            "server_id": self.server_id,
            "description": self.description,
            "trust_requirements": {
                "required_kya_level": reqs.required_kya_level,
                "required_reputation": reqs.required_reputation,
                "required_scope": reqs.required_scope,
                "kya_level_name": reqs.kya_level_name,
            },
        }


class ToolRegistry:
    """Manages upstream server registrations and tool discovery."""

    def __init__(self) -> None:
        self.servers: dict[str, UpstreamServer] = {}
        self.tools: dict[str, DiscoveredTool] = {}
        self._load_from_env()

    def _load_from_env(self) -> None:
        for entry in get_upstream_servers():
            sid = entry.get("id", "")
            url = entry.get("url", "")
            if sid and url:
                self.register_server(UpstreamServer(
                    id=sid,
                    url=url,
                    name=entry.get("name", sid),
                    description=entry.get("description", ""),
                ))

    def register_server(self, server: UpstreamServer) -> None:
        self.servers[server.id] = server

    def register_tool(
        self,
        tool_name: str,
        server_id: str,
        description: str = "",
        requirements: ToolTrustRequirements | None = None,
    ) -> None:
        self.tools[tool_name] = DiscoveredTool(
            name=tool_name,
            server_id=server_id,
            description=description,
            trust_requirements=requirements or default_requirements_for_scope(MCPScope.TOOL_INVOKE),
        )

    def register_tools_from_mcp_list(
        self,
        server_id: str,
        tools_list: list[dict],
    ) -> None:
        """Register tools from an MCP tools/list response."""
        for tool in tools_list:
            name = tool.get("name", "")
            if not name:
                continue
            annotations = tool.get("annotations")
            reqs = requirements_from_annotations(annotations)
            if reqs is None:
                reqs = default_requirements_for_scope(MCPScope.TOOL_INVOKE)
            self.register_tool(
                tool_name=name,
                server_id=server_id,
                description=tool.get("description", ""),
                requirements=reqs,
            )

    async def discover_from_exchange(self) -> list[dict]:
        """Pull agent directory from the exchange and merge with local registry."""
        base = get_exchange_url()
        api_key = get_exchange_api_key()
        url = f"{base}/api/v1/accounts/directory"
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        agents: list[dict] = []
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    agents = data if isinstance(data, list) else data.get("agents", [])
        except Exception as exc:
            logger.warning("Failed to fetch exchange directory: %s", exc)

        return agents

    def get_server_manifest(self) -> list[dict]:
        return [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "url": s.url,
                **({"agent_card_url": s.agent_card_url} if s.agent_card_url else {}),
            }
            for s in self.servers.values()
        ]

    def get_tool_manifest(self) -> list[dict]:
        return [t.to_manifest_entry() for t in self.tools.values()]
