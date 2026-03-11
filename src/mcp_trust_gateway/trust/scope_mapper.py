"""Scope-to-KYA tier mapping — gives MCP scopes meaning grounded in identity verification.

Maps MCP tool categories to KYA trust tiers and bridges to A2A-SE settlement scopes.
"""

from __future__ import annotations

from enum import IntEnum, Enum
from dataclasses import dataclass


class KYALevel(IntEnum):
    """Know Your Agent identity verification tiers.

    Mirrors the KYA levels defined in the A2A Settlement Exchange.
    """

    SANDBOX = 0
    ORGANIZATIONAL = 1
    AUDITABLE = 2


KYA_LEVEL_NAMES: dict[int, str] = {
    KYALevel.SANDBOX: "SANDBOX",
    KYALevel.ORGANIZATIONAL: "ORGANIZATIONAL",
    KYALevel.AUDITABLE: "AUDITABLE",
}


class MCPScope(str, Enum):
    """MCP trust-tier-mapped scopes defined by this specification."""

    READ = "mcp:read"
    TOOL_INVOKE = "mcp:tool:invoke"
    TOOL_WRITE = "mcp:tool:write"
    TOOL_FINANCIAL = "mcp:tool:financial"
    DELEGATE = "mcp:delegate"


# The core mapping from Section 3 of the spec
SCOPE_KYA_MAP: dict[str, KYALevel] = {
    MCPScope.READ: KYALevel.SANDBOX,
    MCPScope.TOOL_INVOKE: KYALevel.SANDBOX,
    MCPScope.TOOL_WRITE: KYALevel.ORGANIZATIONAL,
    MCPScope.TOOL_FINANCIAL: KYALevel.AUDITABLE,
    MCPScope.DELEGATE: KYALevel.AUDITABLE,
}

SCOPE_DESCRIPTIONS: dict[str, str] = {
    MCPScope.READ: "Read-only access to data and resources",
    MCPScope.TOOL_INVOKE: "Invoke tools with no or bounded side effects",
    MCPScope.TOOL_WRITE: "Invoke tools that mutate external state",
    MCPScope.TOOL_FINANCIAL: "Invoke tools with economic impact",
    MCPScope.DELEGATE: "Sub-delegate authority to other agents",
}


@dataclass(frozen=True)
class ToolTrustRequirements:
    """Trust requirements for a specific MCP tool."""

    required_kya_level: int = 0
    required_reputation: float = 0.0
    required_scope: str = MCPScope.TOOL_INVOKE
    economic_impact: bool = False

    @property
    def kya_level_name(self) -> str:
        return KYA_LEVEL_NAMES.get(self.required_kya_level, "UNKNOWN")


def kya_for_scope(scope: str) -> KYALevel:
    """Return the KYA level required for a given scope string.

    Falls back to SANDBOX for unrecognized scopes.
    """
    return SCOPE_KYA_MAP.get(scope, KYALevel.SANDBOX)


def max_kya_for_scopes(scopes: set[str] | list[str]) -> KYALevel:
    """Return the highest KYA level required by any scope in the set."""
    if not scopes:
        return KYALevel.SANDBOX
    return KYALevel(max(kya_for_scope(s) for s in scopes))


def filter_scopes_by_kya(scopes: set[str], agent_kya: int) -> set[str]:
    """Return only the scopes the agent's KYA level permits."""
    return {s for s in scopes if kya_for_scope(s) <= agent_kya}


def default_requirements_for_scope(scope: str) -> ToolTrustRequirements:
    """Derive default tool trust requirements from a scope string."""
    kya = kya_for_scope(scope)
    return ToolTrustRequirements(
        required_kya_level=kya,
        required_reputation=0.0,
        required_scope=scope,
        economic_impact=(scope == MCPScope.TOOL_FINANCIAL),
    )


def requirements_from_annotations(annotations: dict | None) -> ToolTrustRequirements | None:
    """Extract trust requirements from MCP tool annotations.

    Returns None if no trust annotations are present.
    """
    if not annotations:
        return None
    trust = annotations.get("trust")
    if not trust or not isinstance(trust, dict):
        return None
    return ToolTrustRequirements(
        required_kya_level=int(trust.get("required_kya_level", 0)),
        required_reputation=float(trust.get("required_reputation", 0.0)),
        required_scope=str(trust.get("required_scope", MCPScope.TOOL_INVOKE)),
        economic_impact=bool(trust.get("economic_impact", False)),
    )


def scope_taxonomy() -> list[dict]:
    """Return the full scope taxonomy for discovery endpoints."""
    return [
        {
            "scope": scope,
            "kya_level": SCOPE_KYA_MAP[scope],
            "kya_level_name": KYA_LEVEL_NAMES[SCOPE_KYA_MAP[scope]],
            "description": SCOPE_DESCRIPTIONS.get(scope, ""),
        }
        for scope in MCPScope
    ]
