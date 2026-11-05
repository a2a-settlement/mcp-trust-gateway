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


_NOT_IN_PILOT = "not_in_pilot_allowlist"


@dataclass(frozen=True)
class ScopeDecision:
    """Scopes granted and denied for one token request.

    ``reason`` is ``not_in_pilot_allowlist`` when ``mcp:tool:financial`` was
    denied because the agent is outside a non-empty pilot allowlist.
    """

    granted: frozenset[str]
    denied: frozenset[str]
    reason: str | None = None


def decide_scopes(
    requested: set[str],
    agent_id: str,
    kya_level: int,
    allowlist: set[str],
) -> ScopeDecision:
    """Grant scopes for an agent whose identity was just authenticated.

    A non-empty allowlist is the only path to ``mcp:tool:financial``: listed
    agents receive it at any real KYA level (including 0), and every other
    agent is denied it regardless of KYA. All other scopes follow the KYA
    map. An empty allowlist leaves that map unchanged. This does not change
    the agent's KYA level.
    """
    granted: set[str] = set()
    denied: set[str] = set()
    reason: str | None = None
    for scope in requested:
        if not scope:
            continue
        if scope == MCPScope.TOOL_FINANCIAL and allowlist:
            if agent_id in allowlist:
                granted.add(scope)
            else:
                denied.add(scope)
                reason = _NOT_IN_PILOT
            continue
        if int(kya_for_scope(scope)) <= int(kya_level):
            granted.add(scope)
        else:
            denied.add(scope)
    return ScopeDecision(frozenset(granted), frozenset(denied), reason)


def narrow_delegated_scopes(
    parent_scopes: set[str],
    requested_scopes: set[str],
    *,
    actor_id: str,
    parent_kya: int,
    allowlist: set[str],
) -> ScopeDecision:
    """Narrow a parent token for a delegate that was not authenticated.

    The result is always a subset of ``parent_scopes``. Financial scope is
    never added. When ``allowlist`` is non-empty, financial scope already on
    the parent is kept only if ``actor_id`` is listed (parent KYA is not
    consulted for that scope). When the allowlist is empty, financial scope
    follows the parent KYA rule like every other scope.
    """
    intersection = {scope for scope in parent_scopes & requested_scopes if scope}
    rest = intersection - {MCPScope.TOOL_FINANCIAL}
    base = decide_scopes(rest, actor_id, parent_kya, set())
    granted = set(base.granted)
    denied = set(base.denied)
    reason: str | None = None
    financial = MCPScope.TOOL_FINANCIAL.value
    if financial in intersection:
        if allowlist:
            if actor_id in allowlist:
                granted.add(financial)
            else:
                denied.add(financial)
                reason = _NOT_IN_PILOT
        elif int(kya_for_scope(financial)) <= int(parent_kya):
            granted.add(financial)
        else:
            denied.add(financial)
    return ScopeDecision(frozenset(granted), frozenset(denied), reason)


def kya_denial_body(
    requested: set[str],
    decision: ScopeDecision,
    kya_level: int,
) -> dict:
    """JSON body for a 403 ``insufficient_kya_level`` denial."""
    required = int(max_kya_for_scopes(requested))
    current_name = KYA_LEVEL_NAMES.get(kya_level, str(kya_level))
    required_name = KYA_LEVEL_NAMES.get(required, str(required))
    if decision.reason == _NOT_IN_PILOT:
        description = (
            "Requested scope mcp:tool:financial is restricted to the pilot allowlist. "
            f"Agent has level {current_name}."
        )
    else:
        description = (
            f"Requested scopes require KYA level {required_name}. "
            f"Agent has level {current_name}."
        )
    body: dict = {
        "error": "insufficient_kya_level",
        "error_description": description,
        "denied_scopes": sorted(decision.denied),
        "granted_scopes": sorted(decision.granted),
        "required_kya_level": required,
        "current_kya_level": int(kya_level),
    }
    if decision.reason:
        body["reason"] = decision.reason
    return body


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
