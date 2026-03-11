"""Trust evaluation engine — the core decision maker.

Evaluates whether an agent should be allowed to invoke a given MCP tool
based on KYA tier, reputation, spending limits, counterparty policy,
and delegation chain integrity.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from ..config import (
    get_exchange_url,
    get_exchange_api_key,
    get_reputation_cache_ttl,
)
from .scope_mapper import (
    KYALevel,
    KYA_LEVEL_NAMES,
    ToolTrustRequirements,
    default_requirements_for_scope,
    MCPScope,
)
from .trust_decay import TrustScore, compute_trust_score

logger = logging.getLogger("mcp_trust_gateway.trust")


@dataclass(frozen=True)
class DimensionResult:
    """Result of a single trust dimension evaluation."""

    dimension: str
    passed: bool
    required: float | int | str | None = None
    current: float | int | str | None = None
    detail: str = ""


@dataclass(frozen=True)
class TrustEvaluation:
    """Complete trust evaluation result."""

    allowed: bool
    tool_name: str
    trust_score: TrustScore
    dimensions: list[DimensionResult] = field(default_factory=list)
    denial_message: str = ""
    upgrade_path: dict = field(default_factory=dict)

    def to_denial_data(self) -> dict:
        """Format as the structured denial described in SPEC Section 6.2."""
        evaluations = {}
        for dim in self.dimensions:
            entry: dict = {"passed": dim.passed}
            if dim.required is not None:
                entry["required"] = dim.required
            if dim.current is not None:
                entry["current"] = dim.current
            if dim.dimension == "kya_level" and isinstance(dim.required, int):
                entry["required_name"] = KYA_LEVEL_NAMES.get(dim.required, "UNKNOWN")
            if dim.dimension == "kya_level" and isinstance(dim.current, int):
                entry["current_name"] = KYA_LEVEL_NAMES.get(dim.current, "UNKNOWN")
            evaluations[dim.dimension] = entry

        return {
            "error_type": "trust_insufficient",
            "tool": self.tool_name,
            "evaluations": evaluations,
            "upgrade_path": self.upgrade_path,
        }


class _ReputationCache:
    """TTL cache for exchange reputation lookups."""

    def __init__(self, ttl: int | None = None):
        self._ttl = ttl
        self._store: dict[str, tuple[float, float]] = {}

    @property
    def ttl(self) -> int:
        if self._ttl is not None:
            return self._ttl
        return get_reputation_cache_ttl()

    def get(self, agent_id: str) -> float | None:
        entry = self._store.get(agent_id)
        if entry is None:
            return None
        ts, rep = entry
        if time.time() - ts > self.ttl:
            del self._store[agent_id]
            return None
        return rep

    def put(self, agent_id: str, reputation: float) -> None:
        self._store[agent_id] = (time.time(), reputation)


_rep_cache = _ReputationCache()


async def fetch_agent_reputation(agent_id: str) -> float | None:
    """Query the settlement exchange for an agent's current reputation.

    Returns None if the exchange is unreachable or the agent is unknown.
    """
    cached = _rep_cache.get(agent_id)
    if cached is not None:
        return cached

    base = get_exchange_url()
    api_key = get_exchange_api_key()
    url = f"{base}/api/v1/accounts/{agent_id}"
    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning("Exchange returned %s for agent %s", resp.status_code, agent_id)
                return None
            data = resp.json()
            rep = float(data.get("reputation", 0.5))
            _rep_cache.put(agent_id, rep)
            return rep
    except Exception as exc:
        logger.warning("Failed to fetch reputation for %s: %s", agent_id, exc)
        return None


async def fetch_agent_kya_level(agent_id: str) -> int | None:
    """Query the settlement exchange for an agent's KYA level."""
    base = get_exchange_url()
    api_key = get_exchange_api_key()
    url = f"{base}/api/v1/accounts/{agent_id}"
    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
            return int(data.get("kya_level_verified", 0))
    except Exception:
        return None


@dataclass
class TrustEvaluator:
    """Stateful trust evaluator with caching and configurable defaults."""

    tool_requirements: dict[str, ToolTrustRequirements] = field(default_factory=dict)

    def register_tool(self, tool_name: str, requirements: ToolTrustRequirements) -> None:
        """Register trust requirements for a tool (from annotations or admin config)."""
        self.tool_requirements[tool_name] = requirements

    def get_requirements(self, tool_name: str) -> ToolTrustRequirements:
        """Look up requirements for a tool, falling back to defaults."""
        if tool_name in self.tool_requirements:
            return self.tool_requirements[tool_name]
        return default_requirements_for_scope(MCPScope.TOOL_INVOKE)

    async def evaluate(
        self,
        tool_name: str,
        agent_id: str,
        kya_level: int,
        reputation: float | None = None,
        delegation_depth: int = 0,
        spending_remaining: float | None = None,
        counterparty_allowed: bool = True,
    ) -> TrustEvaluation:
        """Evaluate whether an agent should be allowed to invoke a tool."""
        reqs = self.get_requirements(tool_name)

        if reputation is None:
            live_rep = await fetch_agent_reputation(agent_id)
            reputation = live_rep if live_rep is not None else 0.5

        trust = compute_trust_score(reputation, kya_level, delegation_depth)
        dimensions: list[DimensionResult] = []
        all_pass = True

        # KYA level
        kya_pass = kya_level >= reqs.required_kya_level
        dimensions.append(DimensionResult(
            dimension="kya_level",
            passed=kya_pass,
            required=reqs.required_kya_level,
            current=kya_level,
        ))
        if not kya_pass:
            all_pass = False

        # Reputation (effective trust after decay)
        rep_pass = trust.effective_trust >= reqs.required_reputation
        dimensions.append(DimensionResult(
            dimension="reputation",
            passed=rep_pass,
            required=reqs.required_reputation,
            current=round(trust.effective_trust, 4),
        ))
        if not rep_pass:
            all_pass = False

        # Spending limit (only for economic-impact tools)
        if reqs.economic_impact and spending_remaining is not None:
            spend_pass = spending_remaining > 0
            dimensions.append(DimensionResult(
                dimension="spending_limit",
                passed=spend_pass,
                current=spending_remaining,
            ))
            if not spend_pass:
                all_pass = False
        else:
            dimensions.append(DimensionResult(dimension="spending_limit", passed=True))

        # Counterparty policy
        dimensions.append(DimensionResult(
            dimension="counterparty_policy",
            passed=counterparty_allowed,
        ))
        if not counterparty_allowed:
            all_pass = False

        upgrade_path: dict = {}
        denial_message = ""
        if not all_pass:
            failed = [d for d in dimensions if not d.passed]
            parts = []
            for d in failed:
                if d.dimension == "kya_level":
                    req_name = KYA_LEVEL_NAMES.get(reqs.required_kya_level, "UNKNOWN")
                    cur_name = KYA_LEVEL_NAMES.get(kya_level, "UNKNOWN")
                    parts.append(
                        f"This tool requires {req_name} identity verification. "
                        f"Current level: {cur_name}."
                    )
                    upgrade_path["kya_upgrade_url"] = (
                        f"{get_exchange_url()}/kya/upgrade"
                    )
                elif d.dimension == "reputation":
                    parts.append(
                        f"Minimum reputation {reqs.required_reputation} required; "
                        f"current effective trust is {trust.effective_trust:.4f}."
                    )
                elif d.dimension == "spending_limit":
                    parts.append("Insufficient spending balance for this tool.")
                elif d.dimension == "counterparty_policy":
                    parts.append("Counterparty policy does not permit this upstream server.")
            denial_message = " ".join(parts)
            upgrade_path["message"] = denial_message

        return TrustEvaluation(
            allowed=all_pass,
            tool_name=tool_name,
            trust_score=trust,
            dimensions=dimensions,
            denial_message=denial_message,
            upgrade_path=upgrade_path,
        )
