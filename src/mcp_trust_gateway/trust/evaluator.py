"""Trust evaluation engine — the core decision maker.

Evaluates whether an agent should be allowed to invoke a given MCP tool
based on KYA tier, reputation, spending limits, counterparty policy,
and delegation chain integrity.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from ..config import (
    get_exchange_url,
    get_exchange_api_key,
    get_exchange_timeout,
    get_reputation_cache_ttl,
)
from .scope_mapper import (
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


class ExchangeUnavailable(Exception):
    """The exchange could not be queried. Callers must fail closed."""


@dataclass(frozen=True)
class ExchangePrincipal:
    """Identity proven by the caller's own exchange API key."""

    account_id: str
    reputation: float


def exchange_client() -> httpx.AsyncClient:
    """HTTP client for exchange calls. Tests replace this; it does not log."""
    return httpx.AsyncClient(timeout=get_exchange_timeout())


def _safe_log_id(agent_id: str) -> str:
    cleaned = "".join(ch for ch in agent_id if ch.isprintable())
    return cleaned[:200]


async def authenticate_exchange_api_key(
    client_id: str,
    api_key: str,
) -> ExchangePrincipal | None:
    """Prove ``client_id`` by calling the exchange balance route with ``api_key``.

    The key is sent only on this request. Returns None when the key is
    rejected, the account id does not match, or the account is not active.
    Raises ExchangeUnavailable on network errors, 5xx, or a 200 body that
    cannot support a trust claim. The key is never logged.
    """
    url = f"{get_exchange_url()}/v1/exchange/balance"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        async with exchange_client() as client:
            resp = await client.get(url, headers=headers)
    except Exception:
        logger.warning("Exchange balance lookup failed")
        raise ExchangeUnavailable() from None
    if resp.status_code >= 500:
        logger.warning("Exchange balance lookup returned %s", resp.status_code)
        raise ExchangeUnavailable()
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except Exception:
        raise ExchangeUnavailable() from None
    if not isinstance(data, dict):
        raise ExchangeUnavailable()
    account_id = _account_id(data.get("account_id"))
    if account_id is None or account_id != client_id or data.get("account_status") != "active":
        return None
    reputation = _reputation(data.get("reputation"))
    if reputation is None:
        raise ExchangeUnavailable()
    return ExchangePrincipal(account_id=account_id, reputation=reputation)


def _account_id(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    account_id = str(value).strip()
    if not account_id or any(ch.isspace() for ch in account_id):
        return None
    return account_id


def _reputation(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    reputation = float(value)
    if reputation != reputation or reputation < 0.0 or reputation > 1.0:
        return None
    return reputation


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
        async with exchange_client() as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning(
                    "Exchange returned %s for agent %s",
                    resp.status_code,
                    _safe_log_id(agent_id),
                )
                return None
            data = resp.json()
            rep = float(data.get("reputation", 0.5))
            _rep_cache.put(agent_id, rep)
            return rep
    except Exception:
        logger.warning(
            "Failed to fetch reputation for %s",
            _safe_log_id(agent_id),
        )
        return None


async def fetch_agent_kya_level(agent_id: str) -> int | None:
    """Return the verified KYA level from the public account card.

    ``GET /v1/accounts/{id}/card`` is the source of ``kya_level_verified``.
    A 404 (no account card) is KYA 0. Returns None when the exchange cannot
    be queried or the card is unusable, so callers can fail closed.
    """
    url = f"{get_exchange_url()}/v1/accounts/{quote(agent_id, safe='')}/card"
    try:
        async with exchange_client() as client:
            resp = await client.get(url)
    except Exception:
        logger.warning("KYA card lookup failed for %s", _safe_log_id(agent_id))
        return None
    if resp.status_code == 404:
        return 0
    if resp.status_code != 200:
        logger.warning(
            "KYA card lookup returned %s for %s",
            resp.status_code,
            _safe_log_id(agent_id),
        )
        return None
    try:
        data = resp.json()
        level = data["kya_level_verified"]
    except Exception:
        logger.warning("KYA card payload unusable for %s", _safe_log_id(agent_id))
        return None
    if isinstance(level, bool) or not isinstance(level, int) or level < 0 or level > 5:
        logger.warning("KYA card level unusable for %s", _safe_log_id(agent_id))
        return None
    return level


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
