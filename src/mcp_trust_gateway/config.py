"""Environment-based configuration for the MCP Trust Gateway."""

from __future__ import annotations

import os


def _get_str(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _get_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return int(val)


def _get_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return float(val)


def _get_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


# -- Exchange ------------------------------------------------------------------

def get_exchange_url() -> str:
    """A2A Settlement Exchange base URL."""
    return _get_str("A2A_EXCHANGE_URL", "http://localhost:3000").rstrip("/")


def get_exchange_api_key() -> str:
    """API key for exchange queries (reputation, directory, KYA lookups)."""
    return _get_str("A2A_EXCHANGE_API_KEY", "")


# -- Gateway -------------------------------------------------------------------

def get_gateway_port() -> int:
    return _get_int("MCP_TRUST_GATEWAY_PORT", 3100)


def get_gateway_host() -> str:
    return _get_str("MCP_TRUST_GATEWAY_HOST", "127.0.0.1")


# -- Trust ---------------------------------------------------------------------

def get_trust_decay_factor() -> float:
    return _get_float("MCP_TRUST_DECAY_FACTOR", 0.85)


def get_min_reputation() -> float:
    return _get_float("MCP_TRUST_MIN_REPUTATION", 0.0)


def get_default_kya_level() -> int:
    return _get_int("MCP_TRUST_DEFAULT_KYA", 0)


def get_max_delegation_depth() -> int:
    return _get_int("MCP_TRUST_MAX_DELEGATION_DEPTH", 5)


def get_reputation_cache_ttl() -> int:
    """Reputation cache TTL in seconds. Max 300 per spec."""
    return min(_get_int("MCP_TRUST_REPUTATION_CACHE_TTL", 60), 300)


# -- OAuth ---------------------------------------------------------------------

def get_oauth_issuer() -> str:
    return _get_str("OAUTH_ISSUER", "")


def get_oauth_signing_key() -> str:
    return _get_str("OAUTH_SIGNING_KEY", "")


def get_oauth_algorithm() -> str:
    return _get_str("OAUTH_ALGORITHM", "HS256")


def get_oauth_token_ttl() -> int:
    """Token lifetime in seconds."""
    return _get_int("OAUTH_TOKEN_TTL", 3600)


def get_oauth_audience() -> str:
    return _get_str("OAUTH_AUDIENCE", "https://gateway.a2a-settlement.org")


# -- Upstream MCP Servers ------------------------------------------------------

def get_upstream_servers() -> list[dict]:
    """Parse upstream MCP server definitions from env.

    Format: MCP_UPSTREAM_SERVERS='[{"id":"s1","url":"http://...","name":"..."}]'
    Returns empty list if not set.
    """
    import json

    raw = os.environ.get("MCP_UPSTREAM_SERVERS", "").strip()
    if not raw:
        return []
    try:
        servers = json.loads(raw)
        if isinstance(servers, list):
            return servers
    except (json.JSONDecodeError, TypeError):
        pass
    return []
