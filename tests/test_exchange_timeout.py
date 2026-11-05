"""The exchange client's timeout must cover the exchange's slow invalid-key path."""

from mcp_trust_gateway.trust import evaluator

# Captured at import, before the autouse fixture replaces it with a blocker.
_real_exchange_client = evaluator.exchange_client


def test_default_timeout_is_15_seconds(monkeypatch):
    monkeypatch.delenv("A2A_EXCHANGE_TIMEOUT_S", raising=False)
    assert _real_exchange_client().timeout.read == 15.0


def test_timeout_comes_from_env(monkeypatch):
    monkeypatch.setenv("A2A_EXCHANGE_TIMEOUT_S", "7.5")
    timeout = _real_exchange_client().timeout
    assert timeout.connect == 7.5 and timeout.read == 7.5
