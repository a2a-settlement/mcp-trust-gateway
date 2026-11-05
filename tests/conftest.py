"""Keep unit tests off live providers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

INTEGRATION_DIR = (Path(__file__).parent / "integration").resolve()

# Credential that would let a unit test query a real exchange.
PROVIDER_CREDENTIAL_VARS = ("A2A_EXCHANGE_API_KEY",)


def _is_integration(path: Path) -> bool:
    resolved = path.resolve()
    return INTEGRATION_DIR == resolved.parent or INTEGRATION_DIR in resolved.parents


def pytest_collection_modifyitems(config, items):
    """Keep live-provider scripts out of the default run."""
    if os.environ.get("RUN_INTEGRATION_TESTS"):
        return
    skip = pytest.mark.skip(
        reason="integration test: hits a live provider. "
        "Set RUN_INTEGRATION_TESTS=1 to run."
    )
    for item in items:
        if _is_integration(Path(str(item.fspath))):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def isolate_provider_credentials(request, monkeypatch):
    """A developer .env must not turn a unit test into a live exchange call."""
    if _is_integration(Path(str(request.node.fspath))):
        return
    for var in PROVIDER_CREDENTIAL_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _block_live_exchange(request, monkeypatch):
    """Exchange HTTP goes through exchange_client. Tests install a mock."""
    if _is_integration(Path(str(request.node.fspath))):
        return

    def _blocked(*args, **kwargs):
        raise RuntimeError("unit test tried to call the settlement exchange")

    monkeypatch.setattr(
        "mcp_trust_gateway.trust.evaluator.exchange_client",
        _blocked,
    )
