"""End-to-end tests for the gateway server."""

import os
import time

import pytest
import jwt as pyjwt
from starlette.testclient import TestClient

from mcp_trust_gateway.server import create_app
from mcp_trust_gateway.trust.scope_mapper import ToolTrustRequirements, MCPScope

SIGNING_KEY = "test-server-secret"
ALGORITHM = "HS256"
AUDIENCE = "https://gateway.a2a-settlement.org"
CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("OAUTH_ALGORITHM", ALGORITHM)
    monkeypatch.setenv("OAUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("OAUTH_ISSUER", "https://test.example.com")
    monkeypatch.setenv("MCP_TRUST_DECAY_FACTOR", "0.85")


@pytest.fixture
def app():
    application = create_app()
    registry = application.state.tool_registry
    evaluator = application.state.trust_evaluator
    reqs = ToolTrustRequirements(
        required_kya_level=1,
        required_reputation=0.5,
        required_scope=MCPScope.TOOL_WRITE,
    )
    registry.register_tool("test_tool", "local", "A test tool", reqs)
    evaluator.register_tool("test_tool", reqs)
    return application


@pytest.fixture
def client(app):
    return TestClient(app)


def _make_token(agent_id="a1", kya=1, rep=0.8, depth=0, scopes="mcp:read mcp:tool:write") -> str:
    now = int(time.time())
    payload = {
        "sub": f"agent:{agent_id}",
        "iss": "https://test.example.com",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "jti": "test-jti",
        "scope": scopes,
        CLAIMS_NAMESPACE: {
            "agent_id": agent_id,
            "org_id": "org-test",
            "spending_limits": {},
            "counterparty_policy": {},
            "delegation": {"chain": [], "transferable": False},
            "trust": {
                "kya_level": kya,
                "reputation": rep,
                "effective_trust": rep * (0.85 ** depth),
                "delegation_depth": depth,
                "decay_factor": 0.85,
            },
        },
    }
    return pyjwt.encode(payload, SIGNING_KEY, algorithm=ALGORITHM)


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestWellKnown:
    def test_mcp_tools_no_auth(self, client):
        resp = client.get("/.well-known/mcp-tools")
        assert resp.status_code == 200
        data = resp.json()
        assert "tools" in data
        assert "scope_taxonomy" in data

    def test_oauth_authorization_server(self, client):
        resp = client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "urn:ietf:params:oauth:grant-type:token-exchange" in data["grant_types_supported"]

    def test_oauth_protected_resource(self, client):
        resp = client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        data = resp.json()
        assert "trust_extension" in data
        assert data["trust_extension"]["spec_version"] == "0.1.0"


class TestMCPEndpoint:
    def test_tools_list_no_auth(self, client):
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        })
        assert resp.status_code == 200
        data = resp.json()
        tools = data["result"]["tools"]
        assert any(t["name"] == "test_tool" for t in tools)

    def test_tools_call_requires_auth(self, client):
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {}},
        })
        assert resp.status_code == 401

    def test_tools_call_denied_low_kya(self, client):
        token = _make_token(kya=0)
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {}},
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
        data = resp.json()
        assert data["error"]["data"]["error_type"] == "trust_insufficient"

    def test_tools_call_allowed(self, client):
        token = _make_token(kya=1, rep=0.8)
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {}},
        }, headers={"Authorization": f"Bearer {token}"})
        # Will fail with -32601 (unknown tool to proxy) since no upstream server
        # but that's AFTER trust evaluation passed, which is what we're testing
        data = resp.json()
        error = data.get("error", {})
        assert error.get("code") != -32001  # not trust failure

    def test_invalid_token_rejected(self, client):
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {}},
        }, headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401


class TestDiscoveryAnnotations:
    def test_tools_list_includes_trust_annotations(self, client):
        resp = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        })
        data = resp.json()
        tools = data["result"]["tools"]
        test_tool = next(t for t in tools if t["name"] == "test_tool")
        assert "annotations" in test_tool
        trust = test_tool["annotations"]["trust"]
        assert trust["required_kya_level"] == 1
        assert trust["required_scope"] == MCPScope.TOOL_WRITE
