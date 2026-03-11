"""Tests for RFC 8693 token exchange with trust decay."""

import os
import time

import pytest
import jwt as pyjwt

from mcp_trust_gateway.oauth.token_exchange import handle_token_exchange

CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"
SIGNING_KEY = "test-secret-key-for-tests"
ALGORITHM = "HS256"
AUDIENCE = "https://gateway.a2a-settlement.org"


@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    monkeypatch.setenv("OAUTH_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("OAUTH_ALGORITHM", ALGORITHM)
    monkeypatch.setenv("OAUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("OAUTH_ISSUER", "https://test-issuer.example.com")
    monkeypatch.setenv("MCP_TRUST_DECAY_FACTOR", "0.85")
    monkeypatch.setenv("MCP_TRUST_MAX_DELEGATION_DEPTH", "5")


def _make_parent_token(
    agent_id="parent-agent",
    scopes="mcp:read mcp:tool:invoke mcp:tool:write",
    reputation=0.92,
    kya_level=2,
    transferable=True,
    delegation_chain=None,
) -> str:
    now = int(time.time())
    chain = delegation_chain or [
        {"principal": "user:alice@acme.com", "delegated_at": "2026-01-01T00:00:00Z"}
    ]
    payload = {
        "sub": f"agent:{agent_id}",
        "iss": "https://test-issuer.example.com",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "jti": "parent-jti-001",
        "scope": scopes,
        CLAIMS_NAMESPACE: {
            "agent_id": agent_id,
            "org_id": "org-acme",
            "spending_limits": {
                "per_transaction": 500,
                "per_day": 5000,
            },
            "counterparty_policy": {},
            "delegation": {
                "chain": chain,
                "transferable": transferable,
            },
            "trust": {
                "kya_level": kya_level,
                "reputation": reputation,
                "effective_trust": reputation,
                "delegation_depth": len(chain),
                "decay_factor": 0.85,
            },
        },
    }
    return pyjwt.encode(payload, SIGNING_KEY, algorithm=ALGORITHM)


class TestTokenExchange:
    @pytest.mark.asyncio
    async def test_successful_exchange(self):
        parent_token = _make_parent_token()
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read mcp:tool:invoke",
            "actor_token_agent_id": "child-agent",
        })
        body = resp.body
        import json
        data = json.loads(body)
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "trust_metadata" in data
        meta = data["trust_metadata"]
        assert meta["delegation_depth"] == 2
        assert meta["effective_trust"] < 0.92

    @pytest.mark.asyncio
    async def test_non_transferable_rejected(self):
        parent_token = _make_parent_token(transferable=False)
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        assert data.get("error") == "delegation_not_transferable"

    @pytest.mark.asyncio
    async def test_scope_narrowing(self):
        parent_token = _make_parent_token(scopes="mcp:read mcp:tool:invoke mcp:tool:write")
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "mcp:read",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        assert "mcp:read" in data["scope"]
        assert "mcp:tool:write" not in data["scope"]

    @pytest.mark.asyncio
    async def test_max_depth_rejected(self, monkeypatch):
        monkeypatch.setenv("MCP_TRUST_MAX_DELEGATION_DEPTH", "2")
        chain = [
            {"principal": "user:a@x.com", "delegated_at": "2026-01-01T00:00:00Z"},
            {"principal": "agent:b", "delegated_at": "2026-01-01T01:00:00Z"},
        ]
        parent_token = _make_parent_token(delegation_chain=chain)
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        assert data.get("error") == "max_delegation_depth"

    @pytest.mark.asyncio
    async def test_spending_limits_reduced(self):
        parent_token = _make_parent_token()
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor_token_agent_id": "child-agent",
        })
        import json
        data = json.loads(resp.body)
        child_token = data["access_token"]
        child_payload = pyjwt.decode(
            child_token, SIGNING_KEY, algorithms=[ALGORITHM],
            audience=AUDIENCE,
        )
        child_claims = child_payload[CLAIMS_NAMESPACE]
        child_limits = child_claims["spending_limits"]
        # Spending limits should be reduced from parent's 500/5000
        assert child_limits["per_transaction"] < 500
        assert child_limits["per_day"] < 5000

    @pytest.mark.asyncio
    async def test_invalid_subject_token_type(self):
        resp = await handle_token_exchange({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "something",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        })
        import json
        data = json.loads(resp.body)
        assert data.get("error") == "invalid_request"
