"""Tests for the trust evaluator."""

import pytest

from mcp_trust_gateway.trust.evaluator import TrustEvaluator
from mcp_trust_gateway.trust.scope_mapper import (
    ToolTrustRequirements,
    MCPScope,
    KYALevel,
)


@pytest.fixture
def evaluator():
    e = TrustEvaluator()
    e.register_tool("read_data", ToolTrustRequirements(
        required_kya_level=0,
        required_reputation=0.0,
        required_scope=MCPScope.READ,
    ))
    e.register_tool("write_db", ToolTrustRequirements(
        required_kya_level=1,
        required_reputation=0.5,
        required_scope=MCPScope.TOOL_WRITE,
    ))
    e.register_tool("execute_trade", ToolTrustRequirements(
        required_kya_level=2,
        required_reputation=0.8,
        required_scope=MCPScope.TOOL_FINANCIAL,
        economic_impact=True,
    ))
    return e


class TestTrustEvaluator:
    @pytest.mark.asyncio
    async def test_sandbox_agent_can_read(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="read_data",
            agent_id="test-agent",
            kya_level=0,
            reputation=0.5,
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_sandbox_agent_cannot_write(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="write_db",
            agent_id="test-agent",
            kya_level=0,
            reputation=0.9,
        )
        assert result.allowed is False
        denial = result.to_denial_data()
        assert denial["evaluations"]["kya_level"]["passed"] is False

    @pytest.mark.asyncio
    async def test_organizational_agent_can_write(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="write_db",
            agent_id="test-agent",
            kya_level=1,
            reputation=0.7,
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_low_reputation_denied(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="execute_trade",
            agent_id="test-agent",
            kya_level=2,
            reputation=0.3,
        )
        assert result.allowed is False
        denial = result.to_denial_data()
        assert denial["evaluations"]["reputation"]["passed"] is False

    @pytest.mark.asyncio
    async def test_auditable_high_rep_can_trade(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="execute_trade",
            agent_id="test-agent",
            kya_level=2,
            reputation=0.9,
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_delegation_decay_reduces_trust(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="execute_trade",
            agent_id="test-agent",
            kya_level=2,
            reputation=0.85,
            delegation_depth=3,
        )
        # 0.85 * 0.85^3 = 0.522 < 0.8 required
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_counterparty_denied(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="read_data",
            agent_id="test-agent",
            kya_level=0,
            reputation=0.5,
            counterparty_allowed=False,
        )
        assert result.allowed is False
        denial = result.to_denial_data()
        assert denial["evaluations"]["counterparty_policy"]["passed"] is False

    @pytest.mark.asyncio
    async def test_denial_has_upgrade_path(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="write_db",
            agent_id="test-agent",
            kya_level=0,
            reputation=0.9,
        )
        denial = result.to_denial_data()
        assert "upgrade_path" in denial
        assert "kya_upgrade_url" in denial.get("upgrade_path", {})

    @pytest.mark.asyncio
    async def test_unknown_tool_uses_default(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="unknown_tool",
            agent_id="test-agent",
            kya_level=0,
            reputation=0.5,
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_spending_limit_check(self, evaluator):
        result = await evaluator.evaluate(
            tool_name="execute_trade",
            agent_id="test-agent",
            kya_level=2,
            reputation=0.9,
            spending_remaining=0,
        )
        assert result.allowed is False
        denial = result.to_denial_data()
        assert denial["evaluations"]["spending_limit"]["passed"] is False
