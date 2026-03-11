"""Tests for EMA-weighted trust decay."""

import os

from mcp_trust_gateway.trust.trust_decay import (
    compute_effective_trust,
    compute_trust_score,
    apply_delegation_decay,
    TrustScore,
)


class TestComputeEffectiveTrust:
    def test_no_delegation(self):
        assert compute_effective_trust(0.9, delegation_depth=0, decay_factor=0.85) == 0.9

    def test_one_hop(self):
        result = compute_effective_trust(0.92, delegation_depth=1, decay_factor=0.85)
        assert abs(result - 0.782) < 0.001

    def test_two_hops(self):
        result = compute_effective_trust(0.92, delegation_depth=2, decay_factor=0.85)
        expected = 0.92 * 0.85 * 0.85
        assert abs(result - expected) < 0.001

    def test_clamps_reputation(self):
        assert compute_effective_trust(1.5, 0, 0.85) == 1.0
        assert compute_effective_trust(-0.5, 0, 0.85) == 0.0

    def test_zero_reputation(self):
        assert compute_effective_trust(0.0, 1, 0.85) == 0.0


class TestComputeTrustScore:
    def test_returns_trust_score(self):
        ts = compute_trust_score(0.87, kya_level=1, delegation_depth=0, decay_factor=0.85)
        assert isinstance(ts, TrustScore)
        assert ts.reputation == 0.87
        assert ts.kya_level == 1
        assert ts.delegation_depth == 0
        assert ts.effective_trust == 0.87

    def test_summary_dict(self):
        ts = compute_trust_score(0.87, 1, 1, 0.85)
        s = ts.summary
        assert "reputation" in s
        assert "effective_trust" in s
        assert s["delegation_depth"] == 1


class TestApplyDelegationDecay:
    def test_increases_depth(self):
        parent = TrustScore(0.9, 1, 0, 0.85, 0.9)
        child = apply_delegation_decay(parent)
        assert child.delegation_depth == 1
        assert abs(child.effective_trust - 0.765) < 0.001

    def test_decay_chain(self):
        ts = TrustScore(0.92, 2, 0, 0.85, 0.92)
        for _ in range(3):
            ts = apply_delegation_decay(ts)
        assert ts.delegation_depth == 3
        expected = 0.92 * (0.85 ** 3)
        assert abs(ts.effective_trust - expected) < 0.001

    def test_exceeds_max_depth_zeroes_trust(self):
        os.environ["MCP_TRUST_MAX_DELEGATION_DEPTH"] = "2"
        try:
            parent = TrustScore(0.9, 1, 2, 0.85, 0.5)
            child = apply_delegation_decay(parent)
            assert child.effective_trust == 0.0
        finally:
            del os.environ["MCP_TRUST_MAX_DELEGATION_DEPTH"]
