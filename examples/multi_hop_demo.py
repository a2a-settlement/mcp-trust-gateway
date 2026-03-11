"""Multi-hop delegation demo — shows trust decay across delegation hops.

Demonstrates:
  1. An original agent with high reputation (0.92)
  2. Delegating authority to a sub-agent via RFC 8693 token exchange
  3. The sub-agent further delegating to a third agent
  4. Trust decaying at each hop (0.92 -> 0.782 -> 0.665)
  5. The third agent being denied access to a tool requiring 0.8 reputation

Run:
    python examples/multi_hop_demo.py
"""

from __future__ import annotations

import os
import time

# Set test configuration before imports
os.environ.setdefault("OAUTH_SIGNING_KEY", "demo-secret-key-change-in-production")
os.environ.setdefault("OAUTH_ALGORITHM", "HS256")
os.environ.setdefault("OAUTH_ISSUER", "https://demo-gateway.example.com")
os.environ.setdefault("OAUTH_AUDIENCE", "https://gateway.a2a-settlement.org")
os.environ.setdefault("MCP_TRUST_DECAY_FACTOR", "0.85")
os.environ.setdefault("MCP_TRUST_MAX_DELEGATION_DEPTH", "5")

import jwt as pyjwt

from mcp_trust_gateway.trust.trust_decay import (
    compute_trust_score,
    apply_delegation_decay,
)
from mcp_trust_gateway.trust.scope_mapper import (
    ToolTrustRequirements,
    MCPScope,
    KYA_LEVEL_NAMES,
)
from mcp_trust_gateway.trust.evaluator import TrustEvaluator

CLAIMS_NAMESPACE = "https://a2a-settlement.org/claims"
SIGNING_KEY = os.environ["OAUTH_SIGNING_KEY"]
ALGORITHM = os.environ["OAUTH_ALGORITHM"]
AUDIENCE = os.environ["OAUTH_AUDIENCE"]


def make_token(agent_id: str, trust_score, scopes: str, chain: list, transferable: bool) -> str:
    now = int(time.time())
    return pyjwt.encode({
        "sub": f"agent:{agent_id}",
        "iss": os.environ["OAUTH_ISSUER"],
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "jti": f"jti-{agent_id}",
        "scope": scopes,
        CLAIMS_NAMESPACE: {
            "agent_id": agent_id,
            "org_id": "org-demo",
            "spending_limits": {"per_transaction": 500, "per_day": 5000},
            "counterparty_policy": {},
            "delegation": {"chain": chain, "transferable": transferable},
            "trust": trust_score.summary,
        },
    }, SIGNING_KEY, algorithm=ALGORITHM)


async def main():
    print("=" * 60)
    print("  MCP Trust Gateway — Multi-Hop Delegation Demo")
    print("=" * 60)
    print()

    # --- Hop 0: Original agent ---
    print("--- Hop 0: Original Agent (Alice's bot) ---")
    agent_a_trust = compute_trust_score(reputation=0.92, kya_level=2, delegation_depth=0)
    print(f"  Agent: orchestrator-a")
    print(f"  Reputation: {agent_a_trust.reputation}")
    print(f"  KYA Level: {KYA_LEVEL_NAMES[agent_a_trust.kya_level]}")
    print(f"  Effective Trust: {agent_a_trust.effective_trust:.4f}")
    print()

    chain_a = [{"principal": "user:alice@acme.com", "delegated_at": "2026-03-01T09:00:00Z"}]

    # --- Hop 1: First delegation ---
    print("--- Hop 1: Delegate to analyst-b ---")
    agent_b_trust = apply_delegation_decay(agent_a_trust)
    print(f"  Agent: analyst-b")
    print(f"  Delegation Depth: {agent_b_trust.delegation_depth}")
    print(f"  Effective Trust: {agent_b_trust.effective_trust:.4f}")
    print(f"  Trust Decay: {agent_a_trust.effective_trust:.4f} x {agent_b_trust.decay_factor} = {agent_b_trust.effective_trust:.4f}")
    print()

    chain_b = chain_a + [
        {"principal": "agent:orchestrator-a", "delegated_at": "2026-03-01T09:01:00Z"}
    ]

    # --- Hop 2: Second delegation ---
    print("--- Hop 2: Delegate to scraper-c ---")
    agent_c_trust = apply_delegation_decay(agent_b_trust)
    print(f"  Agent: scraper-c")
    print(f"  Delegation Depth: {agent_c_trust.delegation_depth}")
    print(f"  Effective Trust: {agent_c_trust.effective_trust:.4f}")
    print(f"  Trust Decay: {agent_b_trust.effective_trust:.4f} x {agent_c_trust.decay_factor} = {agent_c_trust.effective_trust:.4f}")
    print()

    chain_c = chain_b + [
        {"principal": "agent:analyst-b", "delegated_at": "2026-03-01T09:02:00Z"}
    ]

    # --- Trust Evaluation ---
    print("=" * 60)
    print("  Trust Evaluation Against Tools")
    print("=" * 60)
    print()

    evaluator = TrustEvaluator()
    evaluator.register_tool("query_data", ToolTrustRequirements(
        required_kya_level=0, required_reputation=0.0, required_scope=MCPScope.READ,
    ))
    evaluator.register_tool("write_report", ToolTrustRequirements(
        required_kya_level=1, required_reputation=0.5, required_scope=MCPScope.TOOL_WRITE,
    ))
    evaluator.register_tool("execute_trade", ToolTrustRequirements(
        required_kya_level=2, required_reputation=0.8, required_scope=MCPScope.TOOL_FINANCIAL,
        economic_impact=True,
    ))

    for agent_name, trust, depth in [
        ("orchestrator-a", agent_a_trust, 0),
        ("analyst-b", agent_b_trust, 1),
        ("scraper-c", agent_c_trust, 2),
    ]:
        print(f"  {agent_name} (trust={trust.effective_trust:.4f}, depth={depth}):")
        for tool in ["query_data", "write_report", "execute_trade"]:
            result = await evaluator.evaluate(
                tool_name=tool,
                agent_id=agent_name,
                kya_level=trust.kya_level,
                reputation=trust.reputation,
                delegation_depth=depth,
            )
            status = "ALLOWED" if result.allowed else "DENIED"
            print(f"    {tool}: {status}", end="")
            if not result.allowed:
                failed = [d.dimension for d in result.dimensions if not d.passed]
                print(f"  (failed: {', '.join(failed)})", end="")
            print()
        print()

    print("Key takeaway: scraper-c was denied execute_trade because")
    print(f"  its effective trust ({agent_c_trust.effective_trust:.4f}) is below the")
    print(f"  required 0.8 — even though the original agent had 0.92 reputation.")
    print(f"  Trust decayed across {agent_c_trust.delegation_depth} delegation hops.")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
