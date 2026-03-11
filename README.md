# MCP Trust Gateway

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-Protocol-green.svg)](https://modelcontextprotocol.io/)

**Trust, reputation, and economic accountability for MCP — the missing layer above OAuth.**

MCP's OAuth 2.1 foundation answers *who is this agent?* This gateway answers the harder question: **authenticated, but trustworthy?** It sits between MCP clients and upstream MCP servers as a protocol-transparent proxy, enriching every tool invocation with trust evaluation powered by [A2A Settlement Exchange](https://github.com/a2a-settlement/a2a-settlement) reputation, KYA tiers, spending limits, and delegation chains.

```
MCP Client                                          Upstream MCP Servers
(Claude, Cursor, agents)                            (any MCP server)
        │                                                   ▲
        │  MCP Streamable HTTP                              │
        │  + OAuth 2.1 / PKCE                               │
        ▼                                                   │
┌───────────────────────────────────────────────────────────────┐
│                     MCP Trust Gateway                         │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ OAuth 2.1   │  │ Trust        │  │ Pre-Auth Tool        │ │
│  │ + Settlement│  │ Evaluator    │  │ Discovery            │ │
│  │   Claims    │  │ (KYA + EMA)  │  │ (/.well-known/       │ │
│  │             │  │              │  │  mcp-tools)          │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────────────────┘ │
│         │                │                                    │
│  ┌──────┴──────┐  ┌──────┴───────┐                            │
│  │ RFC 8693    │  │ Scope-to-KYA │                            │
│  │ Token       │  │ Tier Mapper  │                            │
│  │ Exchange    │  │              │                            │
│  │ + Trust     │  │              │                            │
│  │   Decay     │  │              │                            │
│  └─────────────┘  └──────────────┘                            │
└───────────────────────────┬───────────────────────────────────┘
                            │ queries
                            ▼
                ┌───────────────────────┐
                │  A2A Settlement       │
                │  Exchange             │
                │  (reputation, KYA,    │
                │   agent directory)    │
                └───────────────────────┘
```

## The Gap

MCP has made real progress on authentication. OAuth 2.1 with PKCE, Streamable HTTP transport, the MCP Connector in Claude's API, and enterprise IdP integrations from Auth0 and AWS. The *identity* problem is largely solved.

But four gaps remain — and they all sit above authentication:

| MCP Challenge | Root Problem | What This Gateway Provides |
|---------------|-------------|---------------------------|
| **Scope standardization** | `read:files` means whatever each server decides | Trust-tier-mapped scopes: KYA levels give scopes meaning beyond arbitrary strings |
| **3rd-party agents blocked by redirects** | Autonomous agents can't do browser-based OAuth redirects | Authorization intermediary: the gateway handles OAuth on behalf of agents using the Economic Air Gap pattern |
| **Tool discovery gated behind auth** | Agents must authenticate before knowing what tools exist | Pre-auth discovery endpoint (`/.well-known/mcp-tools`) backed by the exchange's agent directory and Agent Cards |
| **Multi-hop token exchange** | RFC 8693 doesn't address trust decay across delegation hops | Trust-decaying token exchange: EMA reputation scoring layered on top of RFC 8693, with delegation chains that narrow authority per hop |

The common thread: **authentication is necessary but not sufficient for autonomous agents**. OAuth says "this token is valid." The trust gateway adds "and here's how much you should trust the agent presenting it."

## How It Works

### 1. Trust-Enriched OAuth

The gateway implements MCP's OAuth 2.1 flow (Authorization Code + PKCE) but enriches issued tokens with [settlement claims](https://github.com/a2a-settlement/a2a-settlement-auth):

```json
{
  "sub": "agent:analytics-bot-7f3a",
  "scope": "settlement:transact mcp:tool:invoke",
  "https://a2a-settlement.org/claims": {
    "agent_id": "analytics-bot-7f3a",
    "org_id": "org-acme-corp",
    "kya_level": 1,
    "reputation": 0.87,
    "spending_limits": { "per_transaction": 500, "per_day": 5000 },
    "counterparty_policy": { "require_min_reputation": 0.7 },
    "delegation": {
      "chain": [{ "principal": "user:julie@acme.com", "delegated_at": "2026-03-01T09:00:00Z" }],
      "transferable": false
    }
  }
}
```

The token carries identity (OAuth) *and* trustworthiness (settlement claims) in a single artifact.

### 2. Pre-Auth Tool Discovery

Agents can discover available tools and their trust requirements *before* authenticating:

```
GET /.well-known/mcp-tools
```

```json
{
  "tools": [
    {
      "name": "query_database",
      "description": "Run read-only SQL queries",
      "required_kya_level": 0,
      "required_reputation": 0.0,
      "required_scope": "mcp:read"
    },
    {
      "name": "execute_trade",
      "description": "Submit a trade order",
      "required_kya_level": 2,
      "required_reputation": 0.8,
      "required_scope": "mcp:tool:financial"
    }
  ]
}
```

Clients evaluate what permissions they need before initiating OAuth. No more blind authorization prompts.

### 3. Trust Evaluation on Every Call

On every proxied `tools/call`, the gateway evaluates:

- **KYA tier** >= tool's required tier (identity verification depth)
- **EMA reputation** >= tool's minimum threshold (track record)
- **Spending limits** not exceeded (economic guardrails)
- **Counterparty policy** allows the upstream server (organizational constraints)
- **Delegation chain** is intact and transferable flag permits the hop

If trust is insufficient, the gateway returns a structured denial with an upgrade path:

```json
{
  "error": "trust_insufficient",
  "required_kya_level": 2,
  "current_kya_level": 1,
  "upgrade_url": "https://exchange.example.com/kya/upgrade",
  "message": "This tool requires AUDITABLE identity verification. Current level: ORGANIZATIONAL."
}
```

### 4. Trust-Decaying Token Exchange

For multi-hop scenarios (agent A delegates to agent B which calls tool C), the gateway implements RFC 8693 token exchange extended with trust decay:

```
Agent A (reputation: 0.92)
    │
    │  RFC 8693 token exchange
    │  trust_score = 0.92 × 0.85 decay = 0.782
    ▼
Agent B (delegated token, effective trust: 0.782)
    │
    │  second hop
    │  trust_score = 0.782 × 0.85 decay = 0.665
    ▼
Tool C (requires min reputation: 0.6) ✓ allowed
```

Each hop in the delegation chain reduces effective trust via EMA-weighted decay. Scopes narrow (never widen). Spending limits reduce proportionally. The result: "yes this token is valid, but the further it travels from the original principal, the less authority it carries."

### 5. Scope-to-Trust-Tier Mapping

Instead of arbitrary server-defined scope strings, the gateway maps MCP tool categories to trust tiers:

| MCP Scope | KYA Level Required | Meaning |
|-----------|-------------------|---------|
| `mcp:read` | SANDBOX (0) | Read-only access, any agent |
| `mcp:tool:invoke` | SANDBOX (0) | Basic tool invocation |
| `mcp:tool:write` | ORGANIZATIONAL (1) | Tools that mutate state |
| `mcp:tool:financial` | AUDITABLE (2) | Tools with economic impact |
| `mcp:delegate` | AUDITABLE (2) | Sub-delegation of authority |

This gives scopes meaning grounded in verified identity, not server whim.

## Install

```bash
pip install -e .
```

Or from git:

```bash
pip install git+https://github.com/a2a-settlement/mcp-trust-gateway.git
```

## Quick Start

### 1. Start the Gateway

```bash
export A2A_EXCHANGE_URL=http://localhost:3000
export MCP_TRUST_GATEWAY_PORT=3100
python -m mcp_trust_gateway
```

The gateway starts on port 3100, proxying to upstream MCP servers registered in the exchange's agent directory.

### 2. Connect Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trust-gateway": {
      "url": "http://localhost:3100/mcp",
      "authorization": {
        "type": "oauth2",
        "authorization_url": "http://localhost:3100/oauth/authorize",
        "token_url": "http://localhost:3100/oauth/token"
      }
    }
  }
}
```

### 3. Connect Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "trust-gateway": {
      "url": "http://localhost:3100/mcp",
      "env": {
        "A2A_EXCHANGE_URL": "http://localhost:3000"
      }
    }
  }
}
```

## Configuration

| Variable | Default | Description |
|---------|---------|-------------|
| `A2A_EXCHANGE_URL` | `http://localhost:3000` | A2A Settlement Exchange URL |
| `MCP_TRUST_GATEWAY_PORT` | `3100` | Gateway listen port |
| `MCP_TRUST_DECAY_FACTOR` | `0.85` | Trust decay per delegation hop |
| `MCP_TRUST_MIN_REPUTATION` | `0.0` | Global minimum reputation floor |
| `MCP_TRUST_DEFAULT_KYA` | `0` | Default KYA level for unverified agents |
| `OAUTH_ISSUER` | (required) | OAuth token issuer URL |
| `OAUTH_SIGNING_KEY` | (required) | Key for signing issued tokens |

## Project Structure

```
mcp-trust-gateway/
  SPEC.md                          # RFC-style trust layer specification
  README.md
  pyproject.toml
  src/mcp_trust_gateway/
    __init__.py
    __main__.py                    # Entry point
    config.py                      # Environment configuration
    server.py                      # MCP server (client-facing)
    proxy.py                       # MCP client (upstream-facing proxy)
    oauth/
      provider.py                  # OAuth 2.1 + PKCE authorization endpoint
      token_exchange.py            # RFC 8693 with trust decay
      metadata.py                  # RFC 8414 / RFC 9728 metadata
    trust/
      evaluator.py                 # Trust evaluation engine
      scope_mapper.py              # MCP scope <-> SettlementScope <-> KYA tier
      trust_decay.py               # EMA-weighted trust decay for delegation
    discovery/
      well_known.py                # /.well-known/mcp-tools endpoint
      registry.py                  # Exchange directory -> tool manifest bridge
  tests/
  examples/
```

## Design Principles

**Protocol-transparent proxy.** The gateway does not define its own MCP tools. It proxies upstream MCP servers and adds trust evaluation as middleware. Any existing MCP server works without modification.

**Reuse, don't rebuild.** OAuth token validation, scope checking, claims parsing, spending limits, and delegation chains come from [a2a-settlement-auth](https://github.com/a2a-settlement/a2a-settlement-auth). Reputation and KYA queries come from the [a2a-settlement SDK](https://github.com/a2a-settlement/a2a-settlement). The gateway is the glue.

**Spec-first.** The [SPEC.md](SPEC.md) is the primary deliverable — it's what gets proposed back to the MCP ecosystem as the missing trust layer. The code is the reference implementation.

**Additive, not competitive.** This builds on MCP's OAuth 2.1 foundation. It does not replace it, fork it, or compete with it. It answers the question OAuth was never designed to answer: *should you trust this agent?*

## Related Projects

| Project | Description |
|---------|-------------|
| [a2a-settlement](https://github.com/a2a-settlement/a2a-settlement) | Core settlement exchange + SDK (reputation, KYA, escrow) |
| [a2a-settlement-auth](https://github.com/a2a-settlement/a2a-settlement-auth) | OAuth settlement scopes, claims, spending limits, delegation chains |
| [a2a-settlement-mcp](https://github.com/a2a-settlement/a2a-settlement-mcp) | MCP server exposing settlement operations as tools |
| [a2a-settlement-mediator](https://github.com/a2a-settlement/a2a-settlement-mediator) | AI-powered dispute resolution |
| [a2a-settlement-dashboard](https://github.com/a2a-settlement/a2a-settlement-dashboard) | Human oversight dashboard |

**This gateway vs a2a-settlement-mcp:** The [MCP server](https://github.com/a2a-settlement/a2a-settlement-mcp) exposes settlement *operations* as tools (create escrow, check balance, etc.). This gateway evaluates *trust* on MCP tool invocations. They are complementary — you might use the MCP server behind this gateway, or use the gateway to protect any other MCP server.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most impactful contributions right now are to the [SPEC.md](SPEC.md) — helping formalize the trust layer so it can be proposed upstream to the MCP ecosystem.

## License

MIT. See [LICENSE](LICENSE).
