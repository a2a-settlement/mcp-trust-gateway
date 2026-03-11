# MCP Trust Layer Extension

Specification v0.1.0

Extension URI: `https://a2a-settlement.org/extensions/mcp-trust/v1`

---

## 1. Introduction

The Model Context Protocol (MCP) enables AI agents and applications to discover and invoke tools exposed by remote servers. With the adoption of OAuth 2.1 and Streamable HTTP transport, MCP now provides a solid authentication foundation. However, authentication alone is insufficient for autonomous agent ecosystems.

OAuth 2.1 answers: *who is this agent?*

It does not answer: *should you trust this agent? How much authority should it carry? What happens when it misbehaves?*

The MCP Trust Layer Extension fills this gap by adding trust evaluation, reputation scoring, economic accountability, and trust-decaying delegation to the MCP protocol surface. It is designed as an additive layer that sits on top of MCP's existing OAuth 2.1 authentication — it does not replace, fork, or compete with MCP's identity model.

### 1.1. Design Principles

- **Additive.** Builds on MCP's OAuth 2.1 and Streamable HTTP. Requires zero modifications to the core MCP specification.
- **Protocol-transparent.** Operates as an intermediary between MCP clients and servers. Upstream MCP servers require no changes.
- **Trust is not binary.** Trust is a continuous value (0.0–1.0) derived from reputation history, identity verification depth, delegation chain length, and economic stake.
- **Trust decays.** Authority diminishes as it travels through delegation chains. Each hop reduces the effective trust score.
- **Economically grounded.** Trust decisions are backed by escrow, spending limits, and reputation consequences — not just access control lists.
- **Spec-first.** This document is the primary deliverable. The reference implementation demonstrates feasibility; the spec defines interoperability.

### 1.2. Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.3. Relationship to Existing Standards

| Standard | Relationship |
|----------|-------------|
| MCP (Model Context Protocol) | This extension operates within MCP's protocol surface |
| OAuth 2.1 (RFC 6749, draft-ietf-oauth-v2-1) | Foundation for identity; this extension adds trust on top |
| OAuth 2.0 Token Exchange (RFC 8693) | Extended with trust decay for multi-hop delegation |
| Protected Resource Metadata (RFC 9728) | Extended with trust requirements in metadata |
| Authorization Server Metadata (RFC 8414) | Used for gateway OAuth endpoint discovery |
| JWT (RFC 7519) | Token format for settlement claims |
| NIST SP 800-207 (Zero Trust Architecture) | Trust evaluation aligns with zero-trust principles |

---

## 2. Trust Model

### 2.1. Trust Score

Every agent operating through the gateway has a **trust score**: a floating-point value in the range [0.0, 1.0] that represents the gateway's confidence in the agent's reliability and intent.

The trust score is computed from multiple signals:

```
trust_score = f(reputation, kya_level, delegation_depth, economic_stake)
```

Where:

- **reputation** — Exponential Moving Average (EMA) of the agent's task outcome history on the settlement exchange. New agents start at 0.5. Successful completions increase reputation; failures, refunds, and disputes decrease it.
- **kya_level** — Know Your Agent identity verification tier (Section 2.2). Higher tiers indicate deeper identity assurance.
- **delegation_depth** — Number of hops in the delegation chain from the originating human principal. Each hop applies a decay factor.
- **economic_stake** — Whether the agent has escrow at risk for the current interaction.

Gateways MAY use additional signals. This specification defines the minimum required inputs.

### 2.2. Know Your Agent (KYA) Tiers

Identity verification is stratified into three tiers:

| Level | Name | Description | Verification |
|-------|------|-------------|-------------|
| 0 | SANDBOX | Unverified or self-declared identity | None required |
| 1 | ORGANIZATIONAL | Identity linked to an organization | Organization DID, domain verification, or IdP attestation |
| 2 | AUDITABLE | Cryptographically verifiable identity chain | DID document, verifiable credentials, attestation from trusted issuer |

KYA levels are monotonically increasing in trust. A gateway MUST NOT allow an agent with KYA level N to perform actions requiring KYA level N+1.

KYA levels are assigned by the settlement exchange during agent registration and MAY be upgraded through the exchange's verification process. The gateway queries the exchange for the current KYA level at token issuance time.

### 2.3. Reputation (EMA Scoring)

Agent reputation is maintained by the settlement exchange using an Exponential Moving Average:

```
R_new = λ × outcome + (1 - λ) × R_old
```

Where:
- `λ = 0.1` (smoothing factor; exchange-configurable)
- `outcome = 1.0` for successful task completion, `0.0` for failure/refund
- `R_initial = 0.5` for new agents

The gateway MUST query the exchange for the agent's current reputation when evaluating trust. Reputation values MUST be bounded to [0.0, 1.0].

### 2.4. Trust Decay in Delegation

When an agent delegates authority to another agent, the effective trust decays:

```
effective_trust = parent_trust × decay_factor^hop_count
```

Where:
- `decay_factor` defaults to 0.85 (gateway-configurable)
- `hop_count` is the number of delegation links in the chain

A delegation chain of length 3 with `decay_factor = 0.85` and `parent_trust = 0.92`:

```
Hop 0 (original):   0.92
Hop 1:              0.92 × 0.85 = 0.782
Hop 2:              0.782 × 0.85 = 0.665
Hop 3:              0.665 × 0.85 = 0.565
```

Gateways MUST reject delegated tokens whose effective trust falls below the tool's minimum reputation requirement.

---

## 3. Scope Taxonomy

### 3.1. Trust-Tier-Mapped Scopes

This specification defines a standard scope taxonomy that maps MCP tool categories to KYA trust tiers. This replaces arbitrary server-defined scope strings with scopes whose meaning is grounded in identity verification depth.

| Scope | KYA Level | Description |
|-------|-----------|-------------|
| `mcp:read` | SANDBOX (0) | Read-only access to data and resources |
| `mcp:tool:invoke` | SANDBOX (0) | Invoke tools with no side effects or bounded side effects |
| `mcp:tool:write` | ORGANIZATIONAL (1) | Invoke tools that mutate external state |
| `mcp:tool:financial` | AUDITABLE (2) | Invoke tools with economic impact (payments, trades, transfers) |
| `mcp:delegate` | AUDITABLE (2) | Sub-delegate authority to other agents |

Gateways MUST enforce these mappings. An agent with KYA level 0 (SANDBOX) MUST NOT be granted `mcp:tool:write` scope.

### 3.2. Scope Hierarchy

Scopes are not hierarchical by default. Each scope grants exactly the permissions it names. However, the gateway MAY define composite scopes:

- `mcp:full` — expands to `mcp:read` + `mcp:tool:invoke` + `mcp:tool:write`

Composite scopes MUST NOT bypass KYA tier requirements. An agent requesting `mcp:full` MUST satisfy the highest KYA tier required by any constituent scope (ORGANIZATIONAL for `mcp:tool:write`).

### 3.3. Settlement Scope Integration

When the gateway is connected to an A2A Settlement Exchange, the standard settlement scopes (`settlement:*`) from a2a-settlement-auth are also available:

| Scope | Description |
|-------|-------------|
| `settlement:read` | View balances, transaction history, reputation |
| `settlement:escrow:create` | Create escrow holds |
| `settlement:escrow:release` | Release escrowed funds |
| `settlement:escrow:refund` | Refund escrowed funds |
| `settlement:transact` | Composite: create + release + refund + read |

MCP scopes and settlement scopes are orthogonal. A token MAY carry both. The gateway evaluates each independently.

### 3.4. Server-Defined Scope Annotations

Upstream MCP servers MAY annotate their tools with trust requirements by including a `trust` object in the tool's metadata:

```json
{
  "name": "execute_trade",
  "description": "Submit a trade order",
  "inputSchema": { ... },
  "annotations": {
    "trust": {
      "required_kya_level": 2,
      "required_reputation": 0.8,
      "required_scope": "mcp:tool:financial",
      "economic_impact": true
    }
  }
}
```

When a tool does not carry trust annotations, the gateway MUST apply default trust requirements based on the scope taxonomy (Section 3.1).

---

## 4. Trust-Enriched OAuth Tokens

### 4.1. Token Structure

The gateway issues OAuth 2.1 tokens that carry both standard OAuth claims and settlement trust claims. Settlement claims are namespaced under `https://a2a-settlement.org/claims` per RFC 7519 Section 4.2.

```json
{
  "sub": "agent:analytics-bot-7f3a",
  "iss": "https://gateway.example.com",
  "aud": "https://gateway.example.com",
  "iat": 1740000000,
  "exp": 1740003600,
  "jti": "tok-uuid-here",
  "scope": "mcp:read mcp:tool:invoke settlement:transact",

  "https://a2a-settlement.org/claims": {
    "agent_id": "analytics-bot-7f3a",
    "org_id": "org-acme-corp",
    "spending_limits": {
      "per_transaction": 500,
      "per_day": 5000
    },
    "counterparty_policy": {
      "require_min_reputation": 0.7,
      "allowed_categories": ["analytics", "nlp"]
    },
    "delegation": {
      "chain": [
        {
          "principal": "user:julie@acme.com",
          "delegated_at": "2026-03-01T09:00:00Z",
          "purpose": "Q1 analytics procurement"
        }
      ],
      "transferable": false
    },
    "trust": {
      "kya_level": 1,
      "reputation": 0.87,
      "effective_trust": 0.87,
      "delegation_depth": 1,
      "decay_factor": 0.85
    }
  }
}
```

### 4.2. Trust Claims

The `trust` object within settlement claims is new to this specification:

| Claim | Type | Description |
|-------|------|-------------|
| `kya_level` | integer | Agent's KYA verification tier (0, 1, or 2) |
| `reputation` | float | Agent's EMA reputation score at token issuance |
| `effective_trust` | float | Computed trust score including delegation decay |
| `delegation_depth` | integer | Number of hops from the original principal |
| `decay_factor` | float | Decay factor applied per delegation hop |

The `effective_trust` value MUST be computed at token issuance time and MUST be revalidated against live reputation data on each tool invocation (since reputation changes between issuance and use).

### 4.3. Token Issuance Flow

The gateway implements OAuth 2.1 Authorization Code with PKCE:

```
1. Client sends GET /oauth/authorize?response_type=code&client_id=...
   &code_challenge=...&code_challenge_method=S256&scope=mcp:read+mcp:tool:invoke
2. Gateway authenticates the agent (redirect to IdP or API key exchange)
3. Gateway queries the settlement exchange for:
   - Agent's KYA level
   - Agent's EMA reputation
   - Agent's spending limits and counterparty policy
4. Gateway validates requested scopes against KYA level
5. Gateway issues authorization code
6. Client exchanges code for token at POST /oauth/token
7. Token includes settlement claims with trust metadata
```

The gateway MUST reject scope requests that exceed the agent's KYA tier. For example, an agent with KYA level 0 requesting `mcp:tool:write` MUST receive an error indicating that ORGANIZATIONAL verification is required.

---

## 5. Pre-Auth Tool Discovery

### 5.1. Discovery Endpoint

The gateway MUST expose a pre-authentication tool discovery endpoint:

```
GET /.well-known/mcp-tools
```

This endpoint MUST NOT require authentication. It returns a manifest of available tools from registered upstream MCP servers, annotated with trust requirements.

### 5.2. Tool Manifest Format

```json
{
  "gateway": "https://gateway.example.com",
  "protocol_version": "2026.1",
  "upstream_servers": [
    {
      "id": "analytics-server",
      "name": "Analytics MCP Server",
      "description": "SQL queries and data analysis",
      "agent_card_url": "https://exchange.example.com/accounts/analytics-server/card"
    }
  ],
  "tools": [
    {
      "name": "query_database",
      "server_id": "analytics-server",
      "description": "Run read-only SQL queries against the warehouse",
      "trust_requirements": {
        "required_kya_level": 0,
        "required_reputation": 0.0,
        "required_scope": "mcp:read",
        "kya_level_name": "SANDBOX"
      }
    },
    {
      "name": "execute_trade",
      "server_id": "trading-server",
      "description": "Submit a trade order to the exchange",
      "trust_requirements": {
        "required_kya_level": 2,
        "required_reputation": 0.8,
        "required_scope": "mcp:tool:financial",
        "kya_level_name": "AUDITABLE"
      }
    }
  ],
  "scope_taxonomy": {
    "mcp:read": { "kya_level": 0, "description": "Read-only access" },
    "mcp:tool:invoke": { "kya_level": 0, "description": "Basic tool invocation" },
    "mcp:tool:write": { "kya_level": 1, "description": "State-mutating tools" },
    "mcp:tool:financial": { "kya_level": 2, "description": "Economic-impact tools" },
    "mcp:delegate": { "kya_level": 2, "description": "Sub-delegation authority" }
  }
}
```

### 5.3. Agent Card Bridge

When the gateway is connected to an A2A Settlement Exchange, it SHOULD populate the tool manifest from the exchange's agent directory and Agent Card capabilities. Agent Cards published to the exchange include:

- `capabilities.skills` — tool categories the agent provides
- `settlement.exchange_url` — the exchange where reputation is tracked
- `kya_level` — the agent's identity verification tier

The gateway bridges this data into the MCP tool discovery format, allowing MCP clients to understand what tools are available and what trust level they require before initiating OAuth.

---

## 6. Trust Evaluation Protocol

### 6.1. Evaluation on Tool Invocation

On every proxied MCP `tools/call` request, the gateway MUST perform the following trust evaluation:

```
1. Extract bearer token from Authorization header
2. Validate token signature and expiration
3. Extract SettlementClaims from the token
4. Query the exchange for the agent's CURRENT reputation
   (reputation may have changed since token issuance)
5. Compute effective_trust = reputation × decay_factor^delegation_depth
6. Look up trust requirements for the requested tool
7. Evaluate:
   a. kya_level >= tool.required_kya_level
   b. effective_trust >= tool.required_reputation
   c. spending_limits not exceeded (if economic_impact tool)
   d. counterparty_policy allows the upstream server
8. If ALL pass: proxy the request to the upstream MCP server
9. If ANY fail: return a structured denial (Section 6.2)
```

Gateways SHOULD cache reputation queries for a configurable TTL (default: 60 seconds) to avoid excessive exchange round-trips. Gateways MUST NOT cache reputation for longer than 5 minutes.

### 6.2. Structured Denial Response

When trust evaluation fails, the gateway MUST return a JSON-RPC error with a structured `data` field that enables the client to understand what is needed to gain access:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Trust evaluation failed",
    "data": {
      "error_type": "trust_insufficient",
      "tool": "execute_trade",
      "evaluations": {
        "kya_level": {
          "passed": false,
          "required": 2,
          "current": 1,
          "required_name": "AUDITABLE",
          "current_name": "ORGANIZATIONAL"
        },
        "reputation": {
          "passed": true,
          "required": 0.8,
          "current": 0.87
        },
        "spending_limit": {
          "passed": true
        },
        "counterparty_policy": {
          "passed": true
        }
      },
      "upgrade_path": {
        "message": "This tool requires AUDITABLE identity verification. Current level: ORGANIZATIONAL.",
        "kya_upgrade_url": "https://exchange.example.com/kya/upgrade"
      }
    }
  }
}
```

The `evaluations` object MUST include results for all evaluated dimensions, not just failures. This allows clients to provide comprehensive feedback to users.

---

## 7. Trust-Decaying Token Exchange

### 7.1. RFC 8693 Extension

The gateway implements the `urn:ietf:params:oauth:grant-type:token-exchange` grant type from RFC 8693, extended with trust decay semantics.

### 7.2. Exchange Request

An agent requesting a delegated token sends:

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<parent-jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&requested_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=mcp:read+mcp:tool:invoke
&audience=https://gateway.example.com
&actor_token_agent_id=sub-agent-42
```

### 7.3. Exchange Semantics

The gateway MUST apply the following rules during token exchange:

1. **Validate parent token.** Standard JWT validation plus settlement claims extraction.
2. **Check transferable flag.** If `delegation.transferable` is `false`, the exchange MUST be rejected with error `delegation_not_transferable`.
3. **Narrow scopes.** The child token's scopes MUST be the intersection of the parent's scopes and the requested scopes. Scopes can only narrow, never widen.
4. **Apply trust decay.** The child token's `effective_trust` MUST be: `parent_effective_trust × decay_factor`.
5. **Reduce spending limits.** The child token's spending limits MUST NOT exceed the parent's remaining budget. Gateways SHOULD proportionally reduce limits based on the trust decay ratio.
6. **Extend delegation chain.** A new `DelegationLink` MUST be appended to the chain with the parent agent as principal.
7. **Set transferable.** The child token's `transferable` flag MUST be `false` unless the parent explicitly grants sub-delegation and the child's KYA level is AUDITABLE.

### 7.4. Exchange Response

```json
{
  "access_token": "<child-jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "mcp:read mcp:tool:invoke",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "trust_metadata": {
    "effective_trust": 0.782,
    "delegation_depth": 2,
    "parent_trust": 0.92,
    "decay_applied": 0.85,
    "scopes_narrowed_from": "mcp:read mcp:tool:invoke mcp:tool:write",
    "spending_limits_reduced": true
  }
}
```

The `trust_metadata` field is an extension to RFC 8693 that provides transparency about how trust was computed for the delegated token.

---

## 8. Economic Accountability Binding

### 8.1. Escrow-Gated Tool Invocation

For tools annotated with `economic_impact: true`, the gateway MAY require an active escrow before allowing invocation:

1. The requesting agent creates an escrow via the settlement exchange.
2. The escrow ID is included in the MCP request metadata.
3. The gateway validates the escrow exists, has sufficient balance, and names the correct counterparties.
4. On successful tool completion, the escrow is released.
5. On failure, the escrow is refunded.

This binds every economic tool invocation to a financial stake, creating consequences for misbehavior beyond reputation damage.

### 8.2. Reputation Consequences

Every tool invocation that flows through the gateway contributes to the agent's reputation:

- **Successful invocation** (tool returns result, no errors): reputation increases toward 1.0
- **Failed invocation** (tool returns error, timeout, or invalid result): reputation decreases toward 0.0
- **Dispute filed**: reputation is frozen until resolution

The gateway MUST report tool outcomes to the settlement exchange for reputation updates. The exchange applies EMA scoring per Section 2.3.

### 8.3. Audit Trail

The gateway MUST maintain an audit log of all trust evaluations with:

- Timestamp
- Agent identity (sub, agent_id, org_id)
- Tool requested
- Trust score at evaluation time
- Evaluation result (pass/fail per dimension)
- Delegation chain at the time of request

Audit logs SHOULD be compatible with the settlement exchange's Merkle-backed compliance records (RFC 6962).

---

## 9. Gateway Metadata

### 9.1. Protected Resource Metadata (RFC 9728)

The gateway MUST publish protected resource metadata at:

```
GET /.well-known/oauth-protected-resource
```

```json
{
  "resource": "https://gateway.example.com",
  "authorization_servers": ["https://gateway.example.com"],
  "scopes_supported": [
    "mcp:read",
    "mcp:tool:invoke",
    "mcp:tool:write",
    "mcp:tool:financial",
    "mcp:delegate",
    "settlement:read",
    "settlement:transact"
  ],
  "bearer_methods_supported": ["header"],
  "trust_extension": {
    "spec_version": "0.1.0",
    "kya_levels": [
      { "level": 0, "name": "SANDBOX", "description": "Unverified identity" },
      { "level": 1, "name": "ORGANIZATIONAL", "description": "Organization-verified identity" },
      { "level": 2, "name": "AUDITABLE", "description": "Cryptographically verifiable identity" }
    ],
    "trust_decay_factor": 0.85,
    "max_delegation_depth": 5,
    "exchange_url": "https://exchange.a2a-settlement.org",
    "pre_auth_discovery": "/.well-known/mcp-tools"
  }
}
```

### 9.2. Authorization Server Metadata (RFC 8414)

The gateway MUST publish authorization server metadata at:

```
GET /.well-known/oauth-authorization-server
```

This follows standard RFC 8414 format with the addition of:

- `grant_types_supported` MUST include `urn:ietf:params:oauth:grant-type:token-exchange`
- `token_exchange_trust_decay` SHOULD be included indicating support for trust-decaying token exchange

---

## 10. Security Considerations

### 10.1. Trust Score Manipulation

Agents may attempt to inflate their reputation through synthetic successful transactions. Mitigations:

- The settlement exchange SHOULD impose minimum escrow amounts for reputation-affecting transactions
- KYA level upgrades MUST require out-of-band verification, not just transaction volume
- Gateways SHOULD apply rate limiting on reputation queries to detect anomalous patterns

### 10.2. Delegation Chain Attacks

An attacker may attempt to create long delegation chains to obscure the original principal:

- Gateways MUST enforce a maximum delegation depth (default: 5)
- Each hop applies trust decay, making deep chains progressively less useful
- Gateways SHOULD log and alert on delegation chains approaching the maximum depth

### 10.3. Token Replay

Standard OAuth token security applies. Additionally:

- Gateways SHOULD use short-lived tokens (default: 1 hour)
- Delegated tokens SHOULD have shorter lifetimes than their parents
- The `jti` claim MUST be unique and SHOULD be tracked for replay detection

### 10.4. Stale Reputation

Since reputation is queried at evaluation time (not just token issuance), there is a window where cached reputation may be stale:

- Gateways MUST NOT cache reputation for longer than 5 minutes
- For high-value tool invocations (`mcp:tool:financial`), gateways SHOULD query reputation in real-time (no cache)

---

## 11. Conformance

### 11.1. Gateway Requirements

A conforming MCP Trust Gateway implementation MUST:

1. Implement OAuth 2.1 Authorization Code with PKCE
2. Issue tokens with settlement claims (Section 4)
3. Expose pre-auth tool discovery at `/.well-known/mcp-tools` (Section 5)
4. Evaluate trust on every proxied `tools/call` (Section 6)
5. Return structured denial responses on trust failure (Section 6.2)
6. Enforce scope-to-KYA-tier mappings (Section 3)
7. Support RFC 8693 token exchange with trust decay (Section 7)
8. Publish protected resource metadata (Section 9.1)
9. Publish authorization server metadata (Section 9.2)
10. Maintain an audit trail (Section 8.3)

### 11.2. Upstream MCP Server Requirements

Upstream MCP servers require NO changes to work with the gateway. However, servers MAY enhance trust evaluation by:

1. Including trust annotations on tools (Section 3.4)
2. Publishing an Agent Card to the settlement exchange (Section 5.3)

---

## 12. References

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [A2A Settlement Extension (A2A-SE) Specification](https://github.com/a2a-settlement/a2a-settlement/blob/main/SPEC.md)
- [A2A Settlement Auth](https://github.com/a2a-settlement/a2a-settlement-auth)
- [RFC 2119 — Key words for use in RFCs](https://tools.ietf.org/html/rfc2119)
- [RFC 6749 — OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7519 — JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://tools.ietf.org/html/rfc9728)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
