# Cursor Configuration

## Connect Cursor to the MCP Trust Gateway

Add the following to `.cursor/mcp.json` in your workspace:

```json
{
  "mcpServers": {
    "trust-gateway": {
      "url": "http://localhost:3100/mcp"
    }
  }
}
```

## Starting the Gateway

```bash
export A2A_EXCHANGE_URL=http://localhost:3000
export OAUTH_SIGNING_KEY=your-signing-key
export OAUTH_ISSUER=http://localhost:3100
python -m mcp_trust_gateway
```

The gateway starts on port 3100 by default. Override with `MCP_TRUST_GATEWAY_PORT`.

## How It Works with Cursor

1. Cursor connects to the gateway via Streamable HTTP at `/mcp`.
2. Tool discovery returns all upstream tools with trust annotations.
3. On each tool invocation, the gateway evaluates the caller's KYA level and reputation.
4. If trust is insufficient, the error includes what identity verification level is needed.

## Environment Variables

Set these in the `env` block if needed:

```json
{
  "mcpServers": {
    "trust-gateway": {
      "url": "http://localhost:3100/mcp",
      "env": {
        "A2A_EXCHANGE_URL": "http://localhost:3000",
        "OAUTH_SIGNING_KEY": "your-signing-key"
      }
    }
  }
}
```
