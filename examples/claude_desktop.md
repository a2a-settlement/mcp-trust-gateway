# Claude Desktop Configuration

## Connect Claude Desktop to the MCP Trust Gateway

Add the following to your `claude_desktop_config.json`:

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

## What Happens

1. When Claude Desktop connects, it calls `tools/list` to discover available tools (no auth required).
2. Each tool includes trust annotations showing what KYA level and reputation are required.
3. When Claude invokes a tool, the gateway evaluates trust before proxying to the upstream server.
4. If trust is insufficient, Claude receives a structured denial explaining what's needed to gain access.

## Config File Location

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

## Pre-Auth Discovery

Before authenticating, Claude can check what tools are available and their trust requirements:

```bash
curl http://localhost:3100/.well-known/mcp-tools
```

## Gateway Metadata

Claude can discover the gateway's OAuth and trust capabilities:

```bash
curl http://localhost:3100/.well-known/oauth-authorization-server
curl http://localhost:3100/.well-known/oauth-protected-resource
```
