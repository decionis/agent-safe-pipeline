# MCP tool gate

A real stdio MCP server exposes `delete_customer`. The tool handler captures the exact invocation, asks the independent authority, and calls `SafeExecutor`; the fixture policy blocks it.

Build it and configure an MCP host to run `node` with the absolute path to `dist/Index.js`:

```bash
pnpm --filter @decionis/agent-safe-example-mcp-tool-gate build
```

The example pins the production-recommended v1 MCP TypeScript SDK line. Replace the fixture authority and synthetic identity with trusted server configuration before production use.
