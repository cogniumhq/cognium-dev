#!/usr/bin/env node
/**
 * Entry point for the `@cognium/mcp-server` binary. Wires the MCP
 * server to stdio transport — the transport every MCP client (Claude
 * Desktop, Claude Code, Cursor) speaks by default.
 *
 * WASM initialization is deferred to first tool invocation so that
 * `mcp-server-cognium-dev --version` and the initial handshake do not
 * pay the ~200ms tree-sitter cost.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { buildServer } from './server.js';

async function main(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  // stderr is safe for stdio-transport servers (stdout is reserved for
  // MCP messages).
  process.stderr.write(`[mcp-server-cognium-dev] fatal: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
