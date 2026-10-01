#!/usr/bin/env node
/**
 * The `@cognium/mcp-server` binary. Wires the server to stdio — the
 * transport every MCP client (Claude Desktop, Claude Code, Cursor) speaks by
 * default.
 *
 * This file is the bin and nothing else, so it may run `main()`
 * unconditionally. The library entry is `index.ts`, which has no side
 * effects: importing the package no longer attaches a transport to the host
 * process's stdin and stdout, which is what made the package impossible to
 * mount over HTTP before.
 *
 * WASM initialization stays deferred to the first tool invocation so
 * `--version` and the initial handshake do not pay the ~200 ms tree-sitter
 * cost.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';
import { startupLines } from './startup.js';

async function main(): Promise<void> {
  const { server, discovery } = await createServer();
  for (const line of startupLines(discovery)) {
    process.stderr.write(`${line}\n`);
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  // stderr is safe for stdio-transport servers (stdout is reserved for MCP
  // messages).
  process.stderr.write(`[@cognium/mcp-server] fatal: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
