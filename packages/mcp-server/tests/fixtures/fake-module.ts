/**
 * A stand-in tool module for the loader and three-state tests.
 *
 * It mirrors what a real optional module does, without depending on one: a
 * tool that is always available once the module is loaded, and a tool that
 * needs a configured endpoint and is simply not listed when there is none.
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolModule } from '../../src/modules.js';
import type { ToolContext } from '../../src/tools/types.js';

export const DETERMINISTIC_TOOL = 'fixture_deterministic';
export const ENDPOINT_BACKED_TOOL = 'fixture_endpoint_backed';

export interface FakeModuleOptions {
  readonly id?: string;
  readonly version?: string;
  readonly licence?: string;
  readonly circleIrRange?: string;
  /** Throw from `register`, to prove the floor survives it. */
  readonly throwOnRegister?: boolean;
}

export function fakeModule(opts: FakeModuleOptions = {}): ToolModule {
  return {
    id: opts.id ?? 'fixture/mcp',
    version: opts.version ?? '1.0.0',
    licence: opts.licence ?? 'PolyForm-Noncommercial-1.0.0',
    circleIrRange: opts.circleIrRange ?? '4.9',
    register(server: McpServer, ctx: ToolContext): void {
      if (opts.throwOnRegister) throw new Error('fixture refused to register');

      server.registerTool(
        DETERMINISTIC_TOOL,
        { description: 'Always available once the module is loaded.', inputSchema: {} },
        (() => ({ content: [{ type: 'text', text: 'ok' }] })) as never,
      );

      // The module — not the server — decides this. The server only supplies
      // the enablement it computed.
      if (!ctx.enablement.endpoint) return;

      server.registerTool(
        ENDPOINT_BACKED_TOOL,
        {
          description: 'Needs a configured endpoint. Runs only when called by name.',
          inputSchema: { target: z.string() },
        },
        (() => ({
          content: [{ type: 'text', text: 'ok' }],
          structuredContent: { provenance: 'endpoint' },
        })) as never,
      );
    },
  };
}
