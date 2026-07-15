/**
 * MCP resource registration — read-only reference material an LLM can
 * fetch by URI without invoking a tool.
 *
 *   cognium://sast-finding-schema  → JSON Schema for SastFinding
 *   cognium://sink-catalog          → every sink pattern circle-ir knows
 *   cognium://source-catalog        → every source pattern circle-ir knows
 *   cognium://sanitizer-catalog     → every sanitizer entry
 *   cognium://passes                → contents of circle-ir docs/PASSES.md
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createRequire } from 'module';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';
import { SAST_FINDING_SCHEMA } from './schema.js';
import {
  loadSanitizerCatalog,
  loadSinkCatalog,
  loadSourceCatalog,
} from './catalogs.js';

function loadPassesMarkdown(): string {
  try {
    const require = createRequire(import.meta.url);
    const circleIrPkg = require.resolve('circle-ir/package.json');
    const passesPath = join(dirname(circleIrPkg), 'docs', 'PASSES.md');
    return readFileSync(passesPath, 'utf8');
  } catch (err) {
    return `# PASSES.md unavailable\n\nFailed to load from circle-ir install: ${(err as Error).message}`;
  }
}

export function registerResources(server: McpServer): void {
  server.registerResource(
    'sast-finding-schema',
    'cognium://sast-finding-schema',
    {
      title: 'SastFinding JSON Schema',
      description: 'Canonical JSON Schema for SastFinding objects emitted by circle-ir.',
      mimeType: 'application/schema+json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/schema+json',
          text: JSON.stringify(SAST_FINDING_SCHEMA, null, 2),
        },
      ],
    }),
  );

  server.registerResource(
    'sink-catalog',
    'cognium://sink-catalog',
    {
      title: 'Sink catalog',
      description: 'Every taint sink pattern known to circle-ir (method / class / type / cwe / severity / dangerous arg positions).',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(loadSinkCatalog(), null, 2),
        },
      ],
    }),
  );

  server.registerResource(
    'source-catalog',
    'cognium://source-catalog',
    {
      title: 'Source catalog',
      description: 'Every taint source pattern known to circle-ir (framework API, annotation, property, or DB result).',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(loadSourceCatalog(), null, 2),
        },
      ],
    }),
  );

  server.registerResource(
    'sanitizer-catalog',
    'cognium://sanitizer-catalog',
    {
      title: 'Sanitizer catalog',
      description: 'Every sanitizer function circle-ir recognizes, indexed by sink type.',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(loadSanitizerCatalog(), null, 2),
        },
      ],
    }),
  );

  server.registerResource(
    'passes',
    'cognium://passes',
    {
      title: 'Pass + metric registry (PASSES.md)',
      description: 'Canonical pass registry with rule_id, CWE, SARIF level, and status for every circle-ir analysis pass.',
      mimeType: 'text/markdown',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'text/markdown',
          text: loadPassesMarkdown(),
        },
      ],
    }),
  );
}
