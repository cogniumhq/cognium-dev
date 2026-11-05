/**
 * cognium-dev#1146 — path returned from a helper after multi-root allow-list guard.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function pathTraversalFlows(code: string) {
  const r = await analyze(code, 'probe.js', 'javascript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
}

const fixture = [
  "const fs = require('fs');",
  "const path = require('path');",
  "const ROOTS = ['/srv/data'];",
  'function assertPathAllowed(p) {',
  '  const r = path.resolve(p);',
  "  if (!ROOTS.some((root) => r === root || r.startsWith(root + path.sep))) throw new Error('path not allowed');",
  '  return r;',
  '}',
  'const requested = process.argv[2];',
  'const safe = assertPathAllowed(requested);',
  "console.log(fs.readFileSync(safe, 'utf-8'));",
].join('\n');

describe('cognium-dev#1146 — JS allow-list path helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('guarded helper return is clean at readFileSync', async () => {
    expect(await pathTraversalFlows(fixture)).toHaveLength(0);
  });

  it('recall: unguarded resolve still reports', async () => {
    const code = [
      "const fs = require('fs');",
      "const path = require('path');",
      'const p = process.argv[2];',
      'const r = path.resolve(p);',
      "fs.readFileSync(r, 'utf-8');",
    ].join('\n');
    const r = await analyze(code, 'unsafe.js', 'javascript');
    const sinks = (r.taint.sinks ?? []).filter((s) => s.type === 'path_traversal');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
  });
});
