/**
 * cognium-dev #409 — `.ts` files must be parsed with the TypeScript grammar.
 *
 * `ensureAnalyzer()` used to map `typescript` to tree-sitter-javascript. An
 * interface method signature then error-recovered into a `query(...)` call
 * and surfaced as a sql_injection flow + missing-await finding on the
 * signature line.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ProjectCache } from '../src/cache.js';
import type { ToolContext } from '../src/tools/types.js';
import { makeScanHandler } from '../src/tools/scan.js';

let root: string;
let ctx: ToolContext;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'cognium-mcp-ts-grammar-'));
  writeFileSync(
    join(root, 'db.ts'),
    [
      "import { Pool } from 'pg';",
      '',
      '/** Minimal client interface. */',
      'export interface SqlClient {',
      '  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;',
      '}',
      '',
      'const pool = new Pool();',
      '',
      'export async function findUnsafe(req: { query: { id: string } }) {',
      '  const id = req.query.id;',
      "  return pool.query('SELECT * FROM users WHERE id = ' + id);",
      '}',
      '',
      'export async function findSafe(req: { query: { id: string } }) {',
      '  const id = req.query.id;',
      "  return pool.query('SELECT * FROM users WHERE id = $1', [id]);",
      '}',
      '',
    ].join('\n'),
    'utf8',
  );
  ctx = { cache: new ProjectCache(2) };
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  ctx.cache.clear();
});

describe('typescript grammar (#409)', () => {
  it('does not report the interface method signature; the concat query still flows', async () => {
    const res = await makeScanHandler(ctx)({ path: root }) as { content: Array<{ text: string }> };
    const p = JSON.parse(res.content[0].text);

    // (missing-public-doc on `SqlClient.query` is expected — with the right
    // grammar it is a real method signature.)
    expect(p.findings.some((f: { rule_id: string }) => f.rule_id === 'missing-await')).toBe(false);
    expect(p.taintFlows.filter((f: { sink_line: number }) => f.sink_line === 5)).toEqual([]);
    expect(p.taintFlows.some((f: { sink_type: string; sink_line: number }) =>
      f.sink_type === 'sql_injection' && f.sink_line === 12)).toBe(true);
    expect(p.taintFlows.some((f: { sink_line: number }) => f.sink_line === 17)).toBe(false);
  }, 60_000);
});
