import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #409 (cluster B) — FP: a TypeScript interface method signature
 * `query(text: string, ...): Promise<...>;` reported as sql_injection +
 * missing-await on the signature line.
 *
 * Root cause was in the CLI / MCP server, not here: both passed an explicit
 * `languagePaths` map that loaded tree-sitter-javascript for `typescript`,
 * overriding the library's TypeScript grammar (3.24.0, #5). Under the
 * JavaScript grammar the interface is an ERROR node and the signature
 * error-recovers into a `query(...)` call_expression. This locks the library
 * side: with the TypeScript grammar a method signature is never a call.
 */
describe('#409 cluster B — interface method signature is not a call', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const code = [
    "import { Pool } from 'pg';",
    '',
    '/** Minimal client interface. */',
    'export interface SqlClient {',
    '  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;',
    '}',
    '',
    'type Queryable = {',
    '  query(text: string): Promise<unknown>;',
    '};',
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
  ].join('\n');

  it('SAFE: no call, sink, flow or missing-await on the signature lines', async () => {
    const ir = await analyze(code, 'db.ts', 'typescript');
    const sigLines = new Set([5, 9]);
    expect(ir.calls.filter(c => sigLines.has(c.location.line))).toEqual([]);
    expect(ir.taint.sinks.filter(s => sigLines.has(s.line))).toEqual([]);
    expect(ir.taint.flows.filter(f => sigLines.has(f.sink_line))).toEqual([]);
    expect((ir.findings ?? []).filter(f => f.rule_id === 'missing-await')).toEqual([]);
  });

  it('CONTROL: string-concatenated pool.query still flows to sql_injection', async () => {
    const ir = await analyze(code, 'db.ts', 'typescript');
    expect(ir.taint.flows.some(f => f.sink_type === 'sql_injection' && f.sink_line === 16)).toBe(true);
  });

  it('CONTROL: parameterized pool.query($1, [id]) stays clean', async () => {
    const ir = await analyze(code, 'db.ts', 'typescript');
    expect(ir.taint.flows.filter(f => f.sink_line === 21)).toEqual([]);
  });
});
