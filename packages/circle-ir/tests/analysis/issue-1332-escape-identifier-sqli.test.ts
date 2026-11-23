/**
 * cognium-dev#1332 (slice S1) — `escapeIdentifier` before ORDER BY concat must
 * credit SQL injection sanitizer on the safe BenchProctor express_ts shape.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

describe('cognium-dev #1332 escapeIdentifier ORDER BY', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sqlFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');

  it('safe: escapeIdentifier on user ORDER BY drops sql_injection (negative)', async () => {
    const code = `
function escapeIdentifier(id) {
  return String(id).replace(/[^a-zA-Z0-9_]/g, '');
}
export function BenchmarkTest00067OrderSafe(req, res, db) {
  const userInput = req.query.data;
  const data = Buffer.from(userInput, 'base64').toString();
  db.query('SELECT * FROM users ORDER BY ' + escapeIdentifier(String(data)));
}`;
    const r = await analyze(code, 'order-safe-escape-id.ts', 'typescript');
    expect(sqlFlows(r)).toHaveLength(0);
  });

  it('bad: ORDER BY concat without escapeIdentifier still fires (positive control)', async () => {
    const code = `
export function BenchmarkTest00067OrderBad(req, res, db) {
  const userInput = req.query.data;
  const data = Buffer.from(userInput, 'base64').toString();
  db.query('SELECT * FROM users ORDER BY ' + data);
}`;
    const r = await analyze(code, 'order-bad-concat.ts', 'typescript');
    expect(sqlFlows(r).length).toBeGreaterThan(0);
  });
});