/**
 * #460 — a minified / bundled file is one enormous line, and the DFG chain
 * builder plus taint propagation are super-linear in defs-per-line. On a 73 KB
 * single-line webpack bundle that wedges the process synchronously at 100% CPU
 * (no timer fires, so the project-path budget is inert). `analyze()` now returns
 * a minimal IR for a line past `MAX_ANALYZABLE_LINE_LENGTH`, which bounds both
 * `analyze()` and `analyzeProject()`. Real multi-line source is untouched.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

const minifiedBundle = (targetBytes: number) => {
  const chunk = 'function a(n){var e=n.foo,t=n.bar;return e+t}var x=r(1),y=r(2),z=x.query(y.body);';
  let body = '!function(e){';
  while (body.length < targetBytes) body += chunk;
  return (body + '}({});').replace(/\n/g, '');
};

describe('#460 — minified single-line guard', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('returns a bounded minimal IR for a 73 KB single-line bundle', async () => {
    const code = minifiedBundle(73 * 1024);
    expect(code.includes('\n')).toBe(false);
    const t = Date.now();
    const ir = await analyze(code, 'bundle.js', 'javascript');
    const ms = Date.now() - t;
    expect(ms).toBeLessThan(5000);              // was an unbounded hang
    expect(ir.meta.file).toBe('bundle.js');     // meta still populated
    expect(ir.types).toEqual([]);               // analysis skipped
    expect(ir.taint.flows ?? []).toEqual([]);
    expect(ir.dfg.chains).toEqual([]);
  });

  it('bounds analyzeProject on the same bundle', async () => {
    const code = minifiedBundle(73 * 1024);
    const t = Date.now();
    await expect(
      analyzeProject([{ filePath: 'bundle.js', language: 'javascript', code }], { crossFileBudgetMs: 10_000 }),
    ).resolves.toBeDefined();
    expect(Date.now() - t).toBeLessThan(5000);
  });

  it('leaves ordinary multi-line source fully analyzed', async () => {
    const code = Array.from({ length: 200 }, (_, i) =>
      `function h${i}(req){ var q = req.query; child_process.exec(q); }`).join('\n');
    const ir = await analyze(code, 'app.js', 'javascript');
    expect(ir.types.length).toBeGreaterThan(0);
    expect((ir.taint.flows ?? []).length).toBeGreaterThan(0);
  });

  it('analyzes a long line that is still under the threshold', async () => {
    const code = 'var x = req.query.q; child_process.exec(x);'.padEnd(40_000, ' ') + ';';
    const ir = await analyze(code, 'u.js', 'javascript');
    expect((ir.taint.flows ?? []).length).toBeGreaterThanOrEqual(1);
  });
});
