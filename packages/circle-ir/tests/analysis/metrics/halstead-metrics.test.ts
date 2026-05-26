import { describe, it, expect } from 'vitest';
import { HalsteadMetricsPass } from '../../../src/analysis/metrics/passes/halstead-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR } from '../../../src/types/index.js';

function makeCtx(code: string): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types: [], calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code, language: 'typescript', accumulated: [] };
}

describe('HalsteadMetricsPass', () => {
  it('returns zero metrics for empty code', () => {
    const results = new HalsteadMetricsPass().run(makeCtx(''));
    for (const r of results) {
      expect(r.value).toBe(0);
    }
  });

  it('computes positive volume for non-trivial code', () => {
    const code = 'function add(a, b) { return a + b; }';
    const results = new HalsteadMetricsPass().run(makeCtx(code));
    const volume = results.find(r => r.name === 'halstead_volume');
    expect(volume?.value).toBeGreaterThan(0);
  });

  it('computes positive difficulty for non-trivial code', () => {
    const code = 'if (x > 0) { y = x + 1; }';
    const results = new HalsteadMetricsPass().run(makeCtx(code));
    const difficulty = results.find(r => r.name === 'halstead_difficulty');
    expect(difficulty?.value).toBeGreaterThan(0);
  });

  it('emits all four Halstead metrics', () => {
    const code = 'const x = a + b;';
    const results = new HalsteadMetricsPass().run(makeCtx(code));
    const names = results.map(r => r.name);
    expect(names).toContain('halstead_volume');
    expect(names).toContain('halstead_difficulty');
    expect(names).toContain('halstead_effort');
    expect(names).toContain('halstead_bugs');
  });

  it('all Halstead metrics have category complexity', () => {
    const code = 'function foo() { return 42; }';
    const results = new HalsteadMetricsPass().run(makeCtx(code));
    for (const r of results) {
      expect(r.category).toBe('complexity');
    }
  });

  it('larger code produces larger volume than smaller code', () => {
    const small = 'return x;';
    const large = 'function compute(a, b, c) { if (a > 0) { return a + b + c; } else { return b - c; } }';
    const smallResults = new HalsteadMetricsPass().run(makeCtx(small));
    const largeResults = new HalsteadMetricsPass().run(makeCtx(large));
    const smallVol = smallResults.find(r => r.name === 'halstead_volume')?.value ?? 0;
    const largeVol = largeResults.find(r => r.name === 'halstead_volume')?.value ?? 0;
    expect(largeVol).toBeGreaterThan(smallVol);
  });
});
