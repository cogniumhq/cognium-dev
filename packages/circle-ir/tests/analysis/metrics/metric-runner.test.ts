import { describe, it, expect } from 'vitest';
import { MetricRunner } from '../../../src/analysis/metrics/metric-runner.js';
import type { CircleIR } from '../../../src/types/index.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types: [], calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
    ...overrides,
  };
}

describe('MetricRunner', () => {
  it('returns a non-empty array of metrics for minimal IR', () => {
    const runner = new MetricRunner();
    const metrics = runner.run(makeIR(), '', 'typescript');
    expect(metrics.length).toBeGreaterThan(0);
  });

  it('always includes composite metrics', () => {
    const runner = new MetricRunner();
    const metrics = runner.run(makeIR(), '', 'typescript');
    const names = metrics.map(m => m.name);
    expect(names).toContain('maintainability_index');
    expect(names).toContain('code_quality_index');
  });

  it('includes size metrics for any input', () => {
    const runner = new MetricRunner();
    const metrics = runner.run(makeIR(), 'const x = 1;\n', 'typescript');
    const names = metrics.map(m => m.name);
    expect(names).toContain('LOC');
    expect(names).toContain('function_count');
  });

  it('passes accumulated correctly so composite reads prior results', () => {
    // Run with some code so Halstead metrics are non-zero
    const runner = new MetricRunner();
    const code = 'function add(a, b) { if (a > 0) { return a + b; } return b; }';
    const metrics = runner.run(makeIR(), code, 'typescript');
    const mi = metrics.find(m => m.name === 'maintainability_index');
    // MI should be > 0 since the code is not empty
    expect(mi).toBeDefined();
    expect(mi!.value).toBeGreaterThan(0);
  });
});
