import { describe, it, expect } from 'vitest';
import { SizeMetricsPass } from '../../../src/analysis/metrics/passes/size-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR } from '../../../src/types/index.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [],
    enriched: {},
    ...overrides,
  };
}

function makeCtx(code: string, irOverrides: Partial<CircleIR> = {}): MetricContext {
  return { ir: makeIR(irOverrides), code, language: 'typescript', accumulated: [] };
}

describe('SizeMetricsPass', () => {
  it('counts LOC correctly', () => {
    const ctx = makeCtx('line1\nline2\nline3\n');
    const results = new SizeMetricsPass().run(ctx);
    const loc = results.find(r => r.name === 'LOC');
    expect(loc?.value).toBe(4); // 3 lines + trailing newline = 4 elements from split
  });

  it('counts NLOC excluding blank and comment lines', () => {
    const code = 'const x = 1;\n\n// comment\n* star\nconst y = 2;\n';
    const ctx = makeCtx(code);
    const results = new SizeMetricsPass().run(ctx);
    const nloc = results.find(r => r.name === 'NLOC');
    // line1: "const x = 1;" → code
    // line2: "" → blank, skip
    // line3: "// comment" → comment
    // line4: "* star" → comment (starts with *)
    // line5: "const y = 2;" → code
    // line6: "" → blank, skip
    expect(nloc?.value).toBe(2);
  });

  it('computes comment_density as ratio', () => {
    // 2 comment lines out of 4 lines total
    const code = '// a\n// b\ncode\nmore\n';
    const ctx = makeCtx(code);
    const results = new SizeMetricsPass().run(ctx);
    const density = results.find(r => r.name === 'comment_density');
    expect(density?.value).toBeGreaterThan(0);
    expect(density?.value).toBeLessThanOrEqual(1);
  });

  it('counts function_count from ir.types methods', () => {
    const types = [
      {
        name: 'Foo', kind: 'class' as const, package: null, extends: null,
        implements: [], annotations: [], fields: [],
        start_line: 1, end_line: 20,
        methods: [
          { name: 'm1', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 2, end_line: 5 },
          { name: 'm2', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 6, end_line: 10 },
        ],
      },
    ];
    const ctx = makeCtx('...', { types });
    const results = new SizeMetricsPass().run(ctx);
    const fc = results.find(r => r.name === 'function_count');
    expect(fc?.value).toBe(2);
  });

  it('returns 0 function_count for no types', () => {
    const ctx = makeCtx('const x = 1;');
    const results = new SizeMetricsPass().run(ctx);
    const fc = results.find(r => r.name === 'function_count');
    expect(fc?.value).toBe(0);
  });

  it('emits all four size metrics with correct category', () => {
    const ctx = makeCtx('const x = 1;\n');
    const results = new SizeMetricsPass().run(ctx);
    expect(results.map(r => r.name)).toEqual(
      expect.arrayContaining(['LOC', 'NLOC', 'comment_density', 'function_count'])
    );
    for (const r of results) {
      expect(r.category).toBe('size');
    }
  });

  it('handles empty code string', () => {
    const ctx = makeCtx('');
    const results = new SizeMetricsPass().run(ctx);
    const loc = results.find(r => r.name === 'LOC');
    expect(loc?.value).toBeGreaterThanOrEqual(0);
    const density = results.find(r => r.name === 'comment_density');
    expect(density?.value).toBe(0);
  });
});
