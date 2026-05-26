import { describe, it, expect } from 'vitest';
import { ComplexityMetricsPass } from '../../../src/analysis/metrics/passes/complexity-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, CFGBlock, CFGEdge } from '../../../src/types/index.js';

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

function makeCtx(overrides: Partial<CircleIR> = {}): MetricContext {
  return { ir: makeIR(overrides), code: '', language: 'typescript', accumulated: [] };
}

function block(id: number, start: number, end: number, type: CFGBlock['type'] = 'normal'): CFGBlock {
  return { id, type, start_line: start, end_line: end };
}

function edge(from: number, to: number, type: CFGEdge['type'] = 'sequential'): CFGEdge {
  return { from, to, type };
}

describe('ComplexityMetricsPass', () => {
  it('computes v(G) = 1 for a single-block method (no branches)', () => {
    const types = [{
      name: 'A', kind: 'class' as const, package: null, extends: null,
      implements: [], annotations: [], fields: [], start_line: 1, end_line: 10,
      methods: [
        { name: 'foo', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 1, end_line: 5 },
      ],
    }];
    // 1 block, 0 edges → v(G) = 0 - 1 + 2 = 1
    const cfg = {
      blocks: [block(1, 1, 5)],
      edges: [],
    };
    const ctx = makeCtx({ types, cfg });
    const results = new ComplexityMetricsPass().run(ctx);
    const vg = results.find(r => r.name === 'cyclomatic_complexity');
    expect(vg?.value).toBe(1);
    expect(vg?.description).toBe('method: foo');
  });

  it('computes v(G) = 2 for a method with one branch', () => {
    const types = [{
      name: 'A', kind: 'class' as const, package: null, extends: null,
      implements: [], annotations: [], fields: [], start_line: 1, end_line: 20,
      methods: [
        { name: 'bar', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 1, end_line: 10 },
      ],
    }];
    // 3 blocks, 3 edges → v(G) = 3 - 3 + 2 = 2
    const cfg = {
      blocks: [block(1, 1, 3), block(2, 4, 7), block(3, 8, 10)],
      edges: [edge(1, 2, 'true'), edge(1, 3, 'false'), edge(2, 3)],
    };
    const ctx = makeCtx({ types, cfg });
    const results = new ComplexityMetricsPass().run(ctx);
    const vg = results.find(r => r.name === 'cyclomatic_complexity');
    expect(vg?.value).toBe(2);
  });

  it('emits WMC as sum of all method cyclomatic complexities', () => {
    const types = [{
      name: 'A', kind: 'class' as const, package: null, extends: null,
      implements: [], annotations: [], fields: [], start_line: 1, end_line: 30,
      methods: [
        { name: 'm1', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 1, end_line: 5 },
        { name: 'm2', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 6, end_line: 15 },
      ],
    }];
    // m1: 1 block → v(G) = 1; m2: 3 blocks, 3 edges → v(G) = 2
    const cfg = {
      blocks: [block(1, 1, 5), block(2, 6, 9), block(3, 10, 12), block(4, 13, 15)],
      edges: [edge(2, 3, 'true'), edge(2, 4, 'false'), edge(3, 4)],
    };
    const ctx = makeCtx({ types, cfg });
    const results = new ComplexityMetricsPass().run(ctx);
    const wmc = results.find(r => r.name === 'WMC');
    expect(wmc?.value).toBe(3); // 1 + 2
  });

  it('counts loop_complexity from back-edges', () => {
    const cfg = {
      blocks: [block(1, 1, 5), block(2, 6, 10)],
      edges: [edge(1, 2), edge(2, 1, 'back')],
    };
    const ctx = makeCtx({ cfg });
    const results = new ComplexityMetricsPass().run(ctx);
    const loop = results.find(r => r.name === 'loop_complexity');
    expect(loop?.value).toBe(1);
  });

  it('counts condition_complexity from true/false edges', () => {
    const cfg = {
      blocks: [block(1, 1, 3), block(2, 4, 6), block(3, 7, 10)],
      edges: [edge(1, 2, 'true'), edge(1, 3, 'false')],
    };
    const ctx = makeCtx({ cfg });
    const results = new ComplexityMetricsPass().run(ctx);
    const cond = results.find(r => r.name === 'condition_complexity');
    expect(cond?.value).toBe(2);
  });

  it('returns WMC=0 and no cyclomatic_complexity entries for no types', () => {
    const ctx = makeCtx();
    const results = new ComplexityMetricsPass().run(ctx);
    const wmc = results.find(r => r.name === 'WMC');
    expect(wmc?.value).toBe(0);
    const vgEntries = results.filter(r => r.name === 'cyclomatic_complexity');
    expect(vgEntries).toHaveLength(0);
  });

  it('all complexity metrics have category complexity', () => {
    const ctx = makeCtx();
    const results = new ComplexityMetricsPass().run(ctx);
    for (const r of results) {
      expect(r.category).toBe('complexity');
    }
  });
});
