import { describe, it, expect } from 'vitest';
import { CohesionMetricsPass } from '../../../src/analysis/metrics/passes/cohesion-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, TypeInfo, DFGUse } from '../../../src/types/index.js';

function makeType(name: string, methodRanges: [number, number][], fields: string[], staticFields: string[] = []): TypeInfo {
  return {
    name, kind: 'class', package: null, extends: null, implements: [], annotations: [],
    start_line: 1, end_line: 100,
    methods: methodRanges.map(([start, end], i) => ({
      name: `m${i}`, return_type: null, parameters: [], annotations: [], modifiers: [],
      start_line: start, end_line: end,
    })),
    fields: [
      ...fields.map(f => ({ name: f, type: null, modifiers: [], annotations: [] })),
      ...staticFields.map(f => ({ name: f, type: null, modifiers: ['static'], annotations: [] })),
    ],
  };
}

function makeUse(variable: string, line: number): DFGUse {
  return { id: line, variable, line, def_id: null };
}

function makeCtx(types: TypeInfo[], uses: DFGUse[] = []): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types, calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code: '', language: 'typescript', accumulated: [] };
}

describe('CohesionMetricsPass', () => {
  it('returns 0 LCOM for type with fewer than 2 methods', () => {
    const type = makeType('Foo', [[1, 5]], ['x', 'y']);
    const results = new CohesionMetricsPass().run(makeCtx([type]));
    const lcom = results.find(r => r.name === 'LCOM' && r.description === 'type: Foo');
    expect(lcom?.value).toBe(0);
  });

  it('computes LCOM=0 when all methods share a field', () => {
    // m0: lines 1-5, m1: lines 6-10, both use field 'x'
    const type = makeType('Foo', [[1, 5], [6, 10]], ['x']);
    const uses = [makeUse('x', 3), makeUse('x', 8)];
    const results = new CohesionMetricsPass().run(makeCtx([type], uses));
    const lcom = results.find(r => r.name === 'LCOM' && r.description === 'type: Foo');
    // P=0 (no pair without shared field), Q=1 (pair shares 'x') → LCOM = max(0-1, 0) = 0
    expect(lcom?.value).toBe(0);
  });

  it('computes LCOM=1 when methods share no fields', () => {
    // m0: lines 1-5 uses 'a', m1: lines 6-10 uses 'b' — no shared fields
    const type = makeType('Foo', [[1, 5], [6, 10]], ['a', 'b']);
    const uses = [makeUse('a', 3), makeUse('b', 8)];
    const results = new CohesionMetricsPass().run(makeCtx([type], uses));
    const lcom = results.find(r => r.name === 'LCOM' && r.description === 'type: Foo');
    // P=1 (pair shares nothing), Q=0 → LCOM = max(1-0, 0) = 1
    expect(lcom?.value).toBe(1);
  });

  it('ignores static fields in LCOM computation', () => {
    const type = makeType('Foo', [[1, 5], [6, 10]], [], ['staticF']);
    const uses = [makeUse('staticF', 3), makeUse('staticF', 8)];
    // staticF is static — no instance fields to track → early return with LCOM=0
    const results = new CohesionMetricsPass().run(makeCtx([type], uses));
    const lcom = results.find(r => r.name === 'LCOM' && r.description === 'type: Foo');
    expect(lcom?.value).toBe(0);
  });

  it('emits LCOM_avg aggregate', () => {
    const type = makeType('Foo', [[1, 5]], ['x']);
    const results = new CohesionMetricsPass().run(makeCtx([type]));
    expect(results.find(r => r.name === 'LCOM_avg')).toBeDefined();
  });

  it('returns no results for empty types', () => {
    const results = new CohesionMetricsPass().run(makeCtx([]));
    expect(results).toHaveLength(0);
  });
});
