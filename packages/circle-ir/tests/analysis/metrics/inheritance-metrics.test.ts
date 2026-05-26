import { describe, it, expect } from 'vitest';
import { InheritanceMetricsPass } from '../../../src/analysis/metrics/passes/inheritance-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, TypeInfo } from '../../../src/types/index.js';

function makeType(name: string, extendsType: string | null = null): TypeInfo {
  return {
    name, kind: 'class', package: null, extends: extendsType, implements: [],
    annotations: [], fields: [], methods: [], start_line: 1, end_line: 10,
  };
}

function makeCtx(types: TypeInfo[]): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types, calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code: '', language: 'typescript', accumulated: [] };
}

describe('InheritanceMetricsPass', () => {
  it('returns no results for empty types', () => {
    const results = new InheritanceMetricsPass().run(makeCtx([]));
    expect(results).toHaveLength(0);
  });

  it('computes DIT=0 for root class', () => {
    const results = new InheritanceMetricsPass().run(makeCtx([makeType('Base')]));
    const dit = results.find(r => r.name === 'DIT' && r.description === 'type: Base');
    expect(dit?.value).toBe(0);
  });

  it('computes DIT=1 for direct subclass', () => {
    const types = [makeType('Base'), makeType('Child', 'Base')];
    const results = new InheritanceMetricsPass().run(makeCtx(types));
    const dit = results.find(r => r.name === 'DIT' && r.description === 'type: Child');
    expect(dit?.value).toBe(1);
  });

  it('computes DIT=2 for two-level hierarchy', () => {
    const types = [makeType('A'), makeType('B', 'A'), makeType('C', 'B')];
    const results = new InheritanceMetricsPass().run(makeCtx(types));
    const dit = results.find(r => r.name === 'DIT' && r.description === 'type: C');
    expect(dit?.value).toBe(2);
  });

  it('computes NOC correctly', () => {
    const types = [makeType('Animal'), makeType('Dog', 'Animal'), makeType('Cat', 'Animal')];
    const results = new InheritanceMetricsPass().run(makeCtx(types));
    const noc = results.find(r => r.name === 'NOC' && r.description === 'type: Animal');
    expect(noc?.value).toBe(2);
  });

  it('emits DIT_max and NOC_total aggregates', () => {
    const types = [makeType('Base'), makeType('Child', 'Base')];
    const results = new InheritanceMetricsPass().run(makeCtx(types));
    const ditMax = results.find(r => r.name === 'DIT_max');
    expect(ditMax?.value).toBe(1);
    const nocTotal = results.find(r => r.name === 'NOC_total');
    expect(nocTotal?.value).toBe(1);
  });

  it('stops DIT traversal at classes not in the file', () => {
    // 'B' extends 'ExternalBase' which is not in the file
    const types = [makeType('B', 'ExternalBase')];
    const results = new InheritanceMetricsPass().run(makeCtx(types));
    const dit = results.find(r => r.name === 'DIT' && r.description === 'type: B');
    expect(dit?.value).toBe(0); // ExternalBase not in nameMap
  });
});
