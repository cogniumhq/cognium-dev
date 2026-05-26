import { describe, it, expect } from 'vitest';
import { CouplingMetricsPass } from '../../../src/analysis/metrics/passes/coupling-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, TypeInfo, CallInfo } from '../../../src/types/index.js';

function makeType(name: string, start: number, end: number, methodCount = 0, fields: TypeInfo['fields'] = []): TypeInfo {
  return {
    name, kind: 'class', package: null, extends: null, implements: [], annotations: [],
    fields, start_line: start, end_line: end,
    methods: Array.from({ length: methodCount }, (_, i) => ({
      name: `m${i}`, return_type: null, parameters: [], annotations: [], modifiers: [],
      start_line: start + i, end_line: start + i + 1,
    })),
  };
}

function makeCall(method: string, receiverType: string | null, line: number): CallInfo {
  return {
    method_name: method, receiver: null, receiver_type: receiverType,
    arguments: [], location: { line, column: 0 },
  };
}

function makeCtx(types: TypeInfo[], calls: CallInfo[] = []): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types, calls,
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code: '', language: 'typescript', accumulated: [] };
}

describe('CouplingMetricsPass', () => {
  it('returns no results for empty types', () => {
    const results = new CouplingMetricsPass().run(makeCtx([]));
    expect(results).toHaveLength(0);
  });

  it('computes CBO=0 for a type with no external dependencies', () => {
    const types = [makeType('Foo', 1, 10)];
    const results = new CouplingMetricsPass().run(makeCtx(types));
    const cbo = results.find(r => r.name === 'CBO' && r.description === 'type: Foo');
    expect(cbo?.value).toBe(0);
  });

  it('computes CBO based on external receiver types', () => {
    const types = [makeType('Foo', 1, 20, 1)];
    const calls = [
      makeCall('doSomething', 'ExternalLib', 5),
      makeCall('query', 'DbClient', 8),
      makeCall('log', 'ExternalLib', 10), // same type, counts once
    ];
    const results = new CouplingMetricsPass().run(makeCtx(types, calls));
    const cbo = results.find(r => r.name === 'CBO' && r.description === 'type: Foo');
    expect(cbo?.value).toBe(2); // ExternalLib + DbClient
  });

  it('does not count local types as external coupling', () => {
    const types = [makeType('Foo', 1, 10), makeType('Bar', 11, 20)];
    const calls = [makeCall('barMethod', 'Bar', 5)];
    const results = new CouplingMetricsPass().run(makeCtx(types, calls));
    const cbo = results.find(r => r.name === 'CBO' && r.description === 'type: Foo');
    expect(cbo?.value).toBe(0);
  });

  it('computes RFC = methods + distinct external calls', () => {
    const types = [makeType('Foo', 1, 20, 3)]; // 3 methods
    const calls = [
      makeCall('extA', 'Lib', 5),
      makeCall('extB', 'Lib', 8),
      makeCall('extA', 'Lib', 10), // duplicate name, not counted again
    ];
    const results = new CouplingMetricsPass().run(makeCtx(types, calls));
    const rfc = results.find(r => r.name === 'RFC' && r.description === 'type: Foo');
    expect(rfc?.value).toBe(3 + 2); // 3 methods + 2 distinct external method names
  });

  it('emits CBO_avg and RFC_avg aggregates', () => {
    const types = [makeType('Foo', 1, 10)];
    const results = new CouplingMetricsPass().run(makeCtx(types));
    expect(results.find(r => r.name === 'CBO_avg')).toBeDefined();
    expect(results.find(r => r.name === 'RFC_avg')).toBeDefined();
  });

  it('all coupling metrics have category coupling', () => {
    const types = [makeType('Foo', 1, 10)];
    const results = new CouplingMetricsPass().run(makeCtx(types));
    for (const r of results) {
      expect(r.category).toBe('coupling');
    }
  });
});
