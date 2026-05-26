import { describe, it, expect } from 'vitest';
import { DataFlowMetricsPass } from '../../../src/analysis/metrics/passes/data-flow-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, DFGUse } from '../../../src/types/index.js';

function makeCtx(uses: DFGUse[]): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types: [], calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code: '', language: 'typescript', accumulated: [] };
}

describe('DataFlowMetricsPass', () => {
  it('returns 0 for no uses', () => {
    const results = new DataFlowMetricsPass().run(makeCtx([]));
    expect(results[0].value).toBe(0);
  });

  it('counts only uses with def_id !== null', () => {
    const uses: DFGUse[] = [
      { id: 1, variable: 'x', line: 2, def_id: 1 },
      { id: 2, variable: 'y', line: 3, def_id: null },
      { id: 3, variable: 'z', line: 4, def_id: 2 },
    ];
    const results = new DataFlowMetricsPass().run(makeCtx(uses));
    expect(results[0].value).toBe(2);
  });

  it('emits metric named data_flow_complexity', () => {
    const results = new DataFlowMetricsPass().run(makeCtx([]));
    expect(results[0].name).toBe('data_flow_complexity');
    expect(results[0].category).toBe('complexity');
  });
});
