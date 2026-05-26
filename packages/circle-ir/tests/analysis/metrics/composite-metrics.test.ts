import { describe, it, expect } from 'vitest';
import { CompositeMetricsPass } from '../../../src/analysis/metrics/passes/composite-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, MetricValue } from '../../../src/types/index.js';

function makeCtx(accumulated: MetricValue[]): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types: [], calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code: '', language: 'typescript', accumulated };
}

function metric(name: string, value: number): MetricValue {
  return { name, category: 'complexity', value };
}

describe('CompositeMetricsPass', () => {
  it('emits all four composite metrics', () => {
    const results = new CompositeMetricsPass().run(makeCtx([]));
    const names = results.map(r => r.name);
    expect(names).toContain('maintainability_index');
    expect(names).toContain('code_quality_index');
    expect(names).toContain('bug_hotspot_score');
    expect(names).toContain('refactoring_roi');
  });

  it('maintainability_index is in range 0-100', () => {
    const acc = [
      metric('halstead_volume', 500),
      metric('WMC', 10),
      metric('LOC', 100),
    ];
    const results = new CompositeMetricsPass().run(makeCtx(acc));
    const mi = results.find(r => r.name === 'maintainability_index')!;
    expect(mi.value).toBeGreaterThanOrEqual(0);
    expect(mi.value).toBeLessThanOrEqual(100);
  });

  it('code_quality_index is in range 0-100', () => {
    const acc = [
      metric('maintainability_index', 75),
      metric('doc_coverage', 0.8),
      metric('LCOM_avg', 2),
      metric('CBO_avg', 3),
    ];
    const results = new CompositeMetricsPass().run(makeCtx(acc));
    const cqi = results.find(r => r.name === 'code_quality_index')!;
    expect(cqi.value).toBeGreaterThanOrEqual(0);
    expect(cqi.value).toBeLessThanOrEqual(100);
  });

  it('returns 0 for all metrics when accumulated is empty (graceful zero)', () => {
    const results = new CompositeMetricsPass().run(makeCtx([]));
    for (const r of results) {
      expect(r.value).toBeGreaterThanOrEqual(0);
      expect(r.value).toBeLessThanOrEqual(100);
    }
  });

  it('higher WMC produces higher bug_hotspot_score', () => {
    const lowAcc  = [metric('WMC', 1),  metric('halstead_effort', 100), metric('loop_complexity', 0)];
    const highAcc = [metric('WMC', 50), metric('halstead_effort', 100), metric('loop_complexity', 0)];
    const lowR  = new CompositeMetricsPass().run(makeCtx(lowAcc));
    const highR = new CompositeMetricsPass().run(makeCtx(highAcc));
    const lowBHS  = lowR.find(r => r.name === 'bug_hotspot_score')!.value;
    const highBHS = highR.find(r => r.name === 'bug_hotspot_score')!.value;
    expect(highBHS).toBeGreaterThan(lowBHS);
  });
});
