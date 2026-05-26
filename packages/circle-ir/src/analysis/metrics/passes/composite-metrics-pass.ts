import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Composite Metrics Pass
 *
 * MUST be the last pass in MetricRunner — reads from `accumulated`.
 *
 * Emits:
 *   - maintainability_index   Microsoft MI (normalized 0–100)
 *   - code_quality_index      Composite quality score (0–100)
 *   - bug_hotspot_score       Weighted bug-risk indicator (0–100)
 *   - refactoring_roi         Estimated refactoring value (0–100)
 */
export class CompositeMetricsPass implements MetricPass {
  readonly name = 'composite-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const acc = ctx.accumulated;

    const get = (name: string): number =>
      acc.find(m => m.name === name)?.value ?? 0;

    // Microsoft Maintainability Index (normalized 0-100)
    const V = get('halstead_volume');
    const G = get('WMC');
    const L = get('LOC');
    const miRaw = 171 - 5.2 * Math.log(V + 1) - 0.23 * G - 16.2 * Math.log(L + 1);
    const MI = Math.max(0, Math.min(100, (miRaw / 171) * 100));

    // Code Quality Index: weighted average of MI, doc_coverage, inverted LCOM, inverted CBO
    const doc  = get('doc_coverage');                          // 0-1
    const lcom = 1 - Math.min(1, get('LCOM_avg') / 10);       // inverted, normalized
    const cbo  = 1 - Math.min(1, get('CBO_avg') / 10);        // inverted, normalized
    const CQI  = (MI / 100 * 0.4 + doc * 0.3 + lcom * 0.2 + cbo * 0.1) * 100;

    // Bug Hotspot Score: Halstead effort + cyclomatic complexity + loops
    const effort = get('halstead_effort');
    const loop   = get('loop_complexity');
    const BHS    = Math.min(100,
      effort / 10000 * 0.5 * 100 +
      G      / 10    * 0.3 * 100 +
      loop   / 5     * 0.2 * 100
    );

    // Refactoring ROI: low cohesion, deep inheritance, high coupling = high ROI
    const lcomR = get('LCOM_avg');
    const dit   = get('DIT_max');
    const cboR  = get('CBO_avg');
    const ROI   = Math.min(100,
      lcomR / 5  * 0.4 * 100 +
      dit   / 6  * 0.3 * 100 +
      cboR  / 10 * 0.3 * 100
    );

    return [
      {
        name: 'maintainability_index',
        category: 'complexity',
        value: parseFloat(MI.toFixed(2)),
        unit: 'count',
        iso_25010: 'Maintainability',
        description: 'Microsoft Maintainability Index (0=poor, 100=excellent)',
      },
      {
        name: 'code_quality_index',
        category: 'complexity',
        value: parseFloat(CQI.toFixed(2)),
        unit: 'count',
        iso_25010: 'Maintainability',
        description: 'Composite code quality score (0=poor, 100=excellent)',
      },
      {
        name: 'bug_hotspot_score',
        category: 'complexity',
        value: parseFloat(BHS.toFixed(2)),
        unit: 'count',
        iso_25010: 'Reliability.Faultlessness',
        description: 'Bug-risk indicator (0=low risk, 100=high risk)',
      },
      {
        name: 'refactoring_roi',
        category: 'complexity',
        value: parseFloat(ROI.toFixed(2)),
        unit: 'count',
        iso_25010: 'Maintainability',
        description: 'Estimated value of refactoring this file (0=low, 100=high)',
      },
    ];
  }
}
