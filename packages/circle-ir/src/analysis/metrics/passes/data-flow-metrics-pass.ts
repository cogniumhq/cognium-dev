import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Data Flow Metrics Pass
 *
 * Emits: data_flow_complexity
 *
 * data_flow_complexity = number of DFG uses that have a reaching definition
 * (def_id !== null). Measures how many data dependencies exist in the file.
 */
export class DataFlowMetricsPass implements MetricPass {
  readonly name = 'data-flow-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const count = ctx.ir.dfg.uses.filter(u => u.def_id !== null).length;
    return [
      {
        name: 'data_flow_complexity',
        category: 'complexity',
        value: count,
        unit: 'count',
        iso_25010: 'Maintainability.Analysability',
        description: 'DFG use-def pairs (DFG uses with a reaching definition)',
      },
    ];
  }
}
