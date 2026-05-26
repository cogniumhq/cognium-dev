import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Coupling Metrics Pass (CK Suite)
 *
 * Emits per-type CBO and RFC values, plus aggregate averages.
 *
 * CBO (Coupling Between Objects):
 *   Number of distinct external (non-local) types referenced by a class,
 *   counting both call receiver types and field types.
 *
 * RFC (Response For a Class):
 *   Total number of methods in the class plus the number of distinct
 *   external method names called.
 */
export class CouplingMetricsPass implements MetricPass {
  readonly name = 'coupling-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const { ir } = ctx;
    const results: MetricValue[] = [];

    if (ir.types.length === 0) return results;

    const localTypes = new Set(ir.types.map(t => t.name));

    let cboSum = 0;
    let rfcSum = 0;

    for (const type of ir.types) {
      const { start_line, end_line } = type;

      // --- CBO ---
      const externalTypes = new Set<string>();
      // From call receiver_type
      for (const call of ir.calls) {
        const line = call.location.line;
        if (line >= start_line && line <= end_line) {
          if (call.receiver_type && !localTypes.has(call.receiver_type)) {
            externalTypes.add(call.receiver_type);
          }
        }
      }
      // From field types
      for (const field of type.fields) {
        if (field.type && !localTypes.has(field.type)) {
          externalTypes.add(field.type);
        }
      }
      const cbo = externalTypes.size;
      cboSum += cbo;

      results.push({
        name: 'CBO',
        category: 'coupling',
        value: cbo,
        unit: 'count',
        iso_25010: 'Maintainability.Modularity',
        description: `type: ${type.name}`,
      });

      // --- RFC ---
      const externalMethodNames = new Set<string>();
      for (const call of ir.calls) {
        const line = call.location.line;
        if (line >= start_line && line <= end_line) {
          if (call.receiver_type && !localTypes.has(call.receiver_type)) {
            externalMethodNames.add(call.method_name);
          }
        }
      }
      const rfc = type.methods.length + externalMethodNames.size;
      rfcSum += rfc;

      results.push({
        name: 'RFC',
        category: 'coupling',
        value: rfc,
        unit: 'count',
        iso_25010: 'Maintainability.Modularity',
        description: `type: ${type.name}`,
      });
    }

    const count = ir.types.length;
    results.push({
      name: 'CBO_avg',
      category: 'coupling',
      value: parseFloat((cboSum / count).toFixed(2)),
      unit: 'count',
      iso_25010: 'Maintainability.Modularity',
      description: 'Average CBO across all types',
    });
    results.push({
      name: 'RFC_avg',
      category: 'coupling',
      value: parseFloat((rfcSum / count).toFixed(2)),
      unit: 'count',
      iso_25010: 'Maintainability.Modularity',
      description: 'Average RFC across all types',
    });

    return results;
  }
}
