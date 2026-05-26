import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Cohesion Metrics Pass (CK Suite)
 *
 * Emits per-type LCOM values, plus LCOM_avg aggregate.
 *
 * LCOM (Lack of Cohesion in Methods) — Henderson-Sellers variant:
 *   For each pair of methods (Mi, Mj) in the class:
 *     P++  if they share NO instance fields (less cohesion)
 *     Q++  if they share AT LEAST ONE instance field (more cohesion)
 *   LCOM = max(P - Q, 0)
 *
 * Field access is inferred from DFG defs and uses within each method's
 * line range that refer to a name matching an instance field of the class.
 * Types with fewer than 2 methods get LCOM = 0.
 */
export class CohesionMetricsPass implements MetricPass {
  readonly name = 'cohesion-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const { ir } = ctx;
    const results: MetricValue[] = [];

    if (ir.types.length === 0) return results;

    let lcomSum = 0;

    for (const type of ir.types) {
      // Instance (non-static) field names
      const instanceFields = new Set(
        type.fields
          .filter(f => !f.modifiers.includes('static'))
          .map(f => f.name)
      );

      const numMethods = type.methods.length;
      if (numMethods < 2 || instanceFields.size === 0) {
        lcomSum += 0;
        results.push({
          name: 'LCOM',
          category: 'cohesion',
          value: 0,
          unit: 'count',
          iso_25010: 'Maintainability.Modularity',
          description: `type: ${type.name}`,
        });
        continue;
      }

      // Build field-access set per method
      const methodFields: Array<Set<string>> = type.methods.map(method => {
        const { start_line, end_line } = method;
        const accessed = new Set<string>();

        for (const def of ir.dfg.defs) {
          if (def.line >= start_line && def.line <= end_line && instanceFields.has(def.variable)) {
            accessed.add(def.variable);
          }
        }
        for (const use of ir.dfg.uses) {
          if (use.line >= start_line && use.line <= end_line && instanceFields.has(use.variable)) {
            accessed.add(use.variable);
          }
        }
        return accessed;
      });

      // Count pairs
      let P = 0; // no shared fields
      let Q = 0; // at least one shared field
      const numMethodFields = methodFields.length;

      for (let i = 0; i < numMethodFields; i++) {
        for (let j = i + 1; j < numMethodFields; j++) {
          const mi = methodFields[i];
          const mj = methodFields[j];
          let shared = false;
          for (const f of mi) {
            if (mj.has(f)) { shared = true; break; }
          }
          if (shared) Q++; else P++;
        }
      }

      const lcom = Math.max(P - Q, 0);
      lcomSum += lcom;

      results.push({
        name: 'LCOM',
        category: 'cohesion',
        value: lcom,
        unit: 'count',
        iso_25010: 'Maintainability.Modularity',
        description: `type: ${type.name}`,
      });
    }

    const count = ir.types.length;
    results.push({
      name: 'LCOM_avg',
      category: 'cohesion',
      value: parseFloat((lcomSum / count).toFixed(2)),
      unit: 'count',
      iso_25010: 'Maintainability.Modularity',
      description: 'Average LCOM across all types',
    });

    return results;
  }
}
