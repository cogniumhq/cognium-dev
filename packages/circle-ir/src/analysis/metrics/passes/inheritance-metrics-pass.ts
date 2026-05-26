import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Inheritance Metrics Pass (CK Suite)
 *
 * Emits per-type DIT and NOC values, plus DIT_max and NOC_total aggregates.
 *
 * DIT (Depth of Inheritance Tree):
 *   Number of ancestor classes/interfaces in the inheritance chain.
 *   Only counts ancestors that are defined within the same file.
 *
 * NOC (Number of Children):
 *   Count of types in the file that directly extend or implement this type.
 */
export class InheritanceMetricsPass implements MetricPass {
  readonly name = 'inheritance-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const { ir } = ctx;
    const results: MetricValue[] = [];

    if (ir.types.length === 0) return results;

    const nameMap = new Map(ir.types.map(t => [t.name, t]));

    let ditMax = 0;
    let nocTotal = 0;

    for (const type of ir.types) {
      // --- DIT ---
      let depth = 0;
      let current: string | null = type.extends;
      const visited = new Set<string>();
      while (current && nameMap.has(current) && !visited.has(current)) {
        visited.add(current);
        depth++;
        current = nameMap.get(current)?.extends ?? null;
      }
      ditMax = Math.max(ditMax, depth);

      results.push({
        name: 'DIT',
        category: 'inheritance',
        value: depth,
        unit: 'count',
        iso_25010: 'Maintainability.Reusability',
        description: `type: ${type.name}`,
      });

      // --- NOC ---
      const children = ir.types.filter(
        t => t !== type && t.extends === type.name
      ).length;
      nocTotal += children;

      results.push({
        name: 'NOC',
        category: 'inheritance',
        value: children,
        unit: 'count',
        iso_25010: 'Maintainability.Reusability',
        description: `type: ${type.name}`,
      });
    }

    results.push({
      name: 'DIT_max',
      category: 'inheritance',
      value: ditMax,
      unit: 'count',
      iso_25010: 'Maintainability.Reusability',
      description: 'Maximum depth of inheritance tree across all types',
    });

    results.push({
      name: 'NOC_total',
      category: 'inheritance',
      value: nocTotal,
      unit: 'count',
      iso_25010: 'Maintainability.Reusability',
      description: 'Total number of direct child relationships across all types',
    });

    return results;
  }
}
