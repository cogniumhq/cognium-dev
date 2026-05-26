import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Complexity Metrics Pass
 *
 * Emits:
 *   - cyclomatic_complexity — one MetricValue per method (McCabe v(G))
 *   - WMC                  — Weighted Methods per Class (sum of all v(G))
 *   - loop_complexity      — count of back-edges in the CFG
 *   - condition_complexity — count of true/false branch edges in the CFG
 */
export class ComplexityMetricsPass implements MetricPass {
  readonly name = 'complexity-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const { ir } = ctx;
    const results: MetricValue[] = [];

    // Build a set of CFG block IDs for fast lookup
    const allBlockIds = new Set(ir.cfg.blocks.map(b => b.id));

    let wmcTotal = 0;

    for (const type of ir.types) {
      for (const method of type.methods) {
        const { start_line, end_line } = method;

        // Filter blocks that belong to this method's line range
        const methodBlockIds = new Set<number>();
        for (const block of ir.cfg.blocks) {
          if (block.start_line >= start_line && block.end_line <= end_line && allBlockIds.has(block.id)) {
            methodBlockIds.add(block.id);
          }
        }

        // Count in-range edges (both endpoints must be in-range blocks)
        let edgeCount = 0;
        for (const edge of ir.cfg.edges) {
          if (methodBlockIds.has(edge.from) && methodBlockIds.has(edge.to)) {
            edgeCount++;
          }
        }

        const nodeCount = methodBlockIds.size;
        // v(G) = E - N + 2, min 1
        const vg = nodeCount === 0 ? 1 : Math.max(1, edgeCount - nodeCount + 2);
        wmcTotal += vg;

        results.push({
          name: 'cyclomatic_complexity',
          category: 'complexity',
          value: vg,
          unit: 'count',
          iso_25010: 'Maintainability.Testability',
          description: `method: ${method.name}`,
        });
      }
    }

    results.push({
      name: 'WMC',
      category: 'complexity',
      value: wmcTotal,
      unit: 'count',
      iso_25010: 'Maintainability.Testability',
      description: 'Weighted Methods per Class (sum of cyclomatic complexity)',
    });

    const loopComplexity = ir.cfg.edges.filter(e => e.type === 'back').length;
    results.push({
      name: 'loop_complexity',
      category: 'complexity',
      value: loopComplexity,
      unit: 'count',
      iso_25010: 'Maintainability.Analysability',
    });

    const conditionComplexity = ir.cfg.edges.filter(e => e.type === 'true' || e.type === 'false').length;
    results.push({
      name: 'condition_complexity',
      category: 'complexity',
      value: conditionComplexity,
      unit: 'count',
      iso_25010: 'Maintainability.Analysability',
    });

    return results;
  }
}
