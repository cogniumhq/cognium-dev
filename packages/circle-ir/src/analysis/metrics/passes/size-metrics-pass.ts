import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Size Metrics Pass
 *
 * Emits: LOC, NLOC, comment_density, function_count
 */
export class SizeMetricsPass implements MetricPass {
  readonly name = 'size-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const lines = ctx.code.split('\n');
    const loc = lines.length;

    let commentLines = 0;
    let nonBlankNonComment = 0;

    for (const rawLine of lines) {
      const trimmed = rawLine.trim();
      if (trimmed.length === 0) continue;
      if (
        trimmed.startsWith('//') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('*') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('*/')
      ) {
        commentLines++;
      } else {
        nonBlankNonComment++;
      }
    }

    const nloc = nonBlankNonComment;
    const commentDensity = loc > 0 ? commentLines / loc : 0;
    const functionCount = ctx.ir.types.reduce((sum, t) => sum + t.methods.length, 0);

    return [
      {
        name: 'LOC',
        category: 'size',
        value: loc,
        unit: 'lines',
        iso_25010: 'Maintainability.Analysability',
      },
      {
        name: 'NLOC',
        category: 'size',
        value: nloc,
        unit: 'lines',
        iso_25010: 'Maintainability.Analysability',
      },
      {
        name: 'comment_density',
        category: 'size',
        value: parseFloat(commentDensity.toFixed(4)),
        unit: 'ratio',
        iso_25010: 'Maintainability.Analysability',
        description: 'Ratio of comment lines to total lines',
      },
      {
        name: 'function_count',
        category: 'size',
        value: functionCount,
        unit: 'count',
        iso_25010: 'Maintainability.Analysability',
      },
    ];
  }
}
