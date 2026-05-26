import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

/**
 * Documentation Metrics Pass
 *
 * Emits: doc_coverage — ratio of types+methods preceded by a `/** ... *\/` doc block.
 *
 * Detection heuristic: a type or method is "documented" if the source line
 * immediately preceding its `start_line` (1-indexed) is inside a doc comment
 * block that closes with `*\/`.
 */
export class DocumentationMetricsPass implements MetricPass {
  readonly name = 'documentation-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const { ir, code } = ctx;
    const lines = code.split('\n');

    // Build set of line numbers (1-indexed) that are the last line of a /** */ block
    // We need to know: for line N, is line N the closing "*/" of a doc comment?
    const docBlockEndLines = new Set<number>();
    let inDocBlock = false;
    const numLines = lines.length;
    for (let i = 0; i < numLines; i++) {
      const trimmed = lines[i].trim();
      if (!inDocBlock && trimmed.startsWith('/**')) {
        inDocBlock = true;
        // single-line /** ... */
        if (trimmed.endsWith('*/') && trimmed.length > 4) {
          docBlockEndLines.add(i + 1); // 1-indexed
          inDocBlock = false;
        }
      } else if (inDocBlock) {
        if (trimmed.endsWith('*/')) {
          docBlockEndLines.add(i + 1); // 1-indexed
          inDocBlock = false;
        }
      }
    }

    let documentable = 0;
    let documented   = 0;

    for (const type of ir.types) {
      documentable++;
      // Check if the line before start_line is a doc block end
      if (docBlockEndLines.has(type.start_line - 1)) {
        documented++;
      }

      for (const method of type.methods) {
        documentable++;
        if (docBlockEndLines.has(method.start_line - 1)) {
          documented++;
        }
      }
    }

    const docCoverage = documentable === 0 ? 0 : documented / documentable;

    return [
      {
        name: 'doc_coverage',
        category: 'documentation',
        value: parseFloat(docCoverage.toFixed(4)),
        unit: 'ratio',
        iso_25010: 'Maintainability.Analysability',
        description: 'Ratio of types and methods with JSDoc/Javadoc comment blocks',
      },
    ];
  }
}
