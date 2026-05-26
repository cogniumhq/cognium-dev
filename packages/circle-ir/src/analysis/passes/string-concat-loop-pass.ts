/**
 * Pass #50: string-concat-loop (CWE-1046, category: performance)
 *
 * Detects string concatenation using `+=` inside loop bodies, which creates
 * O(n²) string allocations. Each iteration copies the entire accumulated
 * string, making this a common performance anti-pattern.
 *
 * Detection strategy:
 *   1. Identify loop body line ranges via CFG back-edges (graph.loopBodies()).
 *   2. For each line within a loop body, scan for `identifier +=` pattern.
 *   3. Filter out obvious numeric variable names (i, count, sum, etc.) and
 *      numeric-looking RHS literals to avoid FP on arithmetic accumulation.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Matches `varName +=` at a token boundary. Group 1 = variable name. */
const CONCAT_RE = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\+=/;

/**
 * Variable names that almost certainly hold numeric values.
 * These can safely be skipped even if they appear in `+=` expressions.
 */
const NUMERIC_VAR_RE =
  /^(i|j|k|n|m|x|y|z|count|sum|total|size|index|len|length|num|idx|score|counter|offset|pos|col|row|result|ret|value|acc|bits|byte|bytes|flag|flags|step|delta|diff|dist|min|max|avg|mean|page|line|err|error)$/i;

/** Variable name suffixes that strongly suggest numeric accumulation. */
const NUMERIC_SUFFIX_RE =
  /(Count|Sum|Total|Size|Index|Length|Offset|Position|Score|Counter|Num|Amount|Val|Idx|Len|Max|Min|Avg|Delta|Diff|Step|Flag|Flags|Bits|Byte|Bytes|Calls|Items|Nodes|Edges|Blocks|Lines|Chars|Entries|Records|Rows)$/;

/**
 * Matches a right-hand side that starts with a digit or decimal point —
 * these are numeric literals so the `+=` is arithmetic, not string concat.
 */
const NUMERIC_RHS_RE = /^\s*[\d.]/;

export interface StringConcatLoopResult {
  /** `+=` expressions inside loop bodies that are likely string concatenation. */
  concatInLoops: Array<{ line: number; variable: string }>;
}

export class StringConcatLoopPass implements AnalysisPass<StringConcatLoopResult> {
  readonly name = 'string-concat-loop';
  readonly category = 'performance' as const;

  run(ctx: PassContext): StringConcatLoopResult {
    const { graph, code } = ctx;
    const file = graph.ir.meta.file;

    const loops = graph.loopBodies();
    if (loops.length === 0) return { concatInLoops: [] };

    const codeLines = code.split('\n');
    const concatInLoops: Array<{ line: number; variable: string }> = [];
    const reported = new Set<number>(); // one finding per line

    for (const loop of loops) {
      for (let ln = loop.start_line; ln <= loop.end_line; ln++) {
        if (reported.has(ln)) continue;

        const src = codeLines[ln - 1] ?? '';
        const match = CONCAT_RE.exec(src);
        if (!match) continue;

        const varName = match[1];

        // Skip obviously-numeric variable names
        if (NUMERIC_VAR_RE.test(varName)) continue;
        if (NUMERIC_SUFFIX_RE.test(varName)) continue;

        // Skip if the RHS after `+=` starts with a digit/decimal (numeric literal)
        const opIdx = src.indexOf('+=');
        const afterOp = opIdx >= 0 ? src.slice(opIdx + 2) : '';
        if (NUMERIC_RHS_RE.test(afterOp)) continue;

        concatInLoops.push({ line: ln, variable: varName });
        reported.add(ln);

        ctx.addFinding({
          id: `string-concat-loop-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-1046',
          severity: 'low',
          level: 'warning',
          message:
            `String concatenation with '+=' inside a loop: '${varName}' grows O(n²). ` +
            `Each iteration copies the entire accumulated string.`,
          file,
          line: ln,
          snippet: src.trim(),
          fix:
            `Accumulate parts in an array and join() after the loop, ` +
            `or use StringBuilder (Java) / StringJoiner`,
          evidence: {
            variable: varName,
            loop_start: loop.start_line,
            loop_end: loop.end_line,
          },
        });
      }
    }

    return { concatInLoops };
  }
}
