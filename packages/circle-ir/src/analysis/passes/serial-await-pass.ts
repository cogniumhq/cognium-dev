/**
 * Pass #32: serial-await (category: performance)
 *
 * Detects sequential `await` expressions in JavaScript/TypeScript where the
 * two awaited operations have no data dependency — they could be parallelised
 * with `Promise.all()`.
 *
 * Detection strategy:
 *   1. Per function (group lines by enclosing method via `graph.methodAtLine()`),
 *      scan lines in order for `await` patterns.
 *   2. For consecutive pairs `(line1, line2)`:
 *      a. Find the DFG def created at `line1` (if any) — this is the result
 *         variable bound to the first await.
 *      b. Check whether that variable name appears verbatim in the source
 *         line at `line2`.
 *      c. Also check whether any def on `line2` appears in `line1`'s source.
 *      d. If neither direction has a textual dependency: the two awaits are
 *         independent.
 *   3. If a function has ≥ 2 independent consecutive awaits: emit one finding
 *      per function at the first independent pair's line.
 *
 * Languages: JavaScript and TypeScript only.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Matches:  const/let/var? varName = await  or  bare  await  */
const AWAIT_ASSIGN_RE = /(?:const|let|var)?\s*(\w+)\s*=\s*await\s/;
const AWAIT_RE = /\bawait\s/;

export interface SerialAwaitResult {
  serialAwaits: Array<{ functionLine: number; firstAwaitLine: number; secondAwaitLine: number }>;
}

export class SerialAwaitPass implements AnalysisPass<SerialAwaitResult> {
  readonly name = 'serial-await';
  readonly category = 'performance' as const;

  run(ctx: PassContext): SerialAwaitResult {
    const { graph, code, language } = ctx;

    if (language !== 'javascript' && language !== 'typescript') {
      return { serialAwaits: [] };
    }

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const totalLines = codeLines.length;

    const serialAwaits: SerialAwaitResult['serialAwaits'] = [];
    const reportedFunctions = new Set<string>();

    // Collect all await lines
    const awaitLines: Array<{ line: number; boundVar: string | null }> = [];
    for (let i = 0; i < totalLines; i++) {
      const lineText = codeLines[i];
      if (!AWAIT_RE.test(lineText)) continue;
      const m = AWAIT_ASSIGN_RE.exec(lineText);
      const boundVar = m ? m[1] : null;
      awaitLines.push({ line: i + 1, boundVar });
    }

    if (awaitLines.length < 2) return { serialAwaits: [] };

    // Check consecutive pairs
    for (let i = 0; i + 1 < awaitLines.length; i++) {
      const a1 = awaitLines[i];
      const a2 = awaitLines[i + 1];

      // Must be in the same function
      const method1 = graph.methodAtLine(a1.line);
      const method2 = graph.methodAtLine(a2.line);

      const methodKey1 = method1
        ? `${method1.type.name}.${method1.method.name}.${method1.method.start_line}`
        : `top.${a1.line}`;
      const methodKey2 = method2
        ? `${method2.type.name}.${method2.method.name}.${method2.method.start_line}`
        : `top.${a2.line}`;

      if (methodKey1 !== methodKey2) continue;

      // Skip if lines are not consecutive (allow up to 3 lines apart for formatting)
      if (a2.line - a1.line > 4) continue;

      // Check dependency: does line2 reference the variable bound by line1?
      const line2Text = codeLines[a2.line - 1] ?? '';
      const line1Text = codeLines[a1.line - 1] ?? '';

      let dependent = false;

      // Forward dependency: var from line1 used in line2
      if (a1.boundVar && new RegExp(`\\b${a1.boundVar}\\b`).test(line2Text)) {
        dependent = true;
      }

      // Reverse dependency: var from line2's def used in line1 (rare but possible)
      if (!dependent && a2.boundVar && new RegExp(`\\b${a2.boundVar}\\b`).test(line1Text)) {
        dependent = true;
      }

      // DFG-level check: any def at line2 whose variable appears in defs of line1 args
      if (!dependent) {
        const defs1 = graph.defsAtLine(a1.line);
        const defs2 = graph.defsAtLine(a2.line);
        for (const d1 of defs1) {
          for (const d2 of defs2) {
            if (d1.variable === d2.variable) { dependent = true; break; }
          }
          if (dependent) break;
        }
      }

      if (dependent) continue;

      // Skip if already reported for this function
      if (reportedFunctions.has(methodKey1)) continue;
      reportedFunctions.add(methodKey1);

      const funcLine = method1?.method.start_line ?? a1.line;
      serialAwaits.push({ functionLine: funcLine, firstAwaitLine: a1.line, secondAwaitLine: a2.line });

      // Extract readable names from the await expressions
      const expr1 = line1Text.trim().replace(/^(?:const|let|var)\s+/, '');
      const expr2 = line2Text.trim().replace(/^(?:const|let|var)\s+/, '');

      ctx.addFinding({
        id: `serial-await-${file}-${a1.line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: undefined,
        severity: 'low',
        level: 'note',
        message:
          `Serial awaits: \`${expr1}\` (line ${a1.line}) and \`${expr2}\` (line ${a2.line}) ` +
          `appear to have no data dependency — verify ordering requirements before parallelising`,
        file,
        line: a1.line,
        end_line: a2.line,
        fix: `If the operations are truly independent and have no ordering constraints, ` +
          `consider: const [result1, result2] = await Promise.all([operation1, operation2]);`,
        evidence: {
          first_await_line: a1.line,
          second_await_line: a2.line,
          function_line: funcLine,
        },
      });
    }

    return { serialAwaits };
  }
}
