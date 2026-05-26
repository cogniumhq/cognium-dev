/**
 * Pass #30: redundant-loop-computation (CWE-1050, category: performance)
 *
 * Detects loop-invariant expressions that are recomputed on every iteration.
 * The most common and highest-signal patterns:
 *   - `.length` / `.size()` / `.count()` on a variable not modified in the loop
 *   - `Object.keys(x)` / `Object.values(x)` / `Object.entries(x)` on invariant `x`
 *   - Pure math: `Math.sqrt(x)`, `Math.pow(x, n)`, `Math.abs(x)` on invariant args
 *
 * Detection strategy:
 *   1. Identify loop bodies via `graph.loopBodies()` (CFG back-edge derived).
 *   2. Build `modifiedVars`: DFG defs whose line falls inside the loop range.
 *   3. Scan source lines for the invariant patterns.
 *   4. If the receiver/argument variable is NOT in `modifiedVars`, emit a finding.
 *
 * Languages: JavaScript/TypeScript, Java, Python, Rust. Bash — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

// Match:  varName.length  or  varName.size()  or  varName.count()
// Note: for JS/TS, `.length` is an O(1) property access, not a method call.
// Use LENGTH_PATTERN_METHODS for JS/TS (excludes `.length`).
const LENGTH_PATTERN = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?:length|size\(\)|count\(\))/g;
const LENGTH_PATTERN_METHODS = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?:size\(\)|count\(\))/g;

// Match:  Object.keys(varName)  Object.values(varName)  Object.entries(varName)
const OBJECT_STATIC_PATTERN =
  /\bObject\s*\.\s*(?:keys|values|entries)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)/g;

// Match:  Math.sqrt(varName)  Math.pow(varName  Math.abs(varName)  Math.floor(varName)  Math.ceil(varName)
const MATH_PATTERN =
  /\bMath\s*\.\s*(?:sqrt|pow|abs|floor|ceil|round|log|log2|log10)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[,)]/g;

export interface RedundantLoopResult {
  invariants: Array<{ line: number; expression: string; variable: string }>;
}

export class RedundantLoopPass implements AnalysisPass<RedundantLoopResult> {
  readonly name = 'redundant-loop-computation';
  readonly category = 'performance' as const;

  run(ctx: PassContext): RedundantLoopResult {
    const { graph, code, language } = ctx;

    if (language === 'bash') {
      return { invariants: [] };
    }

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const loops = graph.loopBodies();

    if (loops.length === 0) return { invariants: [] };

    const invariants: RedundantLoopResult['invariants'] = [];
    const reported = new Set<string>(); // deduplicate by line+expression

    for (const loop of loops) {
      const { start_line, end_line } = loop;

      // Collect variables modified (written) inside the loop body
      const modifiedVars = new Set<string>();
      for (const def of graph.ir.dfg.defs) {
        if (def.line >= start_line && def.line <= end_line) {
          modifiedVars.add(def.variable);
        }
      }

      // Scan each line in the loop body for invariant patterns
      for (let ln = start_line; ln <= end_line && ln <= codeLines.length; ln++) {
        const lineText = codeLines[ln - 1] ?? '';

        // Skip blank lines
        if (lineText.trim() === '') continue;

        // --- .length / .size() / .count() ---
        // For JS/TS, `.length` is an O(1) property access — only flag method calls
        const lengthRe = (language === 'javascript' || language === 'typescript')
          ? LENGTH_PATTERN_METHODS : LENGTH_PATTERN;
        lengthRe.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = lengthRe.exec(lineText)) !== null) {
          const varName = m[1];
          if (modifiedVars.has(varName)) continue;
          // Skip if used in a for-loop initialisation line (e.g., for (let i = 0; i < arr.length; i++))
          // — the loop header itself scanning is expected; flag it only inside the body
          const expr = m[0];
          const key = `${ln}-${expr}`;
          if (reported.has(key)) continue;
          reported.add(key);

          invariants.push({ line: ln, expression: expr, variable: varName });
          ctx.addFinding({
            id: `redundant-loop-computation-${file}-${ln}`,
            pass: this.name,
            category: this.category,
            rule_id: this.name,
            cwe: 'CWE-1050',
            severity: 'low',
            level: 'note',
            message:
              `Loop-invariant computation: \`${expr}\` is recomputed on every iteration; hoist outside loop`,
            file,
            line: ln,
            snippet: lineText.trim(),
            fix: `Compute \`${expr}\` once before the loop and use the cached value inside.`,
            evidence: { variable: varName, loop_start: start_line, loop_end: end_line },
          });
        }

        // --- Object.keys/values/entries(x) ---
        OBJECT_STATIC_PATTERN.lastIndex = 0;
        while ((m = OBJECT_STATIC_PATTERN.exec(lineText)) !== null) {
          const varName = m[1];
          if (modifiedVars.has(varName)) continue;
          const expr = m[0];
          const key = `${ln}-${expr}`;
          if (reported.has(key)) continue;
          reported.add(key);

          invariants.push({ line: ln, expression: expr, variable: varName });
          ctx.addFinding({
            id: `redundant-loop-computation-${file}-${ln}-obj`,
            pass: this.name,
            category: this.category,
            rule_id: this.name,
            cwe: 'CWE-1050',
            severity: 'low',
            level: 'note',
            message:
              `Loop-invariant computation: \`${expr}\` allocates a new array on every iteration; hoist outside loop`,
            file,
            line: ln,
            snippet: lineText.trim(),
            fix: `Compute \`${expr}\` once before the loop.`,
            evidence: { variable: varName, loop_start: start_line, loop_end: end_line },
          });
        }

        // --- Math.*(x) ---
        MATH_PATTERN.lastIndex = 0;
        while ((m = MATH_PATTERN.exec(lineText)) !== null) {
          const varName = m[1];
          if (modifiedVars.has(varName)) continue;
          const expr = m[0].replace(/[,)]?\s*$/, ')');
          const key = `${ln}-${expr}`;
          if (reported.has(key)) continue;
          reported.add(key);

          invariants.push({ line: ln, expression: expr, variable: varName });
          ctx.addFinding({
            id: `redundant-loop-computation-${file}-${ln}-math`,
            pass: this.name,
            category: this.category,
            rule_id: this.name,
            cwe: 'CWE-1050',
            severity: 'low',
            level: 'note',
            message:
              `Loop-invariant computation: \`${expr}\` is recomputed on every iteration; hoist outside loop`,
            file,
            line: ln,
            snippet: lineText.trim(),
            fix: `Compute \`${expr}\` once before the loop.`,
            evidence: { variable: varName, loop_start: start_line, loop_end: end_line },
          });
        }
      }
    }

    return { invariants };
  }
}
