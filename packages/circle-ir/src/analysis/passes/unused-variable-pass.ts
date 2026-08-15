/**
 * Pass #82: unused-variable (CWE-561, category: reliability)
 *
 * Detects local variables that are declared but whose value is never read.
 * This includes variables whose value is overwritten before any read
 * (the initial assignment is "dead" from a data-flow perspective).
 *
 * Detection strategy:
 *   1. For each `kind='local'` DFG def:
 *      - Skip intentional throwaway names (`_`, `err`, `e`, loop variables…).
 *      - Skip variables in `catch` blocks (common pattern to capture but ignore
 *        exceptions: `catch (err) { ... }`).
 *      - Call `graph.usesOfDef(def.id)` — returns uses with `def_id === defId`.
 *      - If the result is empty, no code ever reads the value stored by this
 *        definition → flag as unused.
 *
 * Notes:
 *   - Test files are excluded to reduce noise (test helpers often define
 *     variables for side-effect checks).
 *   - Parameters (`kind='param'`) are excluded — unused parameters are common
 *     in callbacks and overriding methods and produce too many false positives.
 *   - Fields (`kind='field'`) are excluded — class fields are often read via
 *     `this.x` in ways the DFG may not track precisely.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Variable names that are intentionally declared-but-not-read. */
const SKIP_NAMES = new Set([
  '_', 'unused',
  'e', 'err', 'error', 'ex', 'exception',
  'i', 'j', 'k', 'n', 'idx', 'index',
  // TypeScript/JavaScript built-in type keywords that the DFG extractor may
  // accidentally surface as phantom variable defs from type annotations.
  'boolean', 'string', 'number', 'object', 'symbol', 'undefined',
  'null', 'never', 'void', 'any', 'unknown', 'bigint',
]);

/** Shared empty line-index for names absent from the source text. */
const EMPTY_LINES: readonly number[] = [];

export interface UnusedVariableResult {
  unusedVars: Array<{ line: number; variable: string }>;
}

export class UnusedVariablePass implements AnalysisPass<UnusedVariableResult> {
  readonly name = 'unused-variable';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): UnusedVariableResult {
    const { graph, code } = ctx;
    const file = graph.ir.meta.file;

    // Skip test files — test scaffolding often has unused vars intentionally
    if (/[./](?:test|spec)[./]/.test(file) || /\.(?:test|spec)\.[jt]s$/.test(file)) {
      return { unusedVars: [] };
    }

    const codeLines = code.split('\n');
    const unusedVars: UnusedVariableResult['unusedVars'] = [];
    const reported = new Set<string>(); // deduplicate by variable+line

    // Precompute two indexes ONCE so the per-def fallback is not quadratic on
    // large files (cognium-ai#305): grouping defs by variable avoids an O(defs)
    // rescan per candidate, and a name→line-numbers map avoids an O(lines)
    // text scan per candidate. Both replace the previous O(defs²)+O(defs·lines)
    // work — the dominant cost on files where the DFG surfaces few uses.
    const defsByVar = new Map<string, typeof graph.ir.dfg.defs>();
    for (const d of graph.ir.dfg.defs) {
      const arr = defsByVar.get(d.variable);
      if (arr) arr.push(d); else defsByVar.set(d.variable, [d]);
    }
    // 1-indexed line numbers on which each identifier token appears (deduped
    // per line). Equivalent to a `\bname\b` scan for identifier names; names
    // containing non-identifier chars (dotted paths, `$`) fall back to regex.
    const nameLines = new Map<string, number[]>();
    const idRe = /[A-Za-z_][A-Za-z0-9_]*/g;
    for (let i = 0; i < codeLines.length; i++) {
      const line = codeLines[i];
      idRe.lastIndex = 0;
      let seen: Set<string> | null = null;
      let m: RegExpExecArray | null;
      while ((m = idRe.exec(line)) !== null) {
        const w = m[0];
        if (seen === null) seen = new Set();
        if (seen.has(w)) continue;
        seen.add(w);
        const arr = nameLines.get(w);
        if (arr) arr.push(i + 1); else nameLines.set(w, [i + 1]);
      }
    }

    for (const def of graph.ir.dfg.defs) {
      if (def.kind !== 'local') continue;

      const variable = def.variable;

      // Skip intentional throwaway / loop variable names
      if (variable.startsWith('_')) continue;
      if (SKIP_NAMES.has(variable)) continue;

      // Skip catch-block variables (e.g. `catch (err)`)
      const lineText = codeLines[def.line - 1] ?? '';
      if (/\bcatch\s*\(/.test(lineText)) continue;

      // Skip exported symbols — they are consumed by other modules and
      // single-file DFG analysis cannot see cross-file uses.
      if (/\bexport\b/.test(lineText)) continue;

      // No uses of this specific definition → unused (per DFG)
      const uses = graph.usesOfDef(def.id);
      if (uses.length > 0) continue;

      // Text-search fallback: covers cross-scope uses that the DFG misses (e.g.
      // module-level constants referenced inside a class method body, or
      // conditional reassignments where the DFG links the final read only to
      // the last def so earlier defs appear unused).
      const otherDefs = (defsByVar.get(variable) ?? []).filter(d => d.id !== def.id);
      const otherDefLines = new Set(otherDefs.map(d => d.line));
      // Plain identifier names use the precomputed index; others fall back to a
      // per-line regex (rare — dotted paths / `$`).
      const plainName = /^[A-Za-z_][A-Za-z0-9_]*$/.test(variable);
      const idxLines = plainName ? (nameLines.get(variable) ?? EMPTY_LINES) : null;
      const namePattern = plainName ? null
        : new RegExp(`\\b${variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);

      if (otherDefLines.size === 0) {
        // Single def — any occurrence on another line suppresses.
        const usedElsewhere = idxLines !== null
          ? idxLines.some(ln => ln !== def.line)
          : codeLines.some((line, idx) => idx !== def.line - 1 && namePattern!.test(line));
        if (usedElsewhere) continue;
      } else {
        // Multiple defs exist.
        //
        // Case A — current def IS a true declaration (let/const/var, Java type, Rust let):
        //   Only suppress if a non-def use is found that precedes ALL intermediate defs.
        //   This preserves "overwrite-before-read" detection: if a later def appears
        //   between this def and the text-found use, the value was overwritten and the
        //   use belongs to the later def.
        //
        // Case B — current def is a bare reassignment (part of a conditional pattern):
        //   Suppress if the variable appears anywhere on a non-def line.  This handles
        //   sibling-if-block assignments (`if (x) { fw = 'a'; } if (y) { fw = 'b'; }
        //   return fw;`) where the DFG links the return only to the last branch def.
        const lineText = codeLines[def.line - 1] ?? '';
        const isTrueDeclaration = /\b(?:let|const|var)\s+[\w{[]/.test(lineText)
          || /\b(?:int|long|float|double|boolean|byte|char|short|var|final)\b/.test(lineText)
          || /\b[A-Z]\w*(?:<[^>]*>)?\s+\w/.test(lineText)
          || /\blet\s+(?:mut\s+)?\w/.test(lineText);

        if (isTrueDeclaration) {
          // Case A: suppress only if a use appears before any intermediate def
          // (an intermediate def would mean the value was overwritten first).
          const usedBeforeNextDef = idxLines !== null
            ? idxLines.some(ln =>
                ln !== def.line && !otherDefLines.has(ln) &&
                !otherDefs.some(d => d.line > def.line && d.line < ln))
            : codeLines.some((line, idx) => {
                const lineNum = idx + 1;
                if (lineNum === def.line || otherDefLines.has(lineNum)) return false;
                if (!namePattern!.test(line)) return false;
                return !otherDefs.some(d => d.line > def.line && d.line < lineNum);
              });
          if (usedBeforeNextDef) continue;
        } else {
          // Case B: bare reassignment — suppress if used on any non-def line.
          const usedOnNonDefLine = idxLines !== null
            ? idxLines.some(ln => ln !== def.line && !otherDefLines.has(ln))
            : codeLines.some((line, idx) => {
                const lineNum = idx + 1;
                return lineNum !== def.line && !otherDefLines.has(lineNum) && namePattern!.test(line);
              });
          if (usedOnNonDefLine) continue;
        }
      }

      const key = `${variable}-${def.line}`;
      if (reported.has(key)) continue;
      reported.add(key);

      unusedVars.push({ line: def.line, variable });

      ctx.addFinding({
        id: `unused-variable-${file}-${def.line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-561',
        severity: 'low',
        level: 'note',
        message: `'${variable}' is assigned but its value is never read`,
        file,
        line: def.line,
        snippet: lineText.trim(),
        fix: `Remove the assignment or use the value of '${variable}'`,
        evidence: { variable },
      });
    }

    return { unusedVars };
  }
}
