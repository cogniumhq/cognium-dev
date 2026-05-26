/**
 * Pass #79: variable-shadowing (CWE-1109, category: reliability)
 *
 * Detects when an inner scope declares a variable with the same name as an
 * outer-scope declaration or function parameter, hiding the outer binding and
 * making code harder to reason about.
 *
 * Detection strategy:
 *   1. Build a ScopeGraph to identify which defs are true declarations vs
 *      bare reassignments.
 *   2. For each method, group DFG defs by variable name.
 *   3. Flag two kinds of shadowing within the same method:
 *      - Param shadow  : a `kind='param'` def + a later `kind='local'` def
 *        that is a real declaration (has a decl keyword, or Python which has
 *        no keywords but every local assignment implicitly shadows a param).
 *      - Outer-local shadow : two or more `kind='local'` defs that both have
 *        a declaration keyword (e.g. `let x = 1` then `let x = 2` in a
 *        nested block).
 *
 * Note on Python: Python variables have function scope (not block scope), so
 * two assignments to the same name within a function do NOT shadow each other.
 * However, a local assignment that shares a name with a parameter DOES shadow
 * the parameter (from the assignment point onward). The pass flags that case
 * for Python regardless of `hasDeclKeyword` (since Python has no decl keywords).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ScopeGraph } from '../../graph/scope-graph.js';

/**
 * Variable names that should never be flagged as shadowing — either because
 * they are JS/TS keywords that the DFG extractor may phantom-extract, or
 * because they are built-in TypeScript primitive type names that appear in
 * type annotations and get incorrectly treated as variable defs.
 */
const SKIP_NAMES = new Set([
  // JS/TS declaration keywords (phantom defs from DFG parsing keywords as vars)
  'let', 'const', 'var',
  // TypeScript primitive type names (phantom defs from type annotations)
  'boolean', 'string', 'number', 'object', 'symbol', 'undefined',
  'null', 'never', 'void', 'any', 'unknown', 'bigint',
]);

/**
 * Returns true when `innerLine` is inside a block that is nested within the
 * block containing `outerLine`. Returns false when the outer block was closed
 * before `innerLine` (i.e. they are in sibling scopes, not nested scopes).
 *
 * Strategy: scan lines from `outerLine` to `innerLine - 1` (1-based) counting
 * brace pairs. A relative balance below zero means the outer block was closed —
 * the two declarations are siblings, not a real shadowing relationship.
 *
 * Note: ignores braces inside string literals or comments, which may produce
 * occasional false negatives (missed shadows) but never false positives.
 */
function isInNestedScope(
  codeLines: string[],
  outerLine: number,
  innerLine: number,
): boolean {
  let balance = 0;
  let hasOpened = false; // true once we've seen the outer block's opening {
  for (let ln = outerLine; ln < innerLine; ln++) {
    const text = codeLines[ln - 1] ?? ''; // ln is 1-based
    for (const ch of text) {
      if (ch === '{') {
        balance++;
        hasOpened = true;
      } else if (ch === '}') {
        balance--;
        if (balance < 0) return false; // outer block closed before opening — sibling
        // If the outer block opened and has now fully closed, the inner def is
        // outside it (sibling scope, not nested).
        if (hasOpened && balance === 0) return false;
      }
    }
  }
  return true;
}

export interface VariableShadowingResult {
  shadows: Array<{
    /** Line of the shadowing (inner) declaration. */
    line: number;
    variable: string;
    /** Line of the shadowed (outer) declaration or parameter. */
    shadowedAt: number;
    kind: 'param' | 'outer-local';
  }>;
}

export class VariableShadowingPass implements AnalysisPass<VariableShadowingResult> {
  readonly name = 'variable-shadowing';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): VariableShadowingResult {
    const { graph, code, language } = ctx;
    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const scope = new ScopeGraph(graph, code, language);
    const shadows: VariableShadowingResult['shadows'] = [];
    const reported = new Set<string>(); // deduplicate by variable+line

    for (const type of graph.ir.types) {
      for (const method of type.methods) {
        const entries = scope.defsInMethod(method.start_line, method.end_line);

        // Group entries by variable name
        const byVar = new Map<string, typeof entries>();
        for (const entry of entries) {
          const existing = byVar.get(entry.def.variable);
          if (existing) {
            existing.push(entry);
          } else {
            byVar.set(entry.def.variable, [entry]);
          }
        }

        for (const [variable, varEntries] of byVar) {
          if (varEntries.length < 2) continue;

          // Skip keywords, TS primitive types, and common throwaway names
          if (SKIP_NAMES.has(variable)) continue;

          // Skip PascalCase identifiers — these are almost always type annotation
          // phantoms (class names, interface names, generic type params) that the
          // DFG extractor incorrectly surfaces as variable defs.
          if (variable.length > 0 && variable[0]! >= 'A' && variable[0]! <= 'Z') continue;

          const params  = varEntries.filter(e => e.def.kind === 'param');
          const locals  = varEntries.filter(e => e.def.kind === 'local');

          // -------------------------------------------------------
          // Case 1: Param shadowed by a local declaration
          // -------------------------------------------------------
          if (params.length > 0 && locals.length > 0) {
            const paramEntry = params[0]!;

            for (const local of locals) {
              // For Python: every assignment to a param name shadows it.
              // For other languages: only flag if the line is a real declaration.
              if (language !== 'python' && !local.hasDeclKeyword) continue;
              if (local.def.line <= paramEntry.def.line) continue;

              const key = `${variable}-${local.def.line}`;
              if (reported.has(key)) continue;
              reported.add(key);

              shadows.push({
                line: local.def.line,
                variable,
                shadowedAt: paramEntry.def.line,
                kind: 'param',
              });

              ctx.addFinding({
                id: `variable-shadowing-${file}-${local.def.line}`,
                pass: this.name,
                category: this.category,
                rule_id: this.name,
                cwe: 'CWE-1109',
                severity: 'medium',
                level: 'warning',
                message:
                  `'${variable}' shadows the parameter declared at line ${paramEntry.def.line}`,
                file,
                line: local.def.line,
                fix: `Rename the inner variable to avoid hiding the parameter '${variable}'`,
                evidence: {
                  variable,
                  outer_kind: 'param',
                  outer_line: paramEntry.def.line,
                },
              });
            }
            continue; // skip outer-local check when params are involved
          }

          // -------------------------------------------------------
          // Case 2: Outer local shadowed by an inner local declaration
          // -------------------------------------------------------
          if (locals.length >= 2) {
            // Python has no decl keywords → skip outer-local shadow for Python
            if (language === 'python') continue;

            // Only consider entries that are true declarations
            const declLocals = locals
              .filter(e => e.hasDeclKeyword)
              .sort((a, b) => a.def.line - b.def.line);

            const numDeclLocals = declLocals.length;
            if (numDeclLocals < 2) continue;

            const outerEntry = declLocals[0]!;

            for (let i = 1; i < numDeclLocals; i++) {
              const inner = declLocals[i]!;
              // Skip if the outer block was already closed before the inner
              // declaration — those are sibling scopes, not nested scopes.
              if (!isInNestedScope(codeLines, outerEntry.def.line, inner.def.line)) continue;
              const key = `${variable}-${inner.def.line}`;
              if (reported.has(key)) continue;
              reported.add(key);

              shadows.push({
                line: inner.def.line,
                variable,
                shadowedAt: outerEntry.def.line,
                kind: 'outer-local',
              });

              ctx.addFinding({
                id: `variable-shadowing-${file}-${inner.def.line}`,
                pass: this.name,
                category: this.category,
                rule_id: this.name,
                cwe: 'CWE-1109',
                severity: 'medium',
                level: 'warning',
                message:
                  `'${variable}' shadows the outer declaration at line ${outerEntry.def.line}`,
                file,
                line: inner.def.line,
                fix: `Rename the inner variable to avoid hiding the outer '${variable}'`,
                evidence: {
                  variable,
                  outer_kind: 'local',
                  outer_line: outerEntry.def.line,
                },
              });
            }
          }
        }
      }
    }

    return { shadows };
  }
}
