/**
 * Pass #81: leaked-global (CWE-1109, category: reliability)
 *
 * Detects assignments to undeclared variables inside function bodies in
 * JavaScript/TypeScript.  In non-strict mode JS (and absent `"use strict"`)
 * writing to a variable that has no `let`/`const`/`var` declaration anywhere
 * in the enclosing function silently creates (or mutates) a property on the
 * global object — a classic source of hard-to-trace bugs.
 *
 * Detection strategy:
 *   1. Language filter: JS/TS only.
 *   2. Build a ScopeGraph for declaration-keyword awareness.
 *   3. For each `kind='local'` def whose source line has NO declaration keyword:
 *      - Skip intentional throwaway names (_, err, e, …) and loop vars.
 *      - Skip if the variable IS declared (hasDeclKeyword=true) somewhere
 *        else in the same enclosing function → it is a legitimate reassignment.
 *      - Skip top-level assignments (methodStart === -1) — module-level bare
 *        assignments are an ES module pattern.
 *      - Flag the rest as potential global leaks.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ScopeGraph } from '../../graph/scope-graph.js';

/** Variable names that are intentionally never declared with a keyword. */
const SKIP_NAMES = new Set([
  '_', 'e', 'err', 'error', 'event', 'ex', 'exception',
  'i', 'j', 'k', 'n', 'idx', 'index',
]);

export interface LeakedGlobalResult {
  leaks: Array<{
    line: number;
    variable: string;
    /** Name of the enclosing function/method, or null if unavailable. */
    enclosingFunction: string | null;
  }>;
}

export class LeakedGlobalPass implements AnalysisPass<LeakedGlobalResult> {
  readonly name = 'leaked-global';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): LeakedGlobalResult {
    const { graph, code, language } = ctx;

    // JS/TS only — Python, Java, Rust all require explicit declarations
    if (language !== 'javascript' && language !== 'typescript') {
      return { leaks: [] };
    }

    const file = graph.ir.meta.file;

    // Skip test files — test helpers often use bare assignments intentionally
    if (/[./](?:test|spec)[./]/.test(file) || /\.(?:test|spec)\.[jt]s$/.test(file)) {
      return { leaks: [] };
    }

    const scope = new ScopeGraph(graph, code, language);
    const codeLines = code.split('\n');
    const leaks: LeakedGlobalResult['leaks'] = [];
    const reported = new Set<number>(); // deduplicate by line

    for (const entry of scope.entries) {
      const { def, hasDeclKeyword, methodStart } = entry;

      // Only look at bare assignments (no let/const/var on this line)
      if (hasDeclKeyword) continue;
      if (def.kind !== 'local') continue;

      const variable = def.variable;

      // Intentionally-unnamed / loop variables → skip
      if (variable.startsWith('_')) continue;
      if (SKIP_NAMES.has(variable)) continue;

      // Top-level (module scope) assignments → not a leaked global
      if (methodStart === -1) continue;

      // If the same variable has a declared def (let/const/var) anywhere in
      // this function body, this line is a legitimate reassignment — not a leak.
      if (scope.hasDeclaredDef(variable, methodStart)) continue;

      // Text-search fallback: `let x;` (no initializer) creates no DFG def, so
      // hasDeclaredDef misses it. Scan source lines within the method for any
      // `let/const/var ... varName` declaration.
      const methodInfo = graph.methodAtLine(def.line);
      if (methodInfo) {
        const { start_line, end_line } = methodInfo.method;
        const escapedVar = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // Match: let/const/var followed (possibly after { or [ for destructuring) by the name
        const declPattern = new RegExp(`\\b(?:let|const|var)\\b[^=;\\n]*\\b${escapedVar}\\b`);
        const hasTextDecl = codeLines.slice(start_line - 1, end_line).some(l => declPattern.test(l));
        if (hasTextDecl) continue;
        // Also check module-level lines (before the method) for `let varName`
        const moduleDecl = new RegExp(`^(?:export\\s+)?(?:let|const|var)\\b[^=;\\n]*\\b${escapedVar}\\b`);
        const hasModuleDecl = codeLines.slice(0, start_line - 1).some(l => moduleDecl.test(l));
        if (hasModuleDecl) continue;
      }

      if (reported.has(def.line)) continue;
      reported.add(def.line);

      const enclosingFunction = methodInfo?.method.name ?? null;

      leaks.push({ line: def.line, variable, enclosingFunction });

      const fnDesc = enclosingFunction ? ` inside '${enclosingFunction}'` : '';

      ctx.addFinding({
        id: `leaked-global-${file}-${def.line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1109',
        severity: 'medium',
        level: 'warning',
        message:
          `'${variable}' is assigned without a declaration keyword${fnDesc} — ` +
          `creates an accidental global in non-strict mode`,
        file,
        line: def.line,
        fix: `Add \`let\`, \`const\`, or \`var\` before the first assignment to '${variable}'`,
        evidence: { variable, enclosing_function: enclosingFunction },
      });
    }

    return { leaks };
  }
}
