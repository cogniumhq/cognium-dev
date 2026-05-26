/**
 * Pass #20: null-deref (CWE-476, category: reliability)
 *
 * Detects variables that are explicitly assigned null/None/undefined and then
 * used as a receiver (method call or field access) without an intervening
 * null guard.
 *
 * Detection strategy:
 *   1. Find DFG defs where the expression is an explicit null literal
 *      (null / None / undefined).
 *   2. For each such def, find all DFG uses via graph.usesOfDef().
 *   3. For each use that occurs after the def in the same method and is used
 *      as a receiver, check whether any line between def and use contains a
 *      null-check for that variable.
 *   4. Emit a finding if no guard is found.
 *
 * Scope is limited to the enclosing method to avoid cross-method FPs.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Expression values that represent an explicit null assignment. */
const NULL_EXPR_RE = /^\s*(null|None|undefined)\s*$/;

/** Escape a variable name for use in a RegExp. */
function escRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Returns true if any source line in the range [fromLine, toLine) contains a
 * null-guard pattern referencing varName.
 *
 * Guards recognised:
 *   - Java/JS: `x != null`, `x !== null`, `null != x`
 *   - Java/JS: `x == null`, `x === null` (guard on the null branch)
 *   - Python: `x is not None`, `if x:`
 *   - Optional chaining: `x?.`
 *   - Optional API: `x.isPresent()`, `Optional`
 *   - Java assertions: `assert x != null`
 *   - Java stdlib: `Objects.requireNonNull(x)`
 *   - Guava: `Preconditions.checkNotNull(x)`
 *   - Spring: `Assert.notNull(x, ...)`
 *   - JUnit/TestNG: `assertNotNull(x)`
 */
function hasNullGuard(
  codeLines: string[],
  varName: string,
  fromLine: number,
  toLine: number,
): boolean {
  const esc = escRe(varName);
  // Build one composite regex (OR of guard patterns)
  const pattern = new RegExp(
    `\\b${esc}\\b\\s*!==?\\s*(null|None|undefined)` +
    `|(null|None|undefined)\\s*!==?\\s*\\b${esc}\\b` +
    `|\\b${esc}\\b\\s*===?\\s*(null|None|undefined)` +   // null-branch check
    `|(null|None|undefined)\\s*===?\\s*\\b${esc}\\b` +
    `|\\bis\\s+not\\s+None\\b.*\\b${esc}\\b` +           // Python is not None
    `|\\b${esc}\\b.*\\bis\\s+not\\s+None\\b` +
    `|if\\s*\\(\\s*${esc}\\s*[)!&|]` +                  // if (x), if (!x)
    `|if\\s+${esc}\\s*:` +                               // Python: if x:
    `|\\b${esc}\\b\\s*\\.\\s*isPresent\\(\\)` +          // Optional.isPresent()
    `|\\bOptional\\b` +
    // Java assertion: assert x != null
    `|\\bassert\\s+${esc}\\s*!=\\s*null\\b` +
    `|\\bassert\\s+null\\s*!=\\s*${esc}\\b` +
    // Java stdlib: Objects.requireNonNull(x) or requireNonNull(x)
    `|\\b(?:Objects\\.)?requireNonNull\\s*\\(\\s*${esc}\\b` +
    // Guava: Preconditions.checkNotNull(x) or checkNotNull(x)
    `|\\b(?:Preconditions\\.)?checkNotNull\\s*\\(\\s*${esc}\\b` +
    // Spring: Assert.notNull(x, ...) or notNull(x)
    `|\\b(?:Assert\\.)?notNull\\s*\\(\\s*${esc}\\b` +
    // JUnit/TestNG: assertNotNull(x) or Assertions.assertNotNull(x)
    `|\\b(?:Assertions?\\.)?assertNotNull\\s*\\(\\s*${esc}\\b`,
  );

  for (let l = fromLine; l < toLine; l++) {
    const line = codeLines[l - 1] ?? '';
    if (pattern.test(line)) return true;
  }
  return false;
}

export interface NullDerefResult {
  /** Potential null-dereferences detected. */
  potentialNullDerefs: Array<{
    defLine: number;
    useLine: number;
    variable: string;
  }>;
}

export class NullDerefPass implements AnalysisPass<NullDerefResult> {
  readonly name = 'null-deref';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): NullDerefResult {
    const { graph, code, language } = ctx;

    // Rust has the Option/Result type system — NPE is not applicable.
    // Bash has no objects to dereference.
    if (language === 'rust' || language === 'bash') {
      return { potentialNullDerefs: [] };
    }

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const potentialNullDerefs: NullDerefResult['potentialNullDerefs'] = [];
    const reported = new Set<string>(); // deduplicate by variable+useLine

    for (const def of graph.ir.dfg.defs) {
      if (!def.expression || !NULL_EXPR_RE.test(def.expression)) continue;

      const varName = def.variable;
      const defLine = def.line;

      // Determine enclosing method bounds to limit search scope
      const methodInfo = graph.methodAtLine(defLine);
      const methodEnd = methodInfo?.method.end_line ?? Number.MAX_SAFE_INTEGER;

      // Find all downstream uses of this null-assigned variable
      const uses = graph.usesOfDef(def.id);

      for (const use of uses) {
        const useLine = use.line;

        // Use must be AFTER the assignment and within the same method
        if (useLine <= defLine || useLine > methodEnd) continue;

        // Check if the variable is used as a call receiver at this line
        const callsAtLine = graph.callsAtLine(useLine);
        const isCallReceiver = callsAtLine.some(c => c.receiver === varName);

        // Also detect field-access pattern: `varName.field`
        const lineText = codeLines[useLine - 1] ?? '';
        const fieldAccessRe = new RegExp(`\\b${escRe(varName)}\\s*\\.`);
        const isFieldAccess = fieldAccessRe.test(lineText);

        if (!isCallReceiver && !isFieldAccess) continue;

        // Optional chaining (`?.`) is safe — skip
        const optionalChainRe = new RegExp(`\\b${escRe(varName)}\\s*\\?\\s*\\.`);
        if (optionalChainRe.test(lineText)) continue;

        // Check whether a null guard exists between the assignment and this use
        if (hasNullGuard(codeLines, varName, defLine + 1, useLine)) continue;

        const key = `${varName}-${useLine}`;
        if (reported.has(key)) continue;
        reported.add(key);

        potentialNullDerefs.push({ defLine, useLine, variable: varName });

        ctx.addFinding({
          id: `null-deref-${file}-${useLine}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-476',
          severity: 'high',
          level: 'error',
          message:
            `Potential null dereference: '${varName}' was assigned null at line ${defLine} ` +
            `and is used at line ${useLine} without a null check`,
          file,
          line: useLine,
          snippet: lineText.trim(),
          fix: `Add a null check before dereferencing: \`if (${varName} != null) { ... }\``,
          evidence: {
            variable: varName,
            assigned_null_at: defLine,
          },
        });
      }
    }

    return { potentialNullDerefs };
  }
}
