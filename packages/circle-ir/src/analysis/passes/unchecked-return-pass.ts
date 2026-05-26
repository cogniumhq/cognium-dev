/**
 * Pass #28: unchecked-return (CWE-252, category: reliability)
 *
 * Detects calls to methods that signal success/failure via their return value
 * when that return value is silently discarded. Missing the check means silent
 * failure propagation that can corrupt application state.
 *
 * Detection strategy:
 *   Two-tier curated list:
 *   HIGH: Always flag — the method's name is unambiguous (e.g. File.delete,
 *         Matcher.find, Lock.tryLock) and discarding is almost always a bug.
 *   MEDIUM: Flag only when the receiver name suggests a File object —
 *           guards against common false positives on generic names.
 *
 *   For each candidate call:
 *     1. If there is a DFG def at the call's line, the result was captured.
 *     2. If the source line matches a conditional/assertion pattern, the
 *        return value is already being used.
 *     If neither applies → emit finding.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/**
 * Methods where discarding the return value is almost always a bug.
 * Flagged regardless of receiver.
 */
const MUST_CHECK_HIGH: ReadonlySet<string> = new Set([
  // java.io.File — boolean status
  'createNewFile', 'mkdir', 'mkdirs',
  // java.util.concurrent
  'tryLock', 'tryAcquire', 'compareAndSet', 'compareAndExchange',
]);

/**
 * Java-only methods where discarding the return value is a bug.
 * `delete` (Set.delete / Map.delete) and `find` (Array.find) have common
 * non-Java semantics where ignoring the return value is perfectly normal.
 */
const MUST_CHECK_HIGH_JAVA_ONLY: ReadonlySet<string> = new Set([
  'delete', // java.io.File.delete()
  'find',   // java.util.regex.Matcher.find()
]);

/**
 * Methods flagged only when the receiver name suggests a File instance.
 */
const MUST_CHECK_MEDIUM: ReadonlySet<string> = new Set([
  'renameTo', 'setExecutable', 'setReadable', 'setWritable', 'setLastModified',
]);

/** Receiver names that strongly suggest java.io.File. */
const FILE_RECEIVER_RE =
  /^(file|f|src|dest|target|source|dir|directory|path|tmp|temp)\b/i;

/**
 * Line patterns that indicate the return value IS being used in a conditional,
 * assertion, or ternary — do not flag these.
 */
const CHECKED_LINE_RE =
  /\bif\s*\(|\bwhile\s*\(|\bassert\b|\?[^:]|\|\||\&\&/;

export interface UncheckedReturnResult {
  /** Calls where the return value is silently discarded. */
  uncheckedCalls: Array<{
    line: number;
    method: string;
    receiver: string | null;
  }>;
}

export class UncheckedReturnPass implements AnalysisPass<UncheckedReturnResult> {
  readonly name = 'unchecked-return';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): UncheckedReturnResult {
    const { graph, code, language } = ctx;
    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');

    // Set of lines that have a DFG definition (return value captured in variable)
    const linesWithDefs = new Set(graph.ir.dfg.defs.map(d => d.line));

    const uncheckedCalls: UncheckedReturnResult['uncheckedCalls'] = [];

    for (const call of graph.ir.calls) {
      const { method_name: name, receiver, location: { line } } = call;

      let shouldCheck = false;
      if (MUST_CHECK_HIGH.has(name)) {
        shouldCheck = true;
      } else if (language === 'java' && MUST_CHECK_HIGH_JAVA_ONLY.has(name)) {
        shouldCheck = true;
      } else if (MUST_CHECK_MEDIUM.has(name)) {
        shouldCheck = receiver != null && FILE_RECEIVER_RE.test(receiver);
      }

      if (!shouldCheck) continue;

      // Result captured → not an unchecked return
      if (linesWithDefs.has(line)) continue;

      // Conditional / assertion context → return value being used
      const lineText = codeLines[line - 1] ?? '';
      if (CHECKED_LINE_RE.test(lineText)) continue;

      uncheckedCalls.push({ line, method: name, receiver: receiver ?? null });

      const qualifier = receiver ? `${receiver}.` : '';
      ctx.addFinding({
        id: `unchecked-return-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-252',
        severity: 'medium',
        level: 'warning',
        message:
          `Return value of \`${qualifier}${name}()\` is silently discarded — ` +
          `failures will go undetected`,
        file,
        line,
        snippet: lineText.trim(),
        fix: `Check the return value: \`if (!${qualifier}${name}()) { throw new IOException(...); }\``,
        evidence: { receiver: receiver ?? undefined },
      });
    }

    return { uncheckedCalls };
  }
}
