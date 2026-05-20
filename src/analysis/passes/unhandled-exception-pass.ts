/**
 * Pass #30: unhandled-exception (CWE-390, category: reliability)
 *
 * Detects explicit throw/raise statements that are not covered by any
 * try/catch in the same function.  Uncaught exceptions surface as
 * unhandled-rejection crashes (Node.js) or propagate unexpectedly to
 * callers who may not anticipate them.
 *
 * Detection strategy (conservative, low false-positive):
 *   1. Build ExceptionFlowGraph.  Derive "covered" line ranges as
 *      [tryBlock.start_line, catchBlock.start_line − 1] for each pair.
 *   2. Scan source lines for explicit throw/raise keywords.
 *   3. Skip if the throw line is already inside a catch block (re-throw).
 *   4. Skip if the throw line falls within any covered range.
 *   5. Emit one finding per enclosing method (avoid duplicate findings for
 *      multiple throws in the same uncovered method).
 *
 * Languages: JavaScript, TypeScript, Python only.
 *   - Java: checked exceptions are intentionally propagated via `throws`;
 *     too noisy without type hierarchy support.
 *   - Rust/Bash: no traditional throw/raise; skip.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ExceptionFlowGraph } from '../../graph/exception-flow-graph.js';

const JS_THROW_RE = /^\s*throw\s+/;
const PYTHON_RAISE_RE = /^\s*raise\b/;

/**
 * Detects validation throws: `throw new TypeError(...)` or `throw new RangeError(...)`
 * preceded by a guard condition (`if (typeof ...`, `if (!...`, `if (x === null)`, etc.).
 * These are intentional input-validation patterns, not uncaught security events.
 */
function isValidationThrow(lines: string[], throwLine: number): boolean {
  const throwText = lines[throwLine - 1] ?? '';
  if (!/\bthrow\s+new\s+(TypeError|RangeError|ArgumentError|ERR_\w+)\b/.test(throwText)) {
    return false;
  }
  // Look back 1–3 lines for a guard condition
  for (let i = 1; i <= 3 && throwLine - i >= 1; i++) {
    const prev = lines[throwLine - i - 1] ?? '';
    if (
      /\bif\s*\(/.test(prev) &&
      /typeof|===\s*['"]undefined['"]|===\s*null|!|\.length|<\s*\d|>\s*\d/.test(prev)
    ) {
      return true;
    }
  }
  return false;
}

// Regex to detect try/catch blocks in source (JS/TS and Python)
const JS_TRY_RE = /^\s*try\s*\{/;
const JS_CATCH_RE = /^\s*\}\s*catch\b/;
const PY_TRY_RE = /^\s*try\s*:/;
const PY_EXCEPT_RE = /^\s*except\b/;

/**
 * Build try/catch covered ranges directly from source code.
 * This supplements CFG-based ranges when the CFG builder doesn't emit
 * exception edges for all try/catch blocks (e.g., complex control flow).
 *
 * For JS/TS: uses brace-depth tracking to correctly pair nested try/catch.
 * For Python: uses indent-level matching.
 */
function buildSourceCoveredRanges(
  codeLines: string[],
  language: string,
): Array<{ start: number; end: number }> {
  if (language === 'python') {
    return buildPythonCoveredRanges(codeLines);
  }
  return buildJsCoveredRanges(codeLines);
}

function buildJsCoveredRanges(
  codeLines: string[],
): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  // Stack of try-line numbers; push on `try {`, pop on matching `} catch`
  const tryStack: number[] = [];
  let braceDepthAtTry: number[] = [];
  let braceDepth = 0;

  for (let i = 0; i < codeLines.length; i++) {
    const line = codeLines[i];

    // Check for try before counting braces on this line
    if (JS_TRY_RE.test(line)) {
      tryStack.push(i + 1);
      // Record brace depth BEFORE the try's opening brace
      braceDepthAtTry.push(braceDepth);
    }

    // Check for } catch — this closes the innermost try
    if (JS_CATCH_RE.test(line) && tryStack.length > 0) {
      const tryLine = tryStack.pop()!;
      braceDepthAtTry.pop();
      ranges.push({ start: tryLine, end: i }); // i is 0-based, catch line = i+1, covered = [tryLine, i]
    }

    // Count braces for depth tracking
    for (const ch of line) {
      if (ch === '{') braceDepth++;
      else if (ch === '}') braceDepth--;
    }
  }

  return ranges;
}

function buildPythonCoveredRanges(
  codeLines: string[],
): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  const tryStack: Array<{ line: number; indent: number }> = [];

  for (let i = 0; i < codeLines.length; i++) {
    const line = codeLines[i];
    if (PY_TRY_RE.test(line)) {
      const indent = line.search(/\S/);
      tryStack.push({ line: i + 1, indent });
    }
    if (PY_EXCEPT_RE.test(line) && tryStack.length > 0) {
      const indent = line.search(/\S/);
      // Pop the try with matching indent level
      for (let j = tryStack.length - 1; j >= 0; j--) {
        if (tryStack[j].indent === indent) {
          const tryLine = tryStack[j].line;
          tryStack.splice(j, 1);
          ranges.push({ start: tryLine, end: i });
          break;
        }
      }
    }
  }

  return ranges;
}

export interface UnhandledExceptionResult {
  unhandled: Array<{ line: number; method: string }>;
}

export class UnhandledExceptionPass implements AnalysisPass<UnhandledExceptionResult> {
  readonly name = 'unhandled-exception';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): UnhandledExceptionResult {
    const { graph, code, language } = ctx;

    if (language !== 'javascript' && language !== 'typescript' && language !== 'python') {
      return { unhandled: [] };
    }

    const { cfg } = graph.ir;
    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');

    const exGraph = new ExceptionFlowGraph(cfg, graph.blockById);

    // Build covered ranges: [tryBlock.start_line, catchBlock.start_line - 1]
    // Use both CFG-based ranges (from ExceptionFlowGraph) and source-based ranges
    // to handle cases where the CFG builder doesn't emit exception edges for all try/catch blocks.
    const coveredRanges: Array<{ start: number; end: number }> = [];
    for (const pair of exGraph.pairs) {
      if (pair.catchBlock.start_line > pair.tryBlock.start_line) {
        coveredRanges.push({
          start: pair.tryBlock.start_line,
          end: pair.catchBlock.start_line - 1,
        });
      }
    }

    // Supplement with source-level try/catch detection
    for (const range of buildSourceCoveredRanges(codeLines, language)) {
      // Only add if not already covered by a CFG-based range
      const alreadyCovered = coveredRanges.some(
        r => r.start <= range.start && r.end >= range.end,
      );
      if (!alreadyCovered) {
        coveredRanges.push(range);
      }
    }

    // Collect catch-block start lines (to detect re-throws)
    // Include both CFG-based and source-based catch lines
    const catchStarts = new Set<number>(
      exGraph.pairs.map(p => p.catchBlock.start_line),
    );
    for (const range of coveredRanges) {
      catchStarts.add(range.end + 1); // catch line = end of covered range + 1
    }

    const throwRe = language === 'python' ? PYTHON_RAISE_RE : JS_THROW_RE;

    const unhandled: UnhandledExceptionResult['unhandled'] = [];
    const reportedMethods = new Set<string>();

    for (let ln = 1; ln <= codeLines.length; ln++) {
      const lineText = codeLines[ln - 1] ?? '';
      if (!throwRe.test(lineText)) continue;

      // Skip re-throws inside catch blocks
      let inCatch = false;
      for (const cs of catchStarts) {
        if (ln >= cs) { inCatch = true; break; }
      }
      // More precise: only skip if ln is actually within a catch body
      // (not just any line after a catch start). Use method boundary check.
      // Simplified: if the line is >= any catch start within the same method, skip.
      // Better heuristic: check if any pair has catchBlock.start_line <= ln
      // and the throw is inside that catch body (ln <= methodEnd of that catch).
      // We use a simple check: if the throw line is >= a catch start and
      // the enclosing method contains the corresponding try, treat as re-throw.
      inCatch = false;
      for (const pair of exGraph.pairs) {
        if (ln >= pair.catchBlock.start_line) {
          // Check same method
          const mThrow = graph.methodAtLine(ln);
          const mCatch = graph.methodAtLine(pair.catchBlock.start_line);
          if (
            mThrow &&
            mCatch &&
            mThrow.method.start_line === mCatch.method.start_line
          ) {
            inCatch = true;
            break;
          }
        }
      }
      if (inCatch) continue;

      // Check if covered by a try/catch range
      const isCovered = coveredRanges.some(r => ln >= r.start && ln <= r.end);
      if (isCovered) continue;

      // Deduplicate by enclosing method
      const methodInfo = graph.methodAtLine(ln);
      const methodKey = methodInfo
        ? `${methodInfo.method.start_line}-${methodInfo.method.end_line}`
        : `global-${ln}`;

      if (reportedMethods.has(methodKey)) continue;

      // Skip validation throws: throw new TypeError/RangeError after a guard
      if (isValidationThrow(codeLines, ln)) continue;

      reportedMethods.add(methodKey);

      const methodName = methodInfo?.method.name ?? '<anonymous>';
      unhandled.push({ line: ln, method: methodName });

      const snippet = lineText.trim();
      ctx.addFinding({
        id: `unhandled-exception-${file}-${ln}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-390',
        severity: 'medium',
        level: 'warning',
        message:
          `Unhandled exception: \`throw\` at line ${ln} in \`${methodName}\` is not inside ` +
          `a try/catch — callers receive an unexpected exception`,
        file,
        line: ln,
        snippet,
        fix: 'Wrap throwing code in a try/catch, or document the exception in the function signature',
        evidence: { method: methodName },
      });
    }

    return { unhandled };
  }
}
