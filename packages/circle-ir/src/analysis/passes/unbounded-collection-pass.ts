/**
 * Pass #31: unbounded-collection (CWE-770, category: performance)
 *
 * Detects collections that grow unboundedly inside a loop with no
 * corresponding size limit check or clear/remove operation.
 *
 * Detection strategy:
 *   1. For each loop body (via `graph.loopBodies()`), find all calls in the
 *      range whose method_name is a known "grow" operation.
 *   2. For each grow call, extract the receiver as the collection variable.
 *   3. Check if the loop body also contains any shrink operation (`clear`,
 *      `remove`, `delete`, `shift`, `pop`, `removeFirst`, `poll`) on the
 *      same receiver, OR a size-limit guard in the source text
 *      (`size() <`, `length <`, `size() <=`, etc.).
 *   4. If grow-only with no limit found: emit a finding.
 *
 * Languages: Java, JavaScript/TypeScript, Python, Rust. Bash — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Method names that grow a collection, keyed by language group. */
const GROW_METHODS: Record<string, Set<string>> = {
  java:       new Set(['add', 'put', 'offer', 'push', 'addAll', 'addFirst', 'addLast', 'enqueue', 'insert']),
  javascript: new Set(['push', 'set', 'add', 'unshift', 'append', 'prepend']),
  typescript: new Set(['push', 'set', 'add', 'unshift', 'append', 'prepend']),
  python:     new Set(['append', 'extend', 'update', 'add', 'insert']),
  rust:       new Set(['push', 'insert', 'push_back', 'push_front']),
};

/** Method names that shrink a collection. Language-agnostic. */
const SHRINK_METHODS = new Set([
  'clear', 'remove', 'delete', 'shift', 'pop', 'removeFirst', 'removeLast',
  'poll', 'pollFirst', 'pollLast', 'dequeue', 'discard', 'drain',
]);

/** Regex: size limit guard pattern in source text. */
const SIZE_LIMIT_RE =
  /\b(?:size|length|count|len)\s*\(\)?\s*[<>]=?\s*\d|\b(?:MAX|LIMIT|CAPACITY|MAX_SIZE)\b/i;

/**
 * Regex: bounded iteration patterns.
 * These loops iterate a finite collection, so grow ops inside them are bounded.
 *   - JS/TS: `for (const x of items)`, `for (const k in obj)`, `.forEach(`, `.map(`
 *   - Python: `for x in items:`
 *   - Java: `for (Type x : items)` (enhanced for)
 */
const BOUNDED_LOOP_RE =
  /\bfor\s*\(.*\b(?:of|in)\b|\bfor\s+\w+\s+in\b|\bfor\s*\([^;]*:[^;]*\)|\.(?:forEach|map|flatMap|filter|reduce)\s*\(/;

/**
 * Per-pass options for UnboundedCollectionPass.
 * Pass via `AnalyzerOptions.passOptions.unboundedCollection`.
 */
export interface UnboundedCollectionOptions {
  /**
   * Variable names to skip (not flag as unbounded).
   * Useful for known-safe collections or intentional accumulation.
   */
  skipPatterns?: string[];
}

export interface UnboundedCollectionResult {
  unboundedCollections: Array<{ receiver: string; line: number; loopStart: number; loopEnd: number }>;
}

export class UnboundedCollectionPass implements AnalysisPass<UnboundedCollectionResult> {
  readonly name = 'unbounded-collection';
  readonly category = 'performance' as const;

  private readonly skipPatterns: Set<string>;

  constructor(options?: UnboundedCollectionOptions) {
    this.skipPatterns = new Set(options?.skipPatterns ?? []);
  }

  run(ctx: PassContext): UnboundedCollectionResult {
    const { graph, code, language } = ctx;

    if (language === 'bash') {
      return { unboundedCollections: [] };
    }

    const growMethods = GROW_METHODS[language] ?? GROW_METHODS['javascript'];

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const loops = graph.loopBodies();

    if (loops.length === 0) return { unboundedCollections: [] };

    const unboundedCollections: UnboundedCollectionResult['unboundedCollections'] = [];
    const reported = new Set<string>();

    for (const loop of loops) {
      const { start_line, end_line } = loop;

      // Collect source text for the loop body (for heuristic checks)
      const loopSource = codeLines.slice(start_line - 1, end_line).join('\n');

      // Skip bounded loops: for...of, for...in, forEach, enhanced for (Java)
      // These iterate a finite collection, so grow ops are bounded by input size.
      const loopHeader = codeLines[start_line - 1] ?? '';
      if (BOUNDED_LOOP_RE.test(loopHeader)) continue;

      // Find grow calls in the loop body
      const growCalls: Array<{ receiver: string; line: number }> = [];
      for (const call of graph.ir.calls) {
        const ln = call.location.line;
        if (ln < start_line || ln > end_line) continue;
        if (!growMethods.has(call.method_name)) continue;
        if (!call.receiver) continue;
        // Skip 'this' receiver — can't reliably bound
        if (call.receiver === 'this' || call.receiver === 'self') continue;
        growCalls.push({ receiver: call.receiver, line: ln });
      }

      if (growCalls.length === 0) continue;

      // Group by receiver
      const receiverLines = new Map<string, number>();
      for (const { receiver, line } of growCalls) {
        if (!receiverLines.has(receiver)) {
          receiverLines.set(receiver, line);
        }
      }

      for (const [receiver, firstGrowLine] of receiverLines.entries()) {
        // Skip if receiver matches a skip pattern
        if (this.skipPatterns.has(receiver)) continue;

        // Check for shrink operations on the same receiver in the loop body
        let hasShrink = false;
        for (const call of graph.ir.calls) {
          const ln = call.location.line;
          if (ln < start_line || ln > end_line) continue;
          if (call.receiver !== receiver) continue;
          if (SHRINK_METHODS.has(call.method_name)) {
            hasShrink = true;
            break;
          }
        }
        if (hasShrink) continue;

        // Check for size-limit guard in loop source
        if (SIZE_LIMIT_RE.test(loopSource)) continue;

        const key = `${receiver}-${start_line}`;
        if (reported.has(key)) continue;
        reported.add(key);

        unboundedCollections.push({
          receiver,
          line: firstGrowLine,
          loopStart: start_line,
          loopEnd: end_line,
        });

        ctx.addFinding({
          id: `unbounded-collection-${file}-${firstGrowLine}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-770',
          severity: 'medium',
          level: 'warning',
          message:
            `Unbounded collection: \`${receiver}\` grows inside a loop (lines ${start_line}–${end_line}) ` +
            `with no size limit or clear`,
          file,
          line: firstGrowLine,
          fix:
            `Add a size limit check (e.g., \`if (${receiver}.size() >= MAX) break;\`) ` +
            `or periodically clear/drain \`${receiver}\`.`,
          evidence: { receiver, loop_start: start_line, loop_end: end_line },
        });
      }
    }

    return { unboundedCollections };
  }
}
