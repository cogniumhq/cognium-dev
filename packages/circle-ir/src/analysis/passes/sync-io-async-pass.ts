/**
 * Pass #48: sync-io-async (CWE-1050, category: performance)
 *
 * Detects synchronous (blocking) I/O calls made inside async functions in
 * JavaScript/TypeScript. Blocking calls stall the Node.js event loop,
 * negating the benefits of async/await and starving other concurrent work.
 *
 * Detection strategy:
 *   1. Collect async method line ranges from types[].methods where
 *      modifiers include 'async'.
 *   2. For each call site within an async range, check if the method name
 *      ends in 'Sync' (Node.js blocking variants) or is in the curated
 *      BLOCKING_METHODS set.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/**
 * Methods that are always blocking regardless of name convention.
 * Kept intentionally small — only add names with virtually no async usage.
 */
const BLOCKING_METHODS: ReadonlySet<string> = new Set([
  'sleep', // Python time.sleep / any sync sleep utility
]);

/** Any method whose name ends in 'Sync' is a blocking Node.js API variant. */
const SYNC_SUFFIX_RE = /Sync$/;

export interface SyncIoAsyncResult {
  /** Blocking calls found inside async functions. */
  blockingInAsyncFns: Array<{
    line: number;
    method: string;
    enclosingMethod: string;
  }>;
}

export class SyncIoAsyncPass implements AnalysisPass<SyncIoAsyncResult> {
  readonly name = 'sync-io-async';
  readonly category = 'performance' as const;

  run(ctx: PassContext): SyncIoAsyncResult {
    const { graph, language } = ctx;

    // Only relevant for JS/TS (and Python for sleep)
    if (language !== 'javascript' && language !== 'typescript' && language !== 'python') {
      return { blockingInAsyncFns: [] };
    }

    const file = graph.ir.meta.file;

    // Collect async method line ranges
    const asyncRanges: Array<{ start: number; end: number; name: string }> = [];
    for (const type of graph.ir.types) {
      for (const method of type.methods) {
        if (method.modifiers.includes('async')) {
          asyncRanges.push({
            start: method.start_line,
            end: method.end_line,
            name: method.name,
          });
        }
      }
    }

    if (asyncRanges.length === 0) return { blockingInAsyncFns: [] };

    const blockingInAsyncFns: SyncIoAsyncResult['blockingInAsyncFns'] = [];

    for (const call of graph.ir.calls) {
      const name = call.method_name;
      if (!SYNC_SUFFIX_RE.test(name) && !BLOCKING_METHODS.has(name)) continue;

      const line = call.location.line;
      const range = asyncRanges.find(r => line >= r.start && line <= r.end);
      if (!range) continue;

      blockingInAsyncFns.push({ line, method: name, enclosingMethod: range.name });

      ctx.addFinding({
        id: `sync-io-async-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1050',
        severity: 'medium',
        level: 'warning',
        message:
          `Blocking call \`${name}()\` inside async function '${range.name}' stalls the event loop`,
        file,
        line,
        fix: `Replace \`${name}\` with its async equivalent and await the result`,
        evidence: {
          blocking_method: name,
          async_method: range.name,
        },
      });
    }

    return { blockingInAsyncFns };
  }
}
