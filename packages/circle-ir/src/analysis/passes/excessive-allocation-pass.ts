/**
 * Pass #84: excessive-allocation (CWE-770, category: performance)
 *
 * Detects collection/object allocations inside loop bodies that
 * create unnecessary GC pressure and slow down hot paths.
 * Each allocation forces the garbage collector to do extra work,
 * degrading throughput in tight loops.
 *
 * Detection strategy:
 *   1. Identify loop body line ranges via graph.loopBodies().
 *   2. For each line within a loop body, scan source text for
 *      language-specific allocation patterns.
 *   3. Skip lines with explicit reuse signals (pool, cache, preallocat).
 *   4. Emit one warning per allocation site.
 *
 * Languages: Java, JavaScript/TypeScript, Python, Rust. Bash — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Allocation patterns keyed by language. */
const ALLOC_PATTERNS: Record<string, RegExp> = {
  javascript:
    /\bnew\s+(Array|Map|Set|Object|WeakMap|WeakSet|Error|RegExp|Date|Buffer|Uint8Array|Int8Array|Float32Array|ArrayBuffer)\s*[(<]|\bArray\.from\s*\(|\bstructuredClone\s*\(|\bObject\.create\s*\(/,
  typescript:
    /\bnew\s+(Array|Map|Set|Object|WeakMap|WeakSet|Error|RegExp|Date|Buffer|Uint8Array|Int8Array|Float32Array|ArrayBuffer)\s*[(<]|\bArray\.from\s*\(|\bstructuredClone\s*\(|\bObject\.create\s*\(/,
  java:
    /\bnew\s+(ArrayList|HashMap|HashSet|LinkedList|TreeMap|TreeSet|PriorityQueue|ArrayDeque|StringBuilder|StringBuffer|CopyOnWriteArrayList|ConcurrentHashMap)\s*[(<]|\bnew\s+\w[\w.<>]*\[\s*[a-zA-Z]\w*/,
  python:
    /\b(list|dict|set|tuple|bytearray|defaultdict|OrderedDict|Counter|deque)\s*\(\s*\)|\[\s*\]|\{\s*\}(?!\s*[}\]])/,
  rust:
    /\b(Vec|HashMap|HashSet|BTreeMap|BTreeSet|VecDeque|LinkedList|String|Box|Rc|Arc)\s*::\s*new\s*\(/,
};

/** Signals that the allocation is intentional / is a reuse pattern. */
const BENIGN_RE = /\bpool\b|\bcache\b|\breuse\b|\bpreallocat|\brecycl/i;

export interface ExcessiveAllocationResult {
  allocationsInLoops: Array<{ line: number; pattern: string }>;
}

export class ExcessiveAllocationPass implements AnalysisPass<ExcessiveAllocationResult> {
  readonly name = 'excessive-allocation';
  readonly category = 'performance' as const;

  run(ctx: PassContext): ExcessiveAllocationResult {
    const { graph, code, language } = ctx;

    if (language === 'bash') {
      return { allocationsInLoops: [] };
    }

    const pattern = ALLOC_PATTERNS[language];
    if (!pattern) return { allocationsInLoops: [] };

    const loops = graph.loopBodies();
    if (loops.length === 0) return { allocationsInLoops: [] };

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const allocationsInLoops: ExcessiveAllocationResult['allocationsInLoops'] = [];
    const reported = new Set<number>();

    for (const loop of loops) {
      for (let ln = loop.start_line; ln <= loop.end_line; ln++) {
        if (reported.has(ln)) continue;

        const src = codeLines[ln - 1] ?? '';
        const match = pattern.exec(src);
        if (!match) continue;
        if (BENIGN_RE.test(src)) continue;

        // Extract a short label for the allocation pattern
        const allocLabel = match[0].replace(/\s+/g, ' ').trim();

        allocationsInLoops.push({ line: ln, pattern: allocLabel });
        reported.add(ln);

        ctx.addFinding({
          id: `excessive-allocation-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-770',
          severity: 'medium',
          level: 'warning',
          message:
            `Repeated allocation inside loop (lines ${loop.start_line}–${loop.end_line}): ` +
            `\`${allocLabel}\` creates GC pressure on every iteration`,
          file,
          line: ln,
          snippet: src.trim(),
          fix: 'Pre-allocate outside the loop and reset/reuse the collection each iteration',
          evidence: {
            allocation: allocLabel,
            loop_start: loop.start_line,
            loop_end: loop.end_line,
          },
        });
      }
    }

    return { allocationsInLoops };
  }
}
