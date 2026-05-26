/**
 * Pass #22: dead-code (CWE-561, category: reliability)
 *
 * Detects CFG blocks that are structurally unreachable from the entry block
 * (i.e., no path of control-flow edges leads to them). This is pure CFG
 * reachability — independent of constant-propagation or taint analysis.
 *
 * Examples: code after an unconditional `return`/`throw`, branches of
 * `if (false)` where the condition is a literal (compiler-level dead code).
 *
 * Note: semantic dead code eliminated by constant propagation (e.g.,
 * `if (DEBUG_MODE) { ... }` where DEBUG_MODE is a compile-time constant)
 * is handled by ConstantPropagationPass, not this pass.
 */

import type { CFGBlock } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

export interface DeadCodePassResult {
  /** CFG blocks with no incoming reachable path from the entry block. */
  deadBlocks: CFGBlock[];
}

export class DeadCodePass implements AnalysisPass<DeadCodePassResult> {
  readonly name = 'dead-code';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): DeadCodePassResult {
    const { graph, code } = ctx;
    const { blocks, edges } = graph.ir.cfg;
    const file = graph.ir.meta.file;
    const language = graph.ir.meta.language ?? '';

    if (blocks.length === 0) return { deadBlocks: [] };

    // Build outgoing adjacency: block id → reachable block ids
    const outgoing = new Map<number, number[]>();
    for (const edge of edges) {
      let list = outgoing.get(edge.from);
      if (!list) { list = []; outgoing.set(edge.from, list); }
      list.push(edge.to);
    }

    // Find ALL root blocks: blocks with no incoming edges AND at least one
    // outgoing edge. Each function body, arrow function, and class method
    // creates its own disconnected sub-graph in the CFG (intra-procedural
    // CFGs don't model call edges). These sub-graph roots have no incoming
    // edges but DO have outgoing edges into their body blocks.
    //
    // A completely isolated block (no incoming, no outgoing) is the canonical
    // shape of dead code after an unconditional return/throw — it is NOT
    // treated as a root so it gets correctly reported.
    const hasIncoming = new Set(edges.map(e => e.to));
    const hasOutgoing = new Set(edges.map(e => e.from));
    const roots = blocks.filter(b =>
      !hasIncoming.has(b.id) && hasOutgoing.has(b.id),
    );
    // Always have at least one root: prefer type='entry', then any root,
    // then the lowest-id block.
    if (roots.length === 0) {
      const fallback =
        blocks.find(b => b.type === 'entry') ??
        blocks.find(b => !hasIncoming.has(b.id)) ??
        blocks.reduce((a, b) => (a.id < b.id ? a : b));
      roots.push(fallback);
    }

    // BFS from ALL roots to mark reachable block ids.
    const reachable = new Set<number>(roots.map(r => r.id));
    const queue: number[] = roots.map(r => r.id);
    while (queue.length > 0) {
      const id = queue.shift()!;
      for (const next of outgoing.get(id) ?? []) {
        if (!reachable.has(next)) {
          reachable.add(next);
          queue.push(next);
        }
      }
    }

    // Collect unreachable blocks that are worth reporting:
    // - not the entry or exit sentinel blocks
    // - have a positive start line (skip synthetic 0-line blocks)
    const isJsTs = language === 'javascript' || language === 'typescript';
    const codeLines = isJsTs ? code.split('\n') : [];

    const deadBlocks: CFGBlock[] = [];
    for (const block of blocks) {
      if (reachable.has(block.id)) continue;
      if (block.type === 'entry' || block.type === 'exit') continue;
      if (block.start_line <= 0) continue;

      // In JS/TS, completely isolated blocks (no incoming AND no outgoing edges)
      // are often arrow function expression bodies or simple function bodies — the
      // intra-procedural CFG extractor gives them no edges. Suppress these to avoid
      // false positives. Real dead code (post-return) always has a preceding block
      // with an outgoing edge, so it is not affected by this check.
      if (isJsTs && !hasIncoming.has(block.id) && !hasOutgoing.has(block.id)) {
        const prevLine = codeLines[block.start_line - 2]?.trimEnd() ?? '';
        const startLine = codeLines[block.start_line - 1]?.trimEnd() ?? '';
        // Arrow function body: the line before OR the block's own first line
        // contains '=>' (handles both multi-line and inline arrow functions).
        // Regular function/method body: the preceding line ends with '{'.
        if (prevLine.includes('=>') || prevLine.endsWith('{') ||
            startLine.includes('=>')) continue;
      }

      deadBlocks.push(block);

      const loc = block.start_line === block.end_line
        ? `line ${block.start_line}`
        : `lines ${block.start_line}–${block.end_line}`;

      ctx.addFinding({
        id: `dead-code-${file}-${block.start_line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-561',
        severity: 'low',
        level: 'warning',
        message: `Dead code at ${loc}: block is unreachable from any entry point`,
        file,
        line: block.start_line,
        end_line: block.end_line > block.start_line ? block.end_line : undefined,
        fix: 'Remove the unreachable block or fix the control flow that precedes it',
      });
    }

    return { deadBlocks };
  }
}
