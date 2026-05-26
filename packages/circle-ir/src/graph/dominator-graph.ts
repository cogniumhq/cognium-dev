/**
 * DominatorGraph
 *
 * Computes the dominator tree for a control-flow graph using the
 * Cooper et al. "A Simple, Fast Dominance Algorithm" (2001).
 *
 * Chosen over Lengauer-Tarjan because typical intra-procedural CFGs have
 * fewer than 100 blocks — O(n²) worst-case is negligible and the algorithm
 * is straightforward to verify correct.
 *
 * Reference:
 *   Cooper, K.D., Harvey, T.J., Kennedy, K. (2001). "A Simple, Fast Dominance
 *   Algorithm". Software Practice & Experience, 4, 1–10.
 *
 * Design invariants:
 * - No Node.js-specific APIs. Browser + Node.js + Cloudflare Workers safe.
 * - Does not mutate the input CFG.
 * - Unreachable blocks are excluded from all dominator queries.
 */

import type { CFG } from '../types/index.js';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Compute Reverse Post-Order starting from `entryId`.
 * Returns the RPO traversal order and a map from blockId → RPO position.
 * Blocks unreachable from `entryId` are excluded.
 */
function computeRPO(
  cfg: CFG,
  entryId: number,
): { rpoOrder: number[]; rpoIndex: Map<number, number> } {
  // Build outgoing adjacency
  const outgoing = new Map<number, number[]>();
  for (const edge of cfg.edges) {
    const list = outgoing.get(edge.from) ?? [];
    list.push(edge.to);
    outgoing.set(edge.from, list);
  }

  // Iterative DFS to compute post-order, then reverse
  const visited = new Set<number>();
  const postOrder: number[] = [];
  const stack: Array<{ id: number; childIndex: number }> = [{ id: entryId, childIndex: 0 }];
  visited.add(entryId);

  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    const children = outgoing.get(top.id) ?? [];

    // Find next unvisited child
    let pushed = false;
    while (top.childIndex < children.length) {
      const child = children[top.childIndex++];
      if (!visited.has(child)) {
        visited.add(child);
        stack.push({ id: child, childIndex: 0 });
        pushed = true;
        break;
      }
    }

    if (!pushed) {
      // All children visited — add to post-order
      postOrder.push(top.id);
      stack.pop();
    }
  }

  const rpoOrder = postOrder.reverse();
  const rpoIndex = new Map<number, number>();
  for (let i = 0; i < rpoOrder.length; i++) {
    rpoIndex.set(rpoOrder[i], i);
  }

  return { rpoOrder, rpoIndex };
}

/**
 * Cooper et al. intersect function.
 * Walks up the idom tree from b1 and b2 until a common ancestor is found.
 * Uses RPO positions for comparisons (smaller RPO index = earlier in RPO = closer to entry).
 *
 * IMPORTANT: The entry block must have idom[entry] = entry (self-loop sentinel)
 * so the walk terminates. This sentinel is removed from the public idom map after
 * computation, but must be present during computation.
 */
function intersect(
  b1: number,
  b2: number,
  idom: Map<number, number>,
  rpoIndex: Map<number, number>,
): number {
  let finger1 = b1;
  let finger2 = b2;

  while (finger1 !== finger2) {
    // Walk finger1 up while its RPO position is deeper (larger index) than finger2
    while ((rpoIndex.get(finger1) ?? Number.MAX_SAFE_INTEGER) >
           (rpoIndex.get(finger2) ?? Number.MAX_SAFE_INTEGER)) {
      const parent = idom.get(finger1);
      if (parent === undefined || parent === finger1) break; // at root or self-loop
      finger1 = parent;
    }

    // Walk finger2 up while its RPO position is deeper than finger1
    while ((rpoIndex.get(finger2) ?? Number.MAX_SAFE_INTEGER) >
           (rpoIndex.get(finger1) ?? Number.MAX_SAFE_INTEGER)) {
      const parent = idom.get(finger2);
      if (parent === undefined || parent === finger2) break; // at root or self-loop
      finger2 = parent;
    }

    // If neither changed (both at root or unreachable), break
    if (finger1 === finger2) break;
    // Safety: if both are at positions we can't walk further, break
    const rpo1 = rpoIndex.get(finger1) ?? Number.MAX_SAFE_INTEGER;
    const rpo2 = rpoIndex.get(finger2) ?? Number.MAX_SAFE_INTEGER;
    if (rpo1 === rpo2 && finger1 !== finger2) break; // can't converge further
  }

  return finger1;
}

/**
 * Cooper et al. iterative idom computation.
 * Requires rpoOrder and rpoIndex from computeRPO.
 * Returns a map: blockId → immediate dominator blockId.
 * Entry block has idom[entry] = entry (sentinel) during computation;
 * callers remove this after the function returns.
 */
function computeIdom(
  cfg: CFG,
  rpoOrder: number[],
  rpoIndex: Map<number, number>,
  entryId: number,
): Map<number, number> {
  // Build incoming adjacency
  const incoming = new Map<number, number[]>();
  for (const edge of cfg.edges) {
    const list = incoming.get(edge.to) ?? [];
    list.push(edge.from);
    incoming.set(edge.to, list);
  }

  const idom = new Map<number, number>();

  // Initialise: entry block idom = itself (sentinel for termination)
  idom.set(entryId, entryId);

  // Iterate until stable
  let changed = true;
  const numBlocks = rpoOrder.length;
  while (changed) {
    changed = false;

    // Process in RPO order, skip entry (index 0)
    for (let i = 1; i < numBlocks; i++) {
      const b = rpoOrder[i];
      const preds = incoming.get(b) ?? [];

      // Pick the first predecessor that already has an idom computed
      // (i.e., already processed in RPO order)
      let newIdom: number | undefined;
      for (const p of preds) {
        if (idom.has(p)) {
          newIdom = p;
          break;
        }
      }
      if (newIdom === undefined) continue;

      // Intersect with all other processed predecessors
      for (const p of preds) {
        if (p === newIdom) continue;
        if (idom.has(p)) {
          newIdom = intersect(p, newIdom, idom, rpoIndex);
        }
      }

      if (idom.get(b) !== newIdom) {
        idom.set(b, newIdom);
        changed = true;
      }
    }
  }

  return idom;
}

// ---------------------------------------------------------------------------
// Public class
// ---------------------------------------------------------------------------

/**
 * Dominator tree for a CFG, computed with the Cooper et al. algorithm.
 *
 * Entry blocks have no immediate dominator (immediateDominator returns null).
 * Only blocks reachable from the entry are included.
 */
export class DominatorGraph {
  private readonly idom: Map<number, number>;
  private readonly rpoIndex: Map<number, number>;
  private readonly entryId: number;
  /** Cached reverse map: blockId → all blockIds it strictly dominates. */
  private _dominated: Map<number, number[]> | null = null;

  constructor(cfg: CFG, entryId?: number) {
    if (cfg.blocks.length === 0) {
      this.entryId = entryId ?? 0;
      this.idom = new Map();
      this.rpoIndex = new Map();
      return;
    }

    // Determine entry: prefer provided entryId, then type='entry' block,
    // then the block with the smallest id.
    this.entryId =
      entryId ??
      cfg.blocks.find(b => b.type === 'entry')?.id ??
      cfg.blocks.reduce((a, b) => (a.id < b.id ? a : b)).id;

    const { rpoOrder, rpoIndex } = computeRPO(cfg, this.entryId);
    this.rpoIndex = rpoIndex;
    this.idom = computeIdom(cfg, rpoOrder, rpoIndex, this.entryId);

    // Remove the sentinel self-reference for the entry block
    // so immediateDominator(entryId) returns null
    this.idom.delete(this.entryId);
  }

  /**
   * Returns true if block `a` dominates block `b`.
   * A block dominates itself (reflexive).
   */
  dominates(a: number, b: number): boolean {
    if (a === b) return true;
    return this.strictlyDominates(a, b);
  }

  /**
   * Returns true if block `a` strictly dominates block `b` (a ≠ b and a dom b).
   */
  strictlyDominates(a: number, b: number): boolean {
    if (a === b) return false;
    // Walk up the idom chain from b; if we reach a, then a dom b.
    const visited = new Set<number>();
    let cur: number | undefined = this.idom.get(b);
    while (cur !== undefined && !visited.has(cur)) {
      if (cur === a) return true;
      visited.add(cur);
      cur = this.idom.get(cur);
    }
    return false;
  }

  /**
   * Returns the immediate dominator of `blockId`, or null for the entry block
   * (or any block not in the dominator tree).
   */
  immediateDominator(blockId: number): number | null {
    return this.idom.get(blockId) ?? null;
  }

  /**
   * Returns all block IDs strictly dominated by `blockId`.
   * (Computed lazily and cached on first call.)
   */
  dominated(blockId: number): number[] {
    if (!this._dominated) {
      this._dominated = new Map();
      for (const [child, parent] of this.idom.entries()) {
        // Walk up from child to find all ancestors (blocks that dominate child)
        const ancestors: number[] = [];
        const seen = new Set<number>();
        let cur: number | undefined = parent;
        while (cur !== undefined && !seen.has(cur)) {
          seen.add(cur);
          ancestors.push(cur);
          cur = this.idom.get(cur);
        }
        for (const anc of ancestors) {
          const list = this._dominated.get(anc) ?? [];
          list.push(child);
          this._dominated.set(anc, list);
        }
      }
    }
    return this._dominated.get(blockId) ?? [];
  }
}
