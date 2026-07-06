/**
 * Tests for the DFG-walk sanitizer credit primitive.
 *
 * cognium-dev #238 — sanitize-then-sink chains never received sanitizer
 * credit because `checkSanitized` only checked sanitizers on the exact
 * hop line. The `walkBackwardDefs` primitive collects every line
 * reachable from a use's reaching def through the DFG chain graph
 * so callers can query sanitizers along the entire chain.
 *
 * These tests target the primitive directly. Higher-level integration
 * through `checkSanitized` / `propagateTaint` is exercised by the
 * pass-level tests in `taint-propagation-pass.test.ts`.
 */

import { describe, it, expect } from 'vitest';
import { walkBackwardDefs } from '../../../src/analysis/dfg-walk.js';
import type { DFGDef, DFGChain } from '../../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function def(id: number, variable: string, line: number): DFGDef {
  return { id, variable, line, kind: 'local' };
}

function chain(fromId: number, toId: number, via = 'v'): DFGChain {
  return { from_def: fromId, to_def: toId, via };
}

function indexDefs(defs: DFGDef[]): Map<number, DFGDef> {
  const map = new Map<number, DFGDef>();
  for (const d of defs) map.set(d.id, d);
  return map;
}

function indexChainsByTo(chains: DFGChain[]): Map<number, DFGChain[]> {
  const map = new Map<number, DFGChain[]>();
  for (const c of chains) {
    const arr = map.get(c.to_def) ?? [];
    arr.push(c);
    map.set(c.to_def, arr);
  }
  return map;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('walkBackwardDefs — single-hop sanitize-then-sink', () => {
  it('collects the sanitizer line on a one-hop chain (safe = escape(x); sink(safe))', () => {
    // Line 10: def#1  x       (source)
    // Line 11: def#2  safe    (sanitize call — sanitizer line 11)
    // Line 12: use    safe    (sink call — reaching def = #2)
    const defs = [def(1, 'x', 10), def(2, 'safe', 11)];
    const chains = [chain(1, 2, 'x')];
    const walk = walkBackwardDefs(2, indexChainsByTo(chains), indexDefs(defs));

    expect(walk.visited.has(2)).toBe(true);
    expect(walk.visited.has(1)).toBe(true);
    expect(walk.lines.has(11)).toBe(true);
    expect(walk.lines.has(10)).toBe(true);
    expect(walk.hopCapReached).toBe(false);
  });
});

describe('walkBackwardDefs — multi-hop', () => {
  it('collects every line on a two-hop chain (safe = escape(x); y = safe; sink(y))', () => {
    const defs = [def(1, 'x', 5), def(2, 'safe', 6), def(3, 'y', 7)];
    const chains = [chain(1, 2, 'x'), chain(2, 3, 'safe')];
    const walk = walkBackwardDefs(3, indexChainsByTo(chains), indexDefs(defs));

    expect(walk.visited.size).toBe(3);
    expect([...walk.lines].sort()).toEqual([5, 6, 7]);
    expect(walk.hopCapReached).toBe(false);
  });

  it('collects all lines on a longer chained normalize/toAbsolute pipeline', () => {
    // path (2) -> normalized (3) -> absolute (4) -> use at sink
    const defs = [
      def(10, 'path',       2),
      def(11, 'normalized', 3),
      def(12, 'absolute',   4),
    ];
    const chains = [chain(10, 11), chain(11, 12)];
    const walk = walkBackwardDefs(12, indexChainsByTo(chains), indexDefs(defs));

    expect([...walk.lines].sort()).toEqual([2, 3, 4]);
    expect(walk.visited.size).toBe(3);
  });
});

describe('walkBackwardDefs — cycles', () => {
  it('does not loop on a back-edge (loop-carried def)', () => {
    // #1 line 10 — outer def
    // #2 line 12 — loop-carried def, reached from #1 and from #2 (self back-edge via join)
    const defs = [def(1, 'x', 10), def(2, 'x', 12)];
    const chains = [chain(1, 2), chain(2, 2)]; // self-cycle
    const walk = walkBackwardDefs(2, indexChainsByTo(chains), indexDefs(defs));

    expect(walk.visited.size).toBe(2);
    expect([...walk.lines].sort()).toEqual([10, 12]);
    expect(walk.hopCapReached).toBe(false);
  });

  it('terminates on a two-node cycle', () => {
    // #1 <-> #2, walk from #2
    const defs = [def(1, 'x', 3), def(2, 'y', 4)];
    const chains = [chain(1, 2), chain(2, 1)];
    const walk = walkBackwardDefs(2, indexChainsByTo(chains), indexDefs(defs));

    expect(walk.visited.size).toBe(2);
    expect([...walk.lines].sort()).toEqual([3, 4]);
  });
});

describe('walkBackwardDefs — hop cap', () => {
  it('reports hopCapReached when the chain exceeds maxHops', () => {
    // Build a long linear chain: def#1 -> def#2 -> ... -> def#50
    const defs: DFGDef[] = [];
    const chains: DFGChain[] = [];
    for (let i = 1; i <= 50; i++) {
      defs.push(def(i, `v${i}`, i));
    }
    for (let i = 1; i < 50; i++) {
      chains.push(chain(i, i + 1));
    }

    const walk = walkBackwardDefs(
      50,
      indexChainsByTo(chains),
      indexDefs(defs),
      { maxHops: 8 },
    );

    // Walk should terminate early with cap flag set. Number of visited
    // defs is bounded by maxHops + 1 (start def).
    expect(walk.hopCapReached).toBe(true);
    expect(walk.visited.size).toBeLessThanOrEqual(9);
  });

  it('does not flag hopCapReached when the walk completes under the cap', () => {
    const defs = [def(1, 'a', 1), def(2, 'b', 2), def(3, 'c', 3)];
    const chains = [chain(1, 2), chain(2, 3)];
    const walk = walkBackwardDefs(
      3,
      indexChainsByTo(chains),
      indexDefs(defs),
      { maxHops: 32 },
    );
    expect(walk.hopCapReached).toBe(false);
    expect(walk.visited.size).toBe(3);
  });
});

describe('walkBackwardDefs — edge cases', () => {
  it('returns just the start def when there are no incoming chains', () => {
    const defs = [def(42, 'orphan', 99)];
    const walk = walkBackwardDefs(42, new Map(), indexDefs(defs));

    expect(walk.visited.size).toBe(1);
    expect(walk.visited.has(42)).toBe(true);
    expect([...walk.lines]).toEqual([99]);
    expect(walk.hopCapReached).toBe(false);
  });

  it('returns an empty result when startDefId is unknown', () => {
    const walk = walkBackwardDefs(999, new Map(), new Map());
    expect(walk.visited.size).toBe(0);
    expect(walk.lines.size).toBe(0);
    expect(walk.hopCapReached).toBe(false);
  });

  it('does not revisit defs reachable through multiple paths (diamond)', () => {
    //     1
    //    / \
    //   2   3
    //    \ /
    //     4
    const defs = [def(1, 'src', 1), def(2, 'a', 2), def(3, 'b', 3), def(4, 'sink', 4)];
    const chains = [chain(1, 2), chain(1, 3), chain(2, 4), chain(3, 4)];
    const walk = walkBackwardDefs(4, indexChainsByTo(chains), indexDefs(defs));

    expect(walk.visited.size).toBe(4);
    expect([...walk.lines].sort()).toEqual([1, 2, 3, 4]);
    expect(walk.hopCapReached).toBe(false);
  });
});
