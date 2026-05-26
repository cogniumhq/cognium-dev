/**
 * Tests for DominatorGraph — Cooper et al. dominator-tree algorithm.
 */

import { describe, it, expect } from 'vitest';
import { DominatorGraph } from '../../src/graph/dominator-graph.js';
import type { CFG } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCFG(
  blocks: Array<{ id: number; type?: string }>,
  edges: Array<{ from: number; to: number; type?: string }>,
): CFG {
  return {
    blocks: blocks.map(b => ({
      id: b.id,
      type: (b.type ?? 'normal') as CFG['blocks'][0]['type'],
      start_line: b.id * 10,
      end_line: b.id * 10 + 5,
    })),
    edges: edges.map(e => ({
      from: e.from,
      to: e.to,
      type: (e.type ?? 'sequential') as CFG['edges'][0]['type'],
    })),
  };
}

// ---------------------------------------------------------------------------
// Test 1: Linear chain  entry → A → B → exit
//   entry (0) dom all
//   A (1) dom B, exit
//   B (2) dom exit
// ---------------------------------------------------------------------------

describe('DominatorGraph - linear chain', () => {
  // 0 → 1 → 2 → 3
  const cfg = makeCFG(
    [{ id: 0, type: 'entry' }, { id: 1 }, { id: 2 }, { id: 3, type: 'exit' }],
    [{ from: 0, to: 1 }, { from: 1, to: 2 }, { from: 2, to: 3 }],
  );
  const dom = new DominatorGraph(cfg);

  it('entry dominates all blocks', () => {
    expect(dom.dominates(0, 0)).toBe(true);
    expect(dom.dominates(0, 1)).toBe(true);
    expect(dom.dominates(0, 2)).toBe(true);
    expect(dom.dominates(0, 3)).toBe(true);
  });

  it('A strictly dominates B and exit', () => {
    expect(dom.strictlyDominates(1, 2)).toBe(true);
    expect(dom.strictlyDominates(1, 3)).toBe(true);
  });

  it('B strictly dominates exit but not A', () => {
    expect(dom.strictlyDominates(2, 3)).toBe(true);
    expect(dom.strictlyDominates(2, 1)).toBe(false);
  });

  it('immediateDominator chain is correct', () => {
    expect(dom.immediateDominator(0)).toBeNull(); // entry
    expect(dom.immediateDominator(1)).toBe(0);
    expect(dom.immediateDominator(2)).toBe(1);
    expect(dom.immediateDominator(3)).toBe(2);
  });

  it('dominated returns strictly dominated set', () => {
    const d0 = dom.dominated(0);
    expect(d0).toContain(1);
    expect(d0).toContain(2);
    expect(d0).toContain(3);

    const d1 = dom.dominated(1);
    expect(d1).toContain(2);
    expect(d1).toContain(3);
    expect(d1).not.toContain(0);
  });
});

// ---------------------------------------------------------------------------
// Test 2: Diamond  entry → {A, B} → C → exit
//   entry dom all
//   A and B dom each other NOT (they're siblings)
//   C is NOT dom'd by A or B (only by entry)
// ---------------------------------------------------------------------------

describe('DominatorGraph - diamond', () => {
  //      0 (entry)
  //     / \
  //    1   2
  //     \ /
  //      3
  //      |
  //      4 (exit)
  const cfg = makeCFG(
    [{ id: 0, type: 'entry' }, { id: 1 }, { id: 2 }, { id: 3 }, { id: 4, type: 'exit' }],
    [
      { from: 0, to: 1, type: 'true' },
      { from: 0, to: 2, type: 'false' },
      { from: 1, to: 3 },
      { from: 2, to: 3 },
      { from: 3, to: 4 },
    ],
  );
  const dom = new DominatorGraph(cfg);

  it('entry dominates all', () => {
    for (const id of [0, 1, 2, 3, 4]) {
      expect(dom.dominates(0, id)).toBe(true);
    }
  });

  it('A does not strictly dominate C (join node) or B', () => {
    expect(dom.strictlyDominates(1, 3)).toBe(false);
    expect(dom.strictlyDominates(1, 2)).toBe(false);
  });

  it('B does not strictly dominate C or A', () => {
    expect(dom.strictlyDominates(2, 3)).toBe(false);
    expect(dom.strictlyDominates(2, 1)).toBe(false);
  });

  it('C is immediately dominated by entry', () => {
    expect(dom.immediateDominator(3)).toBe(0);
  });

  it('exit is immediately dominated by C', () => {
    expect(dom.immediateDominator(4)).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Test 3: Loop  entry → header → body → header (back-edge), header → exit
// ---------------------------------------------------------------------------

describe('DominatorGraph - loop with back-edge', () => {
  //  0 (entry) → 1 (header) ↔ 2 (body, back-edge 2→1)
  //                 1 → 3 (exit)
  const cfg = makeCFG(
    [{ id: 0, type: 'entry' }, { id: 1, type: 'loop' }, { id: 2 }, { id: 3, type: 'exit' }],
    [
      { from: 0, to: 1 },
      { from: 1, to: 2, type: 'true' },
      { from: 2, to: 1, type: 'back' },
      { from: 1, to: 3, type: 'false' },
    ],
  );
  const dom = new DominatorGraph(cfg);

  it('entry dominates all', () => {
    expect(dom.dominates(0, 1)).toBe(true);
    expect(dom.dominates(0, 2)).toBe(true);
    expect(dom.dominates(0, 3)).toBe(true);
  });

  it('header strictly dominates body and exit', () => {
    expect(dom.strictlyDominates(1, 2)).toBe(true);
    expect(dom.strictlyDominates(1, 3)).toBe(true);
  });

  it('body does NOT strictly dominate header (body is dominated by header)', () => {
    expect(dom.strictlyDominates(2, 1)).toBe(false);
  });

  it('immediateDominator of body is header', () => {
    expect(dom.immediateDominator(2)).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Test 4: Empty CFG — no crash
// ---------------------------------------------------------------------------

describe('DominatorGraph - empty CFG', () => {
  it('does not throw on empty CFG', () => {
    const cfg: CFG = { blocks: [], edges: [] };
    expect(() => new DominatorGraph(cfg)).not.toThrow();
  });

  it('returns null idom for any block on empty CFG', () => {
    const dom = new DominatorGraph({ blocks: [], edges: [] });
    expect(dom.immediateDominator(0)).toBeNull();
    expect(dom.dominated(0)).toHaveLength(0);
  });

  it('dominates is reflexive even on empty CFG', () => {
    const dom = new DominatorGraph({ blocks: [], edges: [] });
    expect(dom.dominates(5, 5)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Test 5: Single block
// ---------------------------------------------------------------------------

describe('DominatorGraph - single block', () => {
  const cfg = makeCFG([{ id: 0, type: 'entry' }], []);
  const dom = new DominatorGraph(cfg);

  it('single block dominates itself', () => {
    expect(dom.dominates(0, 0)).toBe(true);
  });

  it('strictly dominates is false for same block', () => {
    expect(dom.strictlyDominates(0, 0)).toBe(false);
  });

  it('immediateDominator is null for entry', () => {
    expect(dom.immediateDominator(0)).toBeNull();
  });
});
