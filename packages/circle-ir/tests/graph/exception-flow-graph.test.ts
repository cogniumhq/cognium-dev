/**
 * Tests for ExceptionFlowGraph.
 */

import { describe, it, expect } from 'vitest';
import { ExceptionFlowGraph } from '../../src/graph/exception-flow-graph.js';
import type { CFG, CFGBlock } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeBlock(id: number, startLine: number, endLine: number): CFGBlock {
  return { id, type: 'normal', start_line: startLine, end_line: endLine };
}

function makeCFG(
  blocks: CFGBlock[],
  edges: Array<{ from: number; to: number; type: CFG['edges'][0]['type'] }>,
): { cfg: CFG; blockById: Map<number, CFGBlock> } {
  const blockById = new Map<number, CFGBlock>(blocks.map(b => [b.id, b]));
  return { cfg: { blocks, edges }, blockById };
}

// ---------------------------------------------------------------------------
// Test 1: Empty CFG
// ---------------------------------------------------------------------------

describe('ExceptionFlowGraph - empty CFG', () => {
  const { cfg, blockById } = makeCFG([], []);
  const g = new ExceptionFlowGraph(cfg, blockById);

  it('has no try/catch pairs', () => {
    expect(g.hasTryCatch).toBe(false);
    expect(g.pairs).toHaveLength(0);
  });

  it('reports empty entry-id sets', () => {
    expect(g.catchEntryIds.size).toBe(0);
    expect(g.tryEntryIds.size).toBe(0);
  });

  it('isCatchEntry returns false for any id', () => {
    expect(g.isCatchEntry(0)).toBe(false);
  });

  it('catchBlocksFor returns empty array', () => {
    expect(g.catchBlocksFor(0)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Test 2: Single try/catch
//   Block 0 (try body) -[exception]-> Block 1 (catch handler)
// ---------------------------------------------------------------------------

describe('ExceptionFlowGraph - single try/catch', () => {
  const tryBlock = makeBlock(0, 1, 3);
  const catchBlock = makeBlock(1, 4, 6);
  const { cfg, blockById } = makeCFG(
    [tryBlock, catchBlock],
    [{ from: 0, to: 1, type: 'exception' }],
  );
  const g = new ExceptionFlowGraph(cfg, blockById);

  it('finds one pair', () => {
    expect(g.hasTryCatch).toBe(true);
    expect(g.pairs).toHaveLength(1);
  });

  it('pair has correct tryBlock and catchBlock', () => {
    const pair = g.pairs[0];
    expect(pair.tryEntryId).toBe(0);
    expect(pair.catchEntryId).toBe(1);
    expect(pair.tryBlock.start_line).toBe(1);
    expect(pair.catchBlock.start_line).toBe(4);
  });

  it('isCatchEntry and isTryEntry are correct', () => {
    expect(g.isCatchEntry(1)).toBe(true);
    expect(g.isCatchEntry(0)).toBe(false);
    expect(g.isTryEntry(0)).toBe(true);
    expect(g.isTryEntry(1)).toBe(false);
  });

  it('catchBlocksFor returns the catch entry id', () => {
    expect(g.catchBlocksFor(0)).toEqual([1]);
    expect(g.catchBlocksFor(1)).toEqual([]);
  });

  it('tryBlockFor returns the try entry id', () => {
    expect(g.tryBlockFor(1)).toBe(0);
    expect(g.tryBlockFor(0)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Test 3: Two catch clauses for the same try
//   Block 0 (try) -[exception]-> Block 1 (catch 1)
//   Block 0 (try) -[exception]-> Block 2 (catch 2)
// ---------------------------------------------------------------------------

describe('ExceptionFlowGraph - two catch clauses', () => {
  const tryBlock = makeBlock(0, 1, 3);
  const catch1 = makeBlock(1, 4, 6);
  const catch2 = makeBlock(2, 7, 9);
  const { cfg, blockById } = makeCFG(
    [tryBlock, catch1, catch2],
    [
      { from: 0, to: 1, type: 'exception' },
      { from: 0, to: 2, type: 'exception' },
    ],
  );
  const g = new ExceptionFlowGraph(cfg, blockById);

  it('finds two pairs', () => {
    expect(g.pairs).toHaveLength(2);
  });

  it('both pairs share the same tryEntryId', () => {
    expect(g.pairs[0].tryEntryId).toBe(0);
    expect(g.pairs[1].tryEntryId).toBe(0);
  });

  it('catchBlocksFor returns both catch ids', () => {
    expect(g.catchBlocksFor(0)).toContain(1);
    expect(g.catchBlocksFor(0)).toContain(2);
    expect(g.catchBlocksFor(0)).toHaveLength(2);
  });

  it('both catch blocks are marked as catch entries', () => {
    expect(g.isCatchEntry(1)).toBe(true);
    expect(g.isCatchEntry(2)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Test 4: Nested try/catch
//   Outer: Block 0 (outer try) -[exception]-> Block 3 (outer catch)
//   Inner: Block 1 (inner try) -[exception]-> Block 2 (inner catch)
// ---------------------------------------------------------------------------

describe('ExceptionFlowGraph - nested try/catch', () => {
  const outerTry = makeBlock(0, 1, 10);
  const innerTry = makeBlock(1, 2, 5);
  const innerCatch = makeBlock(2, 6, 8);
  const outerCatch = makeBlock(3, 11, 13);
  const { cfg, blockById } = makeCFG(
    [outerTry, innerTry, innerCatch, outerCatch],
    [
      { from: 0, to: 3, type: 'exception' },
      { from: 1, to: 2, type: 'exception' },
    ],
  );
  const g = new ExceptionFlowGraph(cfg, blockById);

  it('finds two pairs', () => {
    expect(g.pairs).toHaveLength(2);
  });

  it('outer pair is correct', () => {
    const outer = g.pairs.find(p => p.tryEntryId === 0);
    expect(outer).toBeDefined();
    expect(outer!.catchEntryId).toBe(3);
  });

  it('inner pair is correct', () => {
    const inner = g.pairs.find(p => p.tryEntryId === 1);
    expect(inner).toBeDefined();
    expect(inner!.catchEntryId).toBe(2);
  });

  it('all four entry sets are correctly populated', () => {
    expect(g.isTryEntry(0)).toBe(true);
    expect(g.isTryEntry(1)).toBe(true);
    expect(g.isCatchEntry(2)).toBe(true);
    expect(g.isCatchEntry(3)).toBe(true);
  });
});
