/**
 * ExceptionFlowGraph — lightweight wrapper over CFG exception edges.
 *
 * The CFG builder emits edges with `type === 'exception'` connecting the
 * first block of a try body (`from`) to the first block of the corresponding
 * catch handler (`to`).  This class indexes those edges so exception-aware
 * passes can query try/catch structure without re-scanning the edge list.
 */

import type { CFG, CFGBlock } from '../types/index.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TryCatchInfo {
  tryEntryId: number;
  catchEntryId: number;
  /** First block of the try body. */
  tryBlock: CFGBlock;
  /** First block of the catch handler. */
  catchBlock: CFGBlock;
}

// ---------------------------------------------------------------------------
// ExceptionFlowGraph
// ---------------------------------------------------------------------------

export class ExceptionFlowGraph {
  /** All try/catch pairs found in the CFG. */
  readonly pairs: TryCatchInfo[];

  /** Block IDs that are catch-handler entry blocks. */
  readonly catchEntryIds: Set<number>;

  /** Block IDs that are try-body entry blocks. */
  readonly tryEntryIds: Set<number>;

  private readonly tryCatchMap: Map<number, number[]>; // tryEntryId → [catchEntryId, …]
  private readonly catchTryMap: Map<number, number>;   // catchEntryId → tryEntryId

  constructor(cfg: CFG, blockById: Map<number, CFGBlock>) {
    this.pairs = [];
    this.catchEntryIds = new Set();
    this.tryEntryIds = new Set();
    this.tryCatchMap = new Map();
    this.catchTryMap = new Map();

    for (const edge of cfg.edges) {
      if (edge.type !== 'exception') continue;

      const tryBlock = blockById.get(edge.from);
      const catchBlock = blockById.get(edge.to);
      if (!tryBlock || !catchBlock) continue;

      this.tryEntryIds.add(edge.from);
      this.catchEntryIds.add(edge.to);

      const catches = this.tryCatchMap.get(edge.from) ?? [];
      catches.push(edge.to);
      this.tryCatchMap.set(edge.from, catches);

      this.catchTryMap.set(edge.to, edge.from);

      this.pairs.push({
        tryEntryId: edge.from,
        catchEntryId: edge.to,
        tryBlock,
        catchBlock,
      });
    }
  }

  /** True if at least one try/catch pair was found. */
  get hasTryCatch(): boolean {
    return this.pairs.length > 0;
  }

  /** True if the given block ID is a catch-handler entry block. */
  isCatchEntry(blockId: number): boolean {
    return this.catchEntryIds.has(blockId);
  }

  /** True if the given block ID is a try-body entry block. */
  isTryEntry(blockId: number): boolean {
    return this.tryEntryIds.has(blockId);
  }

  /**
   * Returns the catch-entry block IDs for the given try-entry block.
   * Multiple values mean multiple catch clauses for the same try.
   */
  catchBlocksFor(tryEntryId: number): number[] {
    return this.tryCatchMap.get(tryEntryId) ?? [];
  }

  /**
   * Returns the try-entry block ID corresponding to a catch-entry block,
   * or `undefined` if the block is not a catch entry.
   */
  tryBlockFor(catchEntryId: number): number | undefined {
    return this.catchTryMap.get(catchEntryId);
  }
}
