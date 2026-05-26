/**
 * CodeGraph
 *
 * Wraps a CircleIR and provides lazily-computed indexes over its graph data.
 * Built once per file analysis. All analysis passes consume it — none
 * rebuild their own lookup maps.
 *
 * Design invariants:
 * - `ir` is readonly; CodeGraph never mutates the underlying CircleIR.
 * - All indexes are computed once on first access (null-check lazy init).
 * - No platform-specific APIs: browser + Node.js + Cloudflare Workers safe.
 */

import type {
  CircleIR,
  CFGBlock,
  DFGDef,
  DFGUse,
  DFGChain,
  CallInfo,
  TypeInfo,
  TaintSanitizer,
} from '../types/index.js';
import type { MethodInfo } from '../types/index.js';

export class CodeGraph {
  readonly ir: CircleIR;

  constructor(ir: CircleIR) {
    this.ir = ir;
  }

  // ---------------------------------------------------------------------------
  // DFG indexes
  // ---------------------------------------------------------------------------

  private _defById: Map<number, DFGDef> | null = null;
  get defById(): Map<number, DFGDef> {
    if (!this._defById) {
      this._defById = new Map();
      for (const def of this.ir.dfg.defs) {
        this._defById.set(def.id, def);
      }
    }
    return this._defById;
  }

  private _defsByLine: Map<number, DFGDef[]> | null = null;
  get defsByLine(): Map<number, DFGDef[]> {
    if (!this._defsByLine) {
      this._defsByLine = new Map();
      for (const def of this.ir.dfg.defs) {
        const arr = this._defsByLine.get(def.line) ?? [];
        arr.push(def);
        this._defsByLine.set(def.line, arr);
      }
    }
    return this._defsByLine;
  }

  private _defsByVar: Map<string, DFGDef[]> | null = null;
  get defsByVar(): Map<string, DFGDef[]> {
    if (!this._defsByVar) {
      this._defsByVar = new Map();
      for (const def of this.ir.dfg.defs) {
        const arr = this._defsByVar.get(def.variable) ?? [];
        arr.push(def);
        this._defsByVar.set(def.variable, arr);
      }
    }
    return this._defsByVar;
  }

  private _usesByLine: Map<number, DFGUse[]> | null = null;
  get usesByLine(): Map<number, DFGUse[]> {
    if (!this._usesByLine) {
      this._usesByLine = new Map();
      for (const use of this.ir.dfg.uses) {
        const arr = this._usesByLine.get(use.line) ?? [];
        arr.push(use);
        this._usesByLine.set(use.line, arr);
      }
    }
    return this._usesByLine;
  }

  private _usesByDefId: Map<number, DFGUse[]> | null = null;
  get usesByDefId(): Map<number, DFGUse[]> {
    if (!this._usesByDefId) {
      this._usesByDefId = new Map();
      for (const use of this.ir.dfg.uses) {
        if (use.def_id !== null) {
          const arr = this._usesByDefId.get(use.def_id) ?? [];
          arr.push(use);
          this._usesByDefId.set(use.def_id, arr);
        }
      }
    }
    return this._usesByDefId;
  }

  private _chainsByFromDef: Map<number, DFGChain[]> | null = null;
  get chainsByFromDef(): Map<number, DFGChain[]> {
    if (!this._chainsByFromDef) {
      this._chainsByFromDef = new Map();
      for (const chain of this.ir.dfg.chains ?? []) {
        const arr = this._chainsByFromDef.get(chain.from_def) ?? [];
        arr.push(chain);
        this._chainsByFromDef.set(chain.from_def, arr);
      }
    }
    return this._chainsByFromDef;
  }

  // ---------------------------------------------------------------------------
  // Call indexes
  // ---------------------------------------------------------------------------

  private _callsByLine: Map<number, CallInfo[]> | null = null;
  get callsByLine(): Map<number, CallInfo[]> {
    if (!this._callsByLine) {
      this._callsByLine = new Map();
      for (const call of this.ir.calls) {
        const arr = this._callsByLine.get(call.location.line) ?? [];
        arr.push(call);
        this._callsByLine.set(call.location.line, arr);
      }
    }
    return this._callsByLine;
  }

  private _callsByMethod: Map<string, CallInfo[]> | null = null;
  get callsByMethod(): Map<string, CallInfo[]> {
    if (!this._callsByMethod) {
      this._callsByMethod = new Map();
      for (const call of this.ir.calls) {
        const arr = this._callsByMethod.get(call.method_name) ?? [];
        arr.push(call);
        this._callsByMethod.set(call.method_name, arr);
      }
    }
    return this._callsByMethod;
  }

  // ---------------------------------------------------------------------------
  // Type / method indexes
  // ---------------------------------------------------------------------------

  private _methodsByName: Map<string, Array<{ type: TypeInfo; method: MethodInfo }>> | null = null;
  get methodsByName(): Map<string, Array<{ type: TypeInfo; method: MethodInfo }>> {
    if (!this._methodsByName) {
      this._methodsByName = new Map();
      for (const type of this.ir.types) {
        for (const method of type.methods) {
          const arr = this._methodsByName.get(method.name) ?? [];
          arr.push({ type, method });
          this._methodsByName.set(method.name, arr);
        }
      }
    }
    return this._methodsByName;
  }

  /**
   * Returns the TypeInfo + MethodInfo whose line range contains `line`, or null.
   * Used by passes that need the enclosing method context for a given line.
   */
  methodAtLine(line: number): { type: TypeInfo; method: MethodInfo } | null {
    for (const type of this.ir.types) {
      for (const method of type.methods) {
        if (line >= method.start_line && line <= method.end_line) {
          return { type, method };
        }
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Taint indexes
  // ---------------------------------------------------------------------------

  private _sanitizersByLine: Map<number, TaintSanitizer[]> | null = null;
  get sanitizersByLine(): Map<number, TaintSanitizer[]> {
    if (!this._sanitizersByLine) {
      this._sanitizersByLine = new Map();
      for (const san of this.ir.taint.sanitizers ?? []) {
        const arr = this._sanitizersByLine.get(san.line) ?? [];
        arr.push(san);
        this._sanitizersByLine.set(san.line, arr);
      }
    }
    return this._sanitizersByLine;
  }

  // ---------------------------------------------------------------------------
  // Query primitives
  // ---------------------------------------------------------------------------

  /** All DFGDefs at a given line. Returns [] if none. */
  defsAtLine(line: number): DFGDef[] {
    return this.defsByLine.get(line) ?? [];
  }

  /** All DFGUses at a given line. Returns [] if none. */
  usesAtLine(line: number): DFGUse[] {
    return this.usesByLine.get(line) ?? [];
  }

  /** All DFGUses that reach a specific definition ID. Returns [] if none. */
  usesOfDef(defId: number): DFGUse[] {
    return this.usesByDefId.get(defId) ?? [];
  }

  /** All CallInfos at a given line. Returns [] if none. */
  callsAtLine(line: number): CallInfo[] {
    return this.callsByLine.get(line) ?? [];
  }

  /** DFGChains outgoing from a definition ID. Returns [] if none. */
  chainsFrom(defId: number): DFGChain[] {
    return this.chainsByFromDef.get(defId) ?? [];
  }

  /**
   * All definitions of `variable` that appear strictly after `afterLine`
   * and at or before `upToLine`. Used to detect whether a variable is
   * redefined between a taint source and a sink.
   */
  laterDefsOfVar(variable: string, afterLine: number, upToLine: number): DFGDef[] {
    return (this.defsByVar.get(variable) ?? []).filter(
      d => d.line > afterLine && d.line <= upToLine,
    );
  }

  // ---------------------------------------------------------------------------
  // CFG indexes
  // ---------------------------------------------------------------------------

  private _blockById: Map<number, CFGBlock> | null = null;
  get blockById(): Map<number, CFGBlock> {
    if (!this._blockById) {
      this._blockById = new Map();
      for (const block of this.ir.cfg.blocks) {
        this._blockById.set(block.id, block);
      }
    }
    return this._blockById;
  }

  /**
   * Returns the line range of each detected loop body in the file.
   *
   * A loop is identified by CFG back-edges (type = "back"). For each back edge
   * `A → B`, B is the loop header and A is the last block before the back-jump.
   * The loop body spans from `header.start_line` to `A.end_line` (inclusive).
   *
   * Returns `{ start_line, end_line }` — one entry per back-edge.
   * Overlapping ranges are returned separately; callers can merge as needed.
   *
   * Usage: check whether line L is inside any loop with
   *   `graph.loopBodies().some(r => L >= r.start_line && L <= r.end_line)`
   */
  loopBodies(): Array<{ start_line: number; end_line: number }> {
    const loops: Array<{ start_line: number; end_line: number }> = [];
    for (const edge of this.ir.cfg.edges) {
      if (edge.type !== 'back') continue;
      const header = this.blockById.get(edge.to);
      const tail   = this.blockById.get(edge.from);
      if (header && tail) {
        loops.push({ start_line: header.start_line, end_line: tail.end_line });
      }
    }
    return loops;
  }

  /**
   * Propagate a set of tainted definition IDs through DFGChains to a fixpoint.
   *
   * Returns a new Set (does not mutate the input). Each chain edge
   * `from_def → to_def` spreads taint: if `from_def` is tainted, `to_def`
   * becomes tainted. Iterates until no new IDs are added.
   */
  propagateTaintedDefIds(seed: Set<number>): Set<number> {
    const result = new Set<number>(seed);
    let changed = true;
    while (changed) {
      changed = false;
      for (const [fromDef, chains] of this.chainsByFromDef) {
        if (!result.has(fromDef)) continue;
        for (const chain of chains) {
          if (!result.has(chain.to_def)) {
            result.add(chain.to_def);
            changed = true;
          }
        }
      }
    }
    return result;
  }
}
