/**
 * `node` ids for `ids@0.1`: a body id plus a local index.
 *
 * Today's CFG blocks, DFG defs and uses and call sites carry sequential ids
 * per file, so an edit anywhere shifts every id after it. Here each IR node
 * is assigned to the innermost declaration whose span encloses it, and its
 * index counts only the nodes of the same array inside that same body. An
 * edit to one function therefore leaves every other function's node ids
 * unchanged, and the index is safe because a body id names one body version.
 */

import type { CFG, CallInfo, DFG } from '../types/index.js';
import type { StableDecl, StableIdFile, StableNodeIds } from './types.js';

/** The parts of a `CircleIR` that node ids key. */
export interface NodeIdSource {
  cfg?: Pick<CFG, 'blocks'>;
  dfg?: Pick<DFG, 'defs' | 'uses'>;
  calls?: readonly CallInfo[];
}

interface Span {
  decl: StableDecl;
  size: number;
}

/** Position compare on (line, column); `column` absent means the whole line. */
function encloses(d: StableDecl, line: number, column: number | undefined): boolean {
  if (line < d.start_line || line > d.end_line) return false;
  if (column === undefined) return true;
  if (line === d.start_line && column < d.start_column) return false;
  if (line === d.end_line && column >= d.end_column) return false;
  return true;
}

/** Ranks spans so the innermost declaration wins; on a tie, the later one in source order. */
function spanSize(d: StableDecl): number {
  return (d.end_line - d.start_line) * 1_000_000 + (d.end_column - d.start_column);
}

class Locator {
  private readonly spans: Span[];

  constructor(file: StableIdFile) {
    this.spans = file.decls
      .filter(d => d.body_hash !== '')
      .map(decl => ({ decl, size: spanSize(decl) }));
  }

  /** Innermost declaration enclosing the position. */
  at(line: number, column?: number): StableDecl | null {
    let best: Span | null = null;
    for (const s of this.spans) {
      if (!encloses(s.decl, line, column)) continue;
      if (best === null || s.size <= best.size) best = s;
    }
    return best?.decl ?? null;
  }

  /** Innermost declaration enclosing a whole line range. */
  range(start: number, end: number): StableDecl | null {
    let best: Span | null = null;
    for (const s of this.spans) {
      if (start < s.decl.start_line || end > s.decl.end_line) continue;
      if (best === null || s.size <= best.size) best = s;
    }
    return best?.decl ?? null;
  }
}

/**
 * The innermost declaration (with a body) enclosing a 1-based line and a
 * 0-based column, or `null`.
 */
export function declLocator(file: StableIdFile): (line: number, column?: number) => StableDecl | null {
  const loc = new Locator(file);
  return (line, column) => loc.at(line, column);
}

function keyAll<T>(items: readonly T[], tag: string, find: (item: T) => StableDecl | null): (string | null)[] {
  const counters = new Map<string, number>();
  return items.map(item => {
    const decl = find(item);
    if (!decl) return null;
    const n = counters.get(decl.body_id) ?? 0;
    counters.set(decl.body_id, n + 1);
    return `${decl.body_id}/${tag}${n}`;
  });
}

/**
 * Node ids parallel to the IR arrays: `<body_id>/b<n>` for CFG blocks,
 * `/d<n>` and `/u<n>` for DFG defs and uses, `/c<n>` for call sites, where
 * `n` counts that kind inside that body in array order. Positions are
 * matched by line and, where the IR carries one, column; a CFG block goes to
 * the innermost declaration that encloses all of its lines.
 */
export function assignNodeIds(file: StableIdFile, ir: NodeIdSource): StableNodeIds {
  const loc = new Locator(file);
  return {
    cfg_blocks: keyAll(ir.cfg?.blocks ?? [], 'b', b => loc.range(b.start_line, b.end_line)),
    dfg_defs: keyAll(ir.dfg?.defs ?? [], 'd', d => loc.at(d.line, d.column)),
    dfg_uses: keyAll(ir.dfg?.uses ?? [], 'u', u => loc.at(u.line, u.column)),
    calls: keyAll(ir.calls ?? [], 'c', c => loc.at(c.location.line, c.location.column)),
  };
}
