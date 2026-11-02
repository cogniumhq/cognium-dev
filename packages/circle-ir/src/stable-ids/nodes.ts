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
import { blake3Short128Into, digest128Bytes } from './hash.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableIdFile, type StableNodeIds } from './types.js';

/** The IR arrays node ids key, with the one-letter tag the printed form uses. */
export type StableNodeKind = 'block' | 'def' | 'use' | 'call';
const NODE_TAG: Record<StableNodeKind, string> = { block: 'b', def: 'd', use: 'u', call: 'c' };
const NODE_KIND_OF_TAG: Record<string, StableNodeKind> = { b: 'block', d: 'def', u: 'use', c: 'call' };

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
  /** Spans enclosing a line, by line, filled on first use: a file's nodes cluster on few lines, and a snapshot asks a million times. */
  private readonly byLine = new Map<number, Span[]>();

  constructor(file: StableIdFile) {
    this.spans = file.decls
      .filter(d => d.body_hash !== '')
      .map(decl => ({ decl, size: spanSize(decl) }));
  }

  private onLine(line: number): Span[] {
    let list = this.byLine.get(line);
    if (list === undefined) {
      list = this.spans.filter(s => line >= s.decl.start_line && line <= s.decl.end_line);
      this.byLine.set(line, list);
    }
    return list;
  }

  /** Innermost declaration enclosing the position. */
  at(line: number, column?: number): StableDecl | null {
    const candidates = this.onLine(line);
    let best: Span | null = null;
    for (let i = 0; i < candidates.length; i++) {
      const s = candidates[i];
      if (column !== undefined && !encloses(s.decl, line, column)) continue;
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

/** A node placed in a body: the enclosing declaration and its ordinal among that body's nodes of one kind. */
export interface LocatedNode {
  decl: StableDecl;
  ordinal: number;
}

/**
 * Places every item of one IR array (all of one node kind) in its innermost
 * enclosing body and numbers it there, in array order, per body — the local
 * index of an `ids@0.1` node id. `null` where no body encloses the item.
 */
export function locateNodes<T>(file: StableIdFile, items: readonly T[], find: (item: T, at: (line: number, column?: number) => StableDecl | null) => StableDecl | null): (LocatedNode | null)[] {
  const loc = new Locator(file);
  const at = (line: number, column?: number): StableDecl | null => loc.at(line, column);
  // Counted per declaration object; two declarations never share a body id in one file.
  const counters = new Map<StableDecl, number>();
  const out = new Array<LocatedNode | null>(items.length);
  for (let i = 0; i < items.length; i++) {
    const decl = find(items[i], at);
    if (!decl) { out[i] = null; continue; }
    const ordinal = counters.get(decl) ?? 0;
    counters.set(decl, ordinal + 1);
    out[i] = { decl, ordinal };
  }
  return out;
}

function keyAll<T>(file: StableIdFile, items: readonly T[], kind: StableNodeKind, find: (item: T, at: (line: number, column?: number) => StableDecl | null) => StableDecl | null): (string | null)[] {
  return locateNodes(file, items, find).map(n => (n === null ? null : printedNodeId(n.decl.body_id, kind, n.ordinal)));
}

/** The printed `ids@0.1` node id: `<body_id>/<tag><ordinal>`. */
export function printedNodeId(bodyId: string, kind: StableNodeKind, ordinal: number): string {
  return `${bodyId}/${NODE_TAG[kind]}${ordinal}`;
}

/**
 * The fixed-width form of an `ids@0.1` node id (stable-ids design decision
 * 1a, 2026-11-01): the 128-bit `digest128` over the parts
 * `ids@0.1 · node · <body_id> · <kind> · <ordinal>` — the scheme, the
 * literal `node`, the printed body id (`<decl id>.<body_hash>`), the kind
 * word (`block`, `def`, `use`, `call`) and the ordinal in decimal — each
 * followed by NUL, BLAKE3, first 16 bytes. The same width as every other id,
 * so a `facts@1` `fixed16` column can hold it; it is a function of the
 * printed node id and nothing else.
 */
export function nodeIdBytes(bodyId: string, kind: StableNodeKind, ordinal: number): Uint8Array {
  return digest128Bytes([STABLE_ID_SCHEME, 'node', bodyId, kind, String(ordinal)]);
}

/** `nodeIdBytes` of a printed node id (`<body_id>/<tag><ordinal>`). */
export function nodeIdBytesOfPrinted(printed: string): Uint8Array {
  const slash = printed.lastIndexOf('/');
  const kind = slash >= 0 ? NODE_KIND_OF_TAG[printed[slash + 1]] : undefined;
  const ordinal = slash >= 0 ? Number(printed.slice(slash + 2)) : NaN;
  if (kind === undefined || !Number.isInteger(ordinal) || ordinal < 0 || String(ordinal) !== printed.slice(slash + 2)) {
    throw new Error(`stable-ids: not a printed node id: ${JSON.stringify(printed)}`);
  }
  return nodeIdBytes(printed.slice(0, slash), kind, ordinal);
}

const encoder = new TextEncoder();

/**
 * `nodeIdBytes` for many nodes of one body and kind without re-encoding the
 * parts: the fixed prefix (`ids@0.1 NUL node NUL <body_id> NUL <kind> NUL`)
 * is encoded once, each ordinal's decimal digits and NUL are written after
 * it, and the 16 bytes land in `out` at `offset`. Equal to `nodeIdBytes`
 * byte for byte (tested).
 */
export class NodeIdWriter {
  private readonly buffer = new Uint8Array(256);
  private prefixLength = 0;
  private bodyId = '';
  private kind: StableNodeKind | '' = '';

  /** Select the body and kind the next `write` calls are for. */
  forBody(bodyId: string, kind: StableNodeKind): void {
    if (bodyId === this.bodyId && kind === this.kind) return;
    this.bodyId = bodyId;
    this.kind = kind;
    const prefix = `${STABLE_ID_SCHEME}\u0000node\u0000${bodyId}\u0000${kind}\u0000`;
    const { read, written } = encoder.encodeInto(prefix, this.buffer);
    // An ids@0.1 body id is 53 characters; the buffer leaves room for the ordinal after it.
    if (read !== prefix.length || written > this.buffer.length - 24) throw new RangeError(`stable-ids: body id too long for a node id: ${JSON.stringify(bodyId)}`);
    this.prefixLength = written;
  }

  write(ordinal: number, out: Uint8Array, offset: number): void {
    const b = this.buffer;
    let n = this.prefixLength;
    if (ordinal === 0) b[n++] = 0x30;
    else {
      const start = n;
      for (let v = ordinal; v > 0; v = Math.floor(v / 10)) b[n++] = 0x30 + (v % 10);
      for (let i = start, j = n - 1; i < j; i++, j--) { const t = b[i]; b[i] = b[j]; b[j] = t; }
    }
    b[n++] = 0;
    blake3Short128Into(b.subarray(0, n), out, offset);
  }
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
    cfg_blocks: keyAll(file, ir.cfg?.blocks ?? [], 'block', b => loc.range(b.start_line, b.end_line)),
    dfg_defs: keyAll(file, ir.dfg?.defs ?? [], 'def', (d, at) => at(d.line, d.column)),
    dfg_uses: keyAll(file, ir.dfg?.uses ?? [], 'use', (u, at) => at(u.line, u.column)),
    calls: keyAll(file, ir.calls ?? [], 'call', (c, at) => at(c.location.line, c.location.column)),
  };
}
