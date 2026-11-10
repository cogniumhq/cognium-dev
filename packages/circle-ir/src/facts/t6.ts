/**
 * Graph-store T6 on `facts@2`, walked by the producer: blast radius, reach
 * from declared entries and impacted tests, computed from the relations a
 * store loads (`decl`, `call`, `ref`, `entries`) and nothing else.
 *
 * The semantics are the consumer's rule program (`t6_facts2.dl`, the
 * graph-store plan's T6 record of 5 Nov 2026) one edge for one edge, so this
 * walk is the answer a store running that program must give, and the side
 * that is compared with circle-ir's own graph walk (`graph-facts/reach.ts`):
 *
 * - `call`: strong unless its tier is `inferred` (one row per candidate body);
 * - `ref`: weak;
 * - `contains`: `parent_id` -> the declaration, where `contained`;
 * - `loads`: the declaration -> `parent_id`, where `loads_parent`;
 * - `loads`: every non-module declaration -> its file's `module` declaration.
 *
 * Both ends must be declarations. `facts@2` does not carry the reach core's
 * `field` and declaration-level `import` edges, an entry's `constructors`, or
 * unresolved sites, so every answer is a lower bound where they could add a
 * path. A declaration is `strong` when an all-strong path reaches it and
 * `weak` when only paths through a weak edge (or from an `inferred` entry) do.
 *
 * Pure: rows in, maps out. Browser and Node compatible; only
 * {@link t6RowsFromArrow} needs the optional `apache-arrow`.
 */

import { base32 } from '../stable-ids/hash.js';
import { loadArrow, type Facts2Arrow } from './arrow.js';

export type T6Tier = 'strong' | 'weak';

/** The `facts@2` columns T6 reads; ids as 26-character base32 `ids@0.1` strings. */
export interface T6Rows {
  decl: readonly { id: string; kind: string; file: string; parentId: string | null; contained: boolean; loadsParent: boolean }[];
  call: readonly { callerId: string; calleeId: string; tier: string }[];
  ref: readonly { fromId: string; toId: string }[];
  entries: readonly { declId: string; kind: string; certainty: string }[];
}

/** Edge counts by kind, for a run's record. */
export interface T6EdgeCounts {
  callStrong: number;
  callWeak: number;
  ref: number;
  contains: number;
  loadsParent: number;
  loadsModule: number;
}

/** Adjacency over integer node ids: CSR arrays, one strong and one any-edge view each way. */
interface Csr {
  start: Int32Array;
  to: Int32Array;
}

function csr(n: number, from: readonly number[], to: readonly number[]): Csr {
  const start = new Int32Array(n + 1);
  for (const f of from) start[f + 1]++;
  for (let i = 0; i < n; i++) start[i + 1] += start[i];
  const fill = start.slice(0, n);
  const out = new Int32Array(from.length);
  for (let i = 0; i < from.length; i++) out[fill[from[i]]++] = to[i];
  return { start, to: out };
}

/** Nodes reachable from `frontier` over `g` (frontier included). */
function closure(g: Csr, frontier: readonly number[], n: number): Uint8Array {
  const seen = new Uint8Array(n);
  const queue = new Int32Array(n);
  let tail = 0;
  for (const s of frontier) if (!seen[s]) { seen[s] = 1; queue[tail++] = s; }
  for (let head = 0; head < tail; head++) {
    const v = queue[head];
    for (let i = g.start[v]; i < g.start[v + 1]; i++) {
      const w = g.to[i];
      if (!seen[w]) { seen[w] = 1; queue[tail++] = w; }
    }
  }
  return seen;
}

/** Predecessors of the seed set, as the start of a backward walk (paths of length >= 1). */
function predecessors(g: Csr, seeds: readonly number[]): number[] {
  const out: number[] = [];
  for (const s of seeds) for (let i = g.start[s]; i < g.start[s + 1]; i++) out.push(g.to[i]);
  return out;
}

/** The three T6 answers over one `facts@2` snapshot; build once, query per change. */
export class T6Graph {
  readonly ids: readonly string[];
  readonly edges: T6EdgeCounts;
  private readonly index = new Map<string, number>();
  private readonly fwdStrong: Csr;
  private readonly fwdAny: Csr;
  private readonly backStrong: Csr;
  private readonly backAny: Csr;
  private readonly roots: { id: number; weak: boolean; kind: string }[] = [];

  constructor(rows: T6Rows) {
    const ids: string[] = [];
    for (const d of rows.decl) {
      if (this.index.has(d.id)) continue;
      this.index.set(d.id, ids.length);
      ids.push(d.id);
    }
    this.ids = ids;
    const n = ids.length;
    const sFrom: number[] = [], sTo: number[] = [], wFrom: number[] = [], wTo: number[] = [];
    const edges: T6EdgeCounts = { callStrong: 0, callWeak: 0, ref: 0, contains: 0, loadsParent: 0, loadsModule: 0 };
    const add = (a: string, b: string, strong: boolean): boolean => {
      const x = this.index.get(a);
      const y = this.index.get(b);
      if (x === undefined || y === undefined) return false;
      (strong ? sFrom : wFrom).push(x);
      (strong ? sTo : wTo).push(y);
      return true;
    };
    for (const c of rows.call) {
      const strong = c.tier !== 'inferred';
      if (add(c.callerId, c.calleeId, strong)) edges[strong ? 'callStrong' : 'callWeak']++;
    }
    for (const r of rows.ref) if (add(r.fromId, r.toId, false)) edges.ref++;
    const moduleOf = new Map<string, string[]>();
    for (const d of rows.decl) {
      if (d.kind !== 'module') continue;
      const list = moduleOf.get(d.file);
      if (list) list.push(d.id); else moduleOf.set(d.file, [d.id]);
    }
    for (const d of rows.decl) {
      if (d.parentId !== null && d.contained && add(d.parentId, d.id, true)) edges.contains++;
      if (d.parentId !== null && d.loadsParent && add(d.id, d.parentId, true)) edges.loadsParent++;
      if (d.kind !== 'module') for (const m of moduleOf.get(d.file) ?? []) if (add(d.id, m, true)) edges.loadsModule++;
    }
    this.edges = edges;
    this.fwdStrong = csr(n, sFrom, sTo);
    this.backStrong = csr(n, sTo, sFrom);
    this.fwdAny = csr(n, [...sFrom, ...wFrom], [...sTo, ...wTo]);
    this.backAny = csr(n, [...sTo, ...wTo], [...sFrom, ...wFrom]);
    for (const e of rows.entries) {
      const id = this.index.get(e.declId);
      if (id !== undefined) this.roots.push({ id, weak: e.certainty === 'inferred', kind: e.kind });
    }
  }

  private seeds(changed: Iterable<string>): number[] {
    const out: number[] = [];
    for (const c of changed) {
      const i = this.index.get(c);
      if (i !== undefined) out.push(i);
    }
    return out;
  }

  private tiers(strong: Uint8Array, any: Uint8Array, skip?: Uint8Array): Map<string, T6Tier> {
    const out = new Map<string, T6Tier>();
    for (let i = 0; i < this.ids.length; i++) {
      if (skip?.[i]) continue;
      if (strong[i]) out.set(this.ids[i], 'strong');
      else if (any[i]) out.set(this.ids[i], 'weak');
    }
    return out;
  }

  /** Declarations that reach a changed one, by tier; the changed ones are not in their own radius. */
  blastRadius(changed: Iterable<string>): Map<string, T6Tier> {
    const seeds = this.seeds(changed);
    const n = this.ids.length;
    const isSeed = new Uint8Array(n);
    for (const s of seeds) isSeed[s] = 1;
    return this.tiers(
      closure(this.backStrong, predecessors(this.backStrong, seeds), n),
      closure(this.backAny, predecessors(this.backAny, seeds), n),
      isSeed,
    );
  }

  /** Declarations reached from the entries whose kind is not excluded (default: every kind but `test`). */
  reached(excludeKinds: readonly string[] = ['test']): Map<string, T6Tier> {
    const n = this.ids.length;
    const roots = this.roots.filter(r => !excludeKinds.includes(r.kind));
    return this.tiers(
      closure(this.fwdStrong, roots.filter(r => !r.weak).map(r => r.id), n),
      closure(this.fwdAny, roots.map(r => r.id), n),
    );
  }

  /** `test` entries that are changed or reach a changed declaration, by tier. */
  impactedTests(changed: Iterable<string>): Map<string, T6Tier> {
    const seeds = this.seeds(changed);
    const n = this.ids.length;
    const isSeed = new Uint8Array(n);
    for (const s of seeds) isSeed[s] = 1;
    const backStrong = closure(this.backStrong, predecessors(this.backStrong, seeds), n);
    const backAny = closure(this.backAny, predecessors(this.backAny, seeds), n);
    const strongRoot = new Uint8Array(n);
    const weakRoot = new Uint8Array(n);
    for (const r of this.roots) if (r.kind === 'test') (r.weak ? weakRoot : strongRoot)[r.id] = 1;
    const out = new Map<string, T6Tier>();
    for (let i = 0; i < n; i++) {
      if (!strongRoot[i] && !weakRoot[i]) continue;
      if (strongRoot[i] && (backStrong[i] || isSeed[i])) out.set(this.ids[i], 'strong');
      else if (backAny[i] || (weakRoot[i] && isSeed[i])) out.set(this.ids[i], 'weak');
    }
    return out;
  }
}

const ZERO_ID = 'a'.repeat(26);

/** The T6 columns of a `facts@2` snapshot, from its Arrow IPC relations (needs the optional `apache-arrow`). */
export async function t6RowsFromArrow(facts: Pick<Facts2Arrow, 'relations'>): Promise<T6Rows> {
  const arrow = await loadArrow();
  const read = (name: 'decl' | 'call' | 'ref' | 'entries'): Record<string, unknown>[] =>
    arrow.tableFromIPC(facts.relations[name]).toArray().map(r => r.toJSON() as Record<string, unknown>);
  const id = (v: unknown): string => base32(v as Uint8Array);
  return {
    decl: read('decl').map(r => {
      const parent = id(r.parent_id);
      return {
        id: id(r.id),
        kind: String(r.kind),
        file: id(r.file),
        // No nulls in facts@2: all-zero bytes stand for "no parent".
        parentId: parent === ZERO_ID ? null : parent,
        contained: Boolean(r.contained),
        loadsParent: Boolean(r.loads_parent),
      };
    }),
    call: read('call').map(r => ({ callerId: id(r.caller_id), calleeId: id(r.callee_id), tier: String(r.tier) })),
    ref: read('ref').map(r => ({ fromId: id(r.from_id), toId: id(r.to_id) })),
    entries: read('entries').map(r => ({ declId: id(r.decl_id), kind: String(r.kind), certainty: String(r.certainty) })),
  };
}
