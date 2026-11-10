/**
 * The reach core (`reach@0.1`): from a set of entry points to every
 * declaration, one path per class and the unresolved sites that could add
 * more.
 *
 * - **strong** path: from a `declared` or `conventional` entry over strong
 *   edges only — `exact` and `polymorphic` calls, and the structural edges
 *   that hold whenever their source runs (`contains`: a body creates its
 *   nested functions, a module its top-level values, a class its fields and
 *   constructor; `loads`: running a declaration loads its module; `import`:
 *   loading a module loads what it imports; `field`: a body that runs uses
 *   the fields it reads or writes through `this`; `loads` also covers a
 *   body that loads a module with `import()` or `require()`).
 * - **weak** path: any other path — through an `inferred` call, a
 *   `reference` (a function or class passed, stored, returned or rendered:
 *   it may run, nothing proves it does) or an `inferred` entry.
 * - **unresolved**: call sites in reached bodies that the call graph could
 *   not bind and that could bind to the declaration — same method name, or a
 *   computed callee — plus registrations whose handler was not resolved.
 *   A module is reached this way only by a module load with a computed
 *   specifier (`import(name)`, methodName `<module>`).
 *
 * Each path is the shortest of its class (breadth-first, deterministic:
 * adjacency in id order). `partial[]` lists files that did not parse; their
 * call sites are missing, so any answer that relies on absence is not final.
 */

import type { ParseErrorSite, StableDecl, StableIdFile } from '../stable-ids/types.js';
import type { Tier, UnresolvedReason } from '../navigation/types.js';
import type { EntryCertainty, EntryKind } from '../navigation/ts-entry-tables.js';

export const REACH_SCHEME = 'reach@0.1' as const;

export interface ReachSite {
  file: string;
  line: number;
  col: number;
}

/** The facts the reach core reads. `TsCallGraph` satisfies it. */
export interface ReachInput {
  files: readonly StableIdFile[];
  edges: readonly { from: string; to: string; tier: Tier; site: ReachSite; methodName: string }[];
  references?: readonly { from: string; to: string; site: ReachSite }[];
  /** Strong: a body that runs uses the field (`this.x`). */
  fieldUses?: readonly { from: string; to: string; site: ReachSite }[];
  imports?: readonly { from: string; to: string }[];
  /**
   * Extra strong `loads` edges: running `from` initializes `to` (Java: a
   * member initializes its class; TypeScript: a body loads a module with
   * `import()` / `require()`).
   */
  loads?: readonly { from: string; to: string; site?: ReachSite }[];
  unresolved: readonly { from: string; methodName: string; site: ReachSite; reason: UnresolvedReason }[];
  /** `constructors`: run with the entry's type when its runtime instantiates it (Java); rooted with it. */
  entries: readonly { id: string; kind: EntryKind; certainty: EntryCertainty; method?: string; path?: string; file: string; line: number; constructors?: readonly string[] }[];
  /**
   * Registrations that could load any declaration. Java (#1092): `from` is the body that
   * holds the site (counted only when reached); `boundTypes` the in-tree types the loaded
   * class must be (it then names only declarations of those types).
   */
  unresolvedRegistrations?: readonly { site: ReachSite; reason: string; evidence: string; from?: string; boundTypes?: readonly string[] }[];
  partial: readonly string[];
}

export type EdgeRelation = 'call' | 'reference' | 'field' | 'contains' | 'loads' | 'import';

export interface PathStep {
  /** The declaration this step arrives at. */
  decl: string;
  /** How it was reached from the previous step; `entry` for the first. */
  via: 'entry' | EdgeRelation;
  /** Calls: the edge's tier. */
  tier?: Tier;
  site?: ReachSite;
}

export interface ReachPath {
  class: 'strong' | 'weak';
  entry: { id: string; kind: EntryKind; certainty: EntryCertainty; method?: string; path?: string };
  steps: PathStep[];
}

export interface CouldReachSite {
  kind: 'call' | 'registration';
  from?: string;
  methodName?: string;
  reason: string;
  site: ReachSite;
}

export interface ReachFact {
  id: string;
  qualified_name: string;
  kind: StableDecl['kind'];
  file: string;
  strong: ReachPath | null;
  weak: ReachPath | null;
  /** Up to `maxUnresolved` sites, in site order. */
  unresolved: CouldReachSite[];
  unresolvedCount: number;
}

export interface ReachOptions {
  /** Entry kinds used as roots. Default: every kind except `test`. */
  rootKinds?: readonly EntryKind[];
  /** Declaration ids to answer for. Default: every declaration. */
  targets?: readonly string[];
  /** Most unresolved sites listed per declaration. Default 5. */
  maxUnresolved?: number;
  /**
   * Narrow a `Class.forName` registration to its `boundTypes` (#1092). Off by default: a
   * name outside the bound is still loaded and initialised before the cast fails, so the
   * bound is evidence, not proof, and narrowing by it can drop a live path.
   */
  boundRegistrations?: boolean;
}

export interface ReachResult {
  scheme: typeof REACH_SCHEME;
  ids: 'ids@0.1';
  rootKinds: EntryKind[];
  partial: string[];
  /** One row per `partial` file: where its first blocking parse error is. */
  partialFiles: PartialFile[];
  facts: ReachFact[];
}

/** A file in `partial[]` and the first error that made it partial. */
export interface PartialFile extends Partial<ParseErrorSite> {
  file: string;
}

/**
 * `partial` paths with their first blocking parse error, read from the
 * files' `parseError`, sorted by path. A path with no error recorded (an
 * older `StableIdFile`) keeps only `file`.
 */
export function partialFileDetails(partial: readonly string[], files: readonly StableIdFile[]): PartialFile[] {
  const byFile = new Map(files.map(f => [f.file, f]));
  return [...new Set(partial)].sort().map(file => {
    const e = byFile.get(file)?.parseError;
    return e ? { file, line: e.line, column: e.column, nodeKind: e.nodeKind, parent: e.parent } : { file };
  });
}

export const ALL_ENTRY_KINDS: readonly EntryKind[] = [
  'route', 'listener', 'scheduled', 'main', 'export', 'bean', 'reflection', 'lifecycle', 'test', 'osgi-ds', 'extension-point',
];

interface Edge {
  to: string;
  relation: EdgeRelation;
  strong: boolean;
  tier?: Tier;
  site?: ReachSite;
}

/**
 * The strong `contains` rule: whenever `parent` runs, `d` is in use. An
 * anonymous or nested body, a module's top-level value, and a type's fields
 * and static initializer; a constructor too outside Java, where a class used
 * as a value may be constructed, while a Java constructor runs only when
 * called (the call graph has it). `module` is the first declaration of `d`'s
 * file. The walk adds a `contains` edge for each, and `facts@2` writes it as
 * `decl.contained`.
 */
export function containedIn(d: StableDecl, parent: StableDecl, module: StableDecl, language: StableIdFile['language']): boolean {
  const nested = d.flags.includes('unstable:anonymous');
  const topValue = parent === module && d.kind === 'field';
  const ctor = d.kind === 'method' && (d.name === '<clinit>' || (d.name === 'constructor' && language !== 'java'));
  const classPart = parent.kind === 'type' && (d.kind === 'field' || ctor);
  return nested || topValue || classPart;
}

/** The adjacency the walk uses: call graph edges plus the structural ones. */
export class ReachGraph {
  readonly decls = new Map<string, { decl: StableDecl; file: string }>();
  private readonly out = new Map<string, Edge[]>();

  constructor(readonly input: ReachInput) {
    for (const f of input.files) for (const d of f.decls) this.decls.set(d.id, { decl: d, file: f.file });
    const add = (from: string, e: Edge): void => {
      if (!this.decls.has(from) || !this.decls.has(e.to) || from === e.to) return;
      const list = this.out.get(from);
      if (list) list.push(e);
      else this.out.set(from, [e]);
    };
    for (const e of input.edges) add(e.from, { to: e.to, relation: 'call', strong: e.tier !== 'inferred', tier: e.tier, site: e.site });
    for (const r of input.references ?? []) add(r.from, { to: r.to, relation: 'reference', strong: false, site: r.site });
    for (const u of input.fieldUses ?? []) add(u.from, { to: u.to, relation: 'field', strong: true, site: u.site });
    for (const i of input.imports ?? []) add(i.from, { to: i.to, relation: 'import', strong: true });
    for (const l of input.loads ?? []) add(l.from, { to: l.to, relation: 'loads', strong: true, site: l.site });
    for (const f of input.files) {
      const module = f.decls[0];
      for (const d of f.decls) {
        if (d === module || !module) continue;
        add(d.id, { to: module.id, relation: 'loads', strong: true });
        const parent = d.parent === null ? undefined : this.decls.get(d.parent)?.decl;
        if (!parent) continue;
        if (containedIn(d, parent, module, f.language)) add(parent.id, { to: d.id, relation: 'contains', strong: true });
      }
    }
    const order = (a: Edge, b: Edge): number =>
      a.to < b.to ? -1 : a.to > b.to ? 1 : a.relation < b.relation ? -1 : a.relation > b.relation ? 1
        : (a.site?.line ?? 0) - (b.site?.line ?? 0) || (a.site?.col ?? 0) - (b.site?.col ?? 0);
    for (const list of this.out.values()) list.sort(order);
  }

  edgesFrom(id: string): readonly Edge[] {
    return this.out.get(id) ?? [];
  }
}

interface Visit {
  prev: string | null;
  edge: Edge | null;
  root: number;
}

/** A walk root; `from` makes it one `contains` step from an earlier root (a Java type entry's constructor). */
export interface WalkRoot {
  id: string;
  weak: boolean;
  from?: string;
}

/**
 * Breadth-first over (declaration, weak-so-far) states from the given roots.
 * A state's first visit is its shortest path.
 */
export function walkFrom(
  g: ReachGraph,
  roots: readonly WalkRoot[],
  rootIndex: (i: number) => number = i => i,
): Map<string, Visit> {
  const seen = new Map<string, Visit>();
  const queue: string[] = [];
  roots.forEach((r, i) => {
    const key = `${r.weak ? 1 : 0}${r.id}`;
    if (!g.decls.has(r.id) || seen.has(key)) return;
    const prev = r.from !== undefined ? `${r.weak ? 1 : 0}${r.from}` : null;
    if (prev !== null && !seen.has(prev)) return;
    seen.set(key, prev !== null
      ? { prev, edge: { to: r.id, relation: 'contains', strong: true }, root: rootIndex(i) }
      : { prev: null, edge: null, root: rootIndex(i) });
    queue.push(key);
  });
  for (let head = 0; head < queue.length; head++) {
    const key = queue[head];
    const weak = key[0] === '1';
    const id = key.slice(1);
    const root = (seen.get(key) as Visit).root;
    for (const e of g.edgesFrom(id)) {
      const next = `${weak || !e.strong ? 1 : 0}${e.to}`;
      if (seen.has(next)) continue;
      seen.set(next, { prev: key, edge: e, root });
      queue.push(next);
    }
  }
  return seen;
}

function pathTo(
  visits: Map<string, Visit>,
  key: string,
  roots: readonly ReachInput['entries'][number][],
): ReachPath | null {
  const v = visits.get(key);
  if (!v) return null;
  const steps: PathStep[] = [];
  for (let k: string | null = key; k !== null;) {
    const at = visits.get(k) as Visit;
    const step: PathStep = { decl: k.slice(1), via: at.edge ? at.edge.relation : 'entry' };
    if (at.edge?.tier) step.tier = at.edge.tier;
    if (at.edge?.site) step.site = at.edge.site;
    steps.push(step);
    k = at.prev;
  }
  steps.reverse();
  const e = roots[v.root];
  const entry: ReachPath['entry'] = { id: e.id, kind: e.kind, certainty: e.certainty };
  if (e.method) entry.method = e.method;
  if (e.path) entry.path = e.path;
  return { class: key[0] === '1' ? 'weak' : 'strong', entry, steps };
}

const bySite = (a: { site: ReachSite }, b: { site: ReachSite }): number =>
  a.site.file < b.site.file ? -1 : a.site.file > b.site.file ? 1 : a.site.line - b.site.line || a.site.col - b.site.col;

/** Declarations reached in any class from `visits`. */
export function reachedIds(visits: Map<string, Visit>): Set<string> {
  return new Set([...visits.keys()].map(k => k.slice(1)));
}

/** `methodName` of an unresolved site that loads a module by a computed specifier. */
export const COMPUTED_LOAD = '<module>';

/**
 * Unresolved sites in reached bodies that could bind to `d`: a non-external
 * site with `d`'s name, a computed callee, or an unresolved registration.
 * For a module: a module load with a computed specifier.
 */
/** Whether `d` is, or is declared in, one of `types` (a bound registration's types, #1092). */
function inBound(input: ReachInput, d: StableDecl, types: readonly string[]): boolean {
  if (types.length === 0) return false;
  const set = new Set(types);
  const byId = declIndex(input);
  let cur: StableDecl | undefined = d;
  while (cur) {
    if (cur.kind === 'type' && set.has(cur.id)) return true;
    cur = cur.parent ? byId.get(cur.parent) : undefined;
  }
  return false;
}

const declIndexes = new WeakMap<ReachInput, Map<string, StableDecl>>();
function declIndex(input: ReachInput): Map<string, StableDecl> {
  let m = declIndexes.get(input);
  if (!m) {
    m = new Map();
    for (const f of input.files) for (const d of f.decls) m.set(d.id, d);
    declIndexes.set(input, m);
  }
  return m;
}

export function couldReach(input: ReachInput, reached: ReadonlySet<string>, d: StableDecl, boundRegistrations = false): CouldReachSite[] {
  if (d.kind === 'field') return [];
  const isModule = d.kind === 'module';
  const out: CouldReachSite[] = [];
  for (const u of input.unresolved) {
    if (u.reason === 'external' || !reached.has(u.from)) continue;
    const load = u.methodName === COMPUTED_LOAD;
    if (isModule !== load) continue;
    const computed = u.methodName.startsWith('<') || u.methodName.startsWith('(');
    if (computed || u.methodName === d.name) out.push({ kind: 'call', from: u.from, methodName: u.methodName, reason: u.reason, site: u.site });
  }
  if (isModule) return out.sort(bySite);
  for (const r of input.unresolvedRegistrations ?? []) {
    if (r.reason !== 'handler-unresolved') continue;
    if (r.from !== undefined && !reached.has(r.from)) continue;
    if (boundRegistrations && r.boundTypes !== undefined && !inBound(input, d, r.boundTypes)) continue;
    out.push({ kind: 'registration', reason: r.reason, site: r.site });
  }
  return out.sort(bySite);
}

/**
 * Walk roots for entries. An entry's `constructors` (Java: what the runtime
 * that instantiates a registered class runs) are rooted one `contains` step
 * from it. `rootIndex` maps each walk root back to its entry.
 */
export function entryRoots(entries: readonly ReachInput['entries'][number][]): { roots: WalkRoot[]; rootIndex: (i: number) => number } {
  const roots: WalkRoot[] = [];
  const index: number[] = [];
  entries.forEach((e, i) => {
    const weak = e.certainty === 'inferred';
    roots.push({ id: e.id, weak });
    index.push(i);
    for (const c of e.constructors ?? []) {
      roots.push({ id: c, weak, from: e.id });
      index.push(i);
    }
  });
  return { roots, rootIndex: i => index[i] };
}

export function reach(input: ReachInput, options: ReachOptions = {}): ReachResult {
  const rootKinds = [...(options.rootKinds ?? ALL_ENTRY_KINDS.filter(k => k !== 'test'))];
  const max = options.maxUnresolved ?? 5;
  const g = new ReachGraph(input);
  const roots = input.entries.filter(e => rootKinds.includes(e.kind));
  const seeds = entryRoots(roots);
  const visits = walkFrom(g, seeds.roots, seeds.rootIndex);
  const reached = reachedIds(visits);
  const wanted = options.targets ? new Set(options.targets) : null;
  const facts: ReachFact[] = [];
  for (const f of input.files) {
    for (const d of f.decls) {
      if (wanted && !wanted.has(d.id)) continue;
      const strong = pathTo(visits, `0${d.id}`, roots);
      const weak = pathTo(visits, `1${d.id}`, roots);
      const sites = strong ? [] : couldReach(input, reached, d, options.boundRegistrations);
      facts.push({
        id: d.id,
        qualified_name: d.qualified_name,
        kind: d.kind,
        file: f.file,
        strong,
        weak,
        unresolved: sites.slice(0, max),
        unresolvedCount: sites.length,
      });
    }
  }
  return { scheme: REACH_SCHEME, ids: 'ids@0.1', rootKinds, partial: [...input.partial], partialFiles: partialFileDetails(input.partial, input.files), facts };
}

/**
 * Backward (declaration, weak-so-far) states from `changed`: every declaration
 * with a path of one edge or more to a changed one, over the reach core's
 * edges reversed. A state's weak flag is set once the path crosses a weak edge.
 */
const reverseIndex = new WeakMap<ReachGraph, Map<string, Edge[]>>();

function edgesInto(g: ReachGraph): Map<string, Edge[]> {
  let into = reverseIndex.get(g);
  if (into) return into;
  into = new Map<string, Edge[]>();
  for (const from of g.decls.keys()) {
    for (const e of g.edgesFrom(from)) {
      const list = into.get(e.to);
      const back: Edge = { ...e, to: from };
      if (list) list.push(back); else into.set(e.to, [back]);
    }
  }
  reverseIndex.set(g, into);
  return into;
}

function walkBack(g: ReachGraph, changed: ReadonlySet<string>): Set<string> {
  const into = edgesInto(g);
  const seen = new Set<string>();
  const queue: string[] = [];
  const visit = (key: string): void => { if (!seen.has(key)) { seen.add(key); queue.push(key); } };
  for (const c of changed) {
    for (const e of into.get(c) ?? []) visit(`${e.strong ? 0 : 1}${e.to}`);
  }
  for (let head = 0; head < queue.length; head++) {
    const key = queue[head];
    const weak = key[0] === '1';
    for (const e of into.get(key.slice(1)) ?? []) visit(`${weak || !e.strong ? 1 : 0}${e.to}`);
  }
  return seen;
}

/**
 * Blast radius (graph-store T6): the declarations that reach a changed one,
 * `strong` when an all-strong path does, else `weak`. The changed declarations
 * are not in their own radius. Pass `graph` (built from `input`) to reuse it
 * and its reverse index across many changes.
 */
export function blastRadius(input: ReachInput, changed: Iterable<string>, graph: ReachGraph = new ReachGraph(input)): Map<string, 'strong' | 'weak'> {
  const seeds = new Set(changed);
  const states = walkBack(graph, seeds);
  const out = new Map<string, 'strong' | 'weak'>();
  for (const key of states) {
    const id = key.slice(1);
    if (seeds.has(id)) continue;
    if (key[0] === '0') out.set(id, 'strong');
    else if (!states.has(`0${id}`)) out.set(id, 'weak');
  }
  return out;
}

/**
 * Impacted tests (graph-store T6): the `test` entries that are changed or reach
 * a changed declaration. `strong` when the entry is not `inferred` and an
 * all-strong path joins them, else `weak`.
 */
export function impactedTests(input: ReachInput, changed: Iterable<string>, graph: ReachGraph = new ReachGraph(input)): Map<string, 'strong' | 'weak'> {
  const seeds = new Set(changed);
  const states = walkBack(graph, seeds);
  const strongRoot = new Set<string>();
  const anyRoot = new Set<string>();
  for (const e of input.entries) {
    if (e.kind !== 'test') continue;
    anyRoot.add(e.id);
    if (e.certainty !== 'inferred') strongRoot.add(e.id);
  }
  const out = new Map<string, 'strong' | 'weak'>();
  for (const t of anyRoot) {
    const hit = seeds.has(t) || states.has(`0${t}`) || states.has(`1${t}`);
    if (!hit) continue;
    out.set(t, strongRoot.has(t) && (seeds.has(t) || states.has(`0${t}`)) ? 'strong' : 'weak');
  }
  return out;
}
