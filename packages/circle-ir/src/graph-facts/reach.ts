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

import type { StableDecl, StableIdFile } from '../stable-ids/types.js';
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
  entries: readonly { id: string; kind: EntryKind; certainty: EntryCertainty; method?: string; path?: string; file: string; line: number }[];
  unresolvedRegistrations?: readonly { site: ReachSite; reason: string; evidence: string }[];
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
}

export interface ReachResult {
  scheme: typeof REACH_SCHEME;
  ids: 'ids@0.1';
  rootKinds: EntryKind[];
  partial: string[];
  facts: ReachFact[];
}

export const ALL_ENTRY_KINDS: readonly EntryKind[] = [
  'route', 'listener', 'scheduled', 'main', 'export', 'bean', 'reflection', 'lifecycle', 'test',
];

interface Edge {
  to: string;
  relation: EdgeRelation;
  strong: boolean;
  tier?: Tier;
  site?: ReachSite;
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
        const nested = d.flags.includes('unstable:anonymous');
        const topValue = parent === module && d.kind === 'field';
        // A class creates its fields and runs its static initializer; in
        // TypeScript a class used as a value may also be constructed, while
        // a Java constructor runs only when called (the call graph has it).
        const ctor = d.kind === 'method' && (d.name === '<clinit>' || (d.name === 'constructor' && f.language !== 'java'));
        const classPart = parent.kind === 'type' && (d.kind === 'field' || ctor);
        if (nested || topValue || classPart) add(parent.id, { to: d.id, relation: 'contains', strong: true });
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

/**
 * Breadth-first over (declaration, weak-so-far) states from the given roots.
 * A state's first visit is its shortest path.
 */
export function walkFrom(
  g: ReachGraph,
  roots: readonly { id: string; weak: boolean }[],
): Map<string, Visit> {
  const seen = new Map<string, Visit>();
  const queue: string[] = [];
  roots.forEach((r, i) => {
    const key = `${r.weak ? 1 : 0}${r.id}`;
    if (!g.decls.has(r.id) || seen.has(key)) return;
    seen.set(key, { prev: null, edge: null, root: i });
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
export function couldReach(input: ReachInput, reached: ReadonlySet<string>, d: StableDecl): CouldReachSite[] {
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
    if (r.reason === 'handler-unresolved') out.push({ kind: 'registration', reason: r.reason, site: r.site });
  }
  return out.sort(bySite);
}

export function reach(input: ReachInput, options: ReachOptions = {}): ReachResult {
  const rootKinds = [...(options.rootKinds ?? ALL_ENTRY_KINDS.filter(k => k !== 'test'))];
  const max = options.maxUnresolved ?? 5;
  const g = new ReachGraph(input);
  const roots = input.entries.filter(e => rootKinds.includes(e.kind));
  const visits = walkFrom(g, roots.map(e => ({ id: e.id, weak: e.certainty === 'inferred' })));
  const reached = reachedIds(visits);
  const wanted = options.targets ? new Set(options.targets) : null;
  const facts: ReachFact[] = [];
  for (const f of input.files) {
    for (const d of f.decls) {
      if (wanted && !wanted.has(d.id)) continue;
      const strong = pathTo(visits, `0${d.id}`, roots);
      const weak = pathTo(visits, `1${d.id}`, roots);
      const sites = strong ? [] : couldReach(input, reached, d);
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
  return { scheme: REACH_SCHEME, ids: 'ids@0.1', rootKinds, partial: [...input.partial], facts };
}
