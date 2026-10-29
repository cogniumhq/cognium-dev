/**
 * Path sets of one weakness class, and their difference between two versions
 * of a tree.
 *
 * `pathSetOf` collects every source-to-sink path whose sink carries the given
 * CWE from an already analysed project (per-file `taint.flows` and project
 * `taint_paths`) and gives each a **pin-independent key**: no line number
 * takes part, so an edit that only shifts lines keeps every key. The key is
 * built from the declaration that holds each end (a stable id where the
 * caller supplies `ids@0.1` for the file, else a qualified name built from the
 * IR), the call shape of the end, and its ordinal among same-shape ends in
 * that declaration.
 *
 * `diffPathSets` compares two sets as a set operation and counts, per version,
 * the unresolved edges and the analysis budgets hit, so an empty set on a
 * partly analysed tree is never read as clean. Neither function judges a
 * change: they report which paths exist where.
 *
 * Pure: IR in, values out. Browser and Node compatible.
 */

import { digest128 } from '../stable-ids/hash.js';
import type { StableIdFile } from '../stable-ids/types.js';
import type {
  CircleIR,
  ProjectAnalysis,
  TaintSink,
  TaintSource,
  TypeInfo,
} from '../types/index.js';
import {
  PATH_KEY_SCHEME,
  type DeclKeyScheme,
  type DeclRef,
  type PathChange,
  type PathDiffEntry,
  type PathEntry,
  type PathHop,
  type PathSet,
  type PathSetDiff,
  type PathSink,
  type PathSource,
  type PathState,
  type PinFacts,
} from './types.js';

/** What `pathSetOf` reads: the per-file IR and, when present, cross-file paths. */
export type PathSetInput = Pick<ProjectAnalysis, 'files'> & Partial<Pick<ProjectAnalysis, 'taint_paths'>>;

export interface PathSetOptions {
  /** The weakness class, `CWE-89` or `89`. */
  cwe: string | number;
  /** `ids@0.1` per repository-relative file path, for files the ids cover. */
  stableIds?: Record<string, StableIdFile>;
}

/** `CWE-089`, `cwe-89` and `89` all normalise to `CWE-89`. */
export function normalizeCwe(cwe: string | number): string {
  const m = /^(?:cwe-)?0*(\d+)$/i.exec(String(cwe).trim());
  if (!m) throw new Error(`path-set: not a CWE id: ${JSON.stringify(cwe)}`);
  return `CWE-${m[1]}`;
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

/** `package.Type$Inner` — the qualified@0.1 name of a type. */
export function typePath(t: TypeInfo): string {
  const name = t.enclosing_type ? `${t.enclosing_type}$${t.name}` : t.name;
  return t.package ? `${t.package}.${name}` : name;
}

/** `package.Type$Inner.method(T1,T2)` — the qualified@0.1 name of a method. */
export function qualifiedMethodName(type: TypeInfo, method: TypeInfo['methods'][number]): string {
  return `${typePath(type)}.${method.name}(${method.parameters.map(p => p.type ?? '?').join(',')})`;
}

function span(start: number, end: number): number {
  return end - start;
}

/** The declaration that holds `line` in `file`. */
export function declAt(
  file: string,
  ir: CircleIR,
  line: number,
  ids?: StableIdFile,
): DeclRef {
  if (ids) {
    let best: StableIdFile['decls'][number] | undefined;
    for (const d of ids.decls) {
      if (d.kind !== 'function' && d.kind !== 'method') continue;
      if (line < d.start_line || line > d.end_line) continue;
      if (!best || span(d.start_line, d.end_line) < span(best.start_line, best.end_line)) best = d;
    }
    best ??= ids.decls[0];
    if (best) return { scheme: 'ids@0.1', id: best.id, name: best.qualified_name };
  }

  let type: TypeInfo | undefined;
  for (const t of ir.types) {
    if (line < t.start_line || line > t.end_line) continue;
    if (!type || span(t.start_line, t.end_line) < span(type.start_line, type.end_line)) type = t;
  }
  let qualified: string;
  if (type) {
    const method = type.methods
      .filter(m => line >= m.start_line && line <= m.end_line)
      .sort((a, b) => span(a.start_line, a.end_line) - span(b.start_line, b.end_line))[0];
    qualified = method ? qualifiedMethodName(type, method) : `${typePath(type)}.<init>`;
  } else {
    // No type holds the line (top-level function in a language whose IR keeps
    // functions outside types): fall back to the enclosing method name the
    // call extractor recorded, else the module.
    const inMethod = ir.calls.find(c => c.location.line === line && c.in_method)?.in_method;
    qualified = inMethod ? `<module>.${inMethod}` : '<module>';
  }
  const id = `${file}#${qualified}`;
  return { scheme: 'qualified@0.1', id, name: qualified };
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

/** `req.getParameter() in find` → `getParameter`. */
function callNameFromLocation(location: string): string {
  const head = location.split(' in ')[0].trim().replace(/\(\)$/, '');
  const dot = head.lastIndexOf('.');
  return dot >= 0 ? head.slice(dot + 1) : head;
}

function sourceShape(s: TaintSource): string {
  const what = s.method ?? (s.annotation ? `@${s.annotation}` : callNameFromLocation(s.location));
  return `${s.type}:${what}`;
}

function sinkShape(s: TaintSink): string {
  return `${s.type}:${s.class ?? '?'}.${s.method ?? '?'}(${(s.argPositions ?? []).join(',')})`;
}

interface FileCtx {
  file: string;
  ir: CircleIR;
  ids?: StableIdFile;
}

/** Ordinal of `item` among items of the same shape in the same declaration, by position. */
function ordinalOf<T extends { line: number }>(
  item: T,
  all: readonly T[],
  shape: (x: T) => string,
  declId: (x: T) => string,
  column: (x: T) => number,
): number {
  const myShape = shape(item);
  const myDecl = declId(item);
  const peers = all
    .filter(x => shape(x) === myShape && declId(x) === myDecl)
    .sort((a, b) => a.line - b.line || column(a) - column(b));
  return peers.indexOf(item);
}

function sourceEnd(ctx: FileCtx, line: number, type: string): PathSource | undefined {
  const src = ctx.ir.taint.sources.find(s => s.line === line && s.type === type);
  if (!src) return undefined;
  const decl = declAt(ctx.file, ctx.ir, line, ctx.ids);
  const declIdOf = (s: TaintSource): string => declAt(ctx.file, ctx.ir, s.line, ctx.ids).id;
  const ordinal = ordinalOf(src, ctx.ir.taint.sources, sourceShape, declIdOf, () => 0);
  const end: PathSource = {
    anchor: `${decl.scheme}:${decl.id}|${sourceShape(src)}|#${ordinal}`,
    decl,
    file: ctx.file,
    line,
    type: src.type,
  };
  if (src.code !== undefined) end.code = src.code;
  return end;
}

function sinkEnd(ctx: FileCtx, line: number, type: string): PathSink | undefined {
  const candidates = ctx.ir.taint.sinks
    .filter(s => s.line === line && s.type === type)
    .sort((a, b) => (a.callColumn ?? 0) - (b.callColumn ?? 0));
  const sink = candidates[0];
  if (!sink) return undefined;
  const decl = declAt(ctx.file, ctx.ir, line, ctx.ids);
  const declIdOf = (s: TaintSink): string => declAt(ctx.file, ctx.ir, s.line, ctx.ids).id;
  const ordinal = ordinalOf(sink, ctx.ir.taint.sinks, sinkShape, declIdOf, s => s.callColumn ?? 0);
  const call: PathSink['call'] = {};
  if (sink.class !== undefined) call.class = sink.class;
  if (sink.method !== undefined) call.method = sink.method;
  if (sink.argPositions !== undefined) call.argPositions = sink.argPositions;
  const end: PathSink = {
    anchor: `${decl.scheme}:${decl.id}|${sinkShape(sink)}|#${ordinal}`,
    decl,
    file: ctx.file,
    line,
    type: sink.type,
    cwe: normalizeCwe(sink.cwe),
    call,
  };
  if (sink.code !== undefined) end.code = sink.code;
  return end;
}

/** The pin-independent key of a path. */
export function pathKey(cwe: string, sourceAnchor: string, sinkAnchor: string): string {
  return digest128([PATH_KEY_SCHEME, cwe, sourceAnchor, sinkAnchor]);
}

// ---------------------------------------------------------------------------
// One tree
// ---------------------------------------------------------------------------

interface Variant {
  source: PathSource;
  sink: PathSink;
  sanitized: boolean;
  hops: PathHop[];
  confidence: number;
}

const variantId = (v: Variant): string => `${v.source.file}:${v.source.line}->${v.sink.file}:${v.sink.line}`;

/** Every path of class `cwe` in one analysed tree, keyed and sorted by key. */
export function pathSetOf(project: PathSetInput, options: PathSetOptions): PathSet {
  const cwe = normalizeCwe(options.cwe);
  const ctxByFile = new Map<string, FileCtx>();
  for (const f of project.files) {
    const ctx: FileCtx = { file: f.file, ir: f.analysis };
    const ids = options.stableIds?.[f.file];
    if (ids) ctx.ids = ids;
    ctxByFile.set(f.file, ctx);
  }

  const variants: Variant[] = [];

  for (const ctx of ctxByFile.values()) {
    for (const flow of ctx.ir.taint.flows ?? []) {
      const sink = sinkEnd(ctx, flow.sink_line, flow.sink_type);
      if (!sink || sink.cwe !== cwe) continue;
      const source = sourceEnd(ctx, flow.source_line, flow.source_type);
      if (!source) continue;
      variants.push({
        source,
        sink,
        sanitized: flow.sanitized,
        hops: flow.path.map(s => ({ file: ctx.file, line: s.line, variable: s.variable })),
        confidence: flow.confidence,
      });
    }
  }

  for (const p of project.taint_paths ?? []) {
    if (!p.path_exists || normalizeCwe(p.sink.cwe) !== cwe) continue;
    const sctx = ctxByFile.get(p.source.file);
    const kctx = ctxByFile.get(p.sink.file);
    if (!sctx || !kctx) continue;
    const source = sourceEnd(sctx, p.source.line, p.source.type);
    const sink = sinkEnd(kctx, p.sink.line, p.sink.type);
    if (!source || !sink) continue;
    variants.push({
      source,
      sink,
      sanitized: p.sanitizers_in_path.length > 0,
      hops: p.hops.map(h => {
        const hop: PathHop = { file: h.file, line: h.line };
        if (h.method) hop.method = h.method;
        if (h.variable) hop.variable = h.variable;
        return hop;
      }),
      confidence: p.confidence,
    });
  }

  // Group by key; a variant seen both per-file and cross-file counts once.
  const byKey = new Map<string, Map<string, Variant[]>>();
  for (const v of variants) {
    const key = pathKey(cwe, v.source.anchor, v.sink.anchor);
    let group = byKey.get(key);
    if (!group) byKey.set(key, (group = new Map()));
    const id = variantId(v);
    const list = group.get(id);
    if (list) list.push(v);
    else group.set(id, [v]);
  }

  const paths: PathEntry[] = [];
  const files = new Set<string>();
  const schemes = new Set<DeclKeyScheme>();
  for (const [key, group] of byKey) {
    const ids = [...group.keys()].sort();
    const all = ids.flatMap(id => group.get(id) as Variant[]);
    const first = (group.get(ids[0]) as Variant[])[0];
    // a variant is unsanitized if any of its observations is
    const variantPresent = ids.map(id => (group.get(id) as Variant[]).some(v => !v.sanitized));
    const state: PathEntry['state'] = variantPresent.some(Boolean) ? 'present' : 'sanitized';
    paths.push({
      key,
      cwe,
      source: first.source,
      sink: first.sink,
      state,
      variants: ids.length,
      hops: first.hops,
      confidence: Math.max(...all.map(v => v.confidence)),
    });
    for (const v of all) {
      files.add(v.source.file);
      files.add(v.sink.file);
      for (const h of v.hops) files.add(h.file);
      schemes.add(v.source.decl.scheme);
      schemes.add(v.sink.decl.scheme);
    }
  }
  paths.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  return {
    scheme: PATH_KEY_SCHEME,
    cwe,
    paths,
    declKeySchemes: [...schemes].sort(),
    files: [...files].sort(),
  };
}

// ---------------------------------------------------------------------------
// Two trees
// ---------------------------------------------------------------------------

/** The set change between two states. */
export function changeOf(before: PathState, after: PathState): PathChange {
  if (before === 'present') {
    if (after === 'absent') return 'removed';
    if (after === 'sanitized') return 'sanitized';
    return 'unchanged';
  }
  return after === 'present' ? 'added' : 'other';
}

/** Unresolved edges, budget flags and parse health of one analysed tree. */
export function pinFacts(project: ProjectAnalysis, pathFiles: ReadonlySet<string>, pathCount: number): PinFacts {
  const byType: PinFacts['unresolved']['byType'] = {
    virtual_dispatch: 0,
    taint_propagation: 0,
    reflection: 0,
    dynamic_call: 0,
  };
  let total = 0;
  let onPathFiles = 0;
  const flags: string[] = [];
  for (const f of project.files) {
    for (const u of f.analysis.unresolved) {
      total++;
      byType[u.type]++;
      if (pathFiles.has(f.file)) onPathFiles++;
    }
    const ps = f.analysis.parse_status;
    if (ps && !ps.success && pathFiles.has(f.file)) flags.push(`parse-error:${f.file}`);
  }
  const crossFileCallsUnresolved = project.cross_file_calls.filter(
    c => !c.resolved && (pathFiles.has(c.from.file) || pathFiles.has(c.to.file)),
  ).length;
  if (project.cross_file_budget_exceeded) flags.push('cross_file_budget_exceeded');
  if (project.per_file_budget_exceeded) flags.push('per_file_budget_exceeded');
  if (project.project_size_budget_exceeded) flags.push('project_size_budget_exceeded');
  flags.sort();
  return {
    pathCount,
    unresolved: { total, byType, onPathFiles },
    crossFileCallsUnresolved,
    complete: flags.length === 0,
    flags,
  };
}

/** Compare two path sets of the same class. */
export function diffPathSets(before: PathSet, after: PathSet): Pick<PathSetDiff, 'entries' | 'counts'> {
  if (before.cwe !== after.cwe) throw new Error(`path-set: cannot diff ${before.cwe} against ${after.cwe}`);
  const b = new Map(before.paths.map(p => [p.key, p]));
  const a = new Map(after.paths.map(p => [p.key, p]));
  const keys = [...new Set([...b.keys(), ...a.keys()])].sort();
  const counts: Record<PathChange, number> = { removed: 0, sanitized: 0, unchanged: 0, added: 0, other: 0 };
  const entries = keys.map(key => {
    const pb = b.get(key);
    const pa = a.get(key);
    const state = { before: pb?.state ?? ('absent' as const), after: pa?.state ?? ('absent' as const) };
    const change = changeOf(state.before, state.after);
    counts[change]++;
    const entry: PathDiffEntry = { key, state, change };
    if (pb) entry.before = pb;
    if (pa) entry.after = pa;
    return entry;
  });
  return { entries, counts };
}

/**
 * Every path of class `cwe` at two versions of a tree, the change per key,
 * and per version the unresolved edges and budget flags. Path files are the
 * union over both versions, so both pins are counted over the same region.
 */
export function pathSetDiff(
  before: ProjectAnalysis,
  after: ProjectAnalysis,
  options: { cwe: string | number; stableIds?: { before?: Record<string, StableIdFile>; after?: Record<string, StableIdFile> } },
): PathSetDiff {
  const setB = pathSetOf(before, { cwe: options.cwe, ...(options.stableIds?.before ? { stableIds: options.stableIds.before } : {}) });
  const setA = pathSetOf(after, { cwe: options.cwe, ...(options.stableIds?.after ? { stableIds: options.stableIds.after } : {}) });
  const files = new Set([...setB.files, ...setA.files]);
  const { entries, counts } = diffPathSets(setB, setA);
  return {
    scheme: PATH_KEY_SCHEME,
    cwe: setB.cwe,
    entries,
    counts,
    pins: {
      before: pinFacts(before, files, setB.paths.length),
      after: pinFacts(after, files, setA.paths.length),
    },
  };
}
