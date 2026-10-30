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

import { DEFAULT_SINKS } from '../analysis/config-loader.js';
import { DominatorGraph } from '../graph/dominator-graph.js';
import { digest128 } from '../stable-ids/hash.js';
import { sideOf, type BranchFact } from './branches.js';
import type { TemplateFact } from './templates.js';
import type { StableIdFile } from '../stable-ids/types.js';
import type {
  CallInfo,
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
  type PathGuard,
  type PathHop,
  type PathSet,
  type PathSetDiff,
  type PathSink,
  type PathSource,
  type PathState,
  type PathUnresolved,
  type UnresolvedSite,
  type TemplateUse,
  type PinFacts,
} from './types.js';

/** What `pathSetOf` reads: the per-file IR and, when present, cross-file paths. */
export type PathSetInput = Pick<ProjectAnalysis, 'files'> & Partial<Pick<ProjectAnalysis, 'taint_paths' | 'cross_file_calls'>>;

export interface PathSetOptions {
  /** The weakness class, `CWE-89` or `89`. */
  cwe: string | number;
  /** `ids@0.1` per repository-relative file path, for files the ids cover. */
  stableIds?: Record<string, StableIdFile>;
  /**
   * Branch facts per file (`deriveBranchFacts`). With them a path whose endpoint
   * runs only on one side of a check of the path's own data is reported
   * `guarded`; without them no path is.
   */
  branches?: Record<string, BranchFact[]>;
  /**
   * Template facts per template file (`deriveTemplateFacts`). With them a sink
   * call that hands a value to a view under a literal name (`addAttribute("q", q)`)
   * carries the template constructs that render that name (`sink.templates`).
   */
  templates?: Record<string, TemplateFact[]>;
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
  branches?: BranchFact[];
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

/** Simple-name class of a call's receiver, or of a static receiver written as a type. */
function callClass(c: CallInfo): string | null {
  if (c.receiver_type) return c.receiver_type.slice(c.receiver_type.lastIndexOf('.') + 1);
  const r = c.receiver;
  if (!r || r.includes('(')) return null;
  const last = r.slice(r.lastIndexOf('.') + 1);
  return /^[A-Z]/.test(last) ? last : null;
}

/**
 * Ordinal of a sink call among the calls of the same shape (class, method) in
 * its declaration, by position. Counted over calls, not over the engine's
 * sink records, so a call the engine stops flagging at one version does not
 * shift the ordinals of the others.
 */
function callOrdinal(ctx: FileCtx, declId: string, cls: string | undefined, method: string | undefined, line: number, column?: number): number | null {
  if (!method) return null;
  const same = (c: CallInfo): boolean => c.method_name === method && (cls === undefined || callClass(c) === cls);
  const peers = ctx.ir.calls
    .filter(c => same(c) && declAt(ctx.file, ctx.ir, c.location.line, ctx.ids).id === declId)
    .sort((a, b) => a.location.line - b.location.line || a.location.column - b.location.column);
  const onLine = peers.filter(c => c.location.line === line);
  if (onLine.length === 0) return null;
  const mine = column === undefined
    ? onLine[0]
    : onLine.reduce((best, c) => (Math.abs(c.location.column - column) < Math.abs(best.location.column - column) ? c : best));
  return peers.indexOf(mine);
}

function sinkEnd(ctx: FileCtx, line: number, type: string): PathSink | undefined {
  const candidates = ctx.ir.taint.sinks
    .filter(s => s.line === line && s.type === type)
    .sort((a, b) => (a.callColumn ?? 0) - (b.callColumn ?? 0));
  const sink = candidates[0];
  if (!sink) return undefined;
  const decl = declAt(ctx.file, ctx.ir, line, ctx.ids);
  const declIdOf = (s: TaintSink): string => declAt(ctx.file, ctx.ir, s.line, ctx.ids).id;
  const ordinal = callOrdinal(ctx, decl.id, sink.class, sink.method, line, sink.callColumn)
    ?? ordinalOf(sink, ctx.ir.taint.sinks, sinkShape, declIdOf, s => s.callColumn ?? 0);
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

// ---------------------------------------------------------------------------
// Endpoints: a sink whose result feeds another sink of the class
// ---------------------------------------------------------------------------

const IDENT = /[A-Za-z_$][\w$]*/g;
const STRING_LITERAL = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;

function identifiers(expr: string | null | undefined): Set<string> {
  return new Set((expr ?? '').replace(STRING_LITERAL, '""').match(IDENT) ?? []);
}

function operands(c: CallInfo): string {
  return [c.receiver ?? '', ...c.arguments.map(a => a.expression)].join(' ');
}

/** The engine's own registered sink this call has the shape of, for the CWE. */
function registeredSink(c: CallInfo, cwe: string, language: string): (typeof DEFAULT_SINKS)[number] | undefined {
  const cls = callClass(c);
  return DEFAULT_SINKS.find(p =>
    normalizeCwe(p.cwe) === cwe &&
    p.method === c.method_name &&
    (p.languages === undefined || (p.languages as string[]).includes(language)) &&
    !(p.exclude_languages as string[] | undefined)?.includes(language) &&
    (p.class === undefined || p.class === cls || (cls === null && p.allow_unresolved_receiver === true)),
  );
}

function sinkCallOf(ctx: FileCtx, sink: PathSink): CallInfo | undefined {
  return ctx.ir.calls
    .filter(c => c.location.line === sink.line && (!sink.call.method || c.method_name === sink.call.method))
    .sort((a, b) => a.location.column - b.location.column)[0];
}

/** Def ids reached (via chains) from the defs written on the call's line. */
function reachedFrom(ctx: FileCtx, line: number): Set<number> {
  const next = new Map<number, number[]>();
  for (const ch of ctx.ir.dfg.chains ?? []) {
    const l = next.get(ch.from_def);
    if (l) l.push(ch.to_def);
    else next.set(ch.from_def, [ch.to_def]);
  }
  const seen = new Set<number>();
  const stack = ctx.ir.dfg.defs.filter(d => d.line === line && d.kind !== 'param').map(d => d.id);
  while (stack.length) {
    const d = stack.pop() as number;
    if (seen.has(d)) continue;
    seen.add(d);
    stack.push(...(next.get(d) ?? []));
  }
  return seen;
}

/**
 * Follow a flagged sink to the endpoint its result feeds: an enclosing call on
 * the same line, or a later call in the same declaration that uses a value
 * derived from it, when that call is a registered sink of the class
 * (`Path.resolve(name)` → `Files.readAllBytes(real)`). Returns the sink as is
 * when nothing further is reached.
 */
function endpointOf(ctx: FileCtx, sink: PathSink): PathSink {
  const language = ctx.ir.meta.language;
  let cur = sinkCallOf(ctx, sink);
  if (!cur) return sink;
  const first = cur;
  for (let hop = 0; hop < 5; hop++) {
    const from: CallInfo = cur;
    const declId = declAt(ctx.file, ctx.ir, from.location.line, ctx.ids).id;
    const onLine = ctx.ir.calls.filter(c => c.location.line === from.location.line).filter(c => c !== from && registeredSink(c, sink.cwe, language));
    const enclosing = onLine.find(c => operands(c).includes(`${from.method_name}(`));
    let next: CallInfo | undefined = enclosing;
    if (!next) {
      const reached = reachedFrom(ctx, from.location.line);
      const names = new Set(ctx.ir.dfg.defs.filter(d => reached.has(d.id)).map(d => d.variable));
      next = ctx.ir.calls
        .filter(c => c.location.line > from.location.line && registeredSink(c, sink.cwe, language))
        .filter(c => declAt(ctx.file, ctx.ir, c.location.line, ctx.ids).id === declId)
        .filter(c => {
          const ids = identifiers(operands(c));
          return ctx.ir.dfg.uses.some(u => u.line === c.location.line && u.def_id !== null && reached.has(u.def_id) && ids.has(u.variable))
            || [...names].some(n => ids.has(n) && ctx.ir.dfg.uses.some(u => u.line === c.location.line && u.variable === n));
        })
        .sort((a, b) => a.location.line - b.location.line || a.location.column - b.location.column)[0];
    }
    if (!next) break;
    cur = next;
  }
  if (cur === first) return sink;
  const reg = registeredSink(cur, sink.cwe, language);
  /* c8 ignore next */
  if (!reg) return sink;
  const decl = declAt(ctx.file, ctx.ir, cur.location.line, ctx.ids);
  const cls = reg.class ?? callClass(cur) ?? undefined;
  const ordinal = callOrdinal(ctx, decl.id, reg.class, cur.method_name, cur.location.line, cur.location.column) ?? 0;
  const shape = `${reg.type}:${cls ?? '?'}.${cur.method_name}(${reg.arg_positions.join(',')})`;
  const endpoint: PathSink = {
    anchor: `${decl.scheme}:${decl.id}|${shape}|#${ordinal}`,
    decl,
    file: ctx.file,
    line: cur.location.line,
    type: reg.type,
    cwe: sink.cwe,
    call: { ...(cls !== undefined ? { class: cls } : {}), method: cur.method_name, argPositions: reg.arg_positions },
    intermediate: { line: sink.line, call: sink.call, ...(sink.code !== undefined ? { code: sink.code } : {}) },
  };
  return endpoint;
}

/** Names a sink call hands on as string literals (`addAttribute("q", q)` → `q`). */
export function handedNames(c: CallInfo | undefined): string[] {
  if (!c) return [];
  return c.arguments.map(a => a.literal).filter((x): x is string => typeof x === 'string' && /^[A-Za-z_][\w]*$/.test(x));
}

function templateUsesOf(ctx: FileCtx, sink: PathSink, facts: TemplateFact[]): TemplateUse[] {
  if (facts.length === 0) return [];
  const names = handedNames(sinkCallOf(ctx, sink));
  if (names.length === 0) return [];
  return facts
    .filter(f => f.names.some(n => names.includes(n)))
    .map(f => {
      const u: TemplateUse = { file: f.file, line: f.line, engine: f.engine, construct: f.construct, attributes: f.attributes, names: f.names.filter(n => names.includes(n)) };
      if (f.element !== undefined) u.element = f.element;
      if (f.inAttribute !== undefined) u.inAttribute = f.inAttribute;
      return u;
    })
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || a.construct.localeCompare(b.construct)));
}

// ---------------------------------------------------------------------------
// Guards: the endpoint runs on one side of a check of the path's own data
// ---------------------------------------------------------------------------

function methodRange(ir: CircleIR, line: number): { start: number; end: number } | undefined {
  let best: { start: number; end: number } | undefined;
  for (const t of ir.types) {
    for (const m of t.methods) {
      if (line < m.start_line || line > m.end_line) continue;
      if (!best || m.end_line - m.start_line < best.end - best.start) best = { start: m.start_line, end: m.end_line };
    }
  }
  return best;
}

/** Does the CFG block holding line `a` dominate the block holding line `b` (same method)? */
export function lineDominates(ir: CircleIR, a: number, b: number): boolean {
  const range = methodRange(ir, b);
  const blocks = ir.cfg.blocks.filter(x => !range || (x.start_line >= range.start && x.end_line <= range.end));
  const holding = (line: number) => blocks.find(x => x.start_line <= line && line <= x.end_line);
  const ba = holding(a);
  const bb = holding(b);
  if (!ba || !bb) return false;
  const entry = blocks.find(x => x.type === 'entry') ?? blocks.slice().sort((x, y) => x.id - y.id)[0];
  return new DominatorGraph(ir.cfg, entry.id).dominates(ba.id, bb.id);
}

function guardOf(ctx: FileCtx, sink: PathSink, pathVars: Set<string>): PathGuard | undefined {
  if (!ctx.branches) return undefined;
  const call = sinkCallOf(ctx, sink);
  const vars = new Set([...pathVars, ...identifiers(call ? operands(call) : sink.code)]);
  const declId = sink.decl.id;
  for (const fact of ctx.branches) {
    if (fact.line >= sink.line) continue;
    if (declAt(ctx.file, ctx.ir, fact.line, ctx.ids).id !== declId) continue;
    const side = sideOf(fact, sink.line);
    if (side === 'both') continue;
    for (const bc of fact.calls) {
      const ir = ctx.ir.calls.find(c => c.location.line === bc.line && c.method_name === bc.method);
      if (!ir || ![...identifiers(operands(ir))].some(n => vars.has(n))) continue;
      if (!lineDominates(ctx.ir, fact.line, sink.line)) continue;
      return { file: ctx.file, line: fact.line, method: bc.method, negated: bc.negated, sinkSide: side, callValue: side !== bc.negated };
    }
  }
  return undefined;
}

/** The pin-independent key of a path. */
export function pathKey(cwe: string, sourceAnchor: string, sinkAnchor: string): string {
  return digest128([PATH_KEY_SCHEME, cwe, sourceAnchor, sinkAnchor]);
}

// ---------------------------------------------------------------------------
// Unresolved edges on a path
// ---------------------------------------------------------------------------

function methodSpan(ir: CircleIR, line: number): { start: number; end: number } | undefined {
  let best: { start: number; end: number } | undefined;
  for (const t of ir.types) {
    for (const m of t.methods) {
      if (line < m.start_line || line > m.end_line) continue;
      if (!best || m.end_line - m.start_line < best.end - best.start) best = { start: m.start_line, end: m.end_line };
    }
  }
  return best;
}

/**
 * The lines a path occupies, per file: source, sink (and intermediate sink)
 * and hop lines, plus the lines in the source's and sink's declarations that
 * use one of the path's variables.
 */
function pathLines(ctxByFile: Map<string, FileCtx>, v: { source: PathSource; sink: PathSink; hops: PathHop[] }): Map<string, Set<number>> {
  const out = new Map<string, Set<number>>();
  const add = (file: string, line: number): void => {
    let s = out.get(file);
    if (!s) out.set(file, (s = new Set()));
    s.add(line);
  };
  add(v.source.file, v.source.line);
  add(v.sink.file, v.sink.line);
  if (v.sink.intermediate) add(v.sink.file, v.sink.intermediate.line);
  for (const h of v.hops) add(h.file, h.line);
  const vars = new Set(v.hops.map(h => h.variable).filter((x): x is string => !!x));
  for (const end of [v.source, v.sink]) {
    const ctx = ctxByFile.get(end.file);
    if (!ctx || vars.size === 0) continue;
    const span = methodSpan(ctx.ir, end.line);
    if (!span) continue;
    for (const u of ctx.ir.dfg.uses) {
      if (u.line >= span.start && u.line <= span.end && vars.has(u.variable)) add(end.file, u.line);
    }
  }
  return out;
}

function unresolvedOn(
  ctxByFile: Map<string, FileCtx>,
  projectTypes: Set<string>,
  crossFile: PathSetInput['cross_file_calls'],
  lines: Map<string, Set<number>>,
  sink: PathSink,
): PathUnresolved {
  const sites: UnresolvedSite[] = [];
  const inProject = (cands: string[] | undefined): boolean =>
    (cands ?? []).some(c => projectTypes.has(c.split('.').slice(0, -1).pop() ?? c));
  for (const [file, set] of lines) {
    const ctx = ctxByFile.get(file);
    if (!ctx) continue;
    for (const u of ctx.ir.unresolved) {
      if (!set.has(u.context.line)) continue;
      // the unresolved call is the sink call itself: same line, and its candidate (or its text) names the sink's method
      const methods = (u.context.candidates ?? []).map(c => c.split('.').pop() ?? c);
      const atSink = file === sink.file && u.context.line === sink.line && !!sink.call.method &&
        (methods.length > 0 ? methods.includes(sink.call.method) : u.context.code.includes(`${sink.call.method}(`));
      sites.push({ file, line: u.context.line, type: u.type, reason: u.reason, code: u.context.code, atSink, inProject: inProject(u.context.candidates) });
    }
  }
  for (const c of crossFile ?? []) {
    if (c.resolved || !lines.get(c.from.file)?.has(c.from.line)) continue;
    sites.push({
      file: c.from.file, line: c.from.line, type: 'cross_file_call', reason: 'unresolved_cross_file_call',
      code: `${c.from.method} -> ${c.to.file}#${c.to.method}`, atSink: false, inProject: true,
    });
  }
  sites.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || a.type.localeCompare(b.type) || a.code.localeCompare(b.code)));
  return { count: sites.length, sites };
}

// ---------------------------------------------------------------------------
// One tree
// ---------------------------------------------------------------------------

interface Variant {
  source: PathSource;
  sink: PathSink;
  sanitized: boolean;
  guard?: PathGuard;
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
    const br = options.branches?.[f.file];
    if (br) ctx.branches = br;
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

  // Endpoints and guards (see endpointOf / guardOf), and template hand-offs.
  const templateFacts = Object.values(options.templates ?? {}).flat();
  for (const v of variants) {
    const kctx = ctxByFile.get(v.sink.file) as FileCtx;
    v.sink = endpointOf(kctx, v.sink);
    const uses = templateUsesOf(kctx, v.sink, templateFacts);
    if (uses.length > 0) v.sink = { ...v.sink, templates: uses };
    if (v.sanitized) continue;
    const pathVars = new Set(v.hops.map(h => h.variable).filter((x): x is string => !!x));
    const g = guardOf(kctx, v.sink, pathVars);
    if (g) v.guard = g;
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

  const projectTypes = new Set(project.files.flatMap(f => f.analysis.types.map(t => t.name)));
  const paths: PathEntry[] = [];
  const files = new Set<string>();
  const schemes = new Set<DeclKeyScheme>();
  for (const [key, group] of byKey) {
    const ids = [...group.keys()].sort();
    const all = ids.flatMap(id => group.get(id) as Variant[]);
    const first = (group.get(ids[0]) as Variant[])[0];
    // a variant is open if any of its observations is neither sanitized nor guarded
    const open = ids.some(id => (group.get(id) as Variant[]).some(v => !v.sanitized && !v.guard));
    const guard = all.find(v => !v.sanitized && v.guard)?.guard;
    const state: PathEntry['state'] = open ? 'present' : guard ? 'guarded' : 'sanitized';
    const entry: PathEntry = {
      key,
      cwe,
      source: first.source,
      sink: first.sink,
      state,
      variants: ids.length,
      hops: first.hops,
      confidence: Math.max(...all.map(v => v.confidence)),
      unresolved: { count: 0, sites: [] },
    };
    if (state === 'guarded' && guard) entry.guard = guard;
    // unresolved edges over the lines of every variant of this path
    const lines = new Map<string, Set<number>>();
    for (const v of all) {
      for (const [f, set] of pathLines(ctxByFile, v)) {
        const acc = lines.get(f);
        if (acc) for (const l of set) acc.add(l);
        else lines.set(f, new Set(set));
      }
    }
    entry.unresolved = unresolvedOn(ctxByFile, projectTypes, project.cross_file_calls, lines, first.sink);
    paths.push(entry);
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
    if (after === 'guarded') return 'guarded';
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
  const counts: Record<PathChange, number> = { removed: 0, sanitized: 0, guarded: 0, unchanged: 0, added: 0, other: 0 };
  const entries = keys.map(key => {
    const pb = b.get(key);
    const pa = a.get(key);
    const state = { before: pb?.state ?? ('absent' as const), after: pa?.state ?? ('absent' as const) };
    const change = changeOf(state.before, state.after);
    counts[change]++;
    const entry: PathDiffEntry = { key, state, change };
    if (pb) entry.before = pb;
    if (pa) entry.after = pa;
    // the view this path hands to rendered it differently at the two versions
    if (pb?.sink.templates || pa?.sink.templates) {
      const shape = (p?: PathEntry) => JSON.stringify((p?.sink.templates ?? []).map(t => [t.file, t.engine, t.construct, t.attributes, t.inAttribute ?? null]));
      if (shape(pb) !== shape(pa)) entry.templateChanged = true;
    }
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
  options: {
    cwe: string | number;
    stableIds?: { before?: Record<string, StableIdFile>; after?: Record<string, StableIdFile> };
    branches?: { before?: Record<string, BranchFact[]>; after?: Record<string, BranchFact[]> };
    templates?: { before?: Record<string, TemplateFact[]>; after?: Record<string, TemplateFact[]> };
  },
): PathSetDiff {
  const at = (pin: 'before' | 'after'): PathSetOptions => {
    const o: PathSetOptions = { cwe: options.cwe };
    const ids = options.stableIds?.[pin];
    if (ids) o.stableIds = ids;
    const br = options.branches?.[pin];
    if (br) o.branches = br;
    const tp = options.templates?.[pin];
    if (tp) o.templates = tp;
    return o;
  };
  const setB = pathSetOf(before, at('before'));
  const setA = pathSetOf(after, at('after'));
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
