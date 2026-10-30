/**
 * Remedy-class matcher: for every sink of a path that a version pair closed,
 * report which row of a caller-supplied `safe-construct-table@0.1` the fixed
 * code matches, or that none does, or that the matcher could not observe a
 * row. Facts only: `class` and `remedyClass` are copied from the table, and
 * nothing here judges whether a fix is adequate.
 *
 * Steps are looked for in the same declaration at the fix version as the
 * baseline sink, on the IR circle-ir already produces: calls (receiver,
 * receiver type, arguments, imports), DFG defs, uses and def-to-def chains,
 * and the fix version's taint sources.
 *
 * Observed: `call` (type, methods, arg, ctor, static), `arg-is: tainted |
 * untainted | from-allowlist`, `arg-literal-in`, `role: sink-replacement |
 * binder | sanitizer | guard | normalizer`, `on`, `name` / `order`, `any`,
 * `all`, `missing`, `sink-removed`. A guard needs branch facts
 * (`deriveBranchFacts`) for the fix version's files. Not observed:
 * `template` and `receiver-from` on a step. A row that needs a step it
 * cannot observe **abstains**; it is never reported as unmatched.
 *
 * Pure: IR in, values out. Browser and Node compatible.
 */

import { sideOf, type BranchFact } from '../path-set/branches.js';
import { handedNames, lineDominates, qualifiedMethodName, typePath } from '../path-set/path-set.js';
import type { TemplateFact } from '../path-set/templates.js';
import { htmlContextAt, javaStringLiterals, markupBefore, type OutputContext } from './output-context.js';
import type { DeclRef, PathChange, PathSetDiff, PathSink } from '../path-set/types.js';
import type { StableIdFile } from '../stable-ids/types.js';
import type { CallInfo, CircleIR, DFGDef, ProjectAnalysis } from '../types/index.js';
import type {
  ConstructClass,
  ConstructRow,
  LoadTableResult,
  MatchStep,
  SafeConstructTable,
  TableCall,
  TableProblem,
} from './table.js';

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/** How a call's type was matched to a table type, strongest first. */
/** `template`: the sink hands its value to a view, and the label comes from the template construct that renders it. */
export type TypeMatch = 'fqn' | 'import' | 'simple-name' | 'unresolved' | 'any' | 'template';

export interface StepObservation {
  /** Location of the step in the row, e.g. `/match/all/1`. */
  path: string;
  holds: boolean;
  /** Where the step held (the first witness call), at the fix version. */
  at?: { file: string; line: number };
  typeMatch?: TypeMatch;
}

export interface MatchedRow {
  id: string;
  class: ConstructClass;
  remedyClass: string;
  context?: string;
  steps: StepObservation[];
}

export type RemedyMatch = string | 'multiple' | 'unrecognized' | 'abstained';

export type RemedyReason =
  | 'sink-not-in-table'
  | 'no-row-holds'
  | 'step-outside-declaration'
  | 'declaration-not-found';

export interface RemedySinkObservation {
  /** `<path key>:sink` */
  anchor: string;
  pathKey: string;
  /**
   * `unchanged`: the path is still open in code at the fix version — observed
   * under `scope: 'all'`, or when `templateChanged` (the fix is in the view).
   */
  change: Extract<PathChange, 'removed' | 'sanitized' | 'guarded' | 'unchanged'>;
  /** The baseline sink. */
  sink: {
    /** Table sink id, or `unlisted` when no table sink has its call shape. */
    tableSink: string;
    tableSinkMatch?: TypeMatch;
    /** `call`: the sink call itself; `receiver-def`: the call that made its receiver (a constructor). */
    via?: 'call' | 'receiver-def' | 'template';
    /**
     * Only with `outputContext: true`: where in the HTML document the value lands
     * at the fix version, read from the markup written before it; `unknown` when
     * not read or not one context.
     */
    outputContext?: OutputContext;
    file: string;
    line: number;
    decl: DeclRef;
  };
  /** The view this path hands to renders it differently at the fix version. */
  templateChanged?: true;
  match: RemedyMatch;
  /** Copied from the table, and only when exactly one row matched. */
  class?: ConstructClass;
  /** Every matched row, in table order. */
  rows: MatchedRow[];
  /**
   * Only with `outputContext: true`: rows whose match held but whose `context`
   * is not the observed output context. They are not in `rows`.
   */
  contextExcludedRows?: { id: string; context: string }[];
  /** Applicable rows the matcher could not observe, with why. */
  abstainedRows: { id: string; reason: string }[];
  reason?: RemedyReason;
  /** Taint seeds used for `arg-is` at the fix version. */
  taintSeeds: 'sources' | 'sources+parameters';
  table: { format: string; cwe: number; language: string; version: string; digest: string };
}

export interface RemedyClassResult {
  table: RemedySinkObservation['table'];
  /** Sorted by anchor. */
  sinks: RemedySinkObservation[];
}

/** Thrown when the table was refused by the reader: no observation exists on a refused table. */
export class TableRefused extends Error {
  readonly problems: TableProblem[];
  readonly digest: string;
  constructor(digest: string, problems: TableProblem[]) {
    super(`safe-construct table ${digest} refused: ${problems.length} problem(s); first: ${problems[0]?.path} ${problems[0]?.message}`);
    this.name = 'TableRefused';
    this.problems = problems;
    this.digest = digest;
  }
}

// ---------------------------------------------------------------------------
// Declaration context at one version
// ---------------------------------------------------------------------------

interface DeclCtx {
  file: string;
  ir: CircleIR;
  branches?: BranchFact[];
  calls: CallInfo[];
  defs: DFGDef[];
  /** Def ids whose value derives from a taint seed. */
  tainted: Set<number>;
  /** Def-to-def reach (chains), computed on demand. */
  reach: (from: number) => Set<number>;
}

function inRange(line: number, r: { start: number; end: number }): boolean {
  return line >= r.start && line <= r.end;
}

/** The line range of a declaration at one version, or undefined when it is gone. */
function declRange(file: string, ir: CircleIR, decl: DeclRef, ids?: StableIdFile): { start: number; end: number } | 'by-method' | undefined {
  if (decl.scheme === 'ids@0.1') {
    const d = ids?.decls.find(x => x.id === decl.id);
    return d ? { start: d.start_line, end: d.end_line } : undefined;
  }
  const prefix = `${file}#`;
  if (!decl.id.startsWith(prefix)) return undefined;
  const qualified = decl.id.slice(prefix.length);
  for (const t of ir.types) {
    for (const m of t.methods) {
      if (qualifiedMethodName(t, m) === qualified) return { start: m.start_line, end: m.end_line };
    }
    if (qualified === `${typePath(t)}.<init>`) return { start: t.start_line, end: t.end_line };
  }
  if (qualified.startsWith('<module>')) return 'by-method';
  return undefined;
}

const IDENT = /[A-Za-z_$][\w$]*/g;
const STRING_LITERAL = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;

/** Identifiers in an expression, string literals removed. */
function identifiers(expr: string | null | undefined): Set<string> {
  return new Set((expr ?? '').replace(STRING_LITERAL, '""').match(IDENT) ?? []);
}

function buildCtx(
  file: string,
  ir: CircleIR,
  decl: DeclRef,
  ids: StableIdFile | undefined,
  seedParameters: boolean,
): DeclCtx | undefined {
  const range = declRange(file, ir, decl, ids);
  if (!range) return undefined;
  let calls: CallInfo[];
  let lineOk: (line: number) => boolean;
  if (range === 'by-method') {
    const method = decl.name.startsWith('<module>.') ? decl.name.slice('<module>.'.length) : null;
    calls = ir.calls.filter(c => (c.in_method ?? null) === method);
    const lines = new Set(calls.map(c => c.location.line));
    lineOk = l => lines.has(l);
  } else {
    calls = ir.calls.filter(c => inRange(c.location.line, range));
    lineOk = l => inRange(l, range);
  }
  const defs = ir.dfg.defs.filter(d => lineOk(d.line));
  const defIds = new Set(defs.map(d => d.id));
  const next = new Map<number, number[]>();
  for (const ch of ir.dfg.chains ?? []) {
    if (!defIds.has(ch.from_def) || !defIds.has(ch.to_def)) continue;
    const list = next.get(ch.from_def);
    if (list) list.push(ch.to_def);
    else next.set(ch.from_def, [ch.to_def]);
  }
  const reachCache = new Map<number, Set<number>>();
  const reach = (from: number): Set<number> => {
    const hit = reachCache.get(from);
    if (hit) return hit;
    const seen = new Set<number>([from]);
    const stack = [from];
    while (stack.length) {
      const d = stack.pop() as number;
      for (const n of next.get(d) ?? []) {
        if (!seen.has(n)) {
          seen.add(n);
          stack.push(n);
        }
      }
    }
    reachCache.set(from, seen);
    return seen;
  };

  const seeds: number[] = [];
  for (const s of ir.taint.sources) {
    if (!lineOk(s.line)) continue;
    for (const d of defs) {
      if (d.line === s.line && (s.variable === undefined || d.variable === s.variable)) seeds.push(d.id);
    }
  }
  if (seedParameters) for (const d of defs) if (d.kind === 'param') seeds.push(d.id);
  const tainted = new Set<number>();
  for (const s of seeds) for (const d of reach(s)) tainted.add(d);

  return { file, ir, calls, defs, tainted, reach };
}

/** Uses at `line` whose variable appears in `expr`, as their reaching def ids. */
function defsUsedIn(ctx: DeclCtx, line: number, expr: string | null | undefined): number[] {
  const names = identifiers(expr);
  const out: number[] = [];
  for (const u of ctx.ir.dfg.uses) {
    if (u.line === line && u.def_id !== null && names.has(u.variable)) out.push(u.def_id);
  }
  return out;
}

/** Does a source call appear inline in the expression at this line (`f(req.getParameter("x"))`)? */
function inlineSource(ctx: DeclCtx, line: number, expr: string): boolean {
  return ctx.ir.taint.sources.some(s => {
    if (s.line !== line) return false;
    const name = (s.method ?? s.location.split(' in ')[0].replace(/\(\)$/, '').split('.').pop() ?? '').trim();
    return name.length > 0 && expr.includes(`${name}(`);
  });
}

function argTainted(ctx: DeclCtx, call: CallInfo, expr: string): boolean {
  if (inlineSource(ctx, call.location.line, expr)) return true;
  return defsUsedIn(ctx, call.location.line, expr).some(d => ctx.tainted.has(d));
}

// ---------------------------------------------------------------------------
// Call shapes
// ---------------------------------------------------------------------------

const tail = (fqn: string): string => fqn.slice(fqn.lastIndexOf('.') + 1);
const pkg = (fqn: string): string => fqn.slice(0, Math.max(0, fqn.lastIndexOf('.')));
const RANK: Record<TypeMatch, number> = { fqn: 0, import: 1, any: 2, 'simple-name': 3, unresolved: 4, template: 5 };

function isCtor(c: CallInfo): boolean {
  return c.is_constructor === true || (c.receiver === null && !!c.receiver_type && c.receiver_type === c.method_name);
}

/** A receiver written as a type (`Runtime`, `org.owasp.encoder.Encode`): a static call. */
function staticReceiver(c: CallInfo): string | null {
  const r = c.receiver;
  if (!r || r.includes('(')) return null;
  const last = tail(r);
  return /^[A-Z]/.test(last) ? r : null;
}

function typeMatch(want: string, c: CallInfo, ir: CircleIR): TypeMatch | null {
  if (want === 'java.lang.Object') return 'any';
  const fqn = c.receiver_type_fqn ?? (staticReceiver(c)?.includes('.') ? staticReceiver(c) : null);
  if (fqn) return fqn === want ? 'fqn' : null;
  const simple = c.receiver_type ?? staticReceiver(c);
  if (!simple) {
    // receiver is a call expression or an untyped variable; an unqualified call is the enclosing class
    return c.receiver === null && !isCtor(c) ? null : 'unresolved';
  }
  if (simple.includes('.')) return simple === want ? 'fqn' : null;
  if (simple !== tail(want)) return null;
  const explicit = ir.imports.find(i => !i.is_wildcard && i.imported_name === simple);
  if (explicit) return `${explicit.from_package}.${simple}` === want ? 'import' : null;
  if (ir.imports.some(i => i.is_wildcard && i.from_package === pkg(want))) return 'import';
  if (pkg(want) === 'java.lang') return 'import';
  return 'simple-name';
}

function methodMatches(patterns: string[], name: string): boolean {
  return patterns.some(p => p === '*' || p === name || (p.endsWith('*') && name.startsWith(p.slice(0, -1))));
}

function shapeMatch(want: TableCall, c: CallInfo, ir: CircleIR): TypeMatch | null {
  if (want.ctor) {
    if (!isCtor(c)) return null;
    if (want.type === 'java.lang.Object') return 'any';
    const simple = c.receiver_type ?? c.method_name;
    return typeMatch(want.type, { ...c, receiver_type: simple, receiver: simple }, ir);
  }
  if (isCtor(c)) {
    // `methods: ["*"]` on `java.lang.Object` is any call at the sink, constructors included
    return want.type === 'java.lang.Object' && want.methods.includes('*') ? 'any' : null;
  }
  if (!methodMatches(want.methods, c.method_name)) return null;
  return typeMatch(want.type, c, ir);
}

function argsAt(c: CallInfo, arg: TableCall['arg']): string[] | null {
  if (arg === undefined) return null;
  if (arg === 'all') return c.arguments.map(a => a.expression);
  const a = c.arguments.find(x => x.position === arg);
  return a ? [a.expression] : [];
}

const VECTOR_LITERAL = /^\s*(?:new\s+[\w.]+\s*\[\s*\]\s*\{|[\w.]+\.(?:of|asList)\s*\()/;

/** Element 0 of an array or list literal (`new String[]{a, b}`, `List.of(a, b)`), as text; else null. */
function leadingElement(expr: string): string | null {
  const m = VECTOR_LITERAL.exec(expr);
  if (!m) return null;
  const rest = expr.slice(m[0].length);
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if ((ch === ')' || ch === ']' || ch === '}') && depth > 0) depth--;
    else if ((ch === ',' || ch === ')' || ch === '}') && depth === 0) return rest.slice(0, i).trim();
  }
  return rest.trim() || null;
}

/** The literal at an argument, or element 0 of an array or list literal there. */
function leadingLiteral(c: CallInfo, arg: TableCall['arg']): string | null {
  const a = c.arguments.find(x => x.position === (arg === 'all' || arg === undefined ? 0 : arg));
  if (!a) return null;
  if (a.literal !== null && a.literal !== undefined) return a.literal.trim();
  const first = leadingElement(a.expression);
  const m = first === null ? null : /^"((?:[^"\\]|\\.)*)"$/.exec(first);
  return m ? m[1].trim() : null;
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

interface Hit {
  call: CallInfo;
  typeMatch: TypeMatch;
}

interface StepResult {
  holds: boolean;
  /** Set when the step (or a child it depends on) cannot be observed in this version. */
  unobservable?: string;
  hits: Hit[];
}

interface EvalEnv {
  ctx: DeclCtx | undefined;
  /** Calls at the fix version that match one of the row's applies-to sinks. */
  sinkCalls: CallInfo[];
  /** Of those, the ones whose result feeds no other (the file access, not the path building). */
  endpointCalls: CallInfo[];
  pathRemoved: boolean;
  names: Map<string, Hit[]>;
  observed: StepObservation[];
  /** Template facts at the fix version that render the names this sink hands on; `null` = templates not read. */
  templateFacts: TemplateFact[] | null;
}

/** Def produced by a call: a def on its line when the call is the outermost call there. */
function resultDef(ctx: DeclCtx, c: CallInfo): DFGDef | undefined {
  const line = c.location.line;
  const others = ctx.calls.filter(x => x !== c && x.location.line === line);
  const inner = others.some(o =>
    (o.receiver ?? '').includes(`${c.method_name}(`) || o.arguments.some(a => a.expression.includes(`${c.method_name}(`)),
  );
  if (inner) return undefined;
  // several defs on one line (`try (Connection c = ..; PreparedStatement ps = ..)`): the def written
  // nearest before the call, by column; without columns, the only def on the line
  const onLine = ctx.defs.filter(d => d.line === line && d.kind !== 'param');
  if (onLine.length <= 1) return onLine[0];
  const before = onLine
    .filter(d => d.column !== undefined && d.column <= c.location.column)
    .sort((a, b) => (b.column as number) - (a.column as number));
  return before[0];
}

/** The call on the same line whose receiver or an argument holds `c` (`c` is nested in it). */
function enclosingCall(ctx: DeclCtx, c: CallInfo): CallInfo | undefined {
  return ctx.calls.find(o =>
    o !== c && o.location.line === c.location.line &&
    ((o.receiver ?? '').includes(`${c.method_name}(`) || o.arguments.some(a => a.expression.includes(`${c.method_name}(`))),
  );
}

/** Does `a`'s result (or receiver object) reach `b`'s receiver or an argument? */
function reaches(ctx: DeclCtx, a: CallInfo, b: CallInfo, depth = 0): boolean {
  const texts = [b.receiver ?? '', ...b.arguments.map(x => x.expression)];
  if (texts.some(t => t.includes(`${a.method_name}(`)) && a.location.line === b.location.line) return true;
  // a nested call reaches whatever the call holding it reaches (`base.resolve(n).normalize()`)
  const outer = enclosingCall(ctx, a);
  if (outer && depth < 8) return outer === b || reaches(ctx, outer, b, depth + 1);
  const def = resultDef(ctx, a);
  if (def) {
    const reach = ctx.reach(def.id);
    return texts.some(t => defsUsedIn(ctx, b.location.line, t).some(d => reach.has(d)));
  }
  return reachesByName(ctx, a, b, texts);
}

/**
 * Fallback when the DFG holds no def for a call's result — the Java DFG records none for
 * try-with-resources resources or the locals declared in that block. A name that appears on
 * `a`'s line with no reaching def, and is not one of `a`'s own operands or a method name there,
 * is taken as declared from `a`; it reaches `b` when `b` uses it, also without a reaching def.
 */
function reachesByName(ctx: DeclCtx, a: CallInfo, b: CallInfo, texts: string[]): boolean {
  const line = a.location.line;
  const own = identifiers([a.receiver ?? '', ...a.arguments.map(x => x.expression)].join(' '));
  const methods = new Set(ctx.calls.filter(c => c.location.line === line).map(c => c.method_name));
  const declared = new Set(
    ctx.ir.dfg.uses
      .filter(u => u.line === line && u.def_id === null && !own.has(u.variable) && !methods.has(u.variable))
      .map(u => u.variable),
  );
  if (declared.size === 0) return false;
  const usedUndefined = new Set(ctx.ir.dfg.uses.filter(u => u.line === b.location.line && u.def_id === null).map(u => u.variable));
  return texts.some(t => [...identifiers(t)].some(n => declared.has(n) && usedUndefined.has(n)));
}

function unobservableReason(step: MatchStep, env: EvalEnv): string | undefined {
  if (step.template && env.templateFacts === null) return 'template-not-read';
  if (step.call?.receiverFrom) return 'step-not-observed:receiver-from';
  if (step.argLiteralIn && !step.call) return 'step-not-observed:arg-literal-in-without-call';
  if ((step.role === 'guard' || step.on !== undefined) && env.ctx && !env.ctx.branches) return 'step-not-observed:guard-without-branch-facts';
  return undefined;
}

function evalStep(step: MatchStep, path: string, env: EvalEnv): StepResult {
  const why = unobservableReason(step, env);
  if (why) {
    env.observed.push({ path, holds: false });
    return { holds: false, unobservable: why, hits: [] };
  }

  let result: StepResult;
  if (step.any || step.all) {
    const children = (step.any ?? step.all) as MatchStep[];
    const q = step.any ? 'any' : 'all';
    const rs = children.filter(c => !(c.order && Object.keys(c).length === 1))
      .map((c) => evalStep(c, `${path}/${q}/${children.indexOf(c)}`, env));
    if (step.any) {
      const holds = rs.some(r => r.holds);
      result = { holds, hits: rs.flatMap(r => r.hits) };
      if (!holds) {
        const u = rs.find(r => r.unobservable)?.unobservable;
        if (u) result.unobservable = u;
      }
    } else {
      const failed = rs.filter(r => !r.holds);
      const u = failed.find(r => r.unobservable)?.unobservable;
      result = { holds: failed.length === 0, hits: rs.flatMap(r => r.hits) };
      if (u && failed.every(r => r.unobservable)) result.unobservable = u;
      // order steps after their siblings have bound their names
      children.forEach((c, i) => {
        if (!(c.order && Object.keys(c).length === 1)) return;
        const holds = result.holds && orderHolds(c.order, env);
        env.observed.push({ path: `${path}/${q}/${i}`, holds });
        if (!holds) result.holds = false;
      });
    }
  } else if (step.missing) {
    const inner = evalStep(step.missing, `${path}/missing`, env);
    result = inner.unobservable ? { holds: false, unobservable: inner.unobservable, hits: [] } : { holds: !inner.holds, hits: [] };
    env.observed.push({ path, holds: result.holds });
  } else if (step.sinkRemoved) {
    const holds = env.pathRemoved && env.sinkCalls.length === 0;
    result = { holds, hits: [] };
    env.observed.push({ path, holds });
  } else if (step.template) {
    const want = step.template;
    const hit = (env.templateFacts ?? []).find(f => templateMatches(want, f));
    result = { holds: hit !== undefined, hits: [] };
    const obs: StepObservation = { path, holds: result.holds };
    if (hit) {
      obs.at = { file: hit.file, line: hit.line };
      obs.typeMatch = 'template';
    }
    env.observed.push(obs);
  } else if (step.call) {
    const hits = callHits(step, env);
    result = { holds: hits.length > 0, hits };
    const obs: StepObservation = { path, holds: result.holds };
    if (hits[0]) {
      obs.at = { file: env.ctx?.file ?? '', line: hits[0].call.location.line };
      obs.typeMatch = hits[0].typeMatch;
    }
    env.observed.push(obs);
  } else {
    // a step with only `order` outside an `all`, or `name`/`role` alone: nothing to observe
    result = { holds: false, unobservable: 'step-not-observed:empty', hits: [] };
    env.observed.push({ path, holds: false });
  }
  if (step.name) env.names.set(step.name, result.hits);
  return result;
}

function callHits(step: MatchStep, env: EvalEnv): Hit[] {
  const ctx = env.ctx;
  if (!ctx || !step.call) return [];
  const want = step.call;
  const out: Hit[] = [];
  for (const c of ctx.calls) {
    const tm = shapeMatch(want, c, ctx.ir);
    if (!tm) continue;
    // a sink-replacement is a call at the sink: it must have the shape of one of the row's sinks
    if (step.role === 'sink-replacement' && !env.sinkCalls.includes(c)) continue;
    if (step.argIs) {
      let exprs = argsAt(c, want.arg ?? 0) ?? [];
      if (exprs.length === 0) continue;
      if (step.argIs === 'from-allowlist') {
        if (!allowlisted(ctx, c, exprs)) continue;
      } else {
        // `untainted` on an argument vector (array or list literal) reads its program element, element 0
        if (step.argIs === 'untainted') exprs = exprs.map(e => leadingElement(e) ?? e);
        const flags = exprs.map(e => argTainted(ctx, c, e));
        if (step.argIs === 'tainted' && !flags.some(Boolean)) continue;
        if (step.argIs === 'untainted' && flags.some(Boolean)) continue;
      }
    }
    if ((step.role === 'guard' || step.on !== undefined) && !guards(ctx, c, step.on ?? true, env)) continue;
    if (step.argLiteralIn) {
      const lit = leadingLiteral(c, want.arg);
      if (lit === null || !step.argLiteralIn.includes(lit)) continue;
    }
    if (step.role === 'sanitizer' && !env.sinkCalls.some(s => s !== c && reaches(ctx, c, s))) continue;
    out.push({ call: c, typeMatch: tm });
  }
  out.sort((a, b) => a.call.location.line - b.call.location.line || a.call.location.column - b.call.location.column);
  return out;
}

/** Identifiers of an expression that name values, not called methods. */
function valueNames(expr: string): Set<string> {
  return identifiers(expr.replace(/[A-Za-z_$][\w$]*\s*\(/g, '('));
}

/**
 * A local variable chosen from a finite set of literals: at least two defs in
 * the declaration, and every def written with no call and no other variable on
 * its line (a `switch` or `if` chain of `v = "literal";`, or a bare declaration).
 */
function literalChoice(ctx: DeclCtx, name: string): boolean {
  const defs = ctx.defs.filter(d => d.variable === name);
  if (defs.length < 2 || defs.some(d => d.kind !== 'local')) return false;
  return defs.every(d =>
    !ctx.calls.some(c => c.location.line === d.line) &&
    !ctx.ir.dfg.uses.some(u => u.line === d.line && u.variable !== name),
  );
}

/**
 * `arg-is: from-allowlist`: no argument is tainted, and at least one names a
 * variable chosen from literals (`literalChoice`); the rest are literals or
 * untainted values. A `contains` guard over a literal set is not read in this
 * version (the switch and if-chain forms are).
 */
function allowlisted(ctx: DeclCtx, c: CallInfo, exprs: string[]): boolean {
  if (exprs.some(e => argTainted(ctx, c, e))) return false;
  return exprs.some(e => [...valueNames(e)].some(n => literalChoice(ctx, n)));
}

/**
 * `role: guard` with `on`: a branch whose condition makes this call decides
 * which side the endpoint sinks run on, and on that side the call returned
 * `on`; the condition's block dominates each of them in the CFG. The targets
 * are the endpoint sinks with a tainted argument, else all endpoint sinks.
 */
function guards(ctx: DeclCtx, c: CallInfo, on: boolean, env: EvalEnv): boolean {
  const fact = ctx.branches?.find(f => f.calls.some(bc => bc.line === c.location.line && bc.method === c.method_name));
  if (!fact) return false;
  const bc = fact.calls.find(x => x.line === c.location.line && x.method === c.method_name) as BranchFact['calls'][number];
  const tainted = env.endpointCalls.filter(t => t.arguments.some(a => argTainted(ctx, t, a.expression)));
  const targets = tainted.length > 0 ? tainted : env.endpointCalls;
  if (targets.length === 0) return false;
  return targets.every(t => {
    if (t.location.line <= fact.line) return false;
    const side = sideOf(fact, t.location.line);
    if (side === 'both') return false;
    return (side !== bc.negated) === on && lineDominates(ctx.ir, fact.line, t.location.line);
  });
}

function orderHolds(order: [string, string], env: EvalEnv): boolean {
  const ctx = env.ctx;
  const a = env.names.get(order[0]) ?? [];
  const b = env.names.get(order[1]) ?? [];
  if (!ctx) return false;
  return a.some(x => b.some(y => x.call !== y.call && reaches(ctx, x.call, y.call)));
}

// ---------------------------------------------------------------------------
// Table sinks
// ---------------------------------------------------------------------------

function tableSinkOf(
  table: SafeConstructTable,
  sink: PathSink,
  ir: CircleIR,
): { id: string; typeMatch: TypeMatch; via: 'call' | 'receiver-def' } | undefined {
  const atLine = ir.calls.filter(c => c.location.line === sink.line);
  const direct = atLine.filter(c => !sink.call.method || c.method_name === sink.call.method);
  // the call that made the sink's receiver (`new ProcessBuilder(..)` for `pb.start()`)
  const viaReceiver: CallInfo[] = [];
  for (const c of direct) {
    if (!c.receiver || c.receiver.includes('(')) continue;
    const use = ir.dfg.uses.find(u => u.line === c.location.line && u.variable === c.receiver && u.def_id !== null);
    const def = use ? ir.dfg.defs.find(d => d.id === use.def_id) : undefined;
    if (def) viaReceiver.push(...ir.calls.filter(x => x.location.line === def.line && isCtor(x)));
  }
  let best: { id: string; typeMatch: TypeMatch; via: 'call' | 'receiver-def' } | undefined;
  for (const ts of table.sinks) {
    if (!ts.call) continue;
    for (const [via, calls] of [['call', direct], ['receiver-def', viaReceiver]] as const) {
      for (const c of calls) {
        const tm = shapeMatch(ts.call, c, ir);
        if (!tm) continue;
        if (!best || RANK[tm] < RANK[best.typeMatch]) best = { id: ts.id, typeMatch: tm, via };
      }
    }
  }
  return best;
}

/** Does a template fact have the construct (and attribute value) a table entry names? */
function templateMatches(want: { engine: string; construct: string; attribute?: string; value?: string[] }, f: TemplateFact): boolean {
  if (want.engine !== f.engine || want.construct !== f.construct) return false;
  if (want.attribute === undefined) return true;
  const actual = f.attributes[want.attribute];
  if (want.value === undefined) return actual !== undefined;
  return want.value.includes(actual === undefined ? 'absent' : actual);
}

/** The template facts that render a name the sink call hands on. */
function linkedFacts(facts: Record<string, TemplateFact[]> | undefined, names: string[]): TemplateFact[] | null {
  if (!facts) return null;
  return Object.values(facts).flat().filter(f => f.names.some(n => names.includes(n)));
}

/**
 * A sink that hands its value to a view takes its label from the table's
 * template sinks: the construct that renders it at the baseline, else at the fix.
 */
function templateSinkOf(table: SafeConstructTable, before: TemplateFact[] | null, after: TemplateFact[] | null): string | undefined {
  for (const facts of [before, after]) {
    for (const ts of table.sinks) {
      if (ts.template && (facts ?? []).some(f => templateMatches(ts.template as { engine: string; construct: string; attribute?: string; value?: string[] }, f))) return ts.id;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export interface RemedyClassOptions {
  /** `ids@0.1` per file at each version, as given to `pathSetDiff`. */
  stableIds?: { before?: Record<string, StableIdFile>; after?: Record<string, StableIdFile> };
  /** Branch facts per file at the fix version (`deriveBranchFacts`); guard steps need them. */
  branches?: { after?: Record<string, BranchFact[]> };
  /**
   * Template facts per template file at each version (`deriveTemplateFacts`).
   * With them, a sink that hands its value to a view is labelled by the table's
   * template sinks and `template` steps are evaluated; without them those rows
   * abstain (`template-not-read`).
   */
  templates?: { before?: Record<string, TemplateFact[]>; after?: Record<string, TemplateFact[]> };
  /**
   * `closed` (default): sinks of paths the fix closed (`removed`, `sanitized`,
   * `guarded`), and of paths whose view now renders them differently
   * (`templateChanged`). `all`: also sinks of paths still open at the fix version
   * (`unchanged`), so a fix that left the path open can be described by the row
   * it used (a weak construct). An open path's observation is a description,
   * not a closed sink.
   */
  scope?: 'closed' | 'all';
  /**
   * Observe the output context at writer sinks (`sink.outputContext`) and hold
   * a row with a `context` only where it is that context; rows that held in
   * another context go to `contextExcludedRows`. Off by default: without it the
   * result is exactly what it was.
   */
  outputContext?: boolean;
}

/**
 * Observe, for every sink of a path `diff` reports `removed` or `sanitized`,
 * which row of `table` the fix version matches.
 *
 * `table` is the reader's result; a refused table throws `TableRefused`.
 */
export function remedyClassOf(
  diff: PathSetDiff,
  before: ProjectAnalysis,
  after: ProjectAnalysis,
  loaded: LoadTableResult,
  options: RemedyClassOptions = {},
): RemedyClassResult {
  if (!loaded.ok) throw new TableRefused(loaded.digest, loaded.problems);
  const table = loaded.table;
  if (`CWE-${table.cwe}` !== diff.cwe) throw new Error(`remedy-class: table is CWE-${table.cwe}, path set is ${diff.cwe}`);
  const tableInfo = { format: table.format, cwe: table.cwe, language: table.language, version: table.version, digest: loaded.digest };
  const irBefore = new Map(before.files.map(f => [f.file, f.analysis]));
  const irAfter = new Map(after.files.map(f => [f.file, f.analysis]));
  const rows = table.constructs.filter(r => r.retired === undefined);

  const sinks: RemedySinkObservation[] = [];
  for (const e of diff.entries) {
    // a path still open in code whose view now renders it differently was fixed in the view:
    // observed in both scopes, with `templateChanged`
    const observed = e.change === 'removed' || e.change === 'sanitized' || e.change === 'guarded'
      || (e.change === 'unchanged' && (options.scope === 'all' || e.templateChanged === true));
    if (!observed || !e.before) continue;
    const base = e.before;
    const seedParameters = base.source.decl.id !== base.sink.decl.id;
    const obs: RemedySinkObservation = {
      anchor: `${e.key}:sink`,
      pathKey: e.key,
      change: e.change as RemedySinkObservation['change'],
      ...(e.templateChanged ? { templateChanged: true as const } : {}),
      sink: { tableSink: 'unlisted', file: base.sink.file, line: base.sink.line, decl: base.sink.decl },
      match: 'unrecognized',
      rows: [],
      abstainedRows: [],
      taintSeeds: seedParameters ? 'sources+parameters' : 'sources',
      table: tableInfo,
    };
    sinks.push(obs);

    const beforeIr = irBefore.get(base.sink.file);
    const sinkCall = beforeIr?.calls.find(c => c.location.line === base.sink.line && (!base.sink.call.method || c.method_name === base.sink.call.method));
    const handed = handedNames(sinkCall);
    const factsBefore = handed.length > 0 ? linkedFacts(options.templates?.before, handed) : null;
    const factsAfter = handed.length > 0 ? linkedFacts(options.templates?.after, handed) : null;
    let label: { id: string; typeMatch: TypeMatch; via: 'call' | 'receiver-def' | 'template' } | undefined = beforeIr ? tableSinkOf(table, base.sink, beforeIr) : undefined;
    if (!label) {
      const id = templateSinkOf(table, factsBefore, factsAfter);
      if (id) label = { id, typeMatch: 'template', via: 'template' };
    }
    if (!label) {
      obs.reason = 'sink-not-in-table';
      continue;
    }
    obs.sink.tableSink = label.id;
    obs.sink.tableSinkMatch = label.typeMatch;
    obs.sink.via = label.via;

    const afterIr = irAfter.get(base.sink.file);
    const ids = options.stableIds?.after?.[base.sink.file];
    const ctx = afterIr ? buildCtx(base.sink.file, afterIr, base.sink.decl, ids, seedParameters) : undefined;
    const br = options.branches?.after?.[base.sink.file];
    if (ctx && br) ctx.branches = br;

    for (const row of rows) {
      if (!row.appliesTo.includes(label.id)) continue;
      const rowSinks = table.sinks.filter(s => row.appliesTo.includes(s.id) && s.call);
      const sinkCalls = ctx ? ctx.calls.filter(c => rowSinks.some(s => shapeMatch(s.call as TableCall, c, ctx.ir))) : [];
      const endpointCalls = ctx ? sinkCalls.filter(c => !sinkCalls.some(o => o !== c && reaches(ctx, c, o))) : [];
      const env: EvalEnv = { ctx, sinkCalls, endpointCalls, pathRemoved: e.change === 'removed', names: new Map(), observed: [], templateFacts: options.templates ? (factsAfter ?? []) : null };
      const r = evalStep(row.match, '/match', env);
      if (r.holds) obs.rows.push(matchedRow(row, env.observed));
      else if (r.unobservable) obs.abstainedRows.push({ id: row.id, reason: r.unobservable });
    }

    if (options.outputContext && ctx) {
      const labelled = table.sinks.find(x => x.id === label?.id);
      const oc = labelled?.call ? outputContextOf(ctx, labelled.call) : 'unknown';
      obs.sink.outputContext = oc;
      obs.contextExcludedRows = [];
      if (oc !== 'unknown') {
        const keep: MatchedRow[] = [];
        for (const r of obs.rows) {
          if (r.context !== undefined && r.context !== oc) obs.contextExcludedRows.push({ id: r.id, context: r.context });
          else keep.push(r);
        }
        obs.rows = keep;
      }
    }

    if (obs.rows.length === 1) {
      obs.match = obs.rows[0].id;
      obs.class = obs.rows[0].class;
    } else if (obs.rows.length > 1) {
      obs.match = 'multiple';
    } else if (obs.abstainedRows.length > 0) {
      obs.match = 'abstained';
    } else {
      obs.reason = ctx ? 'no-row-holds' : 'declaration-not-found';
    }
  }
  sinks.sort((a, b) => (a.anchor < b.anchor ? -1 : a.anchor > b.anchor ? 1 : 0));
  return { table: tableInfo, sinks };
}

/**
 * The output context at the fix version's writer sinks of this shape: the
 * markup written before the first tainted value in each call's argument,
 * after any literal-only writes to the same writer earlier in the declaration.
 * One context across the calls, else `unknown`.
 */
function outputContextOf(ctx: DeclCtx, sinkShape: TableCall): OutputContext {
  const names = new Set(ctx.defs.filter(d => ctx.tainted.has(d.id)).map(d => d.variable));
  const calls = ctx.calls
    .filter(c => shapeMatch(sinkShape, c, ctx.ir) !== null)
    .sort((a, b) => a.location.line - b.location.line || a.location.column - b.location.column);
  const seen = new Set<OutputContext>();
  for (const c of calls) {
    const expr = c.arguments[0]?.expression;
    if (!expr) continue;
    const local = markupBefore(expr, names);
    if (local === null) continue;
    const earlier = calls
      .filter(o => o !== c && o.receiver === c.receiver &&
        (o.location.line < c.location.line || (o.location.line === c.location.line && o.location.column < c.location.column)))
      .map(o => o.arguments[0]?.expression ?? '')
      .filter(x => x.trim().startsWith('"') && markupBefore(x, names) === null && !/[A-Za-z_$]\s*\(/.test(x.replace(/"(?:[^"\\]|\\.)*"/g, '')))
      .map(x => javaStringLiterals(x).join(''));
    seen.add(htmlContextAt(earlier.join('') + local));
  }
  return seen.size === 1 ? [...seen][0] : 'unknown';
}

function matchedRow(row: ConstructRow, observed: StepObservation[]): MatchedRow {
  const m: MatchedRow = { id: row.id, class: row.class, remedyClass: row.remedyClass, steps: [...observed].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) };
  if (row.context !== undefined) m.context = row.context;
  return m;
}
