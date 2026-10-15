/**
 * ParamSourceFlowGatePass — cognium-dev #292
 *
 * Drops taint flows whose ONLY evidence of untrusted input is a bare
 * function parameter (`source_type === 'interprocedural_param'`), unless the
 * caller opted in with `AnalyzerOptions.speculativeParamSources`.
 *
 * Why: `taint-matcher.ts` seeds every parameter of every non-private
 * function as an `interprocedural_param` source (untyped JS/Python params
 * unconditionally, Rust `&str` / `String`). `TaintPropagationPass` then
 * connects those seeds to any sink in the same function
 * (`detectParameterSinkFlows`, and the DFG propagator for Rust), so any
 * library function that takes a string and reaches a sink is reported —
 * `function answer(q) { client.chat.completions.create({... content: q}) }`
 * fires `prompt_injection`, `fn f(url: &str) { reqwest::get(url) }` fires
 * `ssrf`. The #267 opt-in (`SpeculativePromptParamSourcePass`) documents
 * that bare-parameter sources are speculative and off by default; this gate
 * makes the default flow list honour that contract for every sink type.
 *
 * Scope (measured on the benchmark corpora, see #292):
 *  - Java / C# are exempt. Java already gates `interprocedural_param` with
 *    the Tier 1/2/3 entry-point classifier (#128), and C# model-binding
 *    parameters (`[FromBody]` etc.) are emitted as `interprocedural_param`
 *    even though they are genuine request input (#273).
 *  - Parameters of recognised framework handlers are real request input and
 *    are kept: route-style decorators / annotations (`@app.route(...)`,
 *    `@router.get(...)`, `@Get()`), Rust route attributes (`#[get("/<x>")]`)
 *    and Rust handlers returning a web response type (`HttpResponse`,
 *    `impl Responder`, `impl warp::Reply`, ...).
 *  - A parameter that a real source in the same file feeds is kept
 *    (cognium-dev #684): `function grep(t) {…}` called as
 *    `grep(req.query.t)`, a class method called as `svc.run(req.body.c)`,
 *    a class constructed with `new C(req.query.u)`, or a function handed to
 *    an executor that runs it (`pool.submit(fn, q)`). A bare call never
 *    feeds a class method and a call through a receiver never feeds a
 *    module function. Arguments passed through a sanitizer do not count,
 *    and `external_taint_escape` stays gated.
 *
 * Only flows are gated; the source list is untouched, so passes and
 * consumers that read `taint.sources` (cross-file resolution, co-occurrence
 * scoring) see exactly what they saw before.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { InterproceduralPassResult } from './interprocedural-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { MethodInfo, TaintFlowInfo, TaintSource } from '../../types/index.js';

export interface ParamSourceFlowGateResult {
  /** True when the gate ran (flag unset, language in scope). */
  applied: boolean;
  /** Number of flows removed. */
  dropped: number;
  /** Removed-flow counts keyed by sink type. */
  droppedBySinkType: Record<string, number>;
}

/** Languages whose parameter seeding is already entry-point aware. */
const EXEMPT_LANGUAGES = new Set(['java', 'csharp']);

/**
 * Decorator / annotation text that marks an HTTP route handler. Matches the
 * decorator as captured by the extractors — with or without a receiver
 * (`app.route('/x')`, `router.get("/")`, `Get`, `Post(':id')`).
 */
const ROUTE_ANNOTATION =
  /(?:^|[.\s@])(?:route|api_route|get|post|put|patch|delete|head|options|websocket|api_view|view_config|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|All)\s*(?:\(|$)/i;

/** Rust route attributes (Rocket / actix-web / poem macros). */
const RUST_ROUTE_ATTR =
  /^\s*#\[\s*(?:[A-Za-z_][\w]*::)*(?:get|post|put|patch|delete|head|options|route|handler)\s*[(\]]/;

/** Rust return types that only a web handler produces. */
const RUST_HANDLER_RETURN =
  /\b(?:HttpResponse|Responder|Reply|IntoResponse|Response(?:<[^>]*>)?)\b/;

function enclosingMethod(methods: MethodInfo[], line: number): MethodInfo | undefined {
  let best: MethodInfo | undefined;
  for (const m of methods) {
    if (m.start_line <= line && line <= m.end_line) {
      if (!best || m.end_line - m.start_line < best.end_line - best.start_line) best = m;
    }
  }
  return best;
}

/** Collect the `#[...]` attribute lines directly above a Rust fn. */
function rustAttributesAbove(lines: string[], startLine: number): string[] {
  const out: string[] = [];
  for (let i = startLine - 2; i >= 0; i--) {
    const t = (lines[i] ?? '').trim();
    if (t.startsWith('#[')) { out.push(t); continue; }
    if (t === '' || t.startsWith('//')) continue;
    break;
  }
  return out;
}

export function isFrameworkHandler(method: MethodInfo, language: string, lines: string[]): boolean {
  if (method.annotations.some(a => ROUTE_ANNOTATION.test(a))) return true;
  if (language === 'rust') {
    if (rustAttributesAbove(lines, method.start_line).some(a => RUST_ROUTE_ATTR.test(a))) return true;
    if (method.return_type && RUST_HANDLER_RETURN.test(method.return_type)) return true;
  }
  return false;
}

/** Sources that stand for a constructor-injected field or a getter over one (#78). */
const FIELD_CARRIED_SOURCE = /constructor-injected field|returns tainted field/;

/**
 * Parameters that a real (non-parameter) source in this file actually feeds,
 * as `<method name>:<argument position>`, plus the classes constructed with
 * such an argument. A parameter-sourced flow whose parameter is fed this way
 * is not speculative: the caller that supplies the request value is in the
 * same file (`new Fetcher(req.query.url)`, `run(req.body.cmd)`).
 */
interface RealFedParams {
  params: Set<string>;
  classes: Set<string>;
}

/**
 * Calls that invoke a function passed to them with the arguments that follow
 * it, keyed by method name. The value is how many of those arguments are not
 * forwarded (`setTimeout(fn, delay, a)` passes only `a`). Executor and
 * scheduler shapes only: `pool.submit(fn, q)`,
 * `loop.run_in_executor(None, fn, q)`, `asyncio.to_thread(fn, q)`,
 * `loop.call_soon(fn, q)`, `setImmediate(fn, q)`, `process.nextTick(fn, q)`.
 */
const EXECUTOR_CALLEES: ReadonlyMap<string, number> = new Map([
  ['submit', 0], ['run_in_executor', 0], ['to_thread', 0], ['run_sync', 0],
  ['call_soon', 0], ['call_soon_threadsafe', 0], ['call_later', 0], ['call_at', 0],
  ['setImmediate', 0], ['nextTick', 0], ['queueMicrotask', 0],
  ['setTimeout', 1], ['setInterval', 1],
]);

/** `name` as a whole identifier (names may contain `$`). */
function identifierRe(name: string): RegExp {
  return new RegExp(`(?:^|[^\\w$.])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`);
}

function realFedParams(ctx: PassContext, sources: TaintSource[]): RealFedParams {
  const out: RealFedParams = { params: new Set(), classes: new Set() };
  const { graph } = ctx;
  const seeds = new Set<number>();
  const allMethods = graph.ir.types.flatMap(t => t.methods);
  // Variables a real source binds directly (`q = request.args.get("q")`),
  // with the method that binds them: a `name` bound in one handler says
  // nothing about a `name` local to another function. The Python DFG does
  // not model every function body, so the binding is the fallback evidence.
  const boundVars = new Map<string, Set<MethodInfo | undefined>>();
  // Source reads written inline as an argument (`sink(request.args.get("q"))`),
  // by line: the read's text as the source location names it.
  const inlineReads = new Map<number, string[]>();
  for (const s of sources) {
    if (s.type === 'interprocedural_param') continue;
    for (const d of graph.defsAtLine(s.line)) seeds.add(d.id);
    if (s.variable) {
      const where = boundVars.get(s.variable) ?? new Set<MethodInfo | undefined>();
      where.add(enclosingMethod(allMethods, s.line));
      boundVars.set(s.variable, where);
    }
    const read = /^([\w$.]+?)(?:\(\))? in /.exec(s.location ?? '')?.[1];
    if (read && read.includes('.')) inlineReads.set(s.line, [...(inlineReads.get(s.line) ?? []), read]);
  }
  const tainted = graph.propagateTaintedDefIds(seeds);
  // Sanitizer calls by line, as the bare method name (`shlex.quote()` -> `quote`).
  const sanitizerNames = new Map<number, string[]>();
  if (ctx.hasResult('sink-filter')) {
    for (const sa of ctx.getResult<SinkFilterResult>('sink-filter').sanitizers) {
      const name = /([\w$]+)\(?\)?$/.exec(sa.method)?.[1];
      if (name) sanitizerNames.set(sa.line, [...(sanitizerNames.get(sa.line) ?? []), name]);
    }
  }
  const classNames = new Set(graph.ir.types.map(t => t.name));
  const functionNames = new Set(graph.ir.types.flatMap(t => t.methods.map(m => m.name)));
  for (const call of graph.ir.calls) {
    const line = call.location.line;
    const uses = graph.usesAtLine(line).filter(u => u.def_id !== null && tainted.has(u.def_id));
    const reads = inlineReads.get(line) ?? [];
    const sanitizersHere = sanitizerNames.get(line) ?? [];
    const callMethod = enclosingMethod(allMethods, line);
    const isFed = (expr: string, variable: string | null | undefined): boolean =>
      // An argument passed through a sanitizer is not the raw request value.
      !sanitizersHere.some(n => expr.includes(`${n}(`)) && (
      (!!variable && !!boundVars.get(variable)?.has(callMethod)) ||
      reads.some(r => expr.includes(r)) ||
      // The argument's own identifiers, not those of a sibling argument.
      uses.some(u => identifierRe(u.variable).test(expr)));
    // A local function handed over by reference to a call that runs it
    // receives the arguments that follow it (`pool.submit(render, q)`,
    // `loop.run_in_executor(None, f, q)`). Only callees known to invoke their
    // function argument count: `print(banner, name)` or
    // `audit.record(banner, name)` only pass `banner` along.
    const skipAfterCallback = EXECUTOR_CALLEES.get(call.method_name);
    let callbackName: string | null = null;
    let callbackPos = -1;
    for (const arg of call.arguments) {
      const expr = typeof arg.expression === 'string' ? arg.expression.trim() : '';
      if (skipAfterCallback !== undefined && callbackName === null && functionNames.has(expr)) {
        callbackName = expr;
        callbackPos = arg.position;
        continue;
      }
      if (!isFed(expr, arg.variable)) continue;
      // `res.send(req.query.m)` is a call on another object; it feeds a
      // class method named `send`, never a module-level `function send`.
      out.params.add(`${call.receiver ? 'm' : 'f'}:${call.method_name}:${arg.position}`);
      if (classNames.has(call.method_name)) out.classes.add(call.method_name);
      if (callbackName !== null) {
        const pos = arg.position - callbackPos - 1 - (skipAfterCallback ?? 0);
        if (pos >= 0) out.params.add(`f:${callbackName}:${pos}`);
      }
    }
  }
  return out;
}

export class ParamSourceFlowGatePass implements AnalysisPass<ParamSourceFlowGateResult> {
  readonly name = 'param-source-flow-gate';
  readonly category = 'security' as const;

  constructor(private readonly keepParamSourcedFlows: boolean) {}

  run(ctx: PassContext): ParamSourceFlowGateResult {
    const result: ParamSourceFlowGateResult = { applied: false, dropped: 0, droppedBySinkType: {} };
    if (this.keepParamSourcedFlows || EXEMPT_LANGUAGES.has(ctx.language)) return result;
    if (!ctx.hasResult('interprocedural')) return result;
    const flows: TaintFlowInfo[] = ctx.getResult<InterproceduralPassResult>('interprocedural').additionalFlows;
    result.applied = true;
    if (flows.length === 0) return result;

    const methods = ctx.graph.ir.types.flatMap(t => t.methods);
    const lines = ctx.code.split('\n');
    const handlerCache = new Map<MethodInfo, boolean>();
    const isHandler = (m: MethodInfo): boolean => {
      let v = handlerCache.get(m);
      if (v === undefined) { v = isFrameworkHandler(m, ctx.language, lines); handlerCache.set(m, v); }
      return v;
    };

    // Lines that also carry a non-parameter source. Flows are deduplicated on
    // (source_line, sink_line, sink_type), so when a real source shares the
    // parameter's line (`function h(req) { const u = req.query.url; ... }`)
    // the surviving flow may cite the parameter while the evidence is the
    // real source. Those flows are kept.
    const realSourceLines = new Set<number>();
    const sources = ctx.hasResult('sink-filter') ? ctx.getResult<SinkFilterResult>('sink-filter').sources : [];
    for (const s of sources) {
      if (s.type !== 'interprocedural_param') realSourceLines.add(s.line);
    }

    // Computed on first need: most files have no parameter-only flow.
    let fed: RealFedParams | undefined;
    const fedByRealSource = (f: TaintFlowInfo, m: MethodInfo): boolean => {
      // The CWE-668 escape fallback names no concrete sink; a fed parameter
      // does not make it more than a hint, so it stays gated.
      if (f.sink_type === 'external_taint_escape') return false;
      fed ??= realFedParams(ctx, sources);
      if (fed.params.size === 0) return false;
      const owner = ctx.graph.ir.types.find(t => t.methods.includes(m));
      // A constructor is invoked through its class name (`new C(…)`, `C(…)`).
      const isCtor = (m.name === 'constructor' || m.name === '__init__') && !!owner;
      const callee = isCtor && owner ? owner.name : m.name;
      // A module-level function or a constructor is called without a
      // receiver; a class method is reached through one (`svc.run(x)`). Each
      // matches its own call shape only: a bare `send(req.query.m)` does not
      // run `Mailer.prototype.send`, and `res.send(…)` does not run a
      // module-level `function send`.
      const viaReceiver = !isCtor && !!owner && owner.name !== '<module>';
      const feeds = (pos: number): boolean =>
        fed!.params.has(`${viaReceiver ? 'm' : 'f'}:${callee}:${pos}`);
      // When the flow's first step names a parameter, only that parameter
      // counts: every parameter shares the signature line, and `f(a, b)`
      // called as `f(req.query.a, 'x')` does not feed `b`.
      const head = f.path[0]?.variable;
      const named = m.parameters.findIndex(p => p.name === head);
      if (named >= 0) return feeds(named);
      for (const s of sources) {
        if (s.line !== f.source_line || s.type !== 'interprocedural_param') continue;
        if (FIELD_CARRIED_SOURCE.test(s.location ?? '')) {
          if (owner && fed.classes.has(owner.name)) return true;
          continue;
        }
        // The source names its parameter in `variable` (Java / C#) or in its
        // location, `<type> <name> in <method>` (taint-matcher).
        const pos = m.parameters.findIndex(p => s.variable
          ? p.name === s.variable
          : (s.location ?? '').endsWith(` ${p.name} in ${m.name}`));
        if (pos < 0) continue;
        if (feeds(pos)) return true;
      }
      return false;
    };

    // In-place filter: `additionalFlows` is the list the analyzer assigns to
    // `taint.flows` after the pipeline.
    let w = 0;
    for (const f of flows) {
      let keep = true;
      if (f.source_type === 'interprocedural_param' && !realSourceLines.has(f.source_line)) {
        const m = enclosingMethod(methods, f.source_line);
        keep = m !== undefined && (isHandler(m) || fedByRealSource(f, m));
      }
      if (keep) flows[w++] = f;
      else {
        result.dropped++;
        result.droppedBySinkType[f.sink_type] = (result.droppedBySinkType[f.sink_type] ?? 0) + 1;
      }
    }
    flows.length = w;
    return result;
  }
}
