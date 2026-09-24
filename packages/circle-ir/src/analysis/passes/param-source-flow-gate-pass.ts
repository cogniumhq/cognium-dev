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
 *
 * Only flows are gated; the source list is untouched, so passes and
 * consumers that read `taint.sources` (cross-file resolution, co-occurrence
 * scoring) see exactly what they saw before.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { InterproceduralPassResult } from './interprocedural-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { MethodInfo, TaintFlowInfo } from '../../types/index.js';

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
    if (ctx.hasResult('sink-filter')) {
      const sources = ctx.getResult<SinkFilterResult>('sink-filter').sources;
      for (const s of sources) {
        if (s.type !== 'interprocedural_param') realSourceLines.add(s.line);
      }
    }

    // In-place filter: `additionalFlows` is the list the analyzer assigns to
    // `taint.flows` after the pipeline.
    let w = 0;
    for (const f of flows) {
      let keep = true;
      if (f.source_type === 'interprocedural_param' && !realSourceLines.has(f.source_line)) {
        const m = enclosingMethod(methods, f.source_line);
        keep = m !== undefined && isHandler(m);
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
