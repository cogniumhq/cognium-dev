/**
 * TaintPropagationPass
 *
 * Propagates taint through the DFG to find verified source-to-sink flows,
 * then supplements with three additional flow-detection strategies that the
 * DFG-based analysis may miss:
 *   - Array element flows (tainted array[idx] → sink)
 *   - Collection/iterator flows (list.get(), queue.poll(), etc.)
 *   - Direct parameter-to-sink flows (interprocedural parameter used at sink)
 *
 * Depends on: sink-filter, constant-propagation
 */

import type { TaintFlowInfo } from '../../types/index.js';
import type { CircleIR } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import { propagateTaint } from '../taint-propagation.js';
import { isFalsePositive, isCorrelatedPredicateFP } from '../constant-propagation.js';
import { buildJavaTaintedVars, buildPythonTaintedVars, buildRustTaintedVars } from './language-sources-pass.js';
import { canSourceReachSink, sourceSemanticsAllowed } from '../findings.js';

export interface TaintPropagationPassResult {
  flows: TaintFlowInfo[];
}

export class TaintPropagationPass implements AnalysisPass<TaintPropagationPassResult> {
  readonly name = 'taint-propagation';
  readonly category = 'security' as const;

  run(ctx: PassContext): TaintPropagationPassResult {
    const { graph } = ctx;
    const { calls, types } = graph.ir;

    const constProp   = ctx.getResult<ConstantPropagatorResult>('constant-propagation');
    const sinkFilter  = ctx.getResult<SinkFilterResult>('sink-filter');
    const { sources, sinks, sanitizers } = sinkFilter;

    if (sinks.length === 0) {
      return { flows: [] };
    }
    // No real sources, but Python may still synthesize sources from derived
    // tainted vars (e.g. for-loop iterables — cognium-dev #76/#83). Defer the
    // empty-source early-return for Python so detectExpressionScanFlows runs.
    const canSynthesize = ctx.language === 'python' && typeof ctx.code === 'string';
    if (sources.length === 0 && !canSynthesize) {
      return { flows: [] };
    }

    // DFG-based taint propagation
    const propagationResult = propagateTaint(graph, sources, sinks, sanitizers);

    // Filter flows: eliminate dead-code paths and constant-propagation FPs
    const verifiedFlows = propagationResult.flows.filter(flow => {
      if (constProp.unreachableLines.has(flow.sink.line)) return false;

      for (const step of flow.path) {
        const fpCheck = isFalsePositive(constProp, step.line, step.variable);
        if (fpCheck.isFalsePositive) return false;
      }

      if (isCorrelatedPredicateFP(constProp, flow)) return false;

      // Note: Sprint 9 #58.1 sanitizer-guard suppression (regex-allowlist
      // and similar positive sanitizer evidence) is applied as a uniform
      // final-pass filter below — see `sanitizedNames` block before return.

      return true;
    });

    // Convert to TaintFlowInfo format
    const flows: TaintFlowInfo[] = verifiedFlows.map(flow => ({
      source_line: flow.source.line,
      sink_line: flow.sink.line,
      source_type: flow.source.type,
      sink_type: flow.sink.type,
      path: flow.path.map(step => ({
        variable: step.variable,
        line: step.line,
        type: step.type,
      })),
      confidence: flow.confidence,
      sanitized: flow.sanitized,
    }));

    // Supplement: array element flows
    // Sprint 82 (#189) — dedup keys on (source_line, sink_line, sink_type) so
    // distinct sink-types at the same call site (e.g. `res.redirect` registered
    // as both `open_redirect` and `crlf`) both survive instead of the second
    // being silently dropped.
    const arrayFlows = detectArrayElementFlows(calls, sources, sinks, constProp.taintedArrayElements, constProp.unreachableLines, types) ?? [];
    for (const f of arrayFlows) {
      if (!flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line && x.sink_type === f.sink_type)) {
        flows.push(f);
      }
    }

    // Supplement: collection/iterator flows — with FP filtering
    const collectionFlows = detectCollectionFlows(calls, sources, sinks, constProp.tainted, constProp.unreachableLines, ctx.code, types) ?? [];
    for (const f of collectionFlows) {
      if (flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line && x.sink_type === f.sink_type)) continue;

      const flowForCheck = {
        source: { line: f.source_line },
        sink:   { line: f.sink_line   },
        path:   f.path.map(p => ({ variable: p.variable, line: p.line })),
      };
      if (isCorrelatedPredicateFP(constProp, flowForCheck)) continue;

      let isFP = false;
      for (const step of f.path) {
        if (isFalsePositive(constProp, step.line, step.variable).isFalsePositive) { isFP = true; break; }
      }
      if (isFP) continue;

      flows.push(f);
    }

    // Supplement: direct parameter-to-sink flows
    // Sprint 82 (#189) — sink-type-aware dedup (see arrayFlows comment).
    const paramFlows = detectParameterSinkFlows(types, calls, sources, sinks, constProp.unreachableLines, constProp.tainted, ctx.code) ?? [];
    for (const f of paramFlows) {
      if (!flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line && x.sink_type === f.sink_type)) {
        flows.push(f);
      }
    }

    // Supplement: expression-scan flows for assignment-style sources (#18).
    //
    // The DFG-based propagator above misses two important cases:
    //   1. Languages without a per-language DFG builder (Python falls through
    //      to buildJavaDFG which finds no `method_declaration` nodes and emits
    //      an empty DFG — defs=[], uses=[], chains=[]).
    //   2. Sink calls whose argument is a compound expression (e.g.
    //      `cur.execute("SELECT ... " + uid)`) where `arg.variable` is null
    //      because the arg node isn't a bare `identifier`.
    //
    // Both cases break the `arg.variable === use.variable` matching in
    // propagateTaint(). For sources that already carry an explicit `variable`
    // field (assignment-style sources from LanguageSourcesPass, e.g.
    // `findPythonAssignmentSources`), we can sidestep the DFG entirely:
    // scan each sink's call-argument expressions for that variable name as
    // an identifier-boundary match. This is language-agnostic but in practice
    // benefits Python the most because Java sources rarely set `variable`.
    const exprScanFlows = detectExpressionScanFlows(calls, sources, sinks, sanitizers, constProp.unreachableLines, constProp.tainted, ctx.code, ctx.language) ?? [];
    for (const f of exprScanFlows) {
      if (flows.some(x =>
        x.source_line === f.source_line &&
        x.sink_line === f.sink_line &&
        x.sink_type === f.sink_type
      )) continue;

      const flowForCheck = {
        source: { line: f.source_line },
        sink:   { line: f.sink_line   },
        path:   f.path.map(p => ({ variable: p.variable, line: p.line })),
      };
      if (isCorrelatedPredicateFP(constProp, flowForCheck)) continue;

      let isFP = false;
      for (const step of f.path) {
        if (isFalsePositive(constProp, step.line, step.variable).isFalsePositive) { isFP = true; break; }
      }
      if (isFP) continue;

      flows.push(f);
    }

    // Sprint 9 #58.1 — final pass: drop any flow whose source variable was
    // explicitly marked sanitized by a guard (e.g. regex-allowlist).
    // Applied to ALL flow generators (DFG-built and the four supplements)
    // so the suppression is uniform regardless of which path emitted the flow.
    const sanitizedNames = constProp.sanitizedVars;
    let finalFlows = sanitizedNames.size === 0 ? flows : flows.filter(f => {
      if (f.path.length === 0) return true;
      const sourceVar = f.path[0].variable;
      if (!sourceVar) return true;
      if (sanitizedNames.has(sourceVar)) return false;
      for (const s of sanitizedNames) {
        if (s.endsWith(`:${sourceVar}`)) return false;
      }
      return true;
    });

    // Sprint 24 (cognium-dev #102) — uniform line-keyed sanitizer
    // suppression. Drop any flow whose sink_line carries a registered
    // sanitizer that covers the flow's sink_type. Several supplementary
    // flow generators (detectCollectionFlows, detectArrayElementFlows,
    // detectParameterSinkFlows, detectExpressionScanFlows DFG-fallback
    // emission) push flows with `sanitized: false` without consulting
    // `sanitizersByLine`. This pass applies the suppression uniformly so
    // language-specific sanitizer detectors (e.g. Go map-allowlist guard,
    // html/template auto-escape) work regardless of which generator
    // emitted the flow.
    if (sanitizers && sanitizers.length > 0) {
      const sanitizersByLine = new Map<number, typeof sanitizers>();
      for (const san of sanitizers) {
        const arr = sanitizersByLine.get(san.line) ?? [];
        arr.push(san);
        sanitizersByLine.set(san.line, arr);
      }
      finalFlows = finalFlows.filter(f => {
        // Two-tier filter:
        //   - `external_taint_escape` (synthetic CWE-668 fallback): no
        //     precise variable tracking; sanitizer anywhere on the
        //     source→sink line range counts. (cognium-dev #102 FP-27.)
        //   - configured sinks: only a sanitizer AT the sink_line counts
        //     (the sanitizer call IS the sink call site, e.g. the
        //     map-allowlist guard sanitizer for the http.Get line). This
        //     preserves positive recall cases like cognium-dev #65 pt2
        //     where a bare `shlex.quote(host)` on a non-sink line does NOT
        //     sanitize a subsequent raw `host` reaching a command sink.
        if (f.sink_type === 'external_taint_escape') {
          const lo = Math.min(f.source_line, f.sink_line);
          const hi = Math.max(f.source_line, f.sink_line);
          for (let line = lo; line <= hi; line++) {
            const sansAtLine = sanitizersByLine.get(line);
            if (!sansAtLine) continue;
            for (const san of sansAtLine) {
              if ((san.sanitizes as readonly string[]).includes(f.sink_type)) {
                return false;
              }
            }
          }
          return true;
        }
        const sansAtSink = sanitizersByLine.get(f.sink_line);
        if (!sansAtSink || sansAtSink.length === 0) return true;
        for (const san of sansAtSink) {
          if ((san.sanitizes as readonly string[]).includes(f.sink_type)) {
            return false;
          }
        }
        return true;
      });
    }

    // cognium-dev #101 (Sprint 14 Phase C/D) — method-level Java post-sink
    // sanitizer idioms:
    //   - path_traversal: canonical-path-startsWith-throw guard
    //     (`new File(base, x)` followed by `x.getCanonicalPath().startsWith(
    //      base.getCanonicalPath() + File.separator)` + `throw`)
    //   - xxe: DocumentBuilderFactory hardening
    //     (`setFeature(...disallow-doctype-decl..., true)` or
    //      `setFeature(...external-general-entities..., false)`)
    // These idioms protect the entire method, so suppress all path_traversal /
    // xxe flows whose sink lies inside a method that contains the pattern.
    if (ctx.language === 'java' && typeof ctx.code === 'string') {
      finalFlows = finalFlows.filter(f => {
        if (f.sink_type !== 'path_traversal' && f.sink_type !== 'xxe') return true;
        if (!isInJavaSanitizedMethod(ctx.code as string, types, f.sink_line, f.sink_type)) return true;
        return false;
      });
    }

    // cognium-dev #105 (Sprint 21 B.2) — MongoDB value-bound filter sanitizer.
    // The `find/findOne/updateOne/deleteOne/aggregate` sinks fire on any
    // tainted dict-literal at arg[0], but pure value-equality dicts
    // (`{ user: name }`) are NOT operator-injection vectors: MongoDB only
    // interprets keys with a `$` prefix (e.g. `$where`, `$ne`, `$gt`) as
    // operators. When the sink's arg[0] is a literal object whose keys are
    // all non-`$`-prefixed identifiers/strings, drop the flow. The
    // operator-injection shape (`findOne(filter)` where `filter` is opaque
    // and may carry `$where`) remains a sink because the arg is not a
    // literal object.
    if (typeof ctx.code === 'string') {
      const sinkByLine = new Map<number, typeof sinks[number]>();
      for (const s of sinks) {
        if (s.type === 'nosql_injection') sinkByLine.set(s.line, s);
      }
      if (sinkByLine.size > 0) {
        finalFlows = finalFlows.filter(f => {
          if (f.sink_type !== 'nosql_injection') return true;
          const sink = sinkByLine.get(f.sink_line);
          if (!sink || !sink.code || !sink.method) return true;
          // cognium-dev #194 / #195 Sprint 54: value-bound suppression must
          // NOT fire when an HTTP-derived source variable lands in a value
          // position. Express body-parser and equivalent framework parsers
          // can normalize bracket-style query strings (`?u[$ne]=null`) into
          // objects, so even a `name: q` pair with tainted `q` from
          // req.query / req.body reaching the find filter is exploitable.
          // Non-HTTP sources (interprocedural_param, etc.) preserve the
          // Sprint 21 #105 FP-32 suppression — see repro-sprint21.test.ts.
          const sourceVar = f.path && f.path.length > 0 ? f.path[0].variable : null;
          const isHttpSource = typeof f.source_type === 'string' && f.source_type.startsWith('http_');
          const sourceVarForFilter = isHttpSource ? sourceVar : null;
          return !isMongoValueBoundFilter(sink.code, sink.method, sourceVarForFilter);
        });
      }
    }

    // cognium-dev #152 (reopen) — JS setInterval/setTimeout code_injection
    // sink fires only when arg[0] is a string. An `interprocedural_param`
    // source is an untyped JS function parameter whose runtime kind cannot
    // be proven at the call site; callers commonly pass function refs
    // (`function schedule(cb) { setTimeout(cb, 1000); }`), which is the
    // benign-callback shape, not eval-style code injection. Drop the flow
    // when the parameter is the only contributing source. Real string
    // sources (http_query/http_body/file_input/...) still flow because
    // they carry a different `source_type`. The earlier 3.96.0 gate in
    // `taint-matcher.ts` covers inline function literals at the sink site;
    // this gate covers the identifier-reference case that the matcher
    // cannot prove function-typed without type info (the unfixed scenario
    // in the #152 reopen comment).
    const setIntervalLines = new Set<number>();
    for (const s of sinks) {
      if (s.type === 'code_injection' &&
          (s.method === 'setInterval' || s.method === 'setTimeout')) {
        setIntervalLines.add(s.line);
      }
    }
    if (setIntervalLines.size > 0) {
      finalFlows = finalFlows.filter(f => {
        if (f.sink_type !== 'code_injection') return true;
        if (f.source_type !== 'interprocedural_param') return true;
        if (!setIntervalLines.has(f.sink_line)) return true;
        return false;
      });
    }

    // cognium-dev #49 — final dedup on (source_line, sink_line, sink_type).
    // The DFG propagator and the four supplementary detectors each emit
    // independently; merge-time dedup at the supplement seams is partial
    // (some only key on source_line+sink_line, not sink_type) and the
    // DFG result itself can contain near-duplicates when multiple
    // tainted-variable chains reach the same sink call (e.g. `xxe ×2` /
    // `xxe ×3` from #49). Keep the highest-confidence flow per key; on a
    // confidence tie keep the first occurrence.
    if (finalFlows.length > 1) {
      const bestByKey = new Map<string, TaintFlowInfo>();
      for (const f of finalFlows) {
        const key = `${f.source_line}|${f.sink_line}|${f.sink_type}`;
        const cur = bestByKey.get(key);
        if (!cur || f.confidence > cur.confidence) {
          bestByKey.set(key, f);
        }
      }
      finalFlows = finalFlows.filter(f => {
        const key = `${f.source_line}|${f.sink_line}|${f.sink_type}`;
        return bestByKey.get(key) === f;
      });
    }

    return { flows: finalFlows };
  }
}

/**
 * cognium-dev #105 (Sprint 21 B.2). Recognise MongoDB value-bound filter
 * dicts at the first argument of `find/findOne/updateOne/deleteOne/aggregate`
 * sink calls.
 *
 * MongoDB only interprets keys with a `$` prefix as query operators
 * (`$where`, `$ne`, `$gt`, `$regex`, …). A literal object whose top-level
 * keys are all plain identifiers/strings reduces to pure value-equality,
 * which is structurally incapable of operator-injection regardless of the
 * value expressions (the values are bound, not the keys).
 *
 * Recognised:
 *   - `findOne({ user: name })`
 *   - `findOne({ "user_id": id, status: 'active' })`
 *   - `find({ name })`  // shorthand
 *
 * NOT recognised (still fires):
 *   - `findOne(filter)`                 // opaque variable — may carry $where
 *   - `findOne({ $where: 'this.x' })`   // explicit operator
 *   - `findOne({ ...filter, name })`    // spread — opaque subset
 *
 * Scope: same-line literal at arg[0]. Multi-line dicts are conservatively
 * left alone — we prefer FP over FN on the operator-injection class.
 */
function isMongoValueBoundFilter(sinkCode: string, sinkMethod: string, sourceVar: string | null): boolean {
  if (!sinkCode || !sinkMethod) return false;
  // Locate the call site for the specific sink method to avoid matching
  // an inner call that happens to share a name.
  const callIdx = sinkCode.indexOf(`${sinkMethod}(`);
  if (callIdx < 0) return false;
  const openIdx = callIdx + sinkMethod.length;
  // Walk to matching close-paren, tracking nested `()` `{}` `[]` and skipping
  // string literals. Cap at 4 KiB to bound the scan on pathological inputs.
  let depth = 0;
  let braceDepth = 0;
  let bracketDepth = 0;
  let inString: string | null = null;
  let firstArgEnd = -1;
  let firstArgComma = -1;
  const limit = Math.min(sinkCode.length, openIdx + 4096);
  for (let i = openIdx; i < limit; i++) {
    const ch = sinkCode[i];
    if (inString) {
      if (ch === '\\' && i + 1 < limit) { i++; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) { firstArgEnd = i; break; }
    } else if (ch === '{') braceDepth++;
    else if (ch === '}') braceDepth--;
    else if (ch === '[') bracketDepth++;
    else if (ch === ']') bracketDepth--;
    else if (ch === ',' && depth === 1 && braceDepth === 0 && bracketDepth === 0) {
      if (firstArgComma < 0) firstArgComma = i;
    }
  }
  if (firstArgEnd < 0) return false;
  const argEnd = firstArgComma >= 0 ? firstArgComma : firstArgEnd;
  const firstArg = sinkCode.slice(openIdx + 1, argEnd).trim();
  if (!firstArg) return false;
  // Must be a literal object (`{...}`), not a bare identifier or spread.
  if (firstArg[0] !== '{' || firstArg[firstArg.length - 1] !== '}') return false;
  const body = firstArg.slice(1, -1).trim();
  if (!body) return false;
  // Strip string literals so `$` inside string values doesn't false-trip.
  const stripped = body.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '""');
  // Spread / rest disqualifies (opaque subset).
  if (/\.\.\./.test(stripped)) return false;
  // Any `$<word>:` key is an operator → not value-bound.
  if (/(^|[,{\s])\$[A-Za-z_]\w*\s*:/.test(stripped)) return false;
  // Quoted-string key starting with `$`.
  if (/(['"])\$[A-Za-z_]\w*\1\s*:/.test(body)) return false;
  // cognium-dev #194 / #195 Sprint 54: when the tainted source variable
  // appears in a value position of the literal, the filter is NOT inert —
  // framework body-parsers (Express bracket-notation, Flask request.args
  // returning array-form) can deliver an object/array payload that injects
  // operators via the value position. Conservatively check if the source
  // variable name appears as a token in any value position (after a `:`).
  if (sourceVar && /^[A-Za-z_]\w*$/.test(sourceVar)) {
    const escaped = sourceVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Word-boundary match anywhere in the (string-stripped) body.
    const tokenRe = new RegExp(`(?<![\\p{L}\\p{N}_])${escaped}(?![\\p{L}\\p{N}_])`, 'u');
    if (tokenRe.test(stripped)) return false;
  }
  return true;
}

/**
 * cognium-dev #101 (Sprint 14 Phase C/D). Detect Java method-level sanitizer
 * idioms that protect the entire method body from a given sink type.
 *
 * `path_traversal` — canonical-path-startsWith-throw guard. Used in OWASP
 *   path-traversal cheatsheet examples and is the standard Java idiom for
 *   confining a derived `new File(base, userInput)` to a known root.
 * `xxe` — DocumentBuilderFactory hardening via `setFeature`. The OWASP XXE
 *   cheatsheet lists `disallow-doctype-decl=true` and the two
 *   external-entity features as the canonical fix; presence of any of them
 *   on the factory in the method suffices.
 *
 * The check is method-scoped (using `types[].methods[]` start/end lines) and
 * conservative — it does NOT verify that the guarded factory is the one used
 * by the sink call. False-negatives are preferred over false-positives in
 * the FP corpus regression context the issue is about.
 */
function isInJavaSanitizedMethod(
  code: string,
  types: CircleIR['types'] | undefined,
  sinkLine: number,
  sinkType: string,
): boolean {
  if (!types || types.length === 0) return false;
  let methodStart = -1;
  let methodEnd = -1;
  for (const t of types) {
    for (const m of t.methods) {
      if (sinkLine >= m.start_line && sinkLine <= m.end_line) {
        methodStart = m.start_line;
        methodEnd = m.end_line;
        break;
      }
    }
    if (methodStart > 0) break;
  }
  if (methodStart < 0) return false;
  const lines = code.split('\n');
  // Lines are 1-indexed; slice is 0-indexed [start, end).
  const body = lines.slice(methodStart - 1, methodEnd).join('\n');
  if (sinkType === 'path_traversal') {
    // Canonical-path-startsWith-throw idiom.
    if (!/\.getCanonicalPath\s*\(/.test(body)) return false;
    if (!/\.startsWith\s*\([^)]*getCanonicalPath/.test(body)) return false;
    if (!/\bthrow\s+new\b/.test(body)) return false;
    return true;
  }
  if (sinkType === 'xxe') {
    // DocumentBuilderFactory / SAXParserFactory / XMLInputFactory hardening.
    // Any one of these features suffices per the OWASP XXE cheatsheet.
    const setFeatureRe =
      /\.setFeature\s*\(\s*"(?:[^"]*disallow-doctype-decl|[^"]*external-general-entities|[^"]*external-parameter-entities|[^"]*load-external-dtd)"/;
    if (setFeatureRe.test(body)) return true;
    // setProperty variant for XMLInputFactory: `XMLInputFactory.SUPPORT_DTD`.
    if (/\.setProperty\s*\([^,]*SUPPORT_DTD[^,]*,\s*false\s*\)/.test(body)) return true;
    return false;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helpers (moved verbatim from analyzer.ts)
// ---------------------------------------------------------------------------

function detectCollectionFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  taintedVars: Set<string>,
  unreachableLines: Set<number>,
  code?: string,
  types?: CircleIR['types'],
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Skip arguments that are not in the sink's dangerous positions
        if (sink.argPositions && sink.argPositions.length > 0 &&
            !sink.argPositions.includes(arg.position)) {
          continue;
        }
        if (arg.variable) {
          const varName = arg.variable;
          const scopedName = call.in_method ? `${call.in_method}:${varName}` : varName;
          if (taintedVars.has(varName) || taintedVars.has(scopedName)) {
            // Sprint 13 #70 — pick a source in the same method scope as the
            // sink, not blanket sources[0]. The varName-based match is
            // primary; method-scope is the tiebreaker; sources[0] is the
            // last-resort fallback to preserve existing behaviour when no
            // better source is available.
            const source = pickScopedSource(sources, sink.line, call.in_method ?? null, types, varName);
            if (source) {
              // cognium-dev #101 (Sprint 14 Phase E): when the picked source
              // has a binding variable that differs from the sink arg's
              // variable, AND the picked source's enclosing method differs
              // from the sink's enclosing method, treat the
              // taintedVars-set match as a cross-method bleed (e.g.
              // `cmd` from method-X's tainted set firing in method-Y
              // against an unrelated picker-fallback source). Same-method
              // cross-variable matches (e.g. `id` loop-var derived from
              // `input` source in the same method body) are preserved.
              if (
                source.variable &&
                source.variable !== varName &&
                source.in_method &&
                call.in_method &&
                source.in_method !== call.in_method
              ) {
                continue;
              }
              // Sprint 9 #56 / #58.3 — same reassign-to-literal guard as
              // detectExpressionScanFlows. Suppress when the variable is
              // demonstrably rewritten to a literal between source and sink.
              if (
                typeof code === 'string' &&
                isReassignedToLiteralBetween(code, varName, source.line, sink.line)
              ) {
                continue;
              }
              flows.push({
                source_line: source.line, sink_line: sink.line,
                source_type: source.type, sink_type: sink.type,
                path: [
                  { variable: varName, line: source.line, type: 'source' as const },
                  { variable: varName, line: sink.line,   type: 'sink'   as const },
                ],
                confidence: 0.8, sanitized: false,
              });
            }
          }
        }

        if (arg.expression) {
          const expr = arg.expression;
          // Pre-compiled patterns for collection taint propagation
          const collectionPatterns = [
            { method: 'getLast',  re: /(\w+)\.getLast\(/ },
            { method: 'getFirst', re: /(\w+)\.getFirst\(/ },
            { method: 'get',      re: /(\w+)\.get\(/ },
            { method: 'next',     re: /(\w+)\.next\(/ },
            { method: 'poll',     re: /(\w+)\.poll\(/ },
            { method: 'peek',     re: /(\w+)\.peek\(/ },
            { method: 'toArray',  re: /(\w+)\.toArray\(/ },
          ];
          for (const { re } of collectionPatterns) {
            const match = expr.match(re);
            if (match) {
              const collectionVar = match[1];
              const scopedCollection = call.in_method ? `${call.in_method}:${collectionVar}` : collectionVar;
              if (taintedVars.has(collectionVar) || taintedVars.has(scopedCollection)) {
                // Sprint 13 #70 — same method-scoped picker as above.
                const source = pickScopedSource(sources, sink.line, call.in_method ?? null, types, collectionVar);
                if (source) {
                  // cognium-dev #101 (Sprint 14 Phase E): cross-method
                  // bleed guard. See the analogous guard in the
                  // arg.variable branch above — only suppress when the
                  // picked source's binding variable differs AND lives
                  // in a different method scope from the sink.
                  if (
                    source.variable &&
                    source.variable !== collectionVar &&
                    source.in_method &&
                    call.in_method &&
                    source.in_method !== call.in_method
                  ) {
                    continue;
                  }
                  if (
                    typeof code === 'string' &&
                    isReassignedToLiteralBetween(code, collectionVar, source.line, sink.line)
                  ) {
                    continue;
                  }
                  flows.push({
                    source_line: source.line, sink_line: sink.line,
                    source_type: source.type, sink_type: sink.type,
                    path: [
                      { variable: collectionVar, line: source.line, type: 'source' as const },
                      { variable: collectionVar, line: sink.line,   type: 'sink'   as const },
                    ],
                    confidence: 0.75, sanitized: false,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return flows;
}

function detectArrayElementFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  taintedArrayElements: Map<string, Set<string>>,
  unreachableLines: Set<number>,
  types?: CircleIR['types'],
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Skip arguments that are not in the sink's dangerous positions
        if (sink.argPositions && sink.argPositions.length > 0 &&
            !sink.argPositions.includes(arg.position)) {
          continue;
        }
        const arrayAccessMatch = arg.expression?.match(/^(\w+)\[(\d+|[^[\]]+)\]$/);
        if (arrayAccessMatch) {
          const arrayName = arrayAccessMatch[1];
          const indexStr  = arrayAccessMatch[2];
          const taintedIndices = taintedArrayElements.get(arrayName);
          if (taintedIndices) {
            const isTainted = taintedIndices.has(indexStr) || taintedIndices.has('*');
            if (isTainted) {
              // Sprint 13 #70 — method-scoped source picker (see detectCollectionFlows).
              const source = pickScopedSource(sources, sink.line, call.in_method ?? null, types, arrayName);
              if (source) {
                flows.push({
                  source_line: source.line, sink_line: sink.line,
                  source_type: source.type, sink_type: sink.type,
                  path: [
                    { variable: arrayName,                    line: source.line, type: 'source' as const },
                    { variable: `${arrayName}[${indexStr}]`, line: sink.line,   type: 'sink'   as const },
                  ],
                  confidence: 0.85, sanitized: false,
                });
              }
            }
          }
        }
      }
    }
  }

  return flows;
}

function detectParameterSinkFlows(
  types: CircleIR['types'],
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  unreachableLines: Set<number>,
  tainted: Set<string>,
  code?: string,
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  const paramSourcesByMethod = new Map<string, Map<string, CircleIR['taint']['sources'][0]>>();
  for (const source of sources) {
    if (source.type === 'interprocedural_param') {
      const match = source.location.match(/(\S+)\s+(\S+)\s+in\s+(\S+)/);
      if (match) {
        const paramName  = match[2];
        const methodName = match[3];
        let methodParams = paramSourcesByMethod.get(methodName);
        if (!methodParams) { methodParams = new Map(); paramSourcesByMethod.set(methodName, methodParams); }
        methodParams.set(paramName, source);
      }
    }
  }

  if (paramSourcesByMethod.size === 0) return flows;

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      const methodName = call.in_method;
      if (!methodName) continue;
      const methodParamSources = paramSourcesByMethod.get(methodName);
      if (!methodParamSources) continue;

      for (const arg of call.arguments) {
        if (arg.variable) {
          // Skip arguments that are not in the sink's dangerous positions.
          // E.g., execSync(cmd, { cwd: path }) — only arg 0 is a command injection sink.
          if (sink.argPositions && sink.argPositions.length > 0 &&
              !sink.argPositions.includes(arg.position)) {
            continue;
          }
          const paramSource = methodParamSources.get(arg.variable);
          if (paramSource) {
            // Sprint 82 (#189) — sink-type-aware dedup so a sink registered
            // under multiple types at the same call site (e.g. `redirect` as
            // both `open_redirect` and `crlf`) emits a flow for each type.
            const exists = flows.some(f => f.source_line === paramSource.line && f.sink_line === sink.line && f.sink_type === sink.type);
            if (!exists) {
              if (
                typeof code === 'string' &&
                isReassignedToLiteralBetween(code, arg.variable, paramSource.line, sink.line)
              ) {
                continue;
              }
              // Note: DFG-flow filter handles sanitizer-guard suppression
              // via `sanitizedVars` (positive-evidence check).
              flows.push({
                source_line: paramSource.line, sink_line: sink.line,
                source_type: paramSource.type, sink_type: sink.type,
                path: [
                  { variable: arg.variable, line: paramSource.line, type: 'source' as const },
                  { variable: arg.variable, line: sink.line,        type: 'sink'   as const },
                ],
                confidence: 0.75, sanitized: false,
              });
            }
          }
        }
      }
    }
  }

  // types parameter is accepted for API compatibility; not used in current implementation
  void types;
  return flows;
}

/**
 * Detect taint flows by scanning sink call argument expressions for any
 * source-variable name (#18).
 *
 * Algorithm — for each source with an explicit `variable` field (set by
 * assignment-style source detectors such as `findPythonAssignmentSources`,
 * which records the LHS variable name when an HTTP/file/env call appears on
 * the RHS):
 *
 *   1. For every sink at a later line, look at its call-site arguments.
 *   2. Respect `sink.argPositions` — skip positions that aren't dangerous
 *      (e.g. `execSync(cmd, opts)` only flags arg 0).
 *   3. If the source `variable` appears as a `\b<var>\b` identifier-boundary
 *      match inside any dangerous argument's expression text, emit a flow.
 *
 * The word-boundary regex prevents accidental substring matches
 * (e.g. tainted `uid` does NOT match `uid_table`). Confidence is moderated
 * by both source and sink confidence and a 0.7 multiplier to keep these
 * expression-scan flows distinguishable from full DFG-tracked flows.
 *
 * This detector unblocks all non-XSS Python categories (sqli, pathtraver,
 * cmdi, xpathi, xxe, deserialization, codeinj, ldapi, redirect, trustbound)
 * which previously emitted `flows: []` because:
 *   - Python has no language-specific DFG builder (falls through to Java DFG
 *     which finds zero `method_declaration` nodes in Python ASTs), AND
 *   - Python call-arg extraction sets `arg.variable = null` for compound
 *     expressions like `"SELECT ... " + uid`.
 *
 * Java is unaffected because Java sources rarely set the `variable` field
 * (they come from getter pattern detection, `@RequestParam` annotations,
 * or YAML sink/source matches that operate at the receiver-type level).
 */

/**
 * Sprint 9 #56 / #58.3 — detect "reassign-to-literal" between a tainted
 * source line and a downstream sink line. When a tainted variable is
 * reassigned to a pure string literal on any intermediate line, the
 * original taint can no longer reach the sink and the flow is suppressed.
 *
 * Recognized patterns (one per line, considering only `srcLine+1 .. sinkLine-1`):
 *
 *   1. Naked literal reassignment (any language):
 *        var = "literal"
 *        var = 'literal'
 *        var := "literal"     (Go short var decl)
 *      Trailing `;` allowed.
 *
 *   2. Allowlist guard with literal fallback (Java/JS/TS):
 *        if (!ALLOWLIST.contains(var))      var = "literal";
 *        if (!ALLOWLIST.includes(var))      var = "literal";
 *        if (ALLOWLIST.indexOf(var) === -1) var = "literal";
 *
 *   3. Allowlist guard with literal fallback (Python):
 *        if var not in ALLOWLIST: var = "literal"
 *
 * Both the single-line and split-across-two-lines forms of (2)/(3) are
 * caught because (1) matches the literal-assignment line regardless of
 * what precedes it on the previous line.
 *
 * Conservatively requires the LHS to be exactly `var` (no attribute access,
 * no array indexing) so we never drop a flow whose downstream use is a
 * different member of the same object.
 */
function isReassignedToLiteralBetween(
  code: string,
  variable: string,
  srcLine: number,
  sinkLine: number,
): boolean {
  if (!variable || sinkLine - srcLine < 2) return false;
  // Bare identifiers only — attribute paths like `obj.attr` are not
  // simple variables and we shouldn't claim they were reassigned.
  if (!/^[A-Za-z_][\w]*$/.test(variable)) return false;
  const lines = code.split('\n');
  const lo = Math.max(0, srcLine); // line numbers are 1-based; lines[] 0-based.
  const hi = Math.min(lines.length, sinkLine - 1);
  // String-literal sub-pattern: double-quoted, single-quoted, or backtick.
  const strLit =
    `(?:"[^"\\\\]*(?:\\\\.[^"\\\\]*)*"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*'|\`[^\`\\\\]*(?:\\\\.[^\`\\\\]*)*\`)`;
  // (1) Naked literal reassignment, anchored at start of line.
  //     Accepts `=` and `:=` (Go).
  const reNaked = new RegExp(
    `^\\s*${variable}\\s*(?::?=)\\s*${strLit}\\s*;?\\s*$`,
  );
  // (2) Single-line allowlist guard with literal fallback. We accept any
  //     line that begins with an `if` and ends with `var = "literal"` on
  //     the same line. This matches Java's
  //     `if (!COLUMNS.contains(col)) col = "name";` and equivalents,
  //     including Python's `if col not in COLUMNS: col = "name"`. Greedy
  //     `.*` (not `.*?`) tolerates nested parentheses in the guard
  //     condition without needing a full expression parser.
  const reGuarded = new RegExp(
    `^\\s*if\\b.*\\b${variable}\\s*=\\s*${strLit}\\s*;?\\s*$`,
  );
  // (3) Switch-case / default literal reassignment (Java/JS/TS/Go).
  //     Matches single-line forms like:
  //       `case "daily":  cmd = "/usr/bin/report-daily";  break;`
  //       `default:       cmd = "/usr/bin/report-default"; break;`
  //     The fall-through `break;` is optional. Used by cognium-dev #101
  //     to suppress the switch→constant FP corpus.
  const reSwitchCase = new RegExp(
    `^\\s*(?:case\\b.*?|default\\s*):\\s*${variable}\\s*=\\s*${strLit}\\s*;?\\s*(?:break\\s*;?)?\\s*$`,
  );
  for (let i = lo; i < hi; i++) {
    const line = lines[i];
    if (!line) continue;
    if (reNaked.test(line) || reGuarded.test(line) || reSwitchCase.test(line)) return true;
  }
  return false;
}

function detectExpressionScanFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  sanitizers: CircleIR['taint']['sanitizers'],
  unreachableLines: Set<number>,
  tainted: Set<string>,
  code?: string,
  language?: string,
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  // Variable-name scan path: only consider sources that carry an explicit
  // variable name. The colocation path below (cognium-dev #83) runs even
  // when this set is empty, so we no longer early-return.
  const sourcesWithVar = sources.filter((s): s is typeof s & { variable: string } =>
    typeof s.variable === 'string' && s.variable.length > 0
  );

  // Per-alias sanitizer coverage (cognium-dev #65 pt2).
  //
  // When Python alias expansion (below) adds a derived variable like
  // `cmd` from `cmd = "ping " + shlex.quote(host)`, the assignment
  // line itself usually carries the sanitizer call. We record which
  // sink types each derived alias is sanitized against so flows of
  // those types can be marked sanitized at emission time. Without
  // this, `subprocess.run(cmd, shell=True)` on the next line is
  // reported as a command-injection FP even though `shlex.quote`
  // wraps the only tainted operand of the concat.
  //
  // Scope: only the alias map populated below uses this; bare-source
  // flows where the user passes the raw tainted var to a separate
  // `shlex.quote(host)` call (not part of an assignment) are
  // unaffected, because the sanitizer call alone does not actually
  // sanitize the original `host` variable.
  const aliasSanitizedFor = new Map<string, Set<string>>();

  // Python alias expansion (#20): seed the scan with not only direct source
  // variables (e.g. `uid` from `uid = request.form.get(...)`) but also any
  // derived/aliased variables produced by simple assignment chains, compound
  // expressions, container set/get round-trips (configparser), list append +
  // subscript reads, dict access, aug-assigns and for-loops. These are already
  // computed deterministically by `buildPythonTaintedVars` for sanitizer and
  // session-boundary checks; here we reuse the same map to fix the long tail
  // of "container round-trip / helper / alias" flows=0 false-negatives that
  // are the dominant driver of OWASP BenchmarkPython misses.
  //
  // We synthesize a virtual source for each derived var, anchored to the
  // earliest real source's line/type so reported flows still point at the
  // original `request.form.get(...)`-style source, not the alias.
  if (language === 'python' && typeof code === 'string') {
    const derived = buildPythonTaintedVars(code);
    if (derived.size > 0) {
      const existingVars = new Set(sourcesWithVar.map(s => s.variable));
      // Earliest real source — used as the anchor for synthetic source lines.
      // When no real source has a `variable` field, we fall back to a per-var
      // synthetic anchor at the derivation line (typical for the for-loop /
      // bare-inline cases targeted by cognium-dev #76 / #83).
      const hasRealSource = sourcesWithVar.length > 0;
      let anchor: typeof sourcesWithVar[0] | undefined = sourcesWithVar[0];
      if (anchor) {
        for (const s of sourcesWithVar) {
          if (s.line < anchor.line) anchor = s;
        }
      }
      for (const [varName, originLine] of derived) {
        if (!varName || existingVars.has(varName)) continue;
        // Don't shadow real sources; build a minimal synthetic record that
        // satisfies the scan loop below. When no real source exists, anchor
        // the synthetic source at the derivation line itself with a generic
        // `http_param` type — the for-loop / bare-inline patterns we want
        // to recover here are all web-request-derived in practice.
        if (hasRealSource && anchor) {
          sourcesWithVar.push({
            ...anchor,
            variable: varName,
          });
        } else {
          sourcesWithVar.push({
            type: 'http_param',
            location: `<derived> ${varName}`,
            severity: 'high',
            line: originLine,
            confidence: 0.9,
            variable: varName,
          });
        }
        existingVars.add(varName);
      }

      // cognium-dev #65 pt2: record per-alias sanitizer coverage.
      // For each derived alias `lhs = ... sanitizer(taintedVar) ...`,
      // pick up the sink types the sanitizer covers so flows of those
      // types can be marked sanitized when emitted below.
      if (sanitizers && sanitizers.length > 0) {
        const sanitizersByLine = new Map<number, typeof sanitizers>();
        for (const s of sanitizers) {
          const arr = sanitizersByLine.get(s.line) ?? [];
          arr.push(s);
          sanitizersByLine.set(s.line, arr);
        }
        const codeLines = code.split('\n');
        for (const [varName, originLine] of derived) {
          const lineSans = sanitizersByLine.get(originLine);
          if (!lineSans || lineSans.length === 0) continue;
          const lineText = codeLines[originLine - 1] ?? '';
          const rhsMatch = lineText.match(/^\s*\w+\s*=\s*(.+)$/);
          if (!rhsMatch) continue;
          const rhs = rhsMatch[1];
          for (const san of lineSans) {
            // Extract the final method-name token before the trailing `()`.
            // Handles:
            //   `realpath()`                → realpath
            //   `os.path.realpath()`        → realpath
            //   `Path(raw).resolve()`       → resolve (chained constructor)
            // Then verify by substring-matching `<name>(` in the RHS text,
            // which is sufficient evidence that the sanitizer call is on
            // this assignment's RHS.
            const sanMatch = san.method.match(/(\w+)\(\)$/);
            if (!sanMatch) continue;
            const sanName = sanMatch[1];
            if (!rhs.includes(`${sanName}(`)) continue;
            let set = aliasSanitizedFor.get(varName);
            if (!set) { set = new Set<string>(); aliasSanitizedFor.set(varName, set); }
            for (const t of san.sanitizes) set.add(t);
          }
        }
      }

      // cognium-dev #120: inherit sanitizer coverage through pure alias
      // copies. The block above only credits coverage when the sanitizer
      // call is on the assignment's RHS itself, so a one-hop indirection
      //   leaf_r = os.path.basename(request.args.get("f", ""))
      //   leaf   = leaf_r
      //   os.open(os.path.join(BASE, leaf), ...)
      // leaves `leaf` without `path_traversal` coverage and the
      // suppression check at sink-emission time misses, producing an FP.
      // Scan for pure `lhs = upstreamIdentifier` lines and propagate
      // `aliasSanitizedFor[upstream]` into `aliasSanitizedFor[lhs]` to a
      // fixpoint so chains of arbitrary length are handled.
      //
      // Soundness gate: the chain copy at line L only counts when it is
      // the LATEST origin of `lhs` per `derived`. If `lhs` is reassigned
      // to a fresh (unsanitized) source on a later line, `derived.get(lhs)`
      // points past L and we MUST NOT inherit — otherwise re-tainting
      // would be incorrectly suppressed.
      const aliasChains: Array<{ lhs: string; upstream: string; line: number }> = [];
      {
        const codeLines2 = code.split('\n');
        for (let i = 0; i < codeLines2.length; i++) {
          const ln = codeLines2[i];
          if (ln.trimStart().startsWith('#')) continue;
          const m = ln.match(/^\s*([\p{L}\p{N}_]+)\s*=\s*([\p{L}\p{N}_]+)\s*$/u);
          if (!m) continue;
          const lineNum = i + 1;
          const lhs = m[1];
          // Only keep chains where the copy is the LATEST origin of `lhs`.
          if (derived.get(lhs) !== lineNum) continue;
          aliasChains.push({ lhs, upstream: m[2], line: lineNum });
        }
      }
      if (aliasChains.length > 0) {
        let changed = true;
        let guard = 0;
        while (changed && guard < aliasChains.length + 2) {
          changed = false;
          guard++;
          for (const { lhs, upstream } of aliasChains) {
            const upCov = aliasSanitizedFor.get(upstream);
            if (!upCov || upCov.size === 0) continue;
            let downCov = aliasSanitizedFor.get(lhs);
            if (!downCov) { downCov = new Set<string>(); aliasSanitizedFor.set(lhs, downCov); }
            for (const t of upCov) {
              if (!downCov.has(t)) { downCov.add(t); changed = true; }
            }
          }
        }
      }
    }
  }

  // Rust alias expansion (#71): mirror the Python branch above so that
  // multi-level extractor chains like
  //   let form = f.into_inner();
  //   let path = form.path;
  //   fs::write(path, ...);
  // produce a flow back to the original `web::Form<T>` parameter source.
  // `buildRustTaintedVars` does a fixpoint over let-bindings + assignments
  // seeded with the real source variables.
  if (language === 'rust' && typeof code === 'string' && sourcesWithVar.length > 0) {
    const seedVars = new Set(sourcesWithVar.map(s => s.variable));
    const derived = buildRustTaintedVars(code, seedVars);
    if (derived.size > 0) {
      let anchor: typeof sourcesWithVar[0] = sourcesWithVar[0];
      for (const s of sourcesWithVar) {
        if (s.line < anchor.line) anchor = s;
      }
      const existingVars = new Set(sourcesWithVar.map(s => s.variable));
      for (const [varName] of derived) {
        if (!varName || existingVars.has(varName)) continue;
        sourcesWithVar.push({
          ...anchor,
          variable: varName,
        });
        existingVars.add(varName);
      }
    }
  }

  // Java alias expansion (cognium-dev #220): mirror the Rust branch so
  // that the array-form `Runtime.exec(String[])` shape
  //   String cmd = "echo " + arg;
  //   Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
  // produces a flow back to `arg`. Without this, the variable-scan below
  // never sees `cmd` (only `arg` is in the source's variable field) and
  // the array literal defeats the sink-arg colocation heuristic. Seeds
  // with real source variables (HTTP source `arg` or the now-populated
  // interprocedural_param parameter name) and iterates to a fixpoint.
  if (language === 'java' && typeof code === 'string' && sourcesWithVar.length > 0) {
    const seedVars = new Set(sourcesWithVar.map(s => s.variable));
    const derived = buildJavaTaintedVars(code, seedVars);
    if (derived.size > 0) {
      let anchor: typeof sourcesWithVar[0] = sourcesWithVar[0];
      for (const s of sourcesWithVar) {
        if (s.line < anchor.line) anchor = s;
      }
      const existingVars = new Set(sourcesWithVar.map(s => s.variable));
      for (const [varName] of derived) {
        if (!varName || existingVars.has(varName)) continue;
        sourcesWithVar.push({
          ...anchor,
          variable: varName,
        });
        existingVars.add(varName);
      }
    }
  }

  // Pre-compile word-boundary regexes per unique source variable.
  // Escape regex-special characters defensively (variable names should be
  // plain identifiers but Python attribute paths like `obj.attr` could leak in).
  const reCache = new Map<string, RegExp>();
  for (const s of sourcesWithVar) {
    if (reCache.has(s.variable)) continue;
    const escaped = s.variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Unicode-aware word boundary so non-ASCII identifiers (e.g. `café`) match.
    reCache.set(s.variable, new RegExp(`(?<![\\p{L}\\p{N}_])${escaped}(?![\\p{L}\\p{N}_])`, 'u'));
  }

  // Group calls by line for O(1) sink-line lookup.
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Respect dangerous-position filtering (e.g. execSync arg 0 only).
        if (sink.argPositions && sink.argPositions.length > 0 &&
            !sink.argPositions.includes(arg.position)) {
          continue;
        }
        const expr = arg.expression;
        if (!expr) continue;

        for (const source of sourcesWithVar) {
          // Source must appear before the sink (no backward flows).
          if (source.line >= sink.line) continue;

          // cognium-dev #101 (Sprint 14 Phase B): when both the source and
          // the sink carry a method-scope tag, restrict variable-name
          // matching to within the same method. Without this guard, a
          // common identifier (e.g. `cmd`, `name`, `id`) used in two
          // unrelated methods would link source-A in method-1 to sink-B in
          // method-2 purely by name collision. The new
          // `TaintSource.in_method` field (taint-matcher.ts) plus
          // `call.in_method` make the gate cheap and precise.
          if (
            source.in_method &&
            call.in_method &&
            source.in_method !== call.in_method
          ) {
            continue;
          }

          const re = reCache.get(source.variable);
          if (!re || !re.test(expr)) continue;

          // cognium-dev #138: source-semantics gate. Drop flows whose
          // source was tagged constant / SPI-loaded by
          // SourceSemanticsPass — a compile-time constant cannot carry
          // attacker-controlled data, and SPI-loaded values are
          // provider-controlled configuration (see the predicate's
          // JSDoc in findings.ts for the exact per-sink policy).
          if (!sourceSemanticsAllowed(source, sink.type)) continue;

          // Dedupe by (source_line, sink_line, sink.type) — a single source
          // can reach multiple distinct sinks at the same line (e.g. an
          // execute() call modeled as both `xss` and `sql_injection`).
          if (flows.some(f =>
            f.source_line === source.line &&
            f.sink_line === sink.line &&
            f.sink_type === sink.type
          )) continue;

          // cognium-dev #65 pt2: suppress flows where the derived alias
          // was created by an assignment that wraps the tainted operand
          // in a sanitizer covering this sink type (e.g.
          // `cmd = "ping " + shlex.quote(host)` → command_injection).
          if (aliasSanitizedFor.get(source.variable)?.has(sink.type)) {
            break;
          }

          // Sprint 9 #58.3 / #56: between source.line and sink.line, if
          // the tainted variable is reassigned to a pure string literal
          // (either naked `var = "lit"` or guarded by an allowlist check
          // such as `if (!ALLOWLIST.contains(var)) var = "lit"` /
          // `if var not in ALLOWLIST: var = "lit"`), the original taint
          // no longer reaches the sink — suppress the flow.
          if (
            typeof code === 'string' &&
            isReassignedToLiteralBetween(code, source.variable, source.line, sink.line)
          ) {
            break;
          }

          // Note: DFG-flow filter handles sanitizer-guard suppression
          // via `sanitizedVars` (positive-evidence check).

          flows.push({
            source_line: source.line,
            sink_line:   sink.line,
            source_type: source.type,
            sink_type:   sink.type,
            path: [
              { variable: source.variable, line: source.line, type: 'source' as const },
              { variable: source.variable, line: sink.line,   type: 'sink'   as const },
            ],
            confidence: source.confidence * sink.confidence * 0.7,
            sanitized: false,
          });
          break; // one source per arg is enough
        }
      }
    }
  }

  // cognium-dev #83: inline-source colocation.
  //
  // When a source expression is used INLINE as a sink argument — e.g.
  // `Runtime.getRuntime().exec(req.getParameter("u"))` (Java),
  // `eval(req.query.x)` (JS), `os.system(request.args.get("u"))` (Python) —
  // the source pattern matcher emits a source at `sink.line`, and no
  // `variable` is bound (the arg node isn't a simple identifier).
  // The DFG-based `propagateTaint` skips it (no `arg.variable`) and the
  // variable-name scan above ignores it (no `source.variable`).
  //
  // Emit a direct flow when (a) the source line is the sink line, and
  // (b) the source type can reach the sink type. Sanitizer checks are
  // intentionally not applied here because an inline source has no
  // intermediate assignment line for a sanitizer to wrap, and the
  // sink-call expression itself either contains the raw source or
  // doesn't; if a sanitizer wraps the source inside the arg expression
  // (e.g. `exec(escape(req.query.x))`), the sanitizer pass will already
  // mark the sink as sanitized via `sinkSanitizationMap`.
  //
  // Subsumes cognium-dev#76's "Python for-loop iterable inline source"
  // for the simple cases where the source pattern matches the iterable
  // and the loop variable is used on the same line.
  //
  // Sources without a `variable` field are the classic inline-pattern case
  // (e.g. `exec(req.getParameter("u"))`). Sources WITH a `variable` field
  // are also admitted when the LHS-bound identifier does NOT appear in the
  // sink call's source-line `code`. This covers Sprint 93 (#189)
  // `Object o = y.load(req.getParameter("y"))` where Java LHS-binding tags
  // the source with the outer assignment target `o`, yet `o` cannot appear
  // in the sink's own arguments because it is being *defined by* the sink
  // expression. The variable-scan path already emits when the sink args
  // reference the source var, so gating on absence of the var in the sink
  // code preserves the "assignment-after-use is impossible" regression
  // guard (`uid = source(); doSink("x = " + uid)` on the same line would
  // still have `uid` present in the sink code and thus fall to
  // variable-scan, not colocation).
  const sourcesByLine = new Map<number, typeof sources>();
  for (const s of sources) {
    const arr = sourcesByLine.get(s.line) ?? [];
    arr.push(s);
    sourcesByLine.set(s.line, arr);
  }
  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const colocSources = sourcesByLine.get(sink.line);
    if (!colocSources || colocSources.length === 0) continue;
    for (const source of colocSources) {
      if (!canSourceReachSink(source.type, sink.type)) continue;
      // cognium-dev #138: source-semantics gate for inline sources.
      // Drop flows tagged constant / SPI (see sourceSemanticsAllowed
      // JSDoc for the per-sink policy).
      if (!sourceSemanticsAllowed(source, sink.type)) continue;
      // Variable-scan handoff — if the source carries an LHS-bound
      // variable AND that identifier is textually present in the RHS of
      // the sink's own source-line code, the variable-scan path is
      // authoritative for this pair. Skipping the colocation emission
      // here preserves the "assignment-then-same-line-use is impossible"
      // regression guard (`uid = source(); doSink(uid)` collapsed onto
      // one line). When the LHS var is absent from the RHS (i.e. the
      // sink expression IS the RHS being assigned to that var), the
      // source is nested inside the sink expression (Sprint 93 (#189)
      // nested `Object o = y.load(req.getParameter("y"))` pattern) and
      // the colocation emission is the only path that will surface the
      // flow. We strip an optional leading `TYPE ident =` prefix from
      // the sink code so the LHS binding of THIS line does not
      // spuriously match the source var.
      const sourceVar = (source as { variable?: string }).variable;
      if (sourceVar && sourceVar.length > 0) {
        const sinkCode = (sink as { code?: string }).code;
        if (!sinkCode) {
          // Conservative fallback: without sink source-line text we
          // cannot verify the nested-source shape, so preserve the
          // pre-Sprint-93 behaviour of dropping variable-bound sources
          // from colocation. The variable-scan supplement remains
          // authoritative for these cases.
          continue;
        }
        // Strip a possible declaration/assignment LHS: `TYPE var =` or
        // `var =`. Matches single `=` only (not ==, !=, <=, >=).
        const assignMatch = sinkCode.match(/^\s*(?:[A-Za-z_][\w.<>[\]\s,?]*\s+)?[A-Za-z_]\w*\s*=(?!=)\s*/);
        const rhs = assignMatch ? sinkCode.slice(assignMatch[0].length) : sinkCode;
        if (new RegExp(`\\b${sourceVar}\\b`).test(rhs)) {
          continue;
        }
      }
      // Skip the degenerate `file_input` → `path_traversal` colocation
      // where the source and sink describe the SAME call (one being the
      // chained accessor of the other). Example: Python
      //   open(safe).read()
      // matches both the `file_input` source pattern (`read` on a file
      // object) and the `path_traversal` sink pattern (`open(...)`),
      // but here `open()` is the sink target, not a downstream consumer
      // of itself. We detect this by checking whether `sink.method(`
      // appears INSIDE the source's location string — if it does, the
      // source's call is a chained derivative of the sink's call (i.e.
      // `<sink>(...).<srcMethod>()`), not a distinct consumer at the
      // same line. Real cross-call cases like Java Zip-Slip —
      //   new File(dir, entry.getName())
      // — are unaffected because the sink location is `File() in m`
      // while the source location is `entry.getName() in m`; neither
      // string contains the other's method-name marker, so the flow is
      // still emitted. Sprint 9 #48.2 / #51.1.
      if (
        source.type === 'file_input' &&
        sink.type === 'path_traversal' &&
        sink.method &&
        source.location.includes(`${sink.method}(`)
      ) {
        continue;
      }
      if (flows.some(f =>
        f.source_line === source.line &&
        f.sink_line === sink.line &&
        f.sink_type === sink.type
      )) continue;
      flows.push({
        source_line: source.line,
        sink_line:   sink.line,
        source_type: source.type,
        sink_type:   sink.type,
        path: [
          { variable: '<inline>', line: source.line, type: 'source' as const },
          { variable: '<inline>', line: sink.line,   type: 'sink'   as const },
        ],
        confidence: source.confidence * sink.confidence * 0.85,
        sanitized: false,
      });
    }
  }

  return flows;
}

// ---------------------------------------------------------------------------
// Sprint 13 #70 — method-scoped source picker.
//
// `detectCollectionFlows` and `detectArrayElementFlows` historically grabbed
// `sources[0]` once they decided a sink was tainted. When a file contained
// multiple methods each with its own source/sink, every supplementary flow
// was misattributed to the first method's source line.
//
// `pickScopedSource` reproduces the matching strategy used by the already-
// correct `detectParameterSinkFlows` / `detectExpressionScanFlows`:
//
//   1. Variable match: if any source carries `source.variable === taintedVar`,
//      prefer it (closest preceding wins).
//   2. Scope match: prefer sources whose `line` falls within the same method
//      as the sink (via `types[].methods[].start_line/end_line`). Closest
//      preceding wins.
//   3. Fallback: closest preceding source globally.
//   4. Last resort: `sources[0]` (preserves pre-fix behaviour when nothing
//      preceding exists — keeps existing test coverage green).
// ---------------------------------------------------------------------------
function pickScopedSource(
  sources: CircleIR['taint']['sources'],
  sinkLine: number,
  methodName: string | null,
  types: CircleIR['types'] | undefined,
  taintedVar: string | undefined,
): CircleIR['taint']['sources'][0] | undefined {
  if (sources.length === 0) return undefined;

  // Closest-preceding selector over a candidate list. Strict-preceding
  // (`s.line < sinkLine`): synthetic same-line sources stamped on the sink
  // itself (e.g. `plugin_param` for `m.get("k")`) are not the true taint
  // origin and would shadow the real upstream source.
  const closestPreceding = (cands: CircleIR['taint']['sources']): CircleIR['taint']['sources'][0] | undefined => {
    let best: CircleIR['taint']['sources'][0] | undefined;
    for (const s of cands) {
      if (s.line >= sinkLine) continue;
      if (!best || s.line > best.line) best = s;
    }
    return best;
  };

  // 1. Variable match (preferred — even across methods, falls within the
  //    method scope check below for the tiebreak).
  if (taintedVar) {
    const byVar = sources.filter(s => s.variable === taintedVar);
    const pick = closestPreceding(byVar);
    if (pick) return pick;
  }

  // 2. Scope match — restrict to sources whose line is inside the same
  //    method as the sink.
  if (methodName && types && types.length > 0) {
    let methodStart = -1;
    let methodEnd = -1;
    for (const t of types) {
      for (const m of t.methods) {
        if (m.name === methodName) {
          methodStart = m.start_line;
          methodEnd = m.end_line;
          break;
        }
      }
      if (methodStart > 0) break;
    }
    if (methodStart > 0 && methodEnd >= methodStart) {
      const inScope = sources.filter(s => s.line >= methodStart && s.line <= methodEnd);
      const pick = closestPreceding(inScope);
      if (pick) return pick;
    }
  }

  // 3. Closest preceding source globally.
  const globalPick = closestPreceding(sources);
  if (globalPick) return globalPick;

  // 4. Last resort — preserve historical behaviour when there's nothing
  //    preceding the sink (e.g. synthetic same-line sources).
  return sources[0];
}
