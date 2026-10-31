/**
 * InterproceduralPass
 *
 * Performs inter-procedural taint analysis: finds taint escaping the current
 * method into callees and surfaces sinks inside those callees.
 *
 * Handles two scenarios:
 *   A) Sources + sinks already found → find additional sinks inside callees
 *      and generate inter-procedural flows between them.
 *   B) Sources found but no sinks yet → detect external taint escapes
 *      (CWE-668 "external_taint_escape") as a fallback.
 *
 * Depends on: sink-filter, constant-propagation, taint-propagation
 */

import type { TaintSink, TaintFlowInfo, InterproceduralInfo, TypeInfo, MethodInfo } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { CSharpCredit } from './csharp-sanitizer-credit.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';
import type { TaintPropagationPassResult } from './taint-propagation-pass.js';
import { analyzeInterprocedural, findTaintBridges, type InterproceduralResult } from '../interprocedural.js';
import { attachSourceLineCode } from '../taint-matcher.js';
import { shouldGateInterproceduralParam } from '../entry-point-detection.js';
import { sanitizerCoversSink } from '../sanitizer-index.js';
import { identifierOutsideSanitizerCalls } from '../taint-propagation.js';
import { buildJavaTaintedVars, computeDeadJavaBranchLines } from './language-sources-pass.js';

export interface InterproceduralPassResult {
  /** Additional sinks surfaced by inter-procedural analysis. */
  additionalSinks: TaintSink[];
  /** Additional flows generated from inter-procedural paths. */
  additionalFlows: TaintFlowInfo[];
  /** Structured inter-procedural summary for the IR output. */
  interprocedural?: InterproceduralInfo;
}

/**
 * Constructor options for InterproceduralPass.
 *
 * Wired from `AnalyzerOptions.enableEntryPointGate` in `analyze()`.
 * See the JSDoc on that field for full semantics.
 */
export interface InterproceduralOptions {
  /**
   * Mirror of `AnalyzerOptions.enableEntryPointGate`. Default `true`.
   *
   * When `true` (the default and pre-3.95.0 always-on behaviour), the
   * Tier 1/2/3 entry-point classifier suppresses `interprocedural_param`
   * sources whose enclosing Java method is a library-API surface not
   * reachable from a recognised entry point.
   *
   * Set `false` to disable the gate and surface the un-gated source set
   * (cognium-dev#137, 3.95.0).
   */
  enableEntryPointGate?: boolean;
}

export class InterproceduralPass implements AnalysisPass<InterproceduralPassResult> {
  readonly name = 'interprocedural';
  readonly category = 'security' as const;

  private readonly enableEntryPointGate: boolean;

  constructor(options?: InterproceduralOptions) {
    this.enableEntryPointGate = options?.enableEntryPointGate ?? true;
  }

  run(ctx: PassContext): InterproceduralPassResult {
    const { graph } = ctx;

    const constProp   = ctx.getResult<ConstantPropagatorResult>('constant-propagation');
    const sinkFilter  = ctx.getResult<SinkFilterResult>('sink-filter');
    const taintProp   = ctx.getResult<TaintPropagationPassResult>('taint-propagation');

    const { sources, sinks, sanitizers } = sinkFilter;

    if (sources.length === 0) {
      // Preserve flows synthesized by TaintPropagationPass (e.g. Python alias
      // expansion for-loop / inline-source cases from cognium-dev #76/#83 where
      // no real source was registered but a derived var reaches a sink).
      return { additionalSinks: [], additionalFlows: [...taintProp.flows] };
    }

    const additionalSinks: TaintSink[] = [];
    const additionalFlows: TaintFlowInfo[] = [...taintProp.flows];
    let interprocedural: InterproceduralInfo | undefined;

    // cognium-dev #128 — build a method-name → {method, type} lookup for the
    // entry-point classifier gate. Used in Scenario A below to drop speculative
    // `interprocedural_param` sources whose enclosing method classifies as
    // TIER_3_LIBRARY_API (e.g. `RuntimeUtil.exec`, `FreemarkerEngine.render`).
    // Built once per pass; O(types * methods) but only consulted for
    // interprocedural_param sources, which are the FP cluster being suppressed.
    const methodNameIndex = new Map<string, { method: MethodInfo; type: TypeInfo }>();
    for (const type of graph.ir.types ?? []) {
      for (const method of type.methods ?? []) {
        if (method.name && !methodNameIndex.has(method.name)) {
          methodNameIndex.set(method.name, { method, type });
        }
      }
    }
    const language = graph.ir.meta.language;

    const csCredit = language === 'csharp' && typeof ctx.code === 'string'
      ? new CSharpCredit(ctx.code, graph.ir.types.flatMap(t => t.methods))
      : null;

    // --- Scenario A: sources AND sinks present --------------------------------
    if (sinks.length > 0) {
      const interProc = analyzeInterprocedural(graph, sources, sinks, sanitizers, {
        taintedVariables: constProp.tainted,
      });

      // Collect propagated sinks (skip external_taint_escape — only used in fallback)
      for (const sink of interProc.propagatedSinks) {
        if (sink.type === 'external_taint_escape') continue;
        if (!sinks.some(s => s.line === sink.line)) {
          additionalSinks.push(sink);
        }
      }

      // Build inter-procedural flows for newly surfaced sinks
      if (interProc.propagatedSinks.length > 0) {
        const sanitizerMethodNames = new Set<string>();
        for (const san of sanitizers) {
          if (san.type === 'javadoc_sanitizer') {
            const match = san.method.match(/^(\w+)\(\)$/);
            sanitizerMethodNames.add(match ? match[1] : san.method);
          }
        }

        for (const sink of interProc.propagatedSinks) {
          if (sink.type === 'external_taint_escape') continue;

          for (const edge of interProc.callEdges) {
            if (!interProc.taintedMethods.has(edge.calleeMethod)) continue;

            const method = interProc.methodNodes.get(edge.calleeMethod);
            if (!method) continue;
            if (sink.line < method.startLine || sink.line > method.endLine) continue;
            if (sanitizerMethodNames.has(method.name)) continue;
            // cognium-dev#518 / #286 A: a tainted argument reaches a sink in
            // the callee only if the parameter, or something derived from it,
            // is what the sink receives.
            if (language === 'csharp' && typeof ctx.code === 'string' &&
                !csharpParamReachesSink(ctx.code, method, edge.taintedArgs, sink, csCredit)) {
              continue;
            }

            for (const source of sources) {
              if (source.line > edge.callLine) continue;
              if (source.type === 'interprocedural_param' && source.confidence < 0.6) continue;
              // cognium-dev #128 — drop `interprocedural_param` sources whose
              // enclosing method is a TIER_3_LIBRARY_API surface (utility/helper
              // classes, template/engine packages, JDK facade implementers, or
              // any non-entry-point Java method). Preserves recall for
              // entry-point-anchored sources (Spring @RequestMapping, JAX-RS,
              // Servlet doGet, `main`, etc.) and for non-Java languages
              // (UNKNOWN tier → pass-through).
              // cognium-dev #137 (3.95.0) — gate guarded by
              // `this.enableEntryPointGate` (default `true`); callers can
              // disable to receive the un-gated pre-#128 source set.
              if (
                this.enableEntryPointGate &&
                source.type === 'interprocedural_param' &&
                source.in_method
              ) {
                const enclosing = methodNameIndex.get(source.in_method);
                if (shouldGateInterproceduralParam(
                  source.type,
                  enclosing?.method,
                  enclosing?.type,
                  {
                    language,
                    types: graph.ir.types,
                    filePath: graph.ir.meta.file,
                    calls: graph.ir.calls,
                    runtimeRegistrations: graph.ir.runtime_registrations ?? null,
                  },
                )) {
                  continue;
                }
              }
              if (additionalFlows.some(f => f.source_line === source.line && f.sink_line === sink.line)) continue;

              additionalFlows.push({
                source_line: source.line,
                sink_line:   sink.line,
                source_type: source.type,
                sink_type:   sink.type,
                path: [
                  { variable: source.location,            line: source.line,    type: 'source' as const },
                  { variable: `call to ${method.name}()`, line: edge.callLine,  type: 'use'    as const },
                  { variable: sink.location,              line: sink.line,      type: 'sink'   as const },
                ],
                confidence: sink.confidence * source.confidence * 0.85,
                sanitized: false,
              });
              break; // one source per sink is enough
            }
            break; // one call edge per sink is enough
          }
        }
      }

      appendCalleeSourceCallerSinkFlows(
        graph,
        sources,
        sinks,
        interProc,
        additionalFlows,
        language === 'java' ? ctx.code : undefined,
        language === 'java' ? constProp : undefined,
      );

      const taintBridges = findTaintBridges(interProc);
      interprocedural = {
        tainted_methods: Array.from(interProc.taintedMethods),
        taint_bridges: taintBridges,
        method_flows: interProc.callEdges
          .filter(edge => interProc.taintedMethods.has(edge.calleeMethod))
          .map(edge => ({
            caller:        edge.callerMethod,
            callee:        edge.calleeMethod,
            call_line:     edge.callLine,
            tainted_args:  edge.taintedArgs,
            returns_taint: interProc.taintedReturns.has(edge.calleeMethod),
          })),
      };
    }

    // --- Scenario B: sources present, no sinks --------------------------------
    if (sinks.length === 0) {
      // `constructor_field` sources are generated by the Java getter pattern
      // detector and are not real external inputs in TypeScript/library code.
      // `interprocedural_param` sources represent "this method's parameter MIGHT be
      // tainted when called with tainted data" — they are speculative signals, not
      // confirmed external inputs.  Using them in Scenario B (no YAML sinks) produces
      // false-positive `external_taint_escape` findings on every internal library
      // method whose typed parameters flow into arithmetic or other operations
      // (e.g. `run(ctx: MetricContext)` computing metrics from `ctx.accumulated`).
      // Real cross-file flows from true web inputs are surfaced by CrossFilePass;
      // there is no value in re-surfacing them here as unvalidated escapes.
      const fallbackSources = sources.filter(
        s => s.type !== 'constructor_field' &&
          s.type !== 'interprocedural_param',
      );
      if (fallbackSources.length === 0) {
        return { additionalSinks, additionalFlows, interprocedural };
      }
      const interProc = analyzeInterprocedural(graph, fallbackSources, [], sanitizers, {
        taintedVariables: constProp.tainted,
      });

      // A call the sink registry matched and SinkFilterPass then cleared (a
      // guard above `res.redirect(x)`, a literal header value, ...) is not an
      // unknown external method for the arguments that sink covers.
      // Re-reporting them as an escape would undo the filter's verdict on the
      // same call. Other tainted arguments (the data in
      // `writeFileSync(constPath, data)`) still escape.
      const cleared = ctx.hasResult('taint-matcher')
        ? ctx.getResult<TaintMatcherResult>('taint-matcher').sinks.filter(s =>
          s.method && !sinks.some(k => k.line === s.line && k.method === s.method))
        : [];
      const isClearedCall = (esc: TaintSink): boolean => cleared.some(s =>
        s.line === esc.line && s.method === esc.method &&
        (!s.argPositions?.length || !esc.argPositions?.length ||
          esc.argPositions.every(p => s.argPositions!.includes(p))));
      for (const sink of interProc.propagatedSinks) {
        if (sink.type === 'external_taint_escape' && isClearedCall(sink)) continue;
        // Bash reports the fallback as an unquoted-argument command_injection.
        // A curl/wget whose ssrf sink Stage 15m cleared has only double-quoted
        // fixed-host URL words, so no argument can be split or read as a flag.
        if (language === 'bash' && cleared.some(s => s.type === 'ssrf' && s.line === sink.line && s.method === sink.method)) continue;
        if (!constProp.unreachableLines.has(sink.line)) {
          additionalSinks.push(sink);
        }
      }

      if (interProc.taintedMethods.size > 0 || interProc.propagatedSinks.length > 0) {
        const taintBridges = findTaintBridges(interProc);
        interprocedural = {
          tainted_methods: Array.from(interProc.taintedMethods),
          taint_bridges: taintBridges,
          method_flows: interProc.callEdges
            .filter(edge => interProc.taintedMethods.has(edge.calleeMethod))
            .map(edge => ({
              caller:        edge.callerMethod,
              callee:        edge.calleeMethod,
              call_line:     edge.callLine,
              tainted_args:  edge.taintedArgs,
              returns_taint: interProc.taintedReturns.has(edge.calleeMethod),
            })),
        };
      }

      // Generate simple source→sink flows for any newly-found sinks
      if (additionalSinks.length > 0 && sources.length > 0) {
        for (const sink of additionalSinks) {
          additionalFlows.push({
            source_line: sources[0].line,
            sink_line:   sink.line,
            source_type: sources[0].type,
            sink_type:   sink.type,
            path: [
              { variable: 'input', line: sources[0].line, type: 'source' as const },
              { variable: 'input', line: sink.line,       type: 'sink'   as const },
            ],
            confidence: sources[0].confidence * sink.confidence,
            sanitized: false,
          });
        }
      }
    }

    // Attach trimmed source-line text to each emitted sink so consumers
    // (LLM enrichment, SARIF reporters) can render the offending line without
    // re-reading the file. Idempotent — only fills `code` when missing.
    if (additionalSinks.length > 0) {
      attachSourceLineCode([], additionalSinks, ctx.code);
    }

    // Sprint 24 (cognium-dev #102 FP-27) — apply the uniform line-keyed
    // sanitizer filter to inter-procedural fallback flows too. Scenario B
    // generates external_taint_escape flows after TaintPropagationPass has
    // already run, so its sanitizer filter never saw them. Drop any flow
    // whose source→sink range overlaps a registered sanitizer covering
    // `sink_type`.
    let filteredAdditionalFlows = additionalFlows;
    let filteredAdditionalSinks  = additionalSinks;
    if (sanitizers && sanitizers.length > 0) {
      const sanitizersByLine = new Map<number, typeof sanitizers>();
      for (const san of sanitizers) {
        const arr = sanitizersByLine.get(san.line) ?? [];
        arr.push(san);
        sanitizersByLine.set(san.line, arr);
      }
      const sanitizedSinkKeys = new Set<string>();
      filteredAdditionalFlows = additionalFlows.filter(f => {
        // Two-tier filter (mirrors TaintPropagationPass):
        //   - external_taint_escape: any sanitizer covering sink_type on
        //     the source→sink line range suppresses (FP-27).
        //   - configured sinks: sanitizer must be AT sink_line and cover
        //     sink_type (FP-20 map-allowlist guard at http.Get line).
        if (f.sink_type === 'external_taint_escape') {
          const lo = Math.min(f.source_line, f.sink_line);
          const hi = Math.max(f.source_line, f.sink_line);
          for (let line = lo; line <= hi; line++) {
            const sansAtLine = sanitizersByLine.get(line);
            if (!sansAtLine) continue;
            for (const san of sansAtLine) {
              if (sanitizerCoversSink(san, f.sink_type)) {
                sanitizedSinkKeys.add(`${f.sink_line}:${f.sink_type}`);
                return false;
              }
            }
          }
          return true;
        }
        const sansAtSink = sanitizersByLine.get(f.sink_line);
        if (!sansAtSink || sansAtSink.length === 0) return true;
        const callsAtSink = graph.callsByLine.get(f.sink_line) ?? [];
        const sinkVar = f.path.length > 0 ? f.path[f.path.length - 1]?.variable : undefined;
        for (const san of sansAtSink) {
          if (!sanitizerCoversSink(san, f.sink_type)) continue;
          // A sanitizer on the sink line covers its own operand. A raw
          // operand beside it still flows (#641).
          if (
            sinkVar &&
            identifierOutsideSanitizerCalls(sinkVar, callsAtSink, sansAtSink, f.sink_type)
          ) {
            continue;
          }
          return false;
        }
        return true;
      });
      // Also drop additionalSinks whose flows were all filtered out and
      // which are synthetic external_taint_escape (otherwise the sink
      // remains in r.taint.sinks producing a stale finding).
      filteredAdditionalSinks = additionalSinks.filter(s => {
        if (s.type !== 'external_taint_escape') return true;
        return !sanitizedSinkKeys.has(`${s.line}:${s.type}`);
      });
    }

    // cognium-dev#518: the escape fallback has no sink type, so the typed C#
    // credit in SinkFilterPass never sees it. A value that was encoded,
    // validated or sent to a constant host is not an unvalidated escape.
    if (csCredit) {
      const csSeeds = sources.flatMap(s => (s.variable ? [{ variable: s.variable, line: s.line }] : []));
      const credited = new Set<number>();
      filteredAdditionalFlows = filteredAdditionalFlows.filter(f => {
        if (f.sink_type !== 'external_taint_escape' || !csCredit.creditedOnLine(f.sink_line, csSeeds)) return true;
        credited.add(f.sink_line);
        return false;
      });
      filteredAdditionalSinks = filteredAdditionalSinks.filter(
        s => !(s.type === 'external_taint_escape' && credited.has(s.line)),
      );
    }

    return { additionalSinks: filteredAdditionalSinks, additionalFlows: filteredAdditionalFlows, interprocedural };
  }
}

/**
 * Does a tainted argument passed to a C# callee reach `sink` inside it?
 *
 * Scenario A used to emit a flow for every sink in a method that received a
 * tainted argument, whatever the sink was given. That flagged a parameterised
 * query (`cmd.Parameters.AddWithValue("@name", name); cmd.ExecuteNonQuery();`)
 * and a constructor with constant arguments in a method that escapes its
 * parameter before using it.
 *
 * Reads the callee top to bottom up to the sink. A name is derived from the
 * parameter when it is assigned an expression that mentions a derived name, or
 * is an object written through a property or a mutating call with one
 * (`cmd.CommandText = … + name`, `sb.Append(name)`). A nested member such as
 * `cmd.Parameters.AddWithValue(…)` binds a value and does not taint `cmd`.
 * The sink is reached when its statement mentions a derived name that is not
 * sanitized or guarded there.
 */
/**
 * True when constant propagation tracked `variable` in `method` and did not
 * mark it tainted. Only a tracked symbol counts: "not in the tainted set" alone
 * also means "never looked at" (see `isFalsePositive` reason 3).
 */
function assigneeIsConstPropClean(
  constProp: ConstantPropagatorResult,
  method: string | null | undefined,
  variable: string,
): boolean {
  if (!method) return false;
  const scoped = `${method}:${variable}`;
  if (!constProp.symbols.has(scoped)) return false;
  if (constProp.tainted.has(scoped)) return false;
  for (const t of constProp.tainted) {
    if (t.startsWith(`${method}:`) && t.endsWith(`:${variable}`)) return false;
  }
  if (constProp.sanitizedVarUncovered?.has(scoped)) return false;
  return true;
}

function constPropTaints(
  constProp: ConstantPropagatorResult,
  method: string,
  variable: string,
): boolean {
  if (constProp.tainted.has(`${method}:${variable}`)) return true;
  for (const t of constProp.tainted) {
    if (t.startsWith(`${method}:`) && t.endsWith(`:${variable}`)) return true;
  }
  return false;
}

/** Does a call on `line` in `method` take an argument const-prop holds tainted? */
function callArgumentIsConstPropTainted(
  graph: PassContext['graph'],
  constProp: ConstantPropagatorResult,
  method: string | null | undefined,
  line: number,
): boolean {
  if (!method) return false;
  for (const call of graph.ir.calls) {
    if (call.location.line !== line) continue;
    for (const arg of call.arguments) {
      const names = arg.variable
        ? [arg.variable]
        : (arg.expression ?? '').match(/[A-Za-z_]\w*/g) ?? [];
      if (names.some(n => constPropTaints(constProp, method, n))) return true;
    }
  }
  return false;
}

/**
 * Does the callee `return` a variable const-prop holds tainted elements or keys
 * for (`vars[i] = "X=" + param; return vars;`)? Const-prop does not carry that
 * into the call's result, so its "clean" assignee is not proof here.
 */
function calleeReturnsTaintedContainer(
  constProp: ConstantPropagatorResult,
  code: string,
  startLine: number,
  endLine: number,
): boolean {
  const lines = code.split('\n');
  for (let l = startLine; l <= endLine; l++) {
    const m = /^\s*return\s+([A-Za-z_]\w*)\s*;/.exec(lines[l - 1] ?? '');
    if (!m) continue;
    if ((constProp.taintedArrayElements.get(m[1])?.size ?? 0) > 0) return true;
    if ((constProp.taintedCollections.get(m[1])?.size ?? 0) > 0) return true;
  }
  return false;
}

/**
 * Sink types whose parameter-sourced helper flows are dropped when the
 * parameter reaches the helper's return only through a constant-dead branch
 * (`if ((7 * 42) - num > 200) bar = "safe"; else bar = param;`).
 */
const DEAD_BRANCH_CHECKED_SINKS: ReadonlySet<string> = new Set([
  'sql_injection', 'trust_boundary', 'path_traversal', 'ldap_injection', 'xpath_injection',
]);

/**
 * Java: do the defs a callee source creates reach a `return` of the callee?
 * Follows def-use chains forward (a use of a reached def reaches the locals
 * defined on its line), so an overwrite before the return ends the chain.
 * A source on the return line itself reaches it.
 */
function calleeSourceReachesReturn(
  graph: PassContext['graph'],
  code: string,
  startLine: number,
  endLine: number,
  sourceLine: number,
): boolean {
  const lines = code.split('\n');
  const returnLines = new Set<number>();
  for (let l = startLine; l <= endLine; l++) {
    if (/^\s*return\b/.test(lines[l - 1] ?? '')) returnLines.add(l);
  }
  if (returnLines.size === 0) return true; // nothing to prove against: keep the source
  if (returnLines.has(sourceLine)) return true;
  const inRange = (l: number) => l >= startLine && l <= endLine;
  // A statement can span lines (`String e =\n new String(\n … d.getBytes()));`):
  // the def sits on its first line, the uses on later ones.
  const ends = (l: number) => /[;{}]\s*$/.test((lines[l - 1] ?? '').replace(/\/\/.*$/, '').trimEnd());
  const statementStart = (l: number) => {
    let s = l;
    while (s > startLine && !ends(s - 1) && (lines[s - 2] ?? '').trim() !== '') s--;
    return s;
  };
  const reached = new Set<number>(
    graph.ir.dfg.defs.filter(d => d.line === sourceLine && d.kind === 'local').map(d => d.id),
  );
  if (reached.size === 0) return true; // the source defines nothing we can follow
  let changed = true;
  while (changed) {
    changed = false;
    for (const u of graph.ir.dfg.uses) {
      if (u.def_id === null || !reached.has(u.def_id) || !inRange(u.line)) continue;
      const stmt = statementStart(u.line);
      if (returnLines.has(u.line) || returnLines.has(stmt)) return true;
      for (const d of graph.ir.dfg.defs) {
        if ((d.line === u.line || d.line === stmt) && d.kind === 'local' && !reached.has(d.id)) {
          reached.add(d.id);
          changed = true;
        }
      }
      // An element or field store (`arr[i] = name + "=" + value;`, `o.f = value;`)
      // defines no local, but the value now lives in the base: follow the base's
      // def (plexus-utils `getEnvironmentVariables()` fills an array it returns).
      // Container calls (`map.put`, `list.add`) are not followed: the keyed
      // overwrite cases above depend on them ending the chain.
      const base = storeBase(lines[stmt - 1] ?? '');
      if (base && base !== u.variable) {
        for (const b of graph.ir.dfg.uses) {
          if ((b.line === u.line || b.line === stmt) && b.variable === base &&
              b.def_id !== null && !reached.has(b.def_id)) {
            reached.add(b.def_id);
            changed = true;
          }
        }
      }
    }
  }
  return false;
}

/** `arr[i] = …` / `arr[i][j] = …` / `obj.field = …` → the base local's name; else null. */
function storeBase(line: string): string | null {
  const m = /^\s*([A-Za-z_]\w*)\s*(?:\[[^\]=]*\]\s*)+=(?!=)/.exec(line) ??
    /^\s*([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*=(?!=)/.exec(line);
  if (!m || m[1] === 'this') return null;
  return m[1];
}

/** cognium-dev#590 — connect a source inside a callee to a sink in the caller. */
function appendCalleeSourceCallerSinkFlows(
  graph: PassContext['graph'],
  sources: import('../../types/index.js').TaintSource[],
  sinks: TaintSink[],
  interProc: InterproceduralResult,
  additionalFlows: TaintFlowInfo[],
  fileCode?: string,
  constProp?: ConstantPropagatorResult,
): void {
  const types = graph.ir.types ?? [];
  for (const edge of interProc.callEdges) {
    const callee = interProc.methodNodes.get(edge.calleeMethod);
    if (!callee) continue;

    // Java: a source the callee overwrites before it returns
    // (`bar = map.get("keyB"); bar = map.get("keyA"); return bar;`) does not
    // reach the caller. Parameters are kept here; their live reach is the
    // dead-branch check below.
    const calleeSources = sources.filter(
      s => s.line >= callee.startLine && s.line <= callee.endLine &&
        (!fileCode || s.type === 'interprocedural_param' ||
          calleeSourceReachesReturn(graph, fileCode, callee.startLine, callee.endLine, s.line)),
    );
    if (calleeSources.length === 0) continue;

    const assignee = graph.ir.dfg.defs.find(
      d => d.line === edge.callLine && d.kind === 'local',
    );
    if (!assignee?.variable) continue;
    // A source inside the callee taints the caller only through the value the
    // callee returns. Constant propagation evaluates that return with the
    // callee's arguments (map keys, list indexes, constant branches, switch
    // arms), and the DFG flows it vetoes are not reported either. When it has
    // the assignee as a tracked, untainted value, the callee's source does not
    // reach the return (OWASP `doSomething` helpers: `map.get("keyA")` after a
    // `map.get("keyB")`, `if ((7 * 42) - num > 200)`, `valuesList.get(1)`).
    // Its verdict is informed only when it saw tainted data go into the call:
    // a value from another file (`scr.getTheParameter(…)`) is not a source to
    // it, and then "clean" means "never tainted here", not "the callee drops it".
    if (
      constProp &&
      callArgumentIsConstPropTainted(graph, constProp, edge.callerMethod, edge.callLine) &&
      assigneeIsConstPropClean(constProp, edge.callerMethod, assignee.variable) &&
      !(fileCode && calleeReturnsTaintedContainer(constProp, fileCode, callee.startLine, callee.endLine))
    ) {
      continue;
    }

    const derivedLocals = localsDerivedFromAssignee(
      graph,
      assignee.variable,
      assignee.line,
    );

    for (const sink of sinks) {
      if (sink.type === 'external_taint_escape') continue;
      if (sink.line <= edge.callLine) continue;
      if (enclosingMethodName(types, sink.line) !== edge.callerMethod) continue;
      const sinkVar = sinkVariableConsumingDerived(graph, sink, derivedLocals);
      if (!sinkVar) continue;
      if (additionalFlows.some(f => f.source_line === calleeSources[0].line && f.sink_line === sink.line)) {
        continue;
      }

      const source = calleeSources[0];
      if (
        fileCode &&
        source.type === 'interprocedural_param' &&
        source.variable &&
        DEAD_BRANCH_CHECKED_SINKS.has(sink.type) &&
        interproceduralParamReachIsDeadBranchOnly(
          fileCode,
          callee.startLine,
          callee.endLine,
          source.variable,
          assignee.variable,
        )
      ) {
        continue;
      }
      // cognium-dev#913 / #914 / #916 / #917 — the helper's return value cannot
      // carry any of its parameters on a live path (constant / literal-slot /
      // folded-ternary returns). Every source inside the callee must be a
      // parameter source, and none may reach the return: a helper taking
      // `(request, param)` is judged on both, and a real source inside the
      // callee is never gated here.
      if (
        fileCode &&
        HELPER_RETURN_GATED_SINKS.has(sink.type) &&
        calleeSources.every(
          s => (s.type === 'interprocedural_param' || s.type === 'plugin_param') && !!s.variable,
        ) &&
        !calleeReturnMayCarryParam(
          fileCode,
          callee.startLine,
          callee.endLine,
          calleeSources.map(s => s.variable!),
        )
      ) {
        continue;
      }
      additionalFlows.push({
        source_line: source.line,
        sink_line: sink.line,
        source_type: source.type,
        sink_type: sink.type,
        path: [
          { variable: source.location, line: source.line, type: 'source' as const },
          { variable: assignee.variable, line: edge.callLine, type: 'use' as const },
          { variable: sinkVar, line: sink.line, type: 'sink' as const },
        ],
        confidence: sink.confidence * source.confidence * 0.85,
        sanitized: false,
      });
    }
  }
}

/**
 * True when `param` would taint `local` only if dead-branch lines are counted
 * (e.g. OWASP #913 `else bar = param`), not when live propagation also reaches
 * `local` (list/Base64 helpers — cognium-dev#913 round 2).
 */
function interproceduralParamReachIsDeadBranchOnly(
  code: string,
  startLine: number,
  endLine: number,
  paramName: string,
  localName: string,
): boolean {
  if (paramName === localName) return false;
  const lines = code.split('\n');
  const slice = lines.slice(startLine - 1, endLine);
  const sliceText = slice.join('\n');
  const dead = computeDeadJavaBranchLines(slice);
  const onLivePaths = buildJavaTaintedVars(sliceText, new Set([paramName]), dead);
  const ifDeadLinesCount = buildJavaTaintedVars(sliceText, new Set([paramName]), new Set());
  return ifDeadLinesCount.has(localName) && !onLivePaths.has(localName);
}

/** Sink types whose caller-side flow is dropped when the helper cannot return the parameter. */
const HELPER_RETURN_GATED_SINKS = new Set([
  'sql_injection',
  'trust_boundary',
  'command_injection',
  'path_traversal',
  // #976: the same helper shapes feed LDAP and XPath sinks (OWASP ldapi/xpathi).
  'ldap_injection',
  'xpath_injection',
]);

/**
 * Can the callee's return value carry any of `sourceVars` (or a declared
 * parameter) on a live path?
 * cognium-dev#913 / #914 / #916 / #917.
 *
 * Conservative: answers false (gate the flow) only when every `return` on a live
 * path is understood and none can carry the parameter. A return expression that
 * mentions the parameter or anything derived from it, or a callee with no
 * readable `return`, answers true.
 * Derivation uses `buildJavaTaintedVars` with slot tracking, so `list.get(1)`
 * after `list.remove(0)`, `map.get("<literal key>")` and a ternary whose
 * condition folds to a constant pick the value actually returned.
 */
export function calleeReturnMayCarryParam(
  code: string,
  startLine: number,
  endLine: number,
  sourceVars: readonly string[],
): boolean {
  const raw = code.split('\n').slice(startLine - 1, endLine);
  // Seed with the helper's declared parameters as well as the sources found in
  // it: a `plugin_param` on `bar = (String) map.get("keyB")` stands for the
  // parameter stored under that key, which the slot tables resolve.
  const paramNames = [...sourceVars, ...javaMethodParamNames(raw)];
  const dead = computeDeadJavaBranchLines(raw);
  const inlined = new Set<number>();
  const slice = joinWrappedStatements(raw, inlined);
  // The tracker follows assignments. A receiver mutated by a call with a carried
  // argument (`sb.append(param)`, `parts.addAll(list)`) carries it too, so it is
  // added as a seed and the tracker re-run until nothing new is reached.
  const text = slice.join('\n');
  const seeds = new Set<string>(paramNames);
  // Receivers that carry a value only because they were mutated with it: their
  // declaration (`new String[n]`, `new StringBuilder()`) never does.
  const mutated = new Set<string>();
  let live = new Set<string>(seeds);
  for (let round = 0; round < 8; round++) {
    live = new Set<string>([...seeds, ...buildJavaTaintedVars(text, seeds, dead, { trackSlots: true }).keys()]);
    let grew = false;
    for (let i = 0; i < slice.length; i++) {
      if (dead.has(i)) continue;
      for (const call of slice[i].matchAll(/([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*\(([^;]*)\)/g)) {
        if (live.has(call[1])) continue;
        const args = call[2].replace(/"(?:[^"\\]|\\.)*"/g, ' ').match(/[\p{L}\p{N}_]+/gu) ?? [];
        if (args.some(t => live.has(t))) {
          seeds.add(call[1]);
          mutated.add(call[1]);
          grew = true;
        }
      }
      // An element or field store (`vars[i] = name + "=" + value;`, `o.f = value;`)
      // carries the value into its base (plexus-utils getEnvironmentVariables()).
      const store = /^\s*([A-Za-z_]\w*)\s*(?:(?:\[[^\]=]*\]\s*)+|\.\s*[A-Za-z_]\w*\s*)=(?!=)\s*(.*?);?\s*$/.exec(slice[i]);
      if (store && store[1] !== 'this' && !live.has(store[1])) {
        const rhs = store[2].replace(/"(?:[^"\\]|\\.)*"/g, ' ').match(/[\p{L}\p{N}_]+/gu) ?? [];
        if (rhs.some(t => live.has(t))) {
          seeds.add(store[1]);
          mutated.add(store[1]);
          grew = true;
        }
      }
    }
    if (!grew) break;
  }

  let sawReturn = false;
  for (let i = 0; i < slice.length; i++) {
    if (dead.has(i) || !/^\s*return\b/.test(slice[i])) continue;
    const m = /^\s*return\b\s*(.*?)\s*;\s*(?:\/\/.*)?$/.exec(slice[i]);
    if (!m) return true; // could not read this return
    sawReturn = true;
    const expr = m[1];
    const bare = /^[A-Za-z_]\w*$/.test(expr) ? expr : null;
    if (bare && mutated.has(bare)) return true;
    if (bare && live.has(bare)) {
      // The tracker is flow-insensitive: `bar = map.get("tainted-key"); bar =
      // map.get("safe-key"); return bar;` reaches it either way. Judge the
      // assignment that actually reaches this return instead, when there is one.
      const def = mustReachingAssignment(slice, dead, i, bare, inlined);
      if (!def) return true;
      const upTo = slice.slice(0, def.line);
      upTo.push(`__helperReturn = ${def.rhs};`);
      const atDef = buildJavaTaintedVars(upTo.join('\n'), seeds, dead, { trackSlots: true });
      if (atDef.has('__helperReturn')) return true;
      continue;
    }
    const idents = (expr.replace(/"(?:[^"\\]|\\.)*"/g, ' ').replace(/'(?:[^'\\]|\\.)'/g, ' ').match(/[\p{L}\p{N}_]+/gu) ?? []);
    if (idents.some(t => live.has(t))) return true;
  }
  return !sawReturn;
}

/** Parameter names from a Java method header (the lines before its body's `{`). */
function javaMethodParamNames(lines: readonly string[]): string[] {
  const header = lines.join('\n').split('{')[0];
  const open = header.indexOf('(');
  if (open < 0) return [];
  let depth = 0;
  let end = -1;
  for (let k = open; k < header.length; k++) {
    if (header[k] === '(') depth++;
    else if (header[k] === ')' && --depth === 0) { end = k; break; }
  }
  if (end < 0) return [];
  const names: string[] = [];
  let angle = 0;
  let piece = '';
  for (const c of header.slice(open + 1, end) + ',') {
    if (c === '<') angle++;
    else if (c === '>') angle--;
    if (c === ',' && angle === 0) {
      const m = /([A-Za-z_]\w*)\s*(?:\[\s*\])*\s*$/.exec(piece.trim());
      if (m) names.push(m[1]);
      piece = '';
    } else piece += c;
  }
  return names;
}

/**
 * Join each statement that wraps over several lines onto its first line and
 * leave the continuation lines blank, so line indices (and dead-branch lines)
 * still line up: `bar =\n  new String(\n    param.getBytes());` reads as one
 * assignment. Control-flow headers (`if (x)` with the statement on the next
 * line) and annotations are left as they are, as are comment lines.
 */
function joinWrappedStatements(lines: readonly string[], inlined: Set<number>): string[] {
  const out = [...lines];
  const ends = /[;{}:]\s*(?:\/\/.*)?$/;
  const header = /^\s*(?:if|else|for|while|do|switch|case|default|try|catch|finally|synchronized)\b|^\s*@|^\s*(?:\/\/|\/?\*)/;
  for (let i = 0; i < out.length; i++) {
    const line = out[i];
    if (line.trim() === '' || ends.test(line) || header.test(line)) continue;
    let joined = line;
    let j = i + 1;
    for (; j < out.length && j < i + 15; j++) {
      joined += ' ' + out[j].trim();
      if (ends.test(out[j])) break;
    }
    if (j >= out.length || j >= i + 15) continue; // never terminated: leave it alone
    out[i] = joined;
    for (let k = i + 1; k <= j; k++) out[k] = '';
    i = j;
  }
  return out.map((line, i) => {
    const body = inlineControlBody(line);
    if (body !== line) inlined.add(i);
    return body;
  });
}

/**
 * `if (c) bar = param;` → `bar = param;` (also `else …`, `else if (c) …`,
 * `for (…) …`, `while (…) …`). The tracker anchors assignments at the start of
 * the line, so a one-line branch body was invisible to it. Dead branches were
 * already computed on the original lines, so only the reading changes.
 */
function inlineControlBody(line: string): string {
  let rest = line;
  const indent = /^\s*/.exec(line)![0];
  for (let guard = 0; guard < 4; guard++) {
    const t = rest.trimStart();
    const elseM = /^(?:\}\s*)?else\b\s*/.exec(t);
    if (elseM && !/^(?:\}\s*)?else\s+if\b/.test(t)) {
      rest = t.slice(elseM[0].length);
      continue;
    }
    const head = /^(?:\}\s*)?(?:else\s+)?(?:if|for|while)\s*\(/.exec(t);
    if (!head) break;
    // Skip the balanced condition.
    let depth = 1;
    let k = head[0].length;
    for (; k < t.length && depth > 0; k++) {
      if (t[k] === '(') depth++;
      else if (t[k] === ')') depth--;
    }
    if (depth !== 0) return line;
    rest = t.slice(k);
  }
  const body = rest.trim();
  if (body === '' || body === rest.trim() && body === line.trim() || body.startsWith('{')) return line;
  return indent + body;
}

/**
 * The assignment to `name` that must reach the `return` on slice line `retLine`:
 * the closest preceding single-line `name = …;` in the same block, with no
 * assignment to `name` in a nested block after it and no exit from the block in
 * between. `null` when there is no such assignment (the caller then stays
 * conservative).
 */
function mustReachingAssignment(
  slice: readonly string[],
  dead: Set<number>,
  retLine: number,
  name: string,
  /** lines that were a one-line branch body: an assignment there is conditional */
  inlined: Set<number>,
): { line: number; rhs: string } | null {
  // Brace depth at the start of each line, string and char literals skipped.
  const depth: number[] = [];
  let d = 0;
  for (const line of slice) {
    depth.push(d);
    const code = line.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)'/g, "''").replace(/\/\/.*$/, '');
    for (const c of code) {
      if (c === '{') d++;
      else if (c === '}') d--;
    }
  }
  const target = depth[retLine];
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const assign = new RegExp(`^\\s*(?:(?:final\\s+)?[A-Za-z_][\\w.]*(?:\\s*<[^>]*>)?(?:\\s*\\[\\s*\\])*\\s+)?${esc}\\s*=\\s*(.+?);\\s*(?://.*)?$`);
  const mentionsAssign = new RegExp(`(?<![\\w.])${esc}\\s*=(?!=)`);
  for (let j = retLine - 1; j >= 0; j--) {
    if (depth[j] < target) return null; // left the return's block
    if (dead.has(j)) continue;
    if (!mentionsAssign.test(slice[j])) continue;
    if (depth[j] > target || inlined.has(j)) return null; // a conditional reassignment
    const m = assign.exec(slice[j]);
    if (!m) return null; // wrapped or compound assignment
    return { line: j, rhs: m[1] };
  }
  return null;
}

/** DFG-forward names reachable from a helper-return assignment LHS (same file). */
function localsDerivedFromAssignee(
  graph: PassContext['graph'],
  seedVar: string,
  seedLine: number,
): Set<string> {
  const defs = graph.ir.dfg.defs;
  const chains = graph.ir.dfg.chains ?? [];
  const seedDefs = defs.filter(
    d => d.variable === seedVar && d.line === seedLine && d.kind === 'local',
  );
  if (seedDefs.length === 0) return new Set([seedVar]);

  const defIds = new Set<number>(seedDefs.map(d => d.id));
  const frontier = seedDefs.map(d => d.id);
  const visited = new Set<number>(frontier);
  while (frontier.length > 0) {
    const cur = frontier.shift()!;
    for (const ch of chains) {
      if (ch.from_def !== cur || visited.has(ch.to_def)) continue;
      visited.add(ch.to_def);
      defIds.add(ch.to_def);
      frontier.push(ch.to_def);
    }
  }

  const names = new Set<string>([seedVar]);
  for (const d of defs) {
    if (d.variable && defIds.has(d.id)) names.add(d.variable);
  }
  return names;
}

function sinkVariableConsumingDerived(
  graph: PassContext['graph'],
  sink: TaintSink,
  derived: Set<string>,
): string | undefined {
  for (const u of graph.usesAtLine(sink.line)) {
    if (u.variable && derived.has(u.variable)) return u.variable;
  }
  for (const call of graph.callsByLine.get(sink.line) ?? []) {
    for (const arg of call.arguments ?? []) {
      if (arg.variable && derived.has(arg.variable)) return arg.variable;
      if (arg.expression) {
        for (const v of derived) {
          const re = new RegExp(`\\b${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
          if (re.test(arg.expression)) return v;
        }
      }
    }
  }
  return undefined;
}

function enclosingMethodName(types: TypeInfo[], line: number): string | null {
  for (const type of types) {
    for (const method of type.methods) {
      if (line >= method.start_line && line <= method.end_line) {
        return method.name;
      }
    }
  }
  return null;
}

export function csharpParamReachesSink(
  code: string,
  method: { parameters: Array<{ name: string; position: number }>; startLine: number },
  taintedArgs: number[],
  sink: { line: number; type: string },
  credit: CSharpCredit | null,
): boolean {
  // CRLF files leave `\r` on every line, which `.` and `$` will not cross.
  const lines = code.split(/\r?\n/);
  const params = taintedArgs.length > 0
    ? method.parameters.filter(p => taintedArgs.includes(p.position))
    : method.parameters;
  if (params.length === 0) return true;
  const derived = new Set(params.map(p => p.name));
  // A name inside a string literal is text, not a use: `"… WHERE name = @name"`
  // does not mention the parameter `name`. Interpolation holes are real uses.
  const codeOf = (text: string): string =>
    text
      .replace(/\$@?"(?:[^"\\]|\\.)*"/g, lit => ' ' + [...lit.matchAll(/\{([^}]*)\}/g)].map(x => x[1]).join(' ') + ' ')
      .replace(/@?"(?:[^"\\]|\\.)*"/g, ' ')
      .replace(/'(?:[^'\\]|\\.)'/g, ' ');
  const mentionsDerived = (text: string): string[] => {
    const bare = codeOf(text);
    return [...derived].filter(v => new RegExp(`(?<![\\w.])${v}(?![\\w])`).test(bare));
  };

  const assignRe = /^\s*(?:var\s+|[A-Za-z_][\w.<>[\]?]*\s+)?([A-Za-z_]\w*)\s*=(?!=)\s*(.+)$/;
  const objectWriteRe = /^\s*([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*(?:\+?=(?!=)|\()(.*)$/;
  for (let i = method.startLine + 1; i < sink.line; i++) {
    const text = lines[i - 1] ?? '';
    const assign = assignRe.exec(text);
    if (assign) {
      if (mentionsDerived(assign[2]).length > 0) derived.add(assign[1]);
      else if (!params.some(p => p.name === assign[1])) derived.delete(assign[1]);
      continue;
    }
    const write = objectWriteRe.exec(text);
    if (write && mentionsDerived(write[2]).length > 0) derived.add(write[1]);
  }

  // The sink statement, joined when it wraps over several lines.
  let statement = lines[sink.line - 1] ?? '';
  for (let i = sink.line; i < lines.length && i < sink.line + 6 && !/[;{}]\s*$/.test(statement.trimEnd()); i++) {
    statement += ' ' + (lines[i] ?? '').trim();
  }
  const reaching = mentionsDerived(statement);
  if (reaching.length === 0) return false;
  if (!credit) return true;
  const safe = new Set([...credit.sanitizedVarsAt(sink.type, sink.line), ...credit.guardedVarsAt(sink.type, sink.line)]);
  return reaching.some(v => !safe.has(v));
}
