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
/** cognium-dev#590 — connect a source inside a callee to a sink in the caller. */
function appendCalleeSourceCallerSinkFlows(
  graph: PassContext['graph'],
  sources: import('../../types/index.js').TaintSource[],
  sinks: TaintSink[],
  interProc: InterproceduralResult,
  additionalFlows: TaintFlowInfo[],
  fileCode?: string,
): void {
  const types = graph.ir.types ?? [];
  for (const edge of interProc.callEdges) {
    const callee = interProc.methodNodes.get(edge.calleeMethod);
    if (!callee) continue;

    const calleeSources = sources.filter(
      s => s.line >= callee.startLine && s.line <= callee.endLine,
    );
    if (calleeSources.length === 0) continue;

    const assignee = graph.ir.dfg.defs.find(
      d => d.line === edge.callLine && d.kind === 'local',
    );
    if (!assignee?.variable) continue;

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
        (sink.type === 'sql_injection' ||
          sink.type === 'trust_boundary' ||
          sink.type === 'command_injection') &&
        (interproceduralParamReachIsDeadBranchOnly(
          fileCode,
          callee.startLine,
          callee.endLine,
          source.variable,
          assignee.variable,
        ) ||
          (sink.type === 'command_injection' &&
            calleeReturnNotTaintedFromParam(
              fileCode,
              callee.startLine,
              callee.endLine,
              source.variable,
            )))
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

/** cognium-dev#914 — param does not reach a `return <id>` on live paths (constant helper return). */
function calleeReturnNotTaintedFromParam(
  code: string,
  startLine: number,
  endLine: number,
  paramName: string,
): boolean {
  const slice = code.split('\n').slice(startLine - 1, endLine);
  const sliceText = slice.join('\n');
  const dead = computeDeadJavaBranchLines(slice);
  const live = buildJavaTaintedVars(sliceText, new Set([paramName]), dead);
  for (const line of slice) {
    const m = line.match(/^\s*return\s+([A-Za-z_]\w*)\s*;\s*$/);
    if (m && live.has(m[1])) return false;
  }
  return true;
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
