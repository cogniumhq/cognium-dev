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
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { TaintPropagationPassResult } from './taint-propagation-pass.js';
import { analyzeInterprocedural, findTaintBridges } from '../interprocedural.js';
import { attachSourceLineCode } from '../taint-matcher.js';
import { shouldGateInterproceduralParam } from '../entry-point-detection.js';

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

      for (const sink of interProc.propagatedSinks) {
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
              if ((san.sanitizes as readonly string[]).includes(f.sink_type)) {
                sanitizedSinkKeys.add(`${f.sink_line}:${f.sink_type}`);
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
      // Also drop additionalSinks whose flows were all filtered out and
      // which are synthetic external_taint_escape (otherwise the sink
      // remains in r.taint.sinks producing a stale finding).
      filteredAdditionalSinks = additionalSinks.filter(s => {
        if (s.type !== 'external_taint_escape') return true;
        return !sanitizedSinkKeys.has(`${s.line}:${s.type}`);
      });
    }

    return { additionalSinks: filteredAdditionalSinks, additionalFlows: filteredAdditionalFlows, interprocedural };
  }
}
