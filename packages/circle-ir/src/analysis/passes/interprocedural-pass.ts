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

import type { TaintSink, TaintFlowInfo, InterproceduralInfo } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { TaintPropagationPassResult } from './taint-propagation-pass.js';
import { analyzeInterprocedural, findTaintBridges } from '../interprocedural.js';

export interface InterproceduralPassResult {
  /** Additional sinks surfaced by inter-procedural analysis. */
  additionalSinks: TaintSink[];
  /** Additional flows generated from inter-procedural paths. */
  additionalFlows: TaintFlowInfo[];
  /** Structured inter-procedural summary for the IR output. */
  interprocedural?: InterproceduralInfo;
}

export class InterproceduralPass implements AnalysisPass<InterproceduralPassResult> {
  readonly name = 'interprocedural';
  readonly category = 'security' as const;

  run(ctx: PassContext): InterproceduralPassResult {
    const { graph } = ctx;

    const constProp   = ctx.getResult<ConstantPropagatorResult>('constant-propagation');
    const sinkFilter  = ctx.getResult<SinkFilterResult>('sink-filter');
    const taintProp   = ctx.getResult<TaintPropagationPassResult>('taint-propagation');

    const { sources, sinks, sanitizers } = sinkFilter;

    if (sources.length === 0) {
      return { additionalSinks: [], additionalFlows: [] };
    }

    const additionalSinks: TaintSink[] = [];
    const additionalFlows: TaintFlowInfo[] = [...taintProp.flows];
    let interprocedural: InterproceduralInfo | undefined;

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

    return { additionalSinks, additionalFlows, interprocedural };
  }
}
