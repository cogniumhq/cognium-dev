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

    if (sources.length === 0 || sinks.length === 0) {
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
    const arrayFlows = detectArrayElementFlows(calls, sources, sinks, constProp.taintedArrayElements, constProp.unreachableLines) ?? [];
    for (const f of arrayFlows) {
      if (!flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line)) {
        flows.push(f);
      }
    }

    // Supplement: collection/iterator flows — with FP filtering
    const collectionFlows = detectCollectionFlows(calls, sources, sinks, constProp.tainted, constProp.unreachableLines) ?? [];
    for (const f of collectionFlows) {
      if (flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line)) continue;

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
    const paramFlows = detectParameterSinkFlows(types, calls, sources, sinks, constProp.unreachableLines) ?? [];
    for (const f of paramFlows) {
      if (!flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line)) {
        flows.push(f);
      }
    }

    return { flows };
  }
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
            const source = sources[0];
            if (source) {
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
                const source = sources[0];
                if (source) {
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
              const source = sources[0];
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
            const exists = flows.some(f => f.source_line === paramSource.line && f.sink_line === sink.line);
            if (!exists) {
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
