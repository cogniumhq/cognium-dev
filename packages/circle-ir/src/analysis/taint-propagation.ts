/**
 * Taint Propagation Engine
 *
 * Tracks taint through variable assignments, method returns, and field accesses
 * using the DFG (Data Flow Graph) to find precise source-to-sink paths.
 */

import type {
  DFG,
  DFGDef,
  DFGUse,
  DFGChain,
  CallInfo,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  SinkType,
} from '../types/index.js';
import { CodeGraph } from '../graph/index.js';

/**
 * Represents a tainted variable at a specific point in the code.
 */
export interface TaintedVariable {
  variable: string;
  defId: number;
  line: number;
  sourceType: string;
  sourceLine: number;
  confidence: number;
}

/**
 * Represents a taint flow from source to sink.
 */
export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  path: TaintFlowStep[];
  sanitized: boolean;
  sanitizer?: TaintSanitizer;
  confidence: number;
}

/**
 * A step in the taint flow path.
 */
export interface TaintFlowStep {
  variable: string;
  line: number;
  type: 'source' | 'assignment' | 'use' | 'return' | 'field' | 'sink';
  description: string;
}

/**
 * Result of taint propagation analysis.
 */
export interface TaintPropagationResult {
  taintedVars: TaintedVariable[];
  flows: TaintFlow[];
  reachableSinks: Map<TaintSink, TaintSource[]>;
}

/**
 * Propagate taint through the dataflow graph.
 *
 * Accepts either a CodeGraph (preferred) or the legacy (dfg, calls, ...) signature
 * for backward compatibility with existing call sites and tests.
 */
export function propagateTaint(
  graphOrDfg: CodeGraph | DFG,
  callsOrSources: CallInfo[] | TaintSource[],
  sourcesOrSinks: TaintSource[] | TaintSink[],
  sinksOrSanitizers: TaintSink[] | TaintSanitizer[],
  sanitizersArg?: TaintSanitizer[]
): TaintPropagationResult {
  let graph: CodeGraph;
  let sources: TaintSource[];
  let sinks: TaintSink[];
  let sanitizers: TaintSanitizer[];

  if (graphOrDfg instanceof CodeGraph) {
    // New signature: (graph, sources, sinks, sanitizers)
    graph = graphOrDfg;
    sources = callsOrSources as TaintSource[];
    sinks = sourcesOrSinks as TaintSink[];
    sanitizers = sinksOrSanitizers as TaintSanitizer[];
  } else {
    // Legacy signature: (dfg, calls, sources, sinks, sanitizers)
    const dfg = graphOrDfg as DFG;
    const calls = callsOrSources as CallInfo[];
    sources = sourcesOrSinks as TaintSource[];
    sinks = sinksOrSanitizers as TaintSink[];
    sanitizers = sanitizersArg ?? [];
    graph = new CodeGraph({
      meta: { circle_ir: '3.0', file: '', language: 'java', loc: 0, hash: '' },
      types: [], calls, cfg: { blocks: [], edges: [] }, dfg,
      taint: { sources: [], sinks: [], sanitizers },
      imports: [], exports: [], unresolved: [], enriched: {},
    });
  }

  const taintedVars: TaintedVariable[] = [];
  const flows: TaintFlow[] = [];
  const reachableSinks = new Map<TaintSink, TaintSource[]>();

  // Use pre-computed indexes from CodeGraph — no local map building needed
  const defsByLine = graph.defsByLine;
  const usesByLine = graph.usesByLine;
  const callsByLine = graph.callsByLine;
  const sanitizersByLine = graph.sanitizersByLine;
  const defById = graph.defById;

  // Step 1: Identify initial tainted definitions (from sources)
  const rawInitialTaint = findInitialTaint(sources, callsByLine, defsByLine);

  // Filter variables added via the "next-line" heuristic that are actually the
  // result of a sanitizer call.  The source variable itself (tv.line ===
  // tv.sourceLine) is always tainted; next-line additions need an extra check.
  const initialTaint = rawInitialTaint.filter(tv => {
    if (tv.line === tv.sourceLine) return true;
    const sanCheck = checkSanitized(tv.sourceLine, tv.line, tv.sourceType, sanitizersByLine);
    return !sanCheck.sanitized;
  });
  taintedVars.push(...initialTaint);

  // Step 2: Propagate taint through def-use chains
  const propagatedTaint = propagateThroughChains(
    initialTaint,
    graph.chainsByFromDef,
    defById,
    sanitizersByLine
  );
  taintedVars.push(...propagatedTaint);

  // Combine all tainted definitions
  const allTaintedDefIds = new Set<number>();
  const taintByDefId = new Map<number, TaintedVariable>();
  for (const tv of taintedVars) {
    allTaintedDefIds.add(tv.defId);
    taintByDefId.set(tv.defId, tv);
  }

  // Step 3: Check which sinks are reachable from tainted variables
  for (const sink of sinks) {
    const usesAtSink = usesByLine.get(sink.line) ?? [];
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    // Check if any argument to the sink call is tainted
    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        if (arg.variable) {
          // If the sink defines dangerous argument positions, skip safe positions.
          // For example, execSync(cmd, opts) has arg_positions: [0] — only arg 0
          // (the command string) is a sink; arg 1 (options with cwd) is safe.
          if (sink.argPositions && sink.argPositions.length > 0) {
            if (!sink.argPositions.includes(arg.position)) {
              continue;
            }
          }
          // Find if this variable use is tainted
          for (const use of usesAtSink) {
            if (use.variable === arg.variable && use.def_id !== null) {
              if (allTaintedDefIds.has(use.def_id)) {
                const taintInfo = taintByDefId.get(use.def_id);
                if (taintInfo) {
                  // Check if sanitized
                  const isSanitized = checkSanitized(
                    taintInfo.line,
                    sink.line,
                    sink.type,
                    sanitizersByLine
                  );

                  if (!isSanitized.sanitized) {
                    // Find the source
                    const source = sources.find(s => s.line === taintInfo.sourceLine);
                    if (source) {
                      // Record the flow
                      const flow = buildTaintFlow(
                        source,
                        sink,
                        taintInfo
                      );
                      flows.push(flow);

                      // Record reachable sink
                      const existingSources = reachableSinks.get(sink) ?? [];
                      if (!existingSources.some(s => s.line === source.line)) {
                        existingSources.push(source);
                      }
                      reachableSinks.set(sink, existingSources);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return { taintedVars, flows, reachableSinks };
}

/**
 * Find initial tainted definitions from sources.
 */
function findInitialTaint(
  sources: TaintSource[],
  callsByLine: Map<number, CallInfo[]>,
  defsByLine: Map<number, DFGDef[]>
): TaintedVariable[] {
  const tainted: TaintedVariable[] = [];

  for (const source of sources) {
    // Find definitions on the same line as the source
    const defsOnLine = defsByLine.get(source.line) ?? [];

    for (const def of defsOnLine) {
      tainted.push({
        variable: def.variable,
        defId: def.id,
        line: def.line,
        sourceType: source.type,
        sourceLine: source.line,
        confidence: source.confidence,
      });
    }

    // Also check the next line (for cases like: String x = request.getParameter("foo"))
    const defsNextLine = defsByLine.get(source.line + 1) ?? [];
    for (const def of defsNextLine) {
      // Only include if there's a call on the source line
      const callsOnSourceLine = callsByLine.get(source.line) ?? [];
      if (callsOnSourceLine.length > 0) {
        tainted.push({
          variable: def.variable,
          defId: def.id,
          line: def.line,
          sourceType: source.type,
          sourceLine: source.line,
          confidence: source.confidence * 0.9, // Slightly lower confidence
        });
      }
    }
  }

  return tainted;
}

/**
 * Propagate taint through def-use chains.
 * Accepts a pre-computed chainsByFromDef index (from CodeGraph) — no internal
 * adjacency list building needed.
 */
function propagateThroughChains(
  initialTaint: TaintedVariable[],
  chainsByFromDef: Map<number, DFGChain[]>,
  defById: Map<number, DFGDef>,
  sanitizersByLine: Map<number, TaintSanitizer[]>
): TaintedVariable[] {
  const propagated: TaintedVariable[] = [];
  const taintedDefIds = new Set<number>(initialTaint.map(t => t.defId));
  const taintInfoByDefId = new Map<number, TaintedVariable>();

  for (const t of initialTaint) {
    taintInfoByDefId.set(t.defId, t);
  }

  // BFS to propagate taint
  const queue = [...initialTaint.map(t => t.defId)];
  const visited = new Set<number>(queue);

  while (queue.length > 0) {
    const currentDefId = queue.shift()!;
    const currentTaint = taintInfoByDefId.get(currentDefId);
    if (!currentTaint) continue;

    const outgoingChains = chainsByFromDef.get(currentDefId) ?? [];

    for (const chain of outgoingChains) {
      if (visited.has(chain.to_def)) continue;

      const targetDef = defById.get(chain.to_def);
      if (!targetDef) continue;

      // Check if there's a sanitizer between source and this def
      const sanitizeCheck = checkSanitized(
        currentTaint.sourceLine,
        targetDef.line,
        currentTaint.sourceType,
        sanitizersByLine
      );

      if (!sanitizeCheck.sanitized) {
        const newTaint: TaintedVariable = {
          variable: targetDef.variable,
          defId: targetDef.id,
          line: targetDef.line,
          sourceType: currentTaint.sourceType,
          sourceLine: currentTaint.sourceLine,
          confidence: currentTaint.confidence * 0.95, // Decay confidence slightly
        };

        propagated.push(newTaint);
        taintedDefIds.add(targetDef.id);
        taintInfoByDefId.set(targetDef.id, newTaint);
        visited.add(targetDef.id);
        queue.push(targetDef.id);
      }
    }
  }

  return propagated;
}

// Sink types recognised by the sanitizer patterns.  Used to distinguish
// "propagation context" (sinkType is a source type like 'request_param') from
// "sink-check context" (sinkType is a real sink type like 'sql_injection').
const KNOWN_SINK_TYPES = new Set<string>([
  'sql_injection', 'xss', 'path_traversal', 'command_injection',
  'ssrf', 'ldap_injection', 'xpath_injection', 'log_injection',
  'xxe', 'deserialization', 'code_injection',
]);

/**
 * Check if a taint flow is sanitized at the target line.
 *
 * Strategy: check for a sanitizer call AT `toLine` only — NOT a range scan
 * between fromLine and toLine. A range scan is intentionally avoided because
 * it was too aggressive: a sanitizer on a *different* variable (e.g.
 * `clean = sanitize(name); sink(name)`) would incorrectly mark the unsanitized
 * path as safe.
 *
 * Checking AT `toLine` is variable-specific: in the propagation chain
 * `from_def → to_def`, if there is a sanitizer at `to_def.line`, the
 * assignment is `to_def.variable = sanitizer(from_def.variable)` — the
 * result variable is the sanitized output and taint should not propagate.
 *
 * Context differentiation via `sinkType`:
 *   Known sink type (e.g. 'sql_injection') — sink-check context; require the
 *     sanitizer to cover that specific type.
 *   Unknown / source type (e.g. 'request_param') — propagation context; accept
 *     any recognised sanitizer, since the eventual sink type is not yet known.
 *     This may miss cross-type scenarios (XSS sanitizer applied to data that
 *     later flows to a SQL sink) but eliminates false positives for correctly
 *     sanitized code.
 */
function checkSanitized(
  _fromLine: number,
  toLine: number,
  sinkType: string,
  sanitizersByLine: Map<number, TaintSanitizer[]>
): { sanitized: boolean; sanitizer?: TaintSanitizer } {
  const sanitizersAtTarget = sanitizersByLine.get(toLine);
  if (!sanitizersAtTarget || sanitizersAtTarget.length === 0) {
    return { sanitized: false };
  }

  const isKnownSinkType = KNOWN_SINK_TYPES.has(sinkType);

  for (const san of sanitizersAtTarget) {
    if (isKnownSinkType) {
      // Sink-check context: sanitizer must cover this specific vulnerability type.
      if (san.sanitizes.includes(sinkType as SinkType)) {
        return { sanitized: true, sanitizer: san };
      }
    } else {
      // Propagation context: accept any sanitizer that covers at least one
      // sink type (i.e. is a genuine sanitizer method, not a no-op stub).
      if (san.sanitizes.length > 0) {
        return { sanitized: true, sanitizer: san };
      }
    }
  }

  return { sanitized: false };
}

/**
 * Build a taint flow path from source to sink.
 */
function buildTaintFlow(
  source: TaintSource,
  sink: TaintSink,
  taintInfo: TaintedVariable
): TaintFlow {
  const path: TaintFlowStep[] = [];

  // Start with source
  path.push({
    variable: taintInfo.variable,
    line: source.line,
    type: 'source',
    description: `Tainted data enters via ${source.type}`,
  });

  // Add intermediate assignments if we can trace them
  // For now, just add the tainted variable assignment
  if (taintInfo.line !== source.line) {
    path.push({
      variable: taintInfo.variable,
      line: taintInfo.line,
      type: 'assignment',
      description: `Tainted value assigned to ${taintInfo.variable}`,
    });
  }

  // End with sink
  path.push({
    variable: taintInfo.variable,
    line: sink.line,
    type: 'sink',
    description: `Tainted value reaches ${sink.type} sink`,
  });

  return {
    source,
    sink,
    path,
    sanitized: false,
    confidence: taintInfo.confidence * 0.9, // Factor in path length
  };
}

/**
 * Analyze method returns to propagate taint through return values.
 */
export function analyzeMethodReturns(
  dfg: DFG,
  calls: CallInfo[],
  taintedVars: TaintedVariable[]
): TaintedVariable[] {
  const additionalTaint: TaintedVariable[] = [];
  const taintedDefIds = new Set(taintedVars.map(t => t.defId));

  // Find return statements that return tainted values
  const returnDefs = dfg.defs.filter(d => d.kind === 'return');

  // For each return def, check if the returned value is tainted
  for (const returnDef of returnDefs) {
    // Find uses on the same line that might be the returned value
    const usesOnLine = dfg.uses.filter(u => u.line === returnDef.line);

    for (const use of usesOnLine) {
      if (use.def_id !== null && taintedDefIds.has(use.def_id)) {
        // This return statement returns a tainted value
        // Now find calls to this method and taint their results
        // (This would require method-level analysis which we'll add later)
      }
    }
  }

  return additionalTaint;
}

/**
 * Calculate confidence score for a taint flow.
 */
export function calculateFlowConfidence(flow: TaintFlow): number {
  let confidence = 1.0;

  // Factor 1: Source confidence
  confidence *= flow.source.confidence;

  // Factor 2: Path length (longer paths = less confident)
  const pathLength = flow.path.length;
  confidence *= Math.pow(0.95, pathLength - 2); // -2 for source and sink

  // Factor 3: Sanitization
  if (flow.sanitized) {
    confidence = 0;
  }

  return Math.max(0, Math.min(1, confidence));
}

/**
 * Get summary statistics for taint propagation.
 */
export function getTaintStats(result: TaintPropagationResult): {
  totalTaintedVars: number;
  totalFlows: number;
  flowsBySinkType: Map<string, number>;
  avgConfidence: number;
} {
  const flowsBySinkType = new Map<string, number>();

  for (const flow of result.flows) {
    const count = flowsBySinkType.get(flow.sink.type) ?? 0;
    flowsBySinkType.set(flow.sink.type, count + 1);
  }

  const avgConfidence = result.flows.length > 0
    ? result.flows.reduce((sum, f) => sum + f.confidence, 0) / result.flows.length
    : 0;

  return {
    totalTaintedVars: result.taintedVars.length,
    totalFlows: result.flows.length,
    flowsBySinkType,
    avgConfidence,
  };
}
