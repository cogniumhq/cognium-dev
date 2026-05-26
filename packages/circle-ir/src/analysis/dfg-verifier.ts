/**
 * DFG Verifier - Track 2 validation using def-use chains
 *
 * Verifies that taint actually flows from source to sink by following
 * the data flow graph. This provides a more precise validation than
 * pattern matching alone.
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
} from '../types/index.js';
import { CodeGraph } from '../graph/index.js';

/**
 * Result of DFG verification
 */
export interface VerificationResult {
  verified: boolean;          // True if taint flow is confirmed
  confidence: number;         // 0.0 - 1.0
  reason: string;             // Explanation
  path?: VerificationPath;    // The verified path (if found)
  alternativePaths?: number;  // Number of alternative paths found
}

/**
 * A verified path through the DFG
 */
export interface VerificationPath {
  steps: VerificationStep[];
  length: number;
  hasDirectFlow: boolean;     // True if no intermediate transforms
}

/**
 * A step in the verification path
 */
export interface VerificationStep {
  defId: number;
  variable: string;
  line: number;
  kind: DFGDef['kind'];
  flowType: 'direct' | 'assignment' | 'call' | 'return' | 'field';
}

/**
 * Configuration for the verifier
 */
export interface VerifierConfig {
  maxDepth?: number;          // Maximum depth to search (default: 30)
  requireDirectFlow?: boolean; // Only accept direct flows (default: false)
  allowFieldFlows?: boolean;   // Allow taint through fields (default: true)
}

/**
 * DFGVerifier - Verifies taint flows using def-use chains
 */
export class DFGVerifier {
  private graph: CodeGraph;
  private sanitizers: TaintSanitizer[];
  private config: Required<VerifierConfig>;
  private sanitizerLines: Set<number>;

  constructor(
    graphOrDfg: CodeGraph | DFG,
    callsOrSanitizers: CallInfo[] | TaintSanitizer[],
    sanitizersOrConfig?: TaintSanitizer[] | VerifierConfig,
    config: VerifierConfig = {}
  ) {
    // Support both new CodeGraph signature and legacy (dfg, calls, sanitizers, config) signature
    if (graphOrDfg instanceof CodeGraph) {
      this.graph = graphOrDfg;
      this.sanitizers = callsOrSanitizers as TaintSanitizer[];
      const cfg = sanitizersOrConfig as VerifierConfig | undefined;
      this.config = {
        maxDepth: cfg?.maxDepth ?? 30,
        requireDirectFlow: cfg?.requireDirectFlow ?? false,
        allowFieldFlows: cfg?.allowFieldFlows ?? true,
      };
    } else {
      // Legacy: (dfg, calls, sanitizers, config)
      const dfg = graphOrDfg as DFG;
      const calls = callsOrSanitizers as CallInfo[];
      const sanitizers = sanitizersOrConfig as TaintSanitizer[] ?? [];
      this.graph = new CodeGraph({
        meta: { circle_ir: '3.0', file: '', language: 'java', loc: 0, hash: '' },
        types: [], calls, cfg: { blocks: [], edges: [] }, dfg,
        taint: { sources: [], sinks: [], sanitizers },
        imports: [], exports: [], unresolved: [], enriched: {},
      });
      this.sanitizers = sanitizers;
      this.config = {
        maxDepth: config.maxDepth ?? 30,
        requireDirectFlow: config.requireDirectFlow ?? false,
        allowFieldFlows: config.allowFieldFlows ?? true,
      };
    }

    this.sanitizerLines = new Set(this.sanitizers.map(s => s.line));
  }

  /**
   * Verify if taint flows from source to sink
   */
  verify(source: TaintSource, sink: TaintSink): VerificationResult {
    // Find definitions at the source line
    const sourceDefs = this.graph.defsAtLine(source.line);

    if (sourceDefs.length === 0) {
      return {
        verified: false,
        confidence: 0,
        reason: `No variable definition found at source line ${source.line}`,
      };
    }

    // Try to find a path from any source definition to the sink
    const allPaths: VerificationPath[] = [];

    for (const sourceDef of sourceDefs) {
      const path = this.findPath(sourceDef, sink);
      if (path) {
        allPaths.push(path);
      }
    }

    if (allPaths.length === 0) {
      return {
        verified: false,
        confidence: 0.2,  // Some confidence since pattern matched
        reason: `No def-use chain found from source (line ${source.line}) to sink (line ${sink.line})`,
      };
    }

    // Find the best path (shortest, direct if possible)
    const bestPath = this.selectBestPath(allPaths);

    // Check for sanitizers in path
    const sanitizerInPath = this.checkSanitizers(bestPath);
    if (sanitizerInPath) {
      return {
        verified: false,
        confidence: 0.1,
        reason: `Flow sanitized at line ${sanitizerInPath.line} by ${sanitizerInPath.method}`,
        path: bestPath,
        alternativePaths: allPaths.length - 1,
      };
    }

    // Calculate confidence based on path characteristics
    const confidence = this.calculateConfidence(bestPath);

    return {
      verified: true,
      confidence,
      reason: `Verified: ${bestPath.length}-step flow from line ${source.line} to line ${sink.line}`,
      path: bestPath,
      alternativePaths: allPaths.length - 1,
    };
  }

  /**
   * Find a path from a definition to a sink using BFS
   */
  private findPath(sourceDef: DFGDef, sink: TaintSink): VerificationPath | null {
    interface SearchState {
      def: DFGDef;
      steps: VerificationStep[];
      visited: Set<number>;
    }

    const initialStep: VerificationStep = {
      defId: sourceDef.id,
      variable: sourceDef.variable,
      line: sourceDef.line,
      kind: sourceDef.kind,
      flowType: 'direct',
    };

    const queue: SearchState[] = [{
      def: sourceDef,
      steps: [initialStep],
      visited: new Set([sourceDef.id]),
    }];

    while (queue.length > 0) {
      const state = queue.shift()!;

      // Check depth limit
      if (state.steps.length > this.config.maxDepth) {
        continue;
      }

      // Check if current definition reaches the sink
      if (this.reachesSink(state.def, sink)) {
        return {
          steps: state.steps,
          length: state.steps.length,
          hasDirectFlow: state.steps.every(s => s.flowType === 'direct' || s.flowType === 'assignment'),
        };
      }

      // Explore via def-use chains (if available)
      const chains = this.graph.chainsFrom(state.def.id);
      for (const chain of chains) {
        const nextDef = this.graph.defById.get(chain.to_def);
        if (!nextDef || state.visited.has(nextDef.id)) continue;

        const step: VerificationStep = {
          defId: nextDef.id,
          variable: nextDef.variable,
          line: nextDef.line,
          kind: nextDef.kind,
          flowType: 'assignment',
        };

        const newVisited = new Set(state.visited);
        newVisited.add(nextDef.id);

        queue.push({
          def: nextDef,
          steps: [...state.steps, step],
          visited: newVisited,
        });
      }

      // Explore via uses of the current definition
      const uses = this.graph.usesOfDef(state.def.id);
      for (const use of uses) {
        // Find definitions at the use line
        const nextDefs = this.graph.defsAtLine(use.line);

        for (const nextDef of nextDefs) {
          if (state.visited.has(nextDef.id)) continue;

          // Skip field flows if not allowed
          if (!this.config.allowFieldFlows && nextDef.kind === 'field') {
            continue;
          }

          const flowType = this.determineFlowType(state.def, nextDef, use.line);

          const step: VerificationStep = {
            defId: nextDef.id,
            variable: nextDef.variable,
            line: nextDef.line,
            kind: nextDef.kind,
            flowType,
          };

          const newVisited = new Set(state.visited);
          newVisited.add(nextDef.id);

          queue.push({
            def: nextDef,
            steps: [...state.steps, step],
            visited: newVisited,
          });
        }
      }

      // Explore same-variable definitions at later lines
      const laterDefs = this.graph.laterDefsOfVar(state.def.variable, state.def.line, sink.line)
        .filter(d => !state.visited.has(d.id))
        .slice(0, 5);  // Limit branching

      for (const nextDef of laterDefs) {
        const step: VerificationStep = {
          defId: nextDef.id,
          variable: nextDef.variable,
          line: nextDef.line,
          kind: nextDef.kind,
          flowType: 'assignment',
        };

        const newVisited = new Set(state.visited);
        newVisited.add(nextDef.id);

        queue.push({
          def: nextDef,
          steps: [...state.steps, step],
          visited: newVisited,
        });
      }
    }

    return null;
  }

  /**
   * Check if a definition reaches a sink
   */
  private reachesSink(def: DFGDef, sink: TaintSink): boolean {
    // Check uses at sink line
    for (const use of this.graph.usesAtLine(sink.line)) {
      if (use.variable === def.variable || use.def_id === def.id) {
        return true;
      }
    }

    // Check call arguments at sink line
    for (const call of this.graph.callsAtLine(sink.line)) {
      for (const arg of call.arguments) {
        if (arg.variable === def.variable) {
          return true;
        }
      }
    }

    // Check if definition is at or before sink line with same variable
    if (def.line <= sink.line) {
      const laterDefs = this.graph.laterDefsOfVar(def.variable, def.line, sink.line);
      // If no redefinition between def and sink, it reaches
      if (laterDefs.length === 0) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determine the type of flow between two definitions
   */
  private determineFlowType(
    fromDef: DFGDef,
    toDef: DFGDef,
    useLine: number
  ): VerificationStep['flowType'] {
    // Check for call at the line
    const calls = this.graph.callsAtLine(useLine);
    if (calls.length > 0) {
      // If the variable changed, it's a return assignment
      if (fromDef.variable !== toDef.variable) {
        return 'return';
      }
      return 'call';
    }

    // Check for field access
    if (toDef.kind === 'field') {
      return 'field';
    }

    // Simple assignment
    if (fromDef.variable === toDef.variable) {
      return 'direct';
    }

    return 'assignment';
  }

  /**
   * Select the best path from multiple candidates
   */
  private selectBestPath(paths: VerificationPath[]): VerificationPath {
    // Prefer direct flows
    const directPaths = paths.filter(p => p.hasDirectFlow);
    if (directPaths.length > 0) {
      return directPaths.reduce((a, b) => a.length <= b.length ? a : b);
    }

    // Otherwise, prefer shortest path
    return paths.reduce((a, b) => a.length <= b.length ? a : b);
  }

  /**
   * Check if any sanitizer is in the path
   */
  private checkSanitizers(path: VerificationPath): TaintSanitizer | null {
    for (const step of path.steps) {
      if (this.sanitizerLines.has(step.line)) {
        return this.sanitizers.find(s => s.line === step.line) || null;
      }
    }
    return null;
  }

  /**
   * Calculate confidence based on path characteristics
   */
  private calculateConfidence(path: VerificationPath): number {
    let confidence = 0.9;  // Base confidence for verified flow

    // Bonus for direct flow
    if (path.hasDirectFlow) {
      confidence += 0.05;
    }

    // Penalty for long paths
    if (path.length > 5) {
      confidence -= 0.05;
    }
    if (path.length > 10) {
      confidence -= 0.1;
    }

    // Penalty for field flows
    const fieldSteps = path.steps.filter(s => s.flowType === 'field').length;
    confidence -= fieldSteps * 0.05;

    return Math.max(0.5, Math.min(1.0, confidence));
  }

  /**
   * Batch verify multiple source-sink pairs
   */
  verifyAll(
    sources: TaintSource[],
    sinks: TaintSink[]
  ): Map<string, VerificationResult> {
    const results = new Map<string, VerificationResult>();

    for (const source of sources) {
      for (const sink of sinks) {
        const key = `${source.line}:${sink.line}`;
        const result = this.verify(source, sink);
        results.set(key, result);
      }
    }

    return results;
  }

  /**
   * Get verification statistics
   */
  getStats(results: Map<string, VerificationResult>): {
    total: number;
    verified: number;
    notVerified: number;
    sanitized: number;
    avgConfidence: number;
  } {
    let verified = 0;
    let notVerified = 0;
    let sanitized = 0;
    let totalConfidence = 0;

    for (const result of results.values()) {
      if (result.verified) {
        verified++;
        totalConfidence += result.confidence;
      } else if (result.reason.includes('sanitized')) {
        sanitized++;
      } else {
        notVerified++;
      }
    }

    return {
      total: results.size,
      verified,
      notVerified,
      sanitized,
      avgConfidence: verified > 0 ? totalConfidence / verified : 0,
    };
  }
}

/**
 * Convenience function to verify a single flow
 */
export function verifyTaintFlow(
  dfg: DFG,
  calls: CallInfo[],
  source: TaintSource,
  sink: TaintSink,
  sanitizers: TaintSanitizer[] = [],
  config: VerifierConfig = {}
): VerificationResult {
  const verifier = new DFGVerifier(dfg, calls, sanitizers, config);
  return verifier.verify(source, sink);
}

/**
 * Format verification result for display
 */
export function formatVerificationResult(result: VerificationResult): string {
  const lines: string[] = [];

  const status = result.verified ? '✓ VERIFIED' : '✗ NOT VERIFIED';
  lines.push(`${status} (${Math.round(result.confidence * 100)}% confidence)`);
  lines.push(`Reason: ${result.reason}`);

  if (result.path) {
    lines.push(`Path length: ${result.path.length} steps`);
    lines.push('Steps:');
    for (const step of result.path.steps) {
      lines.push(`  - Line ${step.line}: ${step.variable} (${step.flowType})`);
    }
  }

  if (result.alternativePaths && result.alternativePaths > 0) {
    lines.push(`Alternative paths found: ${result.alternativePaths}`);
  }

  return lines.join('\n');
}
