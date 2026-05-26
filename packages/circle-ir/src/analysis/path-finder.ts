/**
 * Path Finder - Enumerate all taint paths from sources to sinks
 *
 * Provides detailed flow visualization showing exactly how taint propagates
 * through variable assignments, method calls, and returns.
 */

import type {
  DFG,
  DFGDef,
  DFGUse,
  CallInfo,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  SourceType,
  SinkType,
} from '../types/index.js';
import { CodeGraph } from '../graph/index.js';

/**
 * A single hop in the taint path
 */
export interface TaintHop {
  line: number;
  column?: number;
  variable: string;
  operation: 'source' | 'assign' | 'call_arg' | 'call_return' | 'field_read' | 'field_write' | 'array_access' | 'sink';
  code?: string;              // Source code snippet for this hop
  description: string;        // Human-readable description
}

/**
 * Complete taint path from source to sink
 */
export interface TaintPath {
  id: string;
  source: {
    line: number;
    type: SourceType;
    variable: string;
    code?: string;
  };
  sink: {
    line: number;
    type: SinkType;
    method: string;
    code?: string;
  };
  hops: TaintHop[];
  sanitized: boolean;
  sanitizer?: {
    line: number;
    method: string;
  };
  confidence: number;
  length: number;             // Number of hops
}

/**
 * Result of path finding analysis
 */
export interface PathFinderResult {
  paths: TaintPath[];
  summary: {
    totalPaths: number;
    sanitizedPaths: number;
    vulnerablePaths: number;
    avgPathLength: number;
    maxPathLength: number;
  };
}

/**
 * Configuration for path finding
 */
export interface PathFinderConfig {
  maxPathLength?: number;     // Maximum hops to follow (default: 50)
  maxPathsPerSink?: number;   // Maximum paths per sink (default: 10)
  includeCode?: boolean;      // Include source code snippets
  sourceLines?: string[];     // Source code lines for snippets
}

/**
 * PathFinder - Enumerate taint paths through the DFG
 */
export class PathFinder {
  private graph: CodeGraph;
  private sources: TaintSource[];
  private sinks: TaintSink[];
  private sanitizers: TaintSanitizer[];
  private config: Required<PathFinderConfig>;
  private sanitizerLines: Set<number>;

  constructor(
    graphOrDfg: CodeGraph | DFG,
    callsOrSources: CallInfo[] | TaintSource[],
    sourcesOrSinks: TaintSource[] | TaintSink[],
    sinksOrSanitizers: TaintSink[] | TaintSanitizer[],
    sanitizersOrConfig?: TaintSanitizer[] | PathFinderConfig,
    config: PathFinderConfig = {}
  ) {
    if (graphOrDfg instanceof CodeGraph) {
      // New signature: (graph, sources, sinks, sanitizers, config?)
      this.graph = graphOrDfg;
      this.sources = callsOrSources as TaintSource[];
      this.sinks = sourcesOrSinks as TaintSink[];
      this.sanitizers = sinksOrSanitizers as TaintSanitizer[];
      const cfg = sanitizersOrConfig as PathFinderConfig | undefined;
      this.config = {
        maxPathLength: cfg?.maxPathLength ?? 50,
        maxPathsPerSink: cfg?.maxPathsPerSink ?? 10,
        includeCode: cfg?.includeCode ?? false,
        sourceLines: cfg?.sourceLines ?? [],
      };
    } else {
      // Legacy signature: (dfg, calls, sources, sinks, sanitizers?, config?)
      const dfg = graphOrDfg as DFG;
      const calls = callsOrSources as CallInfo[];
      const sources = sourcesOrSinks as TaintSource[];
      const sinks = sinksOrSanitizers as TaintSink[];
      const sanitizers = (sanitizersOrConfig as TaintSanitizer[] | undefined) ?? [];
      this.graph = new CodeGraph({
        meta: { circle_ir: '3.0', file: '', language: 'java', loc: 0, hash: '' },
        types: [], calls, cfg: { blocks: [], edges: [] }, dfg,
        taint: { sources: [], sinks: [], sanitizers },
        imports: [], exports: [], unresolved: [], enriched: {},
      });
      this.sources = sources;
      this.sinks = sinks;
      this.sanitizers = sanitizers;
      this.config = {
        maxPathLength: config.maxPathLength ?? 50,
        maxPathsPerSink: config.maxPathsPerSink ?? 10,
        includeCode: config.includeCode ?? false,
        sourceLines: config.sourceLines ?? [],
      };
    }

    this.sanitizerLines = new Set(this.sanitizers.map(s => s.line));
  }

  /**
   * Find all taint paths from sources to sinks
   */
  findAllPaths(): PathFinderResult {
    const paths: TaintPath[] = [];
    let pathId = 1;

    for (const source of this.sources) {
      // Find variable defined at source line
      const sourceDefs = this.graph.defsAtLine(source.line);

      for (const sourceDef of sourceDefs) {
        // Find paths from this source to all reachable sinks
        const pathsFromSource = this.findPathsFromSource(source, sourceDef, pathId);
        paths.push(...pathsFromSource);
        pathId += pathsFromSource.length;
      }
    }

    // Calculate summary statistics
    const vulnerablePaths = paths.filter(p => !p.sanitized);
    const avgLength = paths.length > 0
      ? paths.reduce((sum, p) => sum + p.length, 0) / paths.length
      : 0;
    const maxLength = paths.length > 0
      ? Math.max(...paths.map(p => p.length))
      : 0;

    return {
      paths,
      summary: {
        totalPaths: paths.length,
        sanitizedPaths: paths.filter(p => p.sanitized).length,
        vulnerablePaths: vulnerablePaths.length,
        avgPathLength: Math.round(avgLength * 10) / 10,
        maxPathLength: maxLength,
      },
    };
  }

  /**
   * Find all paths from a specific source
   */
  private findPathsFromSource(
    source: TaintSource,
    sourceDef: DFGDef,
    startPathId: number
  ): TaintPath[] {
    const paths: TaintPath[] = [];
    const pathsPerSink = new Map<number, number>();  // sink line -> path count

    // BFS to find all paths
    interface PathState {
      currentDef: DFGDef;
      hops: TaintHop[];
      visited: Set<number>;  // Visited def IDs
      sanitizer?: { line: number; method: string };
    }

    const initialHop: TaintHop = {
      line: source.line,
      variable: sourceDef.variable,
      operation: 'source',
      description: `Taint introduced from ${source.type}`,
      code: this.getCodeAtLine(source.line),
    };

    const queue: PathState[] = [{
      currentDef: sourceDef,
      hops: [initialHop],
      visited: new Set([sourceDef.id]),
      sanitizer: undefined,
    }];

    while (queue.length > 0) {
      const state = queue.shift()!;

      // Check path length limit
      if (state.hops.length > this.config.maxPathLength) {
        continue;
      }

      // Check if current position reaches any sink
      for (const sink of this.sinks) {
        const sinkCount = pathsPerSink.get(sink.line) ?? 0;
        if (sinkCount >= this.config.maxPathsPerSink) continue;

        if (this.reachesSink(state.currentDef, sink)) {
          const sinkHop: TaintHop = {
            line: sink.line,
            variable: state.currentDef.variable,
            operation: 'sink',
            description: `Flows into ${sink.type} sink`,
            code: this.getCodeAtLine(sink.line),
          };

          const call = this.graph.callsAtLine(sink.line)[0];

          paths.push({
            id: `path-${startPathId + paths.length}`,
            source: {
              line: source.line,
              type: source.type,
              variable: sourceDef.variable,
              code: this.getCodeAtLine(source.line),
            },
            sink: {
              line: sink.line,
              type: sink.type,
              method: call?.method_name ?? 'unknown',
              code: this.getCodeAtLine(sink.line),
            },
            hops: [...state.hops, sinkHop],
            sanitized: state.sanitizer !== undefined,
            sanitizer: state.sanitizer,
            confidence: this.calculateConfidence(state.hops.length, state.sanitizer !== undefined),
            length: state.hops.length + 1,
          });

          pathsPerSink.set(sink.line, sinkCount + 1);
        }
      }

      // Find next hops via uses of current definition
      const uses = this.graph.usesOfDef(state.currentDef.id);

      for (const use of uses) {
        // Check for sanitizer at this line
        let sanitizer = state.sanitizer;
        if (this.sanitizerLines.has(use.line) && !sanitizer) {
          const san = this.sanitizers.find(s => s.line === use.line);
          if (san) {
            sanitizer = { line: san.line, method: san.method };
          }
        }

        // Find definitions at the use line (assignments)
        const nextDefs = this.graph.defsAtLine(use.line);

        for (const nextDef of nextDefs) {
          if (state.visited.has(nextDef.id)) continue;

          const hop = this.createHop(state.currentDef, nextDef, use);
          const newVisited = new Set(state.visited);
          newVisited.add(nextDef.id);

          queue.push({
            currentDef: nextDef,
            hops: [...state.hops, hop],
            visited: newVisited,
            sanitizer,
          });
        }

        // Also follow to same variable uses at later lines (implicit flow)
        const laterDefs = (this.graph.defsByVar.get(use.variable) ?? [])
          .filter(d => d.line > use.line && !state.visited.has(d.id));

        for (const laterDef of laterDefs.slice(0, 3)) {  // Limit branching
          const hop: TaintHop = {
            line: laterDef.line,
            variable: laterDef.variable,
            operation: 'assign',
            description: `Reassigned at line ${laterDef.line}`,
            code: this.getCodeAtLine(laterDef.line),
          };

          const newVisited = new Set(state.visited);
          newVisited.add(laterDef.id);

          queue.push({
            currentDef: laterDef,
            hops: [...state.hops, hop],
            visited: newVisited,
            sanitizer,
          });
        }
      }
    }

    return paths;
  }

  /**
   * Check if a definition reaches a sink
   */
  private reachesSink(def: DFGDef, sink: TaintSink): boolean {
    // Check if the variable is used at the sink line
    for (const use of this.graph.usesAtLine(sink.line)) {
      if (use.variable === def.variable || use.def_id === def.id) {
        return true;
      }
    }

    // Check if any call at the sink line uses this variable
    for (const call of this.graph.callsAtLine(sink.line)) {
      for (const arg of call.arguments) {
        if (arg.variable === def.variable) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Create a hop description between two definitions
   */
  private createHop(fromDef: DFGDef, toDef: DFGDef, use: DFGUse): TaintHop {
    const call = this.graph.callsAtLine(toDef.line)[0];

    let operation: TaintHop['operation'] = 'assign';
    let description = `Assigned to ${toDef.variable}`;

    if (call) {
      // Check if it's a call return assignment
      if (toDef.variable !== fromDef.variable) {
        operation = 'call_return';
        description = `Return value from ${call.method_name}() assigned to ${toDef.variable}`;
      } else {
        operation = 'call_arg';
        description = `Passed to ${call.method_name}()`;
      }
    } else if (toDef.kind === 'field') {
      operation = 'field_write';
      description = `Written to field ${toDef.variable}`;
    }

    return {
      line: toDef.line,
      variable: toDef.variable,
      operation,
      description,
      code: this.getCodeAtLine(toDef.line),
    };
  }

  /**
   * Calculate confidence based on path characteristics
   */
  private calculateConfidence(pathLength: number, sanitized: boolean): number {
    if (sanitized) return 0.1;

    // Shorter paths are more confident
    if (pathLength <= 3) return 0.95;
    if (pathLength <= 5) return 0.9;
    if (pathLength <= 10) return 0.8;
    if (pathLength <= 20) return 0.7;
    return 0.6;
  }

  /**
   * Get source code at a specific line
   */
  private getCodeAtLine(line: number): string | undefined {
    if (!this.config.includeCode || this.config.sourceLines.length === 0) {
      return undefined;
    }
    const idx = line - 1;
    if (idx >= 0 && idx < this.config.sourceLines.length) {
      return this.config.sourceLines[idx].trim();
    }
    return undefined;
  }

  /**
   * Find paths to a specific sink
   */
  findPathsToSink(sinkLine: number): TaintPath[] {
    const result = this.findAllPaths();
    return result.paths.filter(p => p.sink.line === sinkLine);
  }

  /**
   * Find paths from a specific source
   */
  findPathsFromSourceLine(sourceLine: number): TaintPath[] {
    const result = this.findAllPaths();
    return result.paths.filter(p => p.source.line === sourceLine);
  }

  /**
   * Get a summary of paths grouped by sink type
   */
  getPathsBySinkType(): Map<SinkType, TaintPath[]> {
    const result = this.findAllPaths();
    const grouped = new Map<SinkType, TaintPath[]>();

    for (const path of result.paths) {
      const existing = grouped.get(path.sink.type) ?? [];
      existing.push(path);
      grouped.set(path.sink.type, existing);
    }

    return grouped;
  }
}

/**
 * Convenience function to find all paths
 */
export function findTaintPaths(
  dfg: DFG,
  calls: CallInfo[],
  sources: TaintSource[],
  sinks: TaintSink[],
  sanitizers: TaintSanitizer[] = [],
  config: PathFinderConfig = {}
): PathFinderResult {
  const finder = new PathFinder(dfg, calls, sources, sinks, sanitizers, config);
  return finder.findAllPaths();
}

/**
 * Format a taint path for display
 */
export function formatTaintPath(path: TaintPath): string {
  const lines: string[] = [];

  lines.push(`Path ${path.id}: ${path.source.type} → ${path.sink.type}`);
  lines.push(`  Confidence: ${Math.round(path.confidence * 100)}%`);
  if (path.sanitized) {
    lines.push(`  ⚠ Sanitized at line ${path.sanitizer?.line} by ${path.sanitizer?.method}`);
  }
  lines.push('  Flow:');

  for (const hop of path.hops) {
    const marker = hop.operation === 'source' ? '→' :
                   hop.operation === 'sink' ? '⇒' : '·';
    const codeSnippet = hop.code ? ` | ${hop.code}` : '';
    lines.push(`    ${marker} Line ${hop.line}: ${hop.description}${codeSnippet}`);
  }

  return lines.join('\n');
}
