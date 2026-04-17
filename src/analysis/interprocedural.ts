/**
 * Inter-procedural Taint Analysis
 *
 * Tracks taint flow through method calls within the same file.
 * - Propagates taint from arguments to parameters
 * - Tracks taint through return values
 * - Handles method call chains
 */

import type {
  CallInfo,
  TypeInfo,
  MethodInfo,
  DFG,
  DFGDef,
  DFGUse,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  SourceType,
  SinkType,
} from '../types/index.js';
import { CodeGraph } from '../graph/index.js';

/**
 * Represents a method in the call graph.
 */
export interface MethodNode {
  /** Simple method name */
  name: string;
  /** Fully qualified name: ClassName.methodName */
  fqn: string;
  /** Class/type this method belongs to */
  className: string | null;
  /** Package name if available */
  packageName: string | null;
  parameters: ParameterTaint[];
  returnsTainted: boolean;
  returnTaintType: string | null;
  /** Which parameter positions flow to the return value (null = all potentially taint) */
  returnTaintedFromParams: number[] | null;
  startLine: number;
  endLine: number;
}

/**
 * Parameter taint information.
 */
export interface ParameterTaint {
  name: string;
  position: number;
  isTainted: boolean;
  taintType: string | null;
  sourceLine: number | null;
}

/**
 * A call edge in the call graph.
 */
export interface CallEdge {
  callerMethod: string;
  calleeMethod: string;
  callLine: number;
  taintedArgs: number[];  // Positions of tainted arguments
}

/**
 * Result of inter-procedural analysis.
 */
export interface InterproceduralResult {
  methodNodes: Map<string, MethodNode>;
  callEdges: CallEdge[];
  taintedMethods: Set<string>;  // Methods that handle tainted data
  taintedReturns: Map<string, string>;  // Method -> taint type it returns
  propagatedSinks: TaintSink[];  // Additional sinks found via inter-proc
}

/**
 * Options for interprocedural analysis.
 */
export interface InterproceduralOptions {
  /** Variables marked as tainted by constant propagation (e.g., collections with tainted elements) */
  taintedVariables?: Set<string>;
}

/**
 * Perform inter-procedural taint analysis.
 *
 * Accepts either a CodeGraph (preferred) or the legacy (types, calls, dfg, ...)
 * signature for backward compatibility.
 */
export function analyzeInterprocedural(
  graphOrTypes: CodeGraph | TypeInfo[],
  callsOrSources: CallInfo[] | TaintSource[],
  dfgOrSinks: DFG | TaintSink[],
  sourcesOrSanitizers: TaintSource[] | TaintSanitizer[],
  sinksOrOptions?: TaintSink[] | InterproceduralOptions,
  sanitizersArg?: TaintSanitizer[],
  optionsArg: InterproceduralOptions = {}
): InterproceduralResult {
  let graph: CodeGraph;
  let sources: TaintSource[];
  let sinks: TaintSink[];
  let sanitizers: TaintSanitizer[];
  let options: InterproceduralOptions;

  if (graphOrTypes instanceof CodeGraph) {
    // New signature: (graph, sources, sinks, sanitizers, options?)
    graph = graphOrTypes;
    sources = callsOrSources as TaintSource[];
    sinks = dfgOrSinks as TaintSink[];
    sanitizers = sourcesOrSanitizers as TaintSanitizer[];
    options = (sinksOrOptions as InterproceduralOptions | undefined) ?? {};
  } else {
    // Legacy: (types, calls, dfg, sources, sinks, sanitizers, options?)
    const types = graphOrTypes as TypeInfo[];
    const calls = callsOrSources as CallInfo[];
    const dfg = dfgOrSinks as DFG;
    sources = sourcesOrSanitizers as TaintSource[];
    sinks = sinksOrOptions as TaintSink[] ?? [];
    sanitizers = sanitizersArg ?? [];
    options = optionsArg;
    graph = new CodeGraph({
      meta: { circle_ir: '3.0', file: '', language: 'java', loc: 0, hash: '' },
      types, calls, cfg: { blocks: [], edges: [] }, dfg,
      taint: { sources: [], sinks: [], sanitizers },
      imports: [], exports: [], unresolved: [], enriched: {},
    });
  }

  const types = graph.ir.types;
  const calls = graph.ir.calls;

  // Build method nodes from type information
  const methodNodes = buildMethodNodes(types);

  // Build call graph edges with receiver type resolution
  const callEdges = buildCallEdges(calls, methodNodes, types);

  // Identify initially tainted parameters (from sources)
  const taintedMethods = new Set<string>();
  const taintedReturns = new Map<string, string>();

  // Mark methods containing sources as tainted (using FQN)
  for (const source of sources) {
    const methodInfo = findMethodAtLine(types, source.line);
    if (methodInfo) {
      const fqn = buildMethodFQN(methodInfo.packageName, methodInfo.className, methodInfo.methodName);
      taintedMethods.add(fqn);
    }
  }

  // Build taint map from DFG via CodeGraph (eliminates O(N) scan per source)
  const seedIds = new Set<number>();
  for (const source of sources) {
    for (const def of graph.defsAtLine(source.line)) {
      seedIds.add(def.id);
    }
  }
  const taintedDefIds = graph.propagateTaintedDefIds(seedIds);

  // Get tainted variables from constant propagation (tracks collections with tainted elements)
  const taintedVarsFromCP = options.taintedVariables ?? new Set<string>();

  // Analyze each call to propagate taint
  const propagatedSinks: TaintSink[] = [];

  // Track which method names are collection methods (should not create external escape sinks)
  const collectionMethods = new Set([
    'add', 'addLast', 'addFirst', 'addAll', 'put', 'putAll', 'set', 'push', 'offer',
    'get', 'getLast', 'getFirst', 'peek', 'poll', 'pop', 'remove', 'removeFirst', 'removeLast',
    'iterator', 'listIterator', 'next', 'hasNext', 'size', 'isEmpty', 'contains', 'containsKey',
    'toString', 'valueOf', 'hashCode', 'equals', 'clone', 'clear',
    // StringBuilder / StringBuffer / Writer accumulator methods — taint propagates through these
    // but the CWE-668 sink check should not fire on pure string accumulation
    'append', 'insert', 'prepend', 'concat', 'delete', 'deleteCharAt', 'replace', 'reverse',
    'write', 'writeln', 'println',
  ]);

  // Track safe utility methods (validation, normalization, path handling)
  // These are utility functions that process data but don't represent security risks
  const safeUtilityMethods = new Set([
    // Path validation and normalization
    'normalizePath', 'normalizeLineEndings', 'isPathWithin', 'isPathWithinAllowedDirectories',
    'isPathAllowed', 'validatePath', 'resolvePath', 'resolve', 'relative', 'join',
    // File utilities (reading/processing, not writing)
    'tailFile', 'headFile', 'readFileContent', 'readFile', 'read',
    // Pattern matching (used in validation)
    'minimatch', 'match', 'test', 'includes', 'startsWith', 'endsWith',
    // General validation
    'validate', 'validateInput', 'check', 'verify',
    // Logging (console.log, logger.info, etc.) — not security sinks
    'log', 'warn', 'error', 'info', 'debug', 'trace', 'dir', 'table',
    'println', 'print', 'printf', 'fprintf',
    // I/O stream wrappers — pure decorators that wrap a stream, not security sinks
    // e.g. new InputStreamReader(proc.getInputStream()) is safe; the underlying stream is the source
    'InputStreamReader', 'OutputStreamWriter',
    'BufferedInputStream', 'BufferedOutputStream',
    'ByteArrayInputStream', 'ByteArrayOutputStream',
    'DataInputStream', 'DataOutputStream',
    'PushbackInputStream', 'SequenceInputStream',
    'BufferedReader', 'BufferedWriter',
    'PrintStream', 'PrintWriter',
    'ObjectOutputStream',  // ObjectInputStream IS a sink (deserialization), keep it out
  ]);

  // Build set of sanitizer method names (methods that clean tainted data)
  // Sanitizer methods may be in formats like "encode" or "URLEncoder.encode()"
  const sanitizerMethods = new Set<string>();
  for (const san of sanitizers) {
    sanitizerMethods.add(san.method);
    // Also extract just the method name if formatted as "Class.method()"
    const match = san.method.match(/\.(\w+)\(\)$/);
    if (match) {
      sanitizerMethods.add(match[1]);
    }
  }

  for (const call of calls) {
    // Check if any arguments are tainted
    const taintedArgPositions: number[] = [];
    const taintedArgVars: string[] = [];
    for (const arg of call.arguments) {
      if (arg.variable) {
        // Check 1: DFG-based taint tracking (indexed lookup, no O(N) scan)
        const use = graph.usesAtLine(call.location.line).find(u => u.variable === arg.variable) ?? null;
        const isTaintedByDFG = use && use.def_id !== null && taintedDefIds.has(use.def_id);

        // Check 2: Constant propagation taint tracking (for collections with tainted elements)
        const isTaintedByCP = taintedVarsFromCP.has(arg.variable);

        if (isTaintedByDFG || isTaintedByCP) {
          taintedArgPositions.push(arg.position);
          taintedArgVars.push(arg.variable);
        }
      }
    }

    // Check if this is an internal method call (resolve using FQN or simple name)
    const targetMethod = getMethodNode(methodNodes, call.method_name);

    if (!targetMethod) {
      // External method call - check if tainted data is escaping
      // Skip collection methods (data manipulation), sanitizer methods (data cleaning),
      // and safe utility methods (validation, normalization)
      if (taintedArgPositions.length > 0 &&
          !collectionMethods.has(call.method_name) &&
          !sanitizerMethods.has(call.method_name) &&
          !safeUtilityMethods.has(call.method_name)) {
        // Create an "external_taint_escape" sink for this call
        // This represents tainted data being passed to code we can't analyze
        const sink: TaintSink = {
          type: 'external_taint_escape',
          cwe: 'CWE-668',  // Exposure of Resource to Wrong Sphere
          location: `Tainted data (${taintedArgVars.join(', ')}) passed to external method ${call.receiver ? call.receiver + '.' : ''}${call.method_name}()`,
          line: call.location.line,
          confidence: 0.7,  // Lower confidence since we can't verify the external method is dangerous
          method: call.method_name,
          argPositions: taintedArgPositions,
        };

        // Only add if not already present
        if (!propagatedSinks.some(s => s.line === sink.line && s.type === sink.type)) {
          propagatedSinks.push(sink);
        }
      }
      continue;
    }

    if (taintedArgPositions.length > 0) {
      // Mark corresponding parameters as tainted
      for (const pos of taintedArgPositions) {
        if (pos < targetMethod.parameters.length) {
          targetMethod.parameters[pos].isTainted = true;
          targetMethod.parameters[pos].sourceLine = call.location.line;
        }
      }
      taintedMethods.add(targetMethod.fqn);

      // Check if target method has sinks
      const methodSinks = sinks.filter(
        s => s.line >= targetMethod.startLine && s.line <= targetMethod.endLine
      );

      // These sinks are now reachable via inter-procedural flow
      for (const sink of methodSinks) {
        // Check if not already in the list
        if (!propagatedSinks.some(s => s.line === sink.line)) {
          propagatedSinks.push({
            ...sink,
            confidence: sink.confidence * 0.85, // Slightly lower confidence for inter-proc
          });
        }
      }
    }
  }

  // Propagate taint through return values
  propagateReturnTaint(types, graph, taintedDefIds, taintedReturns, taintedMethods, methodNodes);

  // Iteratively propagate taint through call chains
  propagateThroughCallChains(
    callEdges,
    methodNodes,
    taintedMethods,
    taintedReturns,
    graph,
    taintedDefIds
  );

  return {
    methodNodes: methodNodes.byFqn,
    callEdges,
    taintedMethods,
    taintedReturns,
    propagatedSinks,
  };
}

/**
 * Build a fully qualified name for a method.
 * Format: [package.]ClassName.methodName
 */
function buildMethodFQN(
  packageName: string | null,
  className: string,
  methodName: string
): string {
  if (packageName) {
    return `${packageName}.${className}.${methodName}`;
  }
  return `${className}.${methodName}`;
}

/**
 * Result of building method nodes - includes both FQN map and simple name index.
 */
interface MethodNodeMaps {
  /** Primary map: FQN -> MethodNode */
  byFqn: Map<string, MethodNode>;
  /** Index for simple name lookups (may have collisions) */
  byName: Map<string, MethodNode>;
}

/**
 * Build method nodes from type information.
 * Uses fully qualified names (FQN) as keys for precise method resolution.
 */
function buildMethodNodes(types: TypeInfo[]): MethodNodeMaps {
  const byFqn = new Map<string, MethodNode>();
  const byName = new Map<string, MethodNode>();

  for (const type of types) {
    for (const method of type.methods) {
      const fqn = buildMethodFQN(type.package, type.name, method.name);

      const node: MethodNode = {
        name: method.name,
        fqn,
        className: type.name,
        packageName: type.package,
        parameters: method.parameters.map((p, i) => ({
          name: p.name,
          position: i,
          isTainted: false,
          taintType: null,
          sourceLine: null,
        })),
        returnsTainted: false,
        returnTaintType: null,
        returnTaintedFromParams: null, // Will be computed during analysis
        startLine: method.start_line,
        endLine: method.end_line,
      };

      // Store with FQN as primary key
      byFqn.set(fqn, node);

      // Store with simple name for fallback (first occurrence wins)
      if (!byName.has(method.name)) {
        byName.set(method.name, node);
      }
    }
  }

  return { byFqn, byName };
}

/**
 * Get a method node by FQN or simple name.
 */
function getMethodNode(maps: MethodNodeMaps, key: string): MethodNode | undefined {
  return maps.byFqn.get(key) ?? maps.byName.get(key);
}

/**
 * Resolve a method call to its target node, considering receiver type.
 * Returns the FQN of the resolved method, or null if not found.
 */
function resolveMethodCall(
  call: CallInfo,
  methodNodes: MethodNodeMaps,
  types: TypeInfo[]
): string | null {
  const methodName = call.method_name;

  // If receiver type is known, try FQN resolution first
  if (call.receiver_type) {
    // Try exact FQN match
    const fqn = `${call.receiver_type}.${methodName}`;
    if (methodNodes.byFqn.has(fqn)) {
      return fqn;
    }

    // Try with common package prefixes
    for (const type of types) {
      if (type.name === call.receiver_type && type.package) {
        const fullFqn = `${type.package}.${type.name}.${methodName}`;
        if (methodNodes.byFqn.has(fullFqn)) {
          return fullFqn;
        }
      }
    }
  }

  // If receiver is known, try ClassName.methodName
  if (call.receiver) {
    // Receiver might be a variable - try to infer its type from types
    for (const type of types) {
      const fqn = type.package
        ? `${type.package}.${type.name}.${methodName}`
        : `${type.name}.${methodName}`;
      if (methodNodes.byFqn.has(fqn)) {
        const node = methodNodes.byFqn.get(fqn)!;
        // Check if this could be a match (same method name, right class)
        if (node.name === methodName) {
          return fqn;
        }
      }
    }
  }

  // Fallback: simple method name
  if (methodNodes.byName.has(methodName)) {
    const node = methodNodes.byName.get(methodName)!;
    return node.fqn;
  }

  return null;
}

/**
 * Build call edges from call information.
 * Uses receiver type information for precise method resolution.
 */
function buildCallEdges(
  calls: CallInfo[],
  methodNodes: MethodNodeMaps,
  types: TypeInfo[]
): CallEdge[] {
  const edges: CallEdge[] = [];

  for (const call of calls) {
    // Resolve the call target using receiver type
    const resolvedFqn = resolveMethodCall(call, methodNodes, types);
    if (!resolvedFqn) continue;

    // Find the caller method
    const callerMethod = call.in_method;
    if (!callerMethod) continue;

    edges.push({
      callerMethod,
      calleeMethod: resolvedFqn,
      callLine: call.location.line,
      taintedArgs: [],
    });
  }

  return edges;
}

/**
 * Result of finding a method at a line, includes context.
 */
interface MethodContext {
  method: MethodInfo;
  methodName: string;
  className: string;
  packageName: string | null;
}

/**
 * Find the method containing a specific line.
 * Returns method info along with class and package context.
 */
function findMethodAtLine(types: TypeInfo[], line: number): MethodContext | null {
  for (const type of types) {
    for (const method of type.methods) {
      if (line >= method.start_line && line <= method.end_line) {
        return {
          method,
          methodName: method.name,
          className: type.name,
          packageName: type.package,
        };
      }
    }
  }
  return null;
}

/**
 * Propagate taint through return values.
 * Tracks which parameters flow to the return value for precise taint mapping.
 */
function propagateReturnTaint(
  types: TypeInfo[],
  graph: CodeGraph,
  taintedDefIds: Set<number>,
  taintedReturns: Map<string, string>,
  taintedMethods: Set<string>,
  methodNodes: MethodNodeMaps
): void {
  // Find return statements that return tainted values
  const returnDefs = graph.ir.dfg.defs.filter(d => d.kind === 'return');

  for (const returnDef of returnDefs) {
    // Find the method this return is in
    const methodCtx = findMethodAtLine(types, returnDef.line);
    if (!methodCtx) continue;

    const fqn = buildMethodFQN(methodCtx.packageName, methodCtx.className, methodCtx.methodName);

    // Find uses on the same line (the returned value) — indexed lookup
    const usesOnLine = graph.usesAtLine(returnDef.line);

    for (const use of usesOnLine) {
      if (use.def_id !== null && taintedDefIds.has(use.def_id)) {
        // This method returns a tainted value
        taintedReturns.set(fqn, 'tainted');
        taintedMethods.add(fqn);

        // Track which parameter this return value came from
        const methodNode = methodNodes.byFqn.get(fqn);
        if (methodNode) {
          // Check if the returned variable matches a parameter name
          const paramIndex = methodNode.parameters.findIndex(p => p.name === use.variable);
          if (paramIndex >= 0) {
            // This return value comes from this parameter
            if (methodNode.returnTaintedFromParams === null) {
              methodNode.returnTaintedFromParams = [paramIndex];
            } else if (!methodNode.returnTaintedFromParams.includes(paramIndex)) {
              methodNode.returnTaintedFromParams.push(paramIndex);
            }
          }
        }
        break;
      }
    }
  }
}

/**
 * Propagate taint through call chains iteratively.
 */
function propagateThroughCallChains(
  callEdges: CallEdge[],
  methodNodes: MethodNodeMaps,
  taintedMethods: Set<string>,
  taintedReturns: Map<string, string>,
  graph: CodeGraph,
  taintedDefIds: Set<number>
): void {
  // Build reverse call graph (callee -> callers)
  const callersOf = new Map<string, CallEdge[]>();
  for (const edge of callEdges) {
    const existing = callersOf.get(edge.calleeMethod) ?? [];
    existing.push(edge);
    callersOf.set(edge.calleeMethod, existing);
  }

  // Iteratively propagate until fixed point
  let changed = true;
  let iterations = 0;
  const maxIterations = 10; // Prevent infinite loops

  while (changed && iterations < maxIterations) {
    changed = false;
    iterations++;

    // For each method that returns tainted data
    for (const [methodName, taintType] of taintedReturns) {
      // Find all callers of this method
      const callers = callersOf.get(methodName) ?? [];

      for (const edge of callers) {
        // The call site now produces tainted data
        // Use indexed lookup instead of O(N) scan through all defs
        for (const def of graph.defsAtLine(edge.callLine)) {
          if (!taintedDefIds.has(def.id)) {
            taintedDefIds.add(def.id);
            changed = true;

            // Mark the caller method as tainted
            if (!taintedMethods.has(edge.callerMethod)) {
              taintedMethods.add(edge.callerMethod);
            }
          }
        }
      }
    }

    // Propagate through chains using indexed adjacency list
    for (const [fromDef, chains] of graph.chainsByFromDef) {
      if (!taintedDefIds.has(fromDef)) continue;
      for (const chain of chains) {
        if (!taintedDefIds.has(chain.to_def)) {
          taintedDefIds.add(chain.to_def);
          changed = true;
        }
      }
    }
  }
}

/**
 * Get summary of inter-procedural analysis.
 */
export function getInterproceduralSummary(result: InterproceduralResult): {
  totalMethods: number;
  taintedMethods: number;
  callEdges: number;
  methodsReturningTaint: number;
} {
  return {
    totalMethods: result.methodNodes.size,
    taintedMethods: result.taintedMethods.size,
    callEdges: result.callEdges.length,
    methodsReturningTaint: result.taintedReturns.size,
  };
}

/**
 * Check if a method exists in the interprocedural result.
 * Accepts either simple name or FQN.
 */
export function hasMethod(result: InterproceduralResult, nameOrFqn: string): boolean {
  // Try exact match first (FQN)
  if (result.methodNodes.has(nameOrFqn)) {
    return true;
  }

  // Try matching by simple name
  for (const [fqn, node] of result.methodNodes) {
    if (node.name === nameOrFqn) {
      return true;
    }
  }

  return false;
}

/**
 * Get a method node by simple name or FQN.
 */
export function getMethod(result: InterproceduralResult, nameOrFqn: string): MethodNode | undefined {
  // Try exact match first (FQN)
  if (result.methodNodes.has(nameOrFqn)) {
    return result.methodNodes.get(nameOrFqn);
  }

  // Try matching by simple name
  for (const [fqn, node] of result.methodNodes) {
    if (node.name === nameOrFqn) {
      return node;
    }
  }

  return undefined;
}

/**
 * Check if a method is tainted (by simple name or FQN).
 */
export function isMethodTainted(result: InterproceduralResult, nameOrFqn: string): boolean {
  // Try exact match first (FQN)
  if (result.taintedMethods.has(nameOrFqn)) {
    return true;
  }

  // Try matching by simple name - check if any tainted method has this name
  for (const fqn of result.taintedMethods) {
    const node = result.methodNodes.get(fqn);
    if (node && node.name === nameOrFqn) {
      return true;
    }
  }

  return false;
}

/**
 * Find methods that act as "taint bridges" - receiving taint and passing it on.
 */
export function findTaintBridges(result: InterproceduralResult): string[] {
  const bridges: string[] = [];

  for (const [name, node] of result.methodNodes) {
    const hasTaintedParams = node.parameters.some(p => p.isTainted);
    const returnsTainted = result.taintedReturns.has(name);

    if (hasTaintedParams && returnsTainted) {
      bridges.push(name);
    }
  }

  return bridges;
}

/**
 * Get taint flow paths through methods.
 */
export function getMethodTaintPaths(
  result: InterproceduralResult,
  maxDepth: number = 5
): string[][] {
  const paths: string[][] = [];

  // Find entry points (methods with tainted parameters from external sources)
  const entryMethods = Array.from(result.methodNodes.entries())
    .filter(([_, node]) => node.parameters.some(p => p.isTainted && p.sourceLine !== null))
    .map(([name]) => name);

  // Build call graph adjacency
  const callsTo = new Map<string, string[]>();
  for (const edge of result.callEdges) {
    const existing = callsTo.get(edge.callerMethod) ?? [];
    if (!existing.includes(edge.calleeMethod)) {
      existing.push(edge.calleeMethod);
    }
    callsTo.set(edge.callerMethod, existing);
  }

  // DFS to find paths
  function dfs(current: string, path: string[], visited: Set<string>): void {
    if (path.length > maxDepth) return;
    if (visited.has(current)) return;

    visited.add(current);
    path.push(current);

    // If this method returns taint and has callees, continue
    const callees = callsTo.get(current) ?? [];

    if (callees.length === 0 || !result.taintedMethods.has(current)) {
      // End of path
      if (path.length > 1) {
        paths.push([...path]);
      }
    } else {
      for (const callee of callees) {
        if (result.taintedMethods.has(callee)) {
          dfs(callee, path, visited);
        }
      }
    }

    path.pop();
    visited.delete(current);
  }

  for (const entry of entryMethods) {
    dfs(entry, [], new Set());
  }

  return paths;
}
