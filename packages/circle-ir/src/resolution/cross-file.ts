/**
 * Cross-File Call Resolution
 *
 * Resolves method calls to their definitions across file boundaries,
 * enabling cross-file taint tracking.
 */

import type {
  CallInfo,
  MethodInfo,
  CircleIR,
  TaintSource,
} from '../types/index.js';
import { SymbolTable, type ExportedSymbol } from './symbol-table.js';
import { TypeHierarchyResolver } from './type-hierarchy.js';

/**
 * Resolved call with target information
 */
export interface ResolvedCall {
  call: CallInfo;
  sourceFile: string;
  targetFile: string;
  targetMethod: string;           // FQN of target method
  targetClass: string;            // FQN of containing class
  resolution: 'exact' | 'polymorphic' | 'inferred';
  candidates?: string[];          // For polymorphic calls
}

/**
 * Taint propagation information for a method
 */
export interface MethodTaintInfo {
  methodFqn: string;
  file: string;
  // Which parameters propagate taint to return value
  taintedParams: number[];
  // Does this method return tainted data from a source?
  returnsSource: boolean;
  sourceType?: string;
  // Does this method sanitize input?
  sanitizes: boolean;
  sanitizedTypes?: string[];
}

/**
 * Cross-file taint flow
 */
export interface CrossFileTaintFlow {
  sourceFile: string;
  sourceLine: number;
  sourceType: string;
  targetFile: string;
  targetLine: number;
  targetMethod: string;
  flowType: 'call_arg' | 'return_value' | 'field_access';
  taintedArgPositions?: number[];
}

/**
 * CrossFileResolver - Resolves calls and tracks taint across files
 */
export class CrossFileResolver {
  private symbolTable: SymbolTable;
  private typeHierarchy: TypeHierarchyResolver;

  // Cache: file -> IR
  private fileIRs: Map<string, CircleIR> = new Map();

  // Cache: method FQN -> taint info
  private methodTaintInfo: Map<string, MethodTaintInfo> = new Map();

  // Resolved calls cache
  private resolvedCalls: Map<string, ResolvedCall> = new Map();

  constructor(
    symbolTable: SymbolTable,
    typeHierarchy: TypeHierarchyResolver
  ) {
    this.symbolTable = symbolTable;
    this.typeHierarchy = typeHierarchy;
  }

  /**
   * Add a file's IR for analysis
   */
  addFile(filePath: string, ir: CircleIR): void {
    this.fileIRs.set(filePath, ir);
    this.symbolTable.addFromIR(ir, filePath);
    this.typeHierarchy.addFromIR(ir, filePath);

    // Analyze methods for taint propagation characteristics
    this.analyzeMethodTaint(ir, filePath);
  }

  /**
   * Resolve a call to its target method(s)
   */
  resolveCall(call: CallInfo, fromFile: string): ResolvedCall | undefined {
    const cacheKey = `${fromFile}:${call.location.line}:${call.method_name}`;
    if (this.resolvedCalls.has(cacheKey)) {
      return this.resolvedCalls.get(cacheKey);
    }

    let resolved: ResolvedCall | undefined;

    // Try to resolve based on receiver type
    if (call.receiver) {
      resolved = this.resolveWithReceiver(call, fromFile);
    } else {
      // Static call or same-class call
      resolved = this.resolveStaticOrLocal(call, fromFile);
    }

    if (resolved) {
      this.resolvedCalls.set(cacheKey, resolved);
    }

    return resolved;
  }

  /**
   * Resolve call with a receiver (instance method call)
   */
  private resolveWithReceiver(call: CallInfo, fromFile: string): ResolvedCall | undefined {
    const receiver = call.receiver!;

    // Try to determine receiver type
    const receiverType = this.inferReceiverType(receiver, fromFile);

    if (receiverType) {
      // Look for method in the type
      const methodSymbol = this.symbolTable.findMethod(receiverType, call.method_name);

      if (methodSymbol) {
        return {
          call,
          sourceFile: fromFile,
          targetFile: methodSymbol.file,
          targetMethod: methodSymbol.fqn,
          targetClass: methodSymbol.parentType || receiverType,
          resolution: 'exact',
        };
      }

      // Check for polymorphic dispatch (interface/superclass)
      const candidates = this.findPolymorphicCandidates(receiverType, call.method_name);
      if (candidates.length > 0) {
        const primary = candidates[0];
        return {
          call,
          sourceFile: fromFile,
          targetFile: primary.file,
          targetMethod: primary.fqn,
          targetClass: primary.parentType || receiverType,
          resolution: 'polymorphic',
          candidates: candidates.map(c => c.fqn),
        };
      }
    }

    // Fallback: search by method name
    return this.resolveByMethodName(call, fromFile);
  }

  /**
   * Resolve static or local method call
   */
  private resolveStaticOrLocal(call: CallInfo, fromFile: string): ResolvedCall | undefined {
    // First check current file's types
    const ir = this.fileIRs.get(fromFile);
    if (ir) {
      for (const type of ir.types) {
        const pkg = type.package || ir.meta.package || '';
        const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;

        for (const method of type.methods) {
          if (method.name === call.method_name) {
            return {
              call,
              sourceFile: fromFile,
              targetFile: fromFile,
              targetMethod: `${typeFqn}.${method.name}`,
              targetClass: typeFqn,
              resolution: 'exact',
            };
          }
        }
      }
    }

    // Check imports and resolve
    return this.resolveByMethodName(call, fromFile);
  }

  /**
   * Resolve by searching all known methods
   */
  private resolveByMethodName(call: CallInfo, fromFile: string): ResolvedCall | undefined {
    // Get all possible FQNs for the method name
    const possibleFqns = this.symbolTable.getPossibleFqns(call.method_name);

    for (const fqn of possibleFqns) {
      const symbol = this.symbolTable.getSymbol(fqn);
      if (symbol && symbol.kind === 'method') {
        return {
          call,
          sourceFile: fromFile,
          targetFile: symbol.file,
          targetMethod: symbol.fqn,
          targetClass: symbol.parentType || '',
          resolution: 'inferred',
        };
      }
    }

    return undefined;
  }

  /**
   * Infer the type of a receiver variable
   */
  private inferReceiverType(receiver: string, fromFile: string): string | undefined {
    // Check if receiver is a known type name directly
    const directType = this.symbolTable.resolveTypeName(receiver, fromFile);
    if (directType) return directType;

    // Check file's IR for variable declarations
    const ir = this.fileIRs.get(fromFile);
    if (ir) {
      // Look in DFG defs for type hints
      for (const def of ir.dfg.defs) {
        if (def.variable === receiver) {
          // Try to find type from calls at this line
          const callsAtLine = ir.calls.filter(c => c.location.line === def.line);
          for (const call of callsAtLine) {
            // Constructor call?
            if (call.method_name === receiver || call.method_name === '<init>') {
              return this.symbolTable.resolveTypeName(receiver, fromFile);
            }
          }
        }
      }
    }

    // Try common type abbreviations
    const commonTypes: Record<string, string> = {
      'stmt': 'java.sql.Statement',
      'pstmt': 'java.sql.PreparedStatement',
      'conn': 'java.sql.Connection',
      'rs': 'java.sql.ResultSet',
      'request': 'javax.servlet.http.HttpServletRequest',
      'response': 'javax.servlet.http.HttpServletResponse',
      'req': 'javax.servlet.http.HttpServletRequest',
      'res': 'javax.servlet.http.HttpServletResponse',
      'session': 'javax.servlet.http.HttpSession',
      'runtime': 'java.lang.Runtime',
      'out': 'java.io.PrintWriter',
    };

    const lowerReceiver = receiver.toLowerCase();
    const commonEntries = Object.entries(commonTypes);
    for (const [abbrev, type] of commonEntries) {
      if (lowerReceiver.includes(abbrev)) {
        return type;
      }
    }

    return undefined;
  }

  /**
   * Find polymorphic candidates (implementations/subclasses)
   */
  private findPolymorphicCandidates(
    typeName: string,
    methodName: string
  ): ExportedSymbol[] {
    const candidates: ExportedSymbol[] = [];

    // Get all implementations if it's an interface
    const implementations = this.typeHierarchy.getAllImplementations(typeName);
    for (const impl of implementations) {
      const method = this.symbolTable.findMethod(impl, methodName);
      if (method) {
        candidates.push(method);
      }
    }

    // Get all subtypes if it's a class
    const subtypes = this.typeHierarchy.getAllSubtypes(typeName);
    for (const subtype of subtypes) {
      const method = this.symbolTable.findMethod(subtype, methodName);
      if (method) {
        candidates.push(method);
      }
    }

    return candidates;
  }

  /**
   * Analyze methods for taint propagation characteristics
   */
  private analyzeMethodTaint(ir: CircleIR, filePath: string): void {
    const pkg = ir.meta.package || '';

    for (const type of ir.types) {
      const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;

      for (const method of type.methods) {
        const methodFqn = `${typeFqn}.${method.name}`;

        // Check if method is a taint source
        const isSource = this.isMethodTaintSource(method, ir.taint.sources);

        // Check if method propagates taint from parameters
        const taintedParams = this.findTaintedParams(method, ir);

        // Check if method sanitizes
        const sanitizes = method.annotations.includes('sanitizer') ||
          this.isSanitizerMethod(method.name);

        const taintInfo: MethodTaintInfo = {
          methodFqn,
          file: filePath,
          taintedParams,
          returnsSource: isSource,
          sourceType: isSource ? this.getSourceType(method, ir.taint.sources) : undefined,
          sanitizes,
          sanitizedTypes: sanitizes ? this.getSanitizedTypes(method.name) : undefined,
        };

        this.methodTaintInfo.set(methodFqn, taintInfo);
      }
    }
  }

  /**
   * Check if method is a taint source
   */
  private isMethodTaintSource(method: MethodInfo, sources: TaintSource[]): boolean {
    // Check annotation-based sources
    const sourceAnnotations = ['RequestParam', 'RequestBody', 'PathVariable', 'QueryParam'];
    for (const param of method.parameters) {
      if (param.annotations.some(a => sourceAnnotations.includes(a))) {
        return true;
      }
    }

    // Check if any source is within this method
    for (const source of sources) {
      if (source.line >= method.start_line && source.line <= method.end_line) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get source type for a method
   */
  private getSourceType(method: MethodInfo, sources: TaintSource[]): string | undefined {
    for (const source of sources) {
      if (source.line >= method.start_line && source.line <= method.end_line) {
        return source.type;
      }
    }
    return undefined;
  }

  /**
   * Find which parameters propagate taint to return value
   */
  private findTaintedParams(method: MethodInfo, ir: CircleIR): number[] {
    const taintedParams: number[] = [];

    // Simple heuristic: if parameter is used in return statement, it propagates taint
    // More sophisticated analysis would track actual data flow
    const numParams = method.parameters.length;

    for (let i = 0; i < numParams; i++) {
      const param = method.parameters[i];

      // Check if param has taint-related annotation
      if (param.annotations.some(a => ['RequestParam', 'RequestBody', 'PathVariable'].includes(a))) {
        taintedParams.push(i);
      }
    }

    return taintedParams;
  }

  /**
   * Check if method name suggests sanitization
   */
  private isSanitizerMethod(methodName: string): boolean {
    const sanitizerPatterns = [
      'escape', 'encode', 'sanitize', 'validate', 'filter',
      'htmlEncode', 'urlEncode', 'prepareStatement',
    ];
    const lowerName = methodName.toLowerCase();
    return sanitizerPatterns.some(p => lowerName.includes(p.toLowerCase()));
  }

  /**
   * Get types sanitized by a method
   */
  private getSanitizedTypes(methodName: string): string[] {
    const lowerName = methodName.toLowerCase();
    const types: string[] = [];

    if (lowerName.includes('html') || lowerName.includes('xss')) {
      types.push('xss');
    }
    if (lowerName.includes('sql') || lowerName.includes('prepare')) {
      types.push('sql_injection');
    }
    if (lowerName.includes('url')) {
      types.push('ssrf', 'path_traversal');
    }
    if (lowerName.includes('command') || lowerName.includes('shell')) {
      types.push('command_injection');
    }

    return types.length > 0 ? types : ['unknown'];
  }

  /**
   * Find all callers of a method across the project
   */
  findCallers(methodFqn: string): ResolvedCall[] {
    const callers: ResolvedCall[] = [];

    for (const [filePath, ir] of this.fileIRs) {
      for (const call of ir.calls) {
        const resolved = this.resolveCall(call, filePath);
        if (resolved && resolved.targetMethod === methodFqn) {
          callers.push(resolved);
        }
      }
    }

    return callers;
  }

  /**
   * Find cross-file taint flows
   */
  findCrossFileTaintFlows(): CrossFileTaintFlow[] {
    const flows: CrossFileTaintFlow[] = [];
    // Deduplicate: same source + target sink should only emit one flow
    const seen = new Set<string>();

    for (const [filePath, ir] of this.fileIRs) {
      // Check each source in the file
      for (const source of ir.taint.sources) {
        // `interprocedural_param` sources represent "this method's parameter MIGHT be
        // tainted when called by tainted code" — they are a per-file meta-analysis result
        // and are not confirmed external inputs suitable for cross-file taint flows.
        // Using them here causes false positives on every internal library function that
        // has typed parameters and happens to call another file that contains any sink.
        if (source.type === 'interprocedural_param') continue;

        // Find calls at or after the source line
        for (const call of ir.calls) {
          if (call.location.line < source.line) continue;

          const resolved = this.resolveCall(call, filePath);
          if (!resolved || resolved.targetFile === filePath) continue;

          // Only proceed if the target file has any YAML-matched sinks at all.
          // Skipping sink-free files prevents the cartesian explosion of flows into
          // utility modules (AST helpers, string utilities, etc.) that have no
          // dangerous operations.
          const targetIR = this.fileIRs.get(resolved.targetFile);
          if (!targetIR || targetIR.taint.sinks.length === 0) continue;

          // Find the target method in the target file so we can locate sinks within it.
          // `resolved.targetMethod` is a FQN like "ClassName.methodName"; we match on
          // the suffix after the last dot.
          const shortName = resolved.targetMethod.split('.').pop() ?? resolved.targetMethod;
          let targetMethod: { start_line: number; end_line: number } | undefined;
          for (const type of targetIR.types) {
            const m = type.methods.find(m => m.name === shortName);
            if (m) { targetMethod = m; break; }
          }
          if (!targetMethod) continue;

          // Only emit a flow when at least one known sink falls inside the target method.
          // This means `targetLine` now correctly points to an actual dangerous operation
          // in the target file (not the caller's line in the source file).
          const sinksInMethod = targetIR.taint.sinks.filter(
            s => s.line >= targetMethod!.start_line && s.line <= targetMethod!.end_line,
          );
          if (sinksInMethod.length === 0) continue;

          for (const sink of sinksInMethod) {
            const key = `${filePath}:${source.line}→${resolved.targetFile}:${sink.line}`;
            if (seen.has(key)) continue;
            seen.add(key);

            flows.push({
              sourceFile: filePath,
              sourceLine: source.line,
              sourceType: source.type,
              targetFile: resolved.targetFile,
              targetLine: sink.line,           // actual sink line in target file
              targetMethod: resolved.targetMethod,
              flowType: 'call_arg',
              taintedArgPositions: call.arguments.map((_, i) => i),
            });
          }
        }
      }
    }

    return flows;
  }

  /**
   * Get taint info for a method
   */
  getMethodTaintInfo(methodFqn: string): MethodTaintInfo | undefined {
    return this.methodTaintInfo.get(methodFqn);
  }

  /**
   * Get all resolved calls from a file
   */
  getResolvedCallsFromFile(filePath: string): ResolvedCall[] {
    const ir = this.fileIRs.get(filePath);
    if (!ir) return [];

    const resolved: ResolvedCall[] = [];
    for (const call of ir.calls) {
      const r = this.resolveCall(call, filePath);
      if (r) {
        resolved.push(r);
      }
    }
    return resolved;
  }

  /**
   * Get statistics
   */
  getStats(): {
    totalFiles: number;
    totalCalls: number;
    resolvedCalls: number;
    crossFileCalls: number;
    methodsWithTaintInfo: number;
  } {
    let totalCalls = 0;
    let crossFileCalls = 0;

    for (const [filePath, ir] of this.fileIRs) {
      totalCalls += ir.calls.length;

      for (const call of ir.calls) {
        const resolved = this.resolveCall(call, filePath);
        if (resolved && resolved.targetFile !== filePath) {
          crossFileCalls++;
        }
      }
    }

    return {
      totalFiles: this.fileIRs.size,
      totalCalls,
      resolvedCalls: this.resolvedCalls.size,
      crossFileCalls,
      methodsWithTaintInfo: this.methodTaintInfo.size,
    };
  }

  /**
   * Clear all caches
   */
  clear(): void {
    this.fileIRs.clear();
    this.methodTaintInfo.clear();
    this.resolvedCalls.clear();
  }
}

/**
 * Build a cross-file resolver from multiple IR results
 */
export function buildCrossFileResolver(
  files: Array<{ ir: CircleIR; path: string }>,
  symbolTable?: SymbolTable,
  typeHierarchy?: TypeHierarchyResolver
): CrossFileResolver {
  const table = symbolTable || new SymbolTable();
  const hierarchy = typeHierarchy || new TypeHierarchyResolver();

  const resolver = new CrossFileResolver(table, hierarchy);

  for (const { ir, path } of files) {
    resolver.addFile(path, ir);
  }

  return resolver;
}
