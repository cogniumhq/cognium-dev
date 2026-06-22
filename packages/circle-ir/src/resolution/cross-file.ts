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
  TaintSink,
  DFGDef,
  DFGUse,
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
 * Inter-procedural taint chain that spans multiple files / call sites.
 *
 * Shape: SOURCE in file A → caller's wrapper-return site → caller's sink-call
 * site → SINK in file B.  Used when no per-file source/sink is co-located in
 * a single caller frame, so `findCrossFileTaintFlows()` cannot fire.
 */
export interface InterproceduralTaintPath {
  source: { file: string; line: number; type: string };
  sink:   { file: string; line: number; type: string; cwe: string };
  hops:   Array<{ file: string; line: number; method: string; kind: 'source' | 'wrapper_return' | 'field_write' | 'field_read' | 'sink_call' | 'sink' }>;
  confidence: number;
}

/**
 * Per-type field-binding taint summary.
 *
 * Records which fields on a class hold tainted data because a method in the
 * class wrote a tainted parameter into the field (`this.field = param`).
 * Used to surface cross-instance flows of the canonical Jenkins shape:
 *   `@DataBoundConstructor C(p)` writes `this.f = p` → another class holds a
 *   `C` instance and reads `instance.f` → that read flows to a sink.
 */
export interface FieldTaintInfo {
  typeFqn: string;
  fieldName: string;
  fieldType: string | null;
  file: string;
  /** Methods that write tainted data into this field. */
  writers: Array<{
    methodFqn: string;
    methodName: string;
    writeLine: number;
    /** Source type carried into the field (`http_param`, `autowired`, etc.). */
    sourceType: string;
    /** Original source line in the writer's method body. */
    sourceLine: number;
  }>;
}

/**
 * Per-file lookup index used inside the resolver hot loops.
 *
 * The pre-3.89.0 implementation re-ran linear `.filter()` scans on
 * `ir.calls`, `ir.taint.sinks`, `ir.dfg.defs`, and `ir.dfg.uses` inside
 * the O(F·T·M) nested walks of `findInterproceduralTaintPaths`,
 * `findFieldBindingTaintPaths`, and `findCrossFileTaintFlows`. On large
 * Java corpora (Sa-Token 895 files, langchain4j 1696 files) that pattern
 * burned 5B+ filter ops and produced the #141 cross-file hang.
 *
 * Building this index once per file at first use collapses each O(N) filter
 * to an O(1) Map lookup. Membership and ordering are byte-equivalent to the
 * original filters (range buckets preserve sort-by-line order; per-line
 * buckets preserve insertion order, which matches Array.filter semantics).
 */
export interface FileIndex {
  /** Calls bucketed by `location.line`. Preserves original array order within each line. */
  callsByLine: Map<number, CallInfo[]>;
  /** DFG defs bucketed by `line`. Preserves original array order. */
  defsByLine: Map<number, DFGDef[]>;
  /** DFG uses bucketed by `line`. Preserves original array order. */
  usesByLine: Map<number, DFGUse[]>;
  /**
   * Calls inside each method's `[start_line, end_line]` range, sorted by line ASC.
   * Matches the pre-refactor `callerIR.calls.filter(...).sort(...)` output order.
   */
  callsByMethod: Map<MethodInfo, CallInfo[]>;
  /**
   * Sinks inside each method's `[start_line, end_line]` range, sorted by line ASC.
   * Set-equivalent to the pre-refactor `callerIR.taint.sinks.filter(...)` output.
   */
  sinksByMethod: Map<MethodInfo, TaintSink[]>;
  /**
   * Defs inside each method's `[start_line, end_line]` range, sorted by line ASC.
   * Set-equivalent to the pre-refactor `callerIR.dfg.defs.filter(...)` output.
   */
  defsByMethod: Map<MethodInfo, DFGDef[]>;
}

export function buildFileIndex(ir: CircleIR): FileIndex {
  const callsByLine = new Map<number, CallInfo[]>();
  for (const c of ir.calls) {
    const ln = c.location.line;
    let arr = callsByLine.get(ln);
    if (!arr) { arr = []; callsByLine.set(ln, arr); }
    arr.push(c);
  }

  const defsByLine = new Map<number, DFGDef[]>();
  for (const d of ir.dfg.defs) {
    let arr = defsByLine.get(d.line);
    if (!arr) { arr = []; defsByLine.set(d.line, arr); }
    arr.push(d);
  }

  const usesByLine = new Map<number, DFGUse[]>();
  for (const u of ir.dfg.uses) {
    let arr = usesByLine.get(u.line);
    if (!arr) { arr = []; usesByLine.set(u.line, arr); }
    arr.push(u);
  }

  // Sort once for efficient range slicing per method.
  const callsSorted = [...ir.calls].sort((a, b) => a.location.line - b.location.line);
  const sinksSorted = [...ir.taint.sinks].sort((a, b) => a.line - b.line);
  const defsSorted = [...ir.dfg.defs].sort((a, b) => a.line - b.line);

  const callsByMethod = new Map<MethodInfo, CallInfo[]>();
  const sinksByMethod = new Map<MethodInfo, TaintSink[]>();
  const defsByMethod = new Map<MethodInfo, DFGDef[]>();

  for (const type of ir.types) {
    for (const method of type.methods) {
      const start = method.start_line;
      const end = method.end_line;

      const inCalls: CallInfo[] = [];
      for (const c of callsSorted) {
        const ln = c.location.line;
        if (ln < start) continue;
        if (ln > end) break;
        inCalls.push(c);
      }
      callsByMethod.set(method, inCalls);

      const inSinks: TaintSink[] = [];
      for (const s of sinksSorted) {
        if (s.line < start) continue;
        if (s.line > end) break;
        inSinks.push(s);
      }
      sinksByMethod.set(method, inSinks);

      const inDefs: DFGDef[] = [];
      for (const d of defsSorted) {
        if (d.line < start) continue;
        if (d.line > end) break;
        inDefs.push(d);
      }
      defsByMethod.set(method, inDefs);
    }
  }

  return { callsByLine, defsByLine, usesByLine, callsByMethod, sinksByMethod, defsByMethod };
}

/**
 * CrossFileResolver - Resolves calls and tracks taint across files
 */
export class CrossFileResolver {
  // -- pre-3.89.0 pre-index cache (see FileIndex above) --
  private readonly fileIndexes: WeakMap<CircleIR, FileIndex> = new WeakMap();

  private getFileIndex(ir: CircleIR): FileIndex {
    let idx = this.fileIndexes.get(ir);
    if (idx) return idx;
    idx = buildFileIndex(ir);
    this.fileIndexes.set(ir, idx);
    return idx;
  }

  private symbolTable: SymbolTable;
  private typeHierarchy: TypeHierarchyResolver;

  // Cache: file -> IR
  private fileIRs: Map<string, CircleIR> = new Map();

  // Cache: method FQN -> taint info
  private methodTaintInfo: Map<string, MethodTaintInfo> = new Map();

  // Cache: `${typeFqn}.${fieldName}` -> field taint info
  private fieldTaintInfo: Map<string, FieldTaintInfo> = new Map();

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

    // Analyze cross-instance field bindings (constructor + setter writers)
    this.analyzeFieldTaint(ir, filePath);
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

    // Preflight (#74 follow-up / Java cross-file E): the Java extractor
    // already populates `receiver_type_fqn` for invocations whose receiver
    // type can be resolved via imports/locals/fields. Honour it before
    // falling through to context-derived inference (which only handles a
    // few common abbreviations and constructor-defined locals).
    const receiverType: string | undefined =
      call.receiver_type_fqn ?? this.inferReceiverType(receiver, fromFile);

    if (receiverType) {
      // Look for method in the type
      const methodSymbol = this.symbolTable.findMethod(receiverType, call.method_name);

      if (methodSymbol) {
        // If the resolved method's parent is an interface, prefer a unique
        // implementor when one exists (Java cross-file E — interface
        // dispatch). The interface declaration carries no body so
        // taint-flow analysis through it is a dead end.
        const parent = methodSymbol.parentType
          ? this.symbolTable.getSymbol(methodSymbol.parentType)
          : undefined;
        if (parent && parent.kind === 'interface') {
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

        // Check if method is a taint source (excludes synthetic interprocedural_param)
        const isSource = this.isMethodTaintSource(method, ir.taint.sources);

        // Check if method propagates taint from parameters.
        // Combines (a) annotation-based params (e.g. @RequestParam) with
        // (b) per-file sink arg matching: any sink in the method body whose
        // call expression references a param by name marks that param as
        // taint-propagating to a sink — this is the summary needed for
        // cross-file chaining of `wrapper(taintedArg)` → sink calls.
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
   * Per-file analysis of cross-instance field bindings.
   *
   * Records `FieldTaintInfo` entries for fields written by:
   *   1. `@DataBoundConstructor`-style constructors  — surfaced as
   *      `constructor_field` sources by `LanguageSourcesPass`.
   *   2. Setter methods `set<Field>(<param>)` — assume the canonical
   *      `this.<field> = <param>` body shape, so the setter PARAMETER acts
   *      as the taint conduit at call sites.
   *   3. `@Autowired` field annotations — the field itself is a framework
   *      injection point; the writer is synthetic (line = field decl).
   *
   * The entries are keyed `${typeFqn}.${fieldName}` and consumed by
   * `findFieldBindingTaintPaths()` to surface flows of the canonical Jenkins
   * shape: ctor writes field → another class reads instance.field → sink.
   */
  private analyzeFieldTaint(ir: CircleIR, filePath: string): void {
    const pkg = ir.meta.package || '';

    // (1) Constructor-bound fields surfaced by LanguageSourcesPass via
    //     `constructor_field` sources. Location string format:
    //       `${className}.${methodName}() returns tainted field '${field}'
    //        (from constructor param '${sourceParam}')`
    const ctorFieldRe =
      /^(\w+)\.(\w+)\(\) returns tainted field '([^']+)' \(from constructor param '([^']+)'\)/;
    for (const src of ir.taint.sources) {
      if (src.type !== 'constructor_field') continue;
      const m = ctorFieldRe.exec(src.location);
      if (!m) continue;
      const [, className, , fieldName, sourceParam] = m;
      const typeFqn = pkg ? `${pkg}.${className}` : className;
      const type = ir.types.find(t => t.name === className);
      if (!type) continue;

      // Locate the constructor (or first method) whose param name matches.
      const writerMethod =
        type.methods.find(
          mth => mth.name === className && mth.parameters.some(p => p.name === sourceParam),
        ) ??
        type.methods.find(mth => mth.parameters.some(p => p.name === sourceParam));
      if (!writerMethod) continue;

      const field = type.fields?.find(f => f.name === fieldName);
      const key = `${typeFqn}.${fieldName}`;
      const existing = this.fieldTaintInfo.get(key);
      const writer = {
        methodFqn: `${typeFqn}.${writerMethod.name}`,
        methodName: writerMethod.name,
        writeLine: writerMethod.start_line,
        sourceType: 'constructor_field',
        sourceLine: src.line,
      };
      if (existing) {
        if (!existing.writers.some(w => w.methodFqn === writer.methodFqn)) {
          existing.writers.push(writer);
        }
      } else {
        this.fieldTaintInfo.set(key, {
          typeFqn,
          fieldName,
          fieldType: field?.type ?? null,
          file: filePath,
          writers: [writer],
        });
      }
    }

    // (2) Setter chains: `setX(x)` with one param. The PARAMETER acts as the
    //     taint conduit — the writer record reflects this so caller-side
    //     `obj.setX(tainted)` followed by `obj.x` read can be wired by
    //     `findFieldBindingTaintPaths()`. We do NOT pre-mark the field as
    //     tainted; tainting requires a tainted argument at call site (handled
    //     by the consumer pass).
    for (const type of ir.types) {
      const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;
      for (const method of type.methods) {
        if (!method.name.startsWith('set') || method.name.length <= 3) continue;
        if (method.parameters.length !== 1) continue;
        const fieldName = method.name.charAt(3).toLowerCase() + method.name.substring(4);
        const field = type.fields?.find(f => f.name === fieldName);
        if (!field) continue;

        const key = `${typeFqn}.${fieldName}`;
        const writer = {
          methodFqn: `${typeFqn}.${method.name}`,
          methodName: method.name,
          writeLine: method.start_line,
          sourceType: 'setter_param',
          sourceLine: method.start_line,
        };
        const existing = this.fieldTaintInfo.get(key);
        if (existing) {
          if (!existing.writers.some(w => w.methodFqn === writer.methodFqn)) {
            existing.writers.push(writer);
          }
        } else {
          this.fieldTaintInfo.set(key, {
            typeFqn,
            fieldName,
            fieldType: field.type ?? null,
            file: filePath,
            writers: [writer],
          });
        }
      }
    }

    // (3) @Autowired / @Inject fields: framework-injected. Treat the field
    //     as unconditionally tainted (writer is synthetic at the field's
    //     declaration line). Covers Spring `@Autowired`, JSR-330 `@Inject`,
    //     CDI `@Inject`, Micronaut `@Inject`, Quarkus `@Inject`.
    const injectAnnotations = new Set(['Autowired', 'Inject', 'Resource']);
    for (const type of ir.types) {
      const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;
      for (const field of type.fields ?? []) {
        if (!field.annotations?.some(a => injectAnnotations.has(a))) continue;
        const key = `${typeFqn}.${field.name}`;
        const writer = {
          methodFqn: `${typeFqn}.<injected>`,
          methodName: '<injected>',
          writeLine: type.start_line,
          sourceType: 'autowired_field',
          sourceLine: type.start_line,
        };
        const existing = this.fieldTaintInfo.get(key);
        if (existing) {
          if (!existing.writers.some(w => w.methodFqn === writer.methodFqn)) {
            existing.writers.push(writer);
          }
        } else {
          this.fieldTaintInfo.set(key, {
            typeFqn,
            fieldName: field.name,
            fieldType: field.type ?? null,
            file: filePath,
            writers: [writer],
          });
        }
      }
    }
  }

  /**
   * Check if method is a taint source.
   *
   * Excludes synthetic `interprocedural_param` sources — those are per-file
   * meta-analysis signals saying "this method's parameter MIGHT be tainted
   * when called with tainted data", not confirmed external inputs.  Treating
   * them as sources for cross-file `returnsSource` would propagate ghost
   * taint into every callee with typed parameters.
   */
  private isMethodTaintSource(method: MethodInfo, sources: TaintSource[]): boolean {
    // Check annotation-based sources
    const sourceAnnotations = ['RequestParam', 'RequestBody', 'PathVariable', 'QueryParam'];
    for (const param of method.parameters) {
      if (param.annotations.some(a => sourceAnnotations.includes(a))) {
        return true;
      }
    }

    // Check if any REAL source is within this method
    for (const source of sources) {
      if (source.type === 'interprocedural_param') continue;
      if (source.line >= method.start_line && source.line <= method.end_line) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get source type for a method (excluding synthetic interprocedural_param)
   */
  private getSourceType(method: MethodInfo, sources: TaintSource[]): string | undefined {
    for (const source of sources) {
      if (source.type === 'interprocedural_param') continue;
      if (source.line >= method.start_line && source.line <= method.end_line) {
        return source.type;
      }
    }
    return undefined;
  }

  /**
   * Find which parameters propagate taint to a sink within this method.
   *
   * Two heuristics, combined:
   *   1. Annotation-based: params with @RequestParam/@RequestBody/@PathVariable.
   *   2. Sink-arg matching: if a known sink call in the method body references
   *      a param by name in its arguments, that param propagates taint to a
   *      sink — this is the summary that cross-file chaining needs to link
   *      a caller's tainted argument to a downstream dangerous operation.
   */
  private findTaintedParams(method: MethodInfo, ir: CircleIR): number[] {
    const taintedParams = new Set<number>();
    const numParams = method.parameters.length;

    // Heuristic 1: annotation-based
    for (let i = 0; i < numParams; i++) {
      const param = method.parameters[i];
      if (param.annotations.some(a => ['RequestParam', 'RequestBody', 'PathVariable'].includes(a))) {
        taintedParams.add(i);
      }
    }

    // Heuristic 2: sink-arg matching.  For each sink inside this method, look
    // at the corresponding call expression's argument variables and mark any
    // matching parameter as taint-propagating.
    const paramNameToIndex = new Map<string, number>();
    for (let i = 0; i < numParams; i++) {
      const name = method.parameters[i].name;
      if (name) paramNameToIndex.set(name, i);
    }

    for (const sink of ir.taint.sinks) {
      if (sink.line < method.start_line || sink.line > method.end_line) continue;

      // Find the call(s) at the sink line — match by line number.
      const callsAtSink = ir.calls.filter(c => c.location.line === sink.line);
      for (const call of callsAtSink) {
        for (const arg of call.arguments) {
          // Argument that's a direct variable reference.
          const candidates: string[] = [];
          if (arg.variable) candidates.push(arg.variable);
          if (arg.expression) {
            // Heuristic: scan the expression for whole-word param-name tokens.
            // Catches concatenations / nested expressions like `prefix + url`.
            for (const [name] of paramNameToIndex) {
              const re = new RegExp(`\\b${name}\\b`);
              if (re.test(arg.expression)) candidates.push(name);
            }
          }
          for (const cand of candidates) {
            const idx = paramNameToIndex.get(cand);
            if (idx !== undefined) taintedParams.add(idx);
          }
        }
      }
    }

    return [...taintedParams].sort((a, b) => a - b);
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

        // Derive the variable that holds the source value (if it's assigned).
        // When known, require the cross-file call's arguments to actually
        // reference it — otherwise the flow is at best speculative and at
        // worst a false positive when the value is sanitized in between.
        const sourceVar = source.variable ?? this.getLocalDefVarAt(ir, source.line);

        // Find calls at or after the source line
        for (const call of ir.calls) {
          if (call.location.line < source.line) continue;

          const resolved = this.resolveCall(call, filePath);
          if (!resolved || resolved.targetFile === filePath) continue;

          // Variable-connectivity gate: when we know the source variable, the
          // call's arguments must reference it (directly or by expression).
          if (sourceVar) {
            const argMentions = call.arguments.some(arg => {
              if (arg.variable === sourceVar) return true;
              if (arg.expression && new RegExp(`\\b${sourceVar}\\b`).test(arg.expression)) return true;
              return false;
            });
            if (!argMentions) continue;
          }

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
          let targetMethod: MethodInfo | undefined;
          for (const type of targetIR.types) {
            const m = type.methods.find(m => m.name === shortName);
            if (m) { targetMethod = m; break; }
          }
          if (!targetMethod) continue;

          // Only emit a flow when at least one known sink falls inside the target method.
          // This means `targetLine` now correctly points to an actual dangerous operation
          // in the target file (not the caller's line in the source file).
          const targetIdx = this.getFileIndex(targetIR);
          const sinksInMethod = targetIdx.sinksByMethod.get(targetMethod) ?? [];
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
   * Find inter-procedural taint chains spanning multiple files / call sites.
   *
   * Bridges the gap that `findCrossFileTaintFlows()` cannot cover: a real
   * source lives in callee A, its return value bubbles up to caller C as a
   * tainted local, and C then passes that local to callee B which contains
   * the actual dangerous sink.  Neither A nor C alone has a co-located
   * source-and-sink, but the chain A → C → B is a real vulnerability.
   *
   * Algorithm (per caller method M):
   *   1. Seed `tainted` with real (non-`interprocedural_param`) sources in M.
   *   2. Walk calls in M in line order:
   *      a. If callee has `returnsSource = true` and is not a sanitizer,
   *         mark every `local` DFG def at this line as tainted, anchored to
   *         the callee's source.
   *      b. For each tainted arg in this call, if the callee's
   *         `taintedParams` covers that position, emit one
   *         `InterproceduralTaintPath` per sink inside the callee body.
   */
  findInterproceduralTaintPaths(): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();

    type Origin = {
      file: string;
      line: number;
      type: string;
      hopChain: InterproceduralTaintPath['hops'];
    };

    // Cache: method FQN → { ir, method }
    const methodIndex = this.buildMethodIndex();

    for (const [callerFile, callerIR] of this.fileIRs) {
      const callerIdx = this.getFileIndex(callerIR);
      for (const type of callerIR.types) {
        for (const method of type.methods) {
          // 1. Seed tainted vars with real sources inside this method.
          const tainted = new Map<string, Origin>();
          for (const src of callerIR.taint.sources) {
            if (src.type === 'interprocedural_param') continue;
            if (src.line < method.start_line || src.line > method.end_line) continue;
            if (!src.variable) continue;
            tainted.set(src.variable, {
              file: callerFile,
              line: src.line,
              type: src.type,
              hopChain: [{ file: callerFile, line: src.line, method: method.name, kind: 'source' }],
            });
          }

          // 2. Walk calls in M in line order (pre-indexed; sorted ASC).
          const callsInMethod = callerIdx.callsByMethod.get(method) ?? [];

          for (const call of callsInMethod) {
            const resolved = this.resolveCall(call, callerFile);
            if (!resolved) continue;

            const callee = this.methodTaintInfo.get(resolved.targetMethod);
            if (!callee) continue;

            // 2a. If callee returns a source and is NOT a sanitizer, mark every
            //     local def on this caller line as tainted (the assignment LHS).
            if (callee.returnsSource && !callee.sanitizes && callee.sourceType) {
              const calleeNode = methodIndex.get(resolved.targetMethod);
              const calleeSourceLine = calleeNode
                ? this.findRealSourceLineInMethod(calleeNode.ir, calleeNode.method)
                : undefined;
              const sourceLine = calleeSourceLine ?? call.location.line;
              const sourceFile = callee.file;
              const sourceType = callee.sourceType;

              const defsAtLine = (callerIdx.defsByLine.get(call.location.line) ?? [])
                .filter(d => d.kind === 'local');
              for (const def of defsAtLine) {
                if (!def.variable) continue;
                const baseChain: InterproceduralTaintPath['hops'] = [
                  { file: sourceFile, line: sourceLine, method: resolved.targetMethod, kind: 'source' },
                  { file: callerFile, line: call.location.line, method: method.name, kind: 'wrapper_return' },
                ];
                tainted.set(def.variable, {
                  file: sourceFile,
                  line: sourceLine,
                  type: sourceType,
                  hopChain: baseChain,
                });
              }
            }

            // 2b. For each tainted arg passed to a callee param that propagates
            //     to a sink, emit a multi-hop path.
            if (callee.taintedParams.length === 0 || callee.sanitizes) continue;

            for (let argIdx = 0; argIdx < call.arguments.length; argIdx++) {
              if (!callee.taintedParams.includes(argIdx)) continue;

              const arg = call.arguments[argIdx];
              const matched = this.matchTaintedArg(arg, tainted);
              if (!matched) continue;

              const calleeNode = methodIndex.get(resolved.targetMethod);
              if (!calleeNode) continue;

              const calleeIdx = this.getFileIndex(calleeNode.ir);
              const sinksInCallee = calleeIdx.sinksByMethod.get(calleeNode.method) ?? [];

              for (const sink of sinksInCallee) {
                const key = `${matched.origin.file}:${matched.origin.line}→${callee.file}:${sink.line}`;
                if (seen.has(key)) continue;
                seen.add(key);

                const hops: InterproceduralTaintPath['hops'] = [
                  ...matched.origin.hopChain,
                  { file: callerFile, line: call.location.line, method: method.name, kind: 'sink_call' },
                  { file: callee.file, line: sink.line, method: resolved.targetMethod, kind: 'sink' },
                ];

                // Confidence: decay by 0.85 per hop beyond the first.
                const decay = Math.max(0.3, Math.pow(0.85, Math.max(hops.length - 1, 0)));

                paths.push({
                  source: {
                    file: matched.origin.file,
                    line: matched.origin.line,
                    type: matched.origin.type,
                  },
                  sink: {
                    file: callee.file,
                    line: sink.line,
                    type: sink.type,
                    cwe: sink.cwe,
                  },
                  hops,
                  confidence: decay,
                });
              }
            }
          }

          // 2c. Caller-body sinks: after marking locals tainted via wrapper-return,
          //     check whether any sink in the CALLER'S OWN method body consumes a
          //     tainted variable. This closes the canonical Jenkins shape where the
          //     final sink (e.g. `Paths.get(p)`, `Runtime.exec(cmd)`) lives in the
          //     caller's file rather than in a cross-file callee.
          if (tainted.size > 0) {
            const sinksInCaller = callerIdx.sinksByMethod.get(method) ?? [];
            for (const sink of sinksInCaller) {
              const callsAtSink = callerIdx.callsByLine.get(sink.line) ?? [];
              for (const sinkCall of callsAtSink) {
                for (const arg of sinkCall.arguments ?? []) {
                  const matched = this.matchTaintedArg(arg, tainted);
                  if (!matched) continue;
                  const key = `${matched.origin.file}:${matched.origin.line}→${callerFile}:${sink.line}`;
                  if (seen.has(key)) continue;
                  seen.add(key);

                  const hops: InterproceduralTaintPath['hops'] = [
                    ...matched.origin.hopChain,
                    { file: callerFile, line: sink.line, method: method.name, kind: 'sink' },
                  ];
                  const decay = Math.max(0.3, Math.pow(0.85, Math.max(hops.length - 1, 0)));
                  paths.push({
                    source: {
                      file: matched.origin.file,
                      line: matched.origin.line,
                      type: matched.origin.type,
                    },
                    sink: {
                      file: callerFile,
                      line: sink.line,
                      type: sink.type,
                      cwe: sink.cwe,
                    },
                    hops,
                    confidence: decay,
                  });
                }
              }
            }
          }
        }
      }
    }

    return paths;
  }

  /**
   * Find cross-instance field-binding taint paths.
   *
   * Closes the canonical Jenkins / framework-DI shape that
   * `findInterproceduralTaintPaths()` cannot cover because the "source" lives
   * on an aliased object's field, not in a callee return:
   *
   *   File A:  class C { @DataBoundConstructor C(p) { this.f = p; } }
   *   File B:  class E { final C step; E(C step){ this.step = step; }
   *                      m() { String x = step.f; sink(x); } }
   *
   * Algorithm (per caller method M in file B):
   *   1. Seed `tainted` with sources inside M (mirrors findInterproc step 1).
   *   2. Scan M's local-def DFG entries for expressions of shape
   *      `<receiver>.<field>` where receiver's declared type owns `<field>`
   *      in the FieldTaintInfo cache. Mark the LHS local as tainted, anchor
   *      its origin to the field-binding writer (e.g. the ctor in file A).
   *   3. After seeding, walk caller-body sinks the same way
   *      `findInterproceduralTaintPaths()` step 2c does, and also forward
   *      tainted locals into cross-file callees whose `taintedParams` mark
   *      the arg position as sink-propagating.
   */
  findFieldBindingTaintPaths(): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();
    if (this.fieldTaintInfo.size === 0) return paths;

    const fieldExprRe = /^(\w+)\.(\w+)$/;
    const methodIndex = this.buildMethodIndex();

    for (const [callerFile, callerIR] of this.fileIRs) {
      const callerIdx = this.getFileIndex(callerIR);
      for (const type of callerIR.types) {
        const callerTypeFqn = callerIR.meta.package
          ? `${callerIR.meta.package}.${type.name}`
          : type.name;

        for (const method of type.methods) {
          // 1. Seed real sources in method.
          type Origin = {
            file: string;
            line: number;
            type: string;
            hopChain: InterproceduralTaintPath['hops'];
          };
          const tainted = new Map<string, Origin>();
          for (const src of callerIR.taint.sources) {
            if (src.type === 'interprocedural_param') continue;
            if (src.line < method.start_line || src.line > method.end_line) continue;
            if (!src.variable) continue;
            tainted.set(src.variable, {
              file: callerFile,
              line: src.line,
              type: src.type,
              hopChain: [{ file: callerFile, line: src.line, method: method.name, kind: 'source' }],
            });
          }

          // 2. Scan local defs for `receiver.field` patterns.
          //
          // DFG defs don't carry RHS expressions on locals, so we co-locate:
          //   - a `local` def at line L
          //   - two uses at line L: a known receiver variable (param or
          //     containing-class field) AND a token matching a field on the
          //     receiver's declared type.
          const defsInMethod = (callerIdx.defsByMethod.get(method) ?? []).filter(
            d => d.kind === 'local' && !!d.variable,
          );

          for (const def of defsInMethod) {
            const usesAtLine = callerIdx.usesByLine.get(def.line) ?? [];
            if (usesAtLine.length < 2) continue;

            // First pass: expression-based (preferred if available).
            let receiver: string | null = null;
            let fieldName: string | null = null;
            if (def.expression) {
              const exprMatch = fieldExprRe.exec(def.expression.trim());
              if (exprMatch) {
                receiver = exprMatch[1];
                fieldName = exprMatch[2];
              }
            }

            // Resolve receiver type from local context.
            const resolveReceiverType = (rcv: string): string | null => {
              const param = method.parameters.find(p => p.name === rcv);
              if (param?.type) return param.type;
              const fieldOnSelf = type.fields?.find(f => f.name === rcv);
              if (fieldOnSelf?.type) return fieldOnSelf.type;
              return null;
            };

            // Fallback: co-located uses heuristic. For each (receiverUse,
            // fieldUse) pair, check whether receiver's declared type owns
            // fieldUse.variable as a field.
            let receiverType: string | null = null;
            if (receiver && fieldName) {
              receiverType = resolveReceiverType(receiver);
            }
            if (!receiverType) {
              for (const rcvUse of usesAtLine) {
                if (!rcvUse.variable || rcvUse.variable === def.variable) continue;
                const rt = resolveReceiverType(rcvUse.variable);
                if (!rt) continue;
                // Find any other use at this line matching a field on rt.
                const fieldUse = usesAtLine.find(
                  u =>
                    u !== rcvUse &&
                    !!u.variable &&
                    u.variable !== def.variable &&
                    u.variable !== rcvUse.variable &&
                    this.typeHasField(rt, u.variable),
                );
                if (fieldUse) {
                  receiver = rcvUse.variable;
                  fieldName = fieldUse.variable!;
                  receiverType = rt;
                  break;
                }
              }
            }

            if (!receiver || !fieldName || !receiverType) continue;

            // FieldTaintInfo is keyed by FQN, but the receiver type may be a
            // simple name. Resolve via symbol table / scan fileIRs.
            const fieldKey = this.resolveFieldTaintKey(receiverType, fieldName, callerIR);
            if (!fieldKey) continue;
            const fieldInfo = this.fieldTaintInfo.get(fieldKey);
            if (!fieldInfo || fieldInfo.writers.length === 0) continue;

            // Anchor origin to the most informative writer (prefer ctor /
            // autowired over setter). Setter writers require a tainted arg
            // at call-site to be relevant; without seeing the call we treat
            // them as non-anchoring here.
            const writer =
              fieldInfo.writers.find(
                w => w.sourceType === 'constructor_field' || w.sourceType === 'autowired_field',
              ) ?? null;
            if (!writer) continue;

            const hopChain: InterproceduralTaintPath['hops'] = [
              {
                file: fieldInfo.file,
                line: writer.sourceLine,
                method: writer.methodName,
                kind: 'source',
              },
              {
                file: fieldInfo.file,
                line: writer.writeLine,
                method: writer.methodName,
                kind: 'field_write',
              },
              {
                file: callerFile,
                line: def.line,
                method: method.name,
                kind: 'field_read',
              },
            ];
            tainted.set(def.variable, {
              file: fieldInfo.file,
              line: writer.sourceLine,
              type: writer.sourceType,
              hopChain,
            });
          }

          if (tainted.size === 0) continue;

          // 3a. Caller-body sinks consuming a tainted local.
          const sinksInCaller = callerIdx.sinksByMethod.get(method) ?? [];
          for (const sink of sinksInCaller) {
            const callsAtSink = callerIdx.callsByLine.get(sink.line) ?? [];
            for (const sinkCall of callsAtSink) {
              for (const arg of sinkCall.arguments ?? []) {
                const matched = this.matchTaintedArg(arg, tainted);
                if (!matched) continue;
                const key = `fb:${matched.origin.file}:${matched.origin.line}→${callerFile}:${sink.line}`;
                if (seen.has(key)) continue;
                seen.add(key);
                const hops: InterproceduralTaintPath['hops'] = [
                  ...matched.origin.hopChain,
                  { file: callerFile, line: sink.line, method: method.name, kind: 'sink' },
                ];
                const decay = Math.max(0.3, Math.pow(0.85, Math.max(hops.length - 1, 0)));
                paths.push({
                  source: {
                    file: matched.origin.file,
                    line: matched.origin.line,
                    type: matched.origin.type,
                  },
                  sink: {
                    file: callerFile,
                    line: sink.line,
                    type: sink.type,
                    cwe: sink.cwe,
                  },
                  hops,
                  confidence: decay,
                });
              }
            }
          }

          // 3b. Cross-file callees: forward tainted locals into resolved
          //     callees whose taintedParams mark the arg as sink-propagating.
          const callsInMethod = callerIdx.callsByMethod.get(method) ?? [];
          for (const call of callsInMethod) {
            const resolved = this.resolveCall(call, callerFile);
            if (!resolved) continue;
            const callee = this.methodTaintInfo.get(resolved.targetMethod);
            if (!callee || callee.sanitizes || callee.taintedParams.length === 0) continue;

            for (let argIdx = 0; argIdx < call.arguments.length; argIdx++) {
              if (!callee.taintedParams.includes(argIdx)) continue;
              const matched = this.matchTaintedArg(call.arguments[argIdx], tainted);
              if (!matched) continue;
              const calleeNode = methodIndex.get(resolved.targetMethod);
              if (!calleeNode) continue;
              const calleeIdx = this.getFileIndex(calleeNode.ir);
              const sinksInCallee = calleeIdx.sinksByMethod.get(calleeNode.method) ?? [];
              for (const sink of sinksInCallee) {
                const key = `fb:${matched.origin.file}:${matched.origin.line}→${callee.file}:${sink.line}`;
                if (seen.has(key)) continue;
                seen.add(key);
                const hops: InterproceduralTaintPath['hops'] = [
                  ...matched.origin.hopChain,
                  { file: callerFile, line: call.location.line, method: method.name, kind: 'sink_call' },
                  { file: callee.file, line: sink.line, method: resolved.targetMethod, kind: 'sink' },
                ];
                const decay = Math.max(0.3, Math.pow(0.85, Math.max(hops.length - 1, 0)));
                paths.push({
                  source: {
                    file: matched.origin.file,
                    line: matched.origin.line,
                    type: matched.origin.type,
                  },
                  sink: {
                    file: callee.file,
                    line: sink.line,
                    type: sink.type,
                    cwe: sink.cwe,
                  },
                  hops,
                  confidence: decay,
                });
              }
            }
          }

          // (silence unused warning for callerTypeFqn — reserved for future
          //  same-class field-read detection)
          void callerTypeFqn;
        }
      }
    }

    return paths;
  }

  /**
   * Check whether any loaded type with name `typeName` (simple or FQN suffix)
   * declares a field named `fieldName`.
   */
  private typeHasField(typeName: string, fieldName: string): boolean {
    for (const [, ir] of this.fileIRs) {
      for (const t of ir.types) {
        if (t.name !== typeName) continue;
        if ((t.fields ?? []).some(f => f.name === fieldName)) return true;
      }
    }
    return false;
  }

  /**
   * Resolve a receiver type-name + field-name to the cache key used by
   * `fieldTaintInfo`. Handles simple-name receivers (e.g. `ReadTrustedStep`)
   * by looking up matching FQN keys across loaded files.
   */
  private resolveFieldTaintKey(
    receiverType: string,
    fieldName: string,
    _callerIR: CircleIR,
  ): string | undefined {
    // Exact FQN hit.
    const direct = `${receiverType}.${fieldName}`;
    if (this.fieldTaintInfo.has(direct)) return direct;

    // Simple-name match: scan keys for `*.<receiver>.<field>` suffix.
    const suffix = `.${receiverType}.${fieldName}`;
    for (const key of this.fieldTaintInfo.keys()) {
      if (key === direct) return key;
      if (key.endsWith(suffix)) return key;
    }
    return undefined;
  }

  /**
   * Find which method a tainted arg expression references.
   */
  private matchTaintedArg(
    arg: { variable?: string | null; expression?: string },
    tainted: Map<string, { file: string; line: number; type: string; hopChain: InterproceduralTaintPath['hops'] }>,
  ): { var: string; origin: { file: string; line: number; type: string; hopChain: InterproceduralTaintPath['hops'] } } | null {
    if (tainted.size === 0) return null;

    // Direct variable reference
    if (arg.variable && tainted.has(arg.variable)) {
      return { var: arg.variable, origin: tainted.get(arg.variable)! };
    }

    // Whole-word scan inside the expression (handles `prefix + url`, `url.trim()`, etc.)
    if (arg.expression) {
      for (const [tv, origin] of tainted) {
        const re = new RegExp(`\\b${tv}\\b`);
        if (re.test(arg.expression)) return { var: tv, origin };
      }
    }

    return null;
  }

  /**
   * Index methods by FQN for quick lookup during chain construction.
   */
  private buildMethodIndex(): Map<string, { ir: CircleIR; method: MethodInfo }> {
    const idx = new Map<string, { ir: CircleIR; method: MethodInfo }>();
    for (const [, ir] of this.fileIRs) {
      const pkg = ir.meta.package || '';
      for (const type of ir.types) {
        const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;
        for (const method of type.methods) {
          idx.set(`${typeFqn}.${method.name}`, { ir, method });
        }
      }
    }
    return idx;
  }

  /** Return the first local-def variable name at a given line, if any. */
  private getLocalDefVarAt(ir: CircleIR, line: number): string | undefined {
    for (const def of ir.dfg.defs) {
      if (def.line === line && def.kind === 'local' && def.variable) return def.variable;
    }
    return undefined;
  }

  private findRealSourceLineInMethod(ir: CircleIR, method: MethodInfo): number | undefined {
    for (const src of ir.taint.sources) {
      if (src.type === 'interprocedural_param') continue;
      if (src.line >= method.start_line && src.line <= method.end_line) {
        return src.line;
      }
    }
    return undefined;
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
    this.fieldTaintInfo.clear();
    this.resolvedCalls.clear();
  }

  /** Expose field-taint summary (for tests + diagnostics). */
  getFieldTaintInfo(typeFqn: string, fieldName: string): FieldTaintInfo | undefined {
    return this.fieldTaintInfo.get(`${typeFqn}.${fieldName}`);
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
