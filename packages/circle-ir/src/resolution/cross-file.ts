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
  TypeInfo,
} from '../types/index.js';
import { SymbolTable, type ExportedSymbol } from './symbol-table.js';
import { TypeHierarchyResolver } from './type-hierarchy.js';
import { constLookupTables, isConstTableLookup } from '../analysis/const-table-lookup.js';

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
  /**
   * The receiver is an injected one (a constructor-injected or `@Autowired`
   * field, a TypeScript constructor parameter property) and the target was
   * taken from its declared type: the class itself, or the one project class
   * that implements a declared interface.
   */
  injected?: true;
  /**
   * JS/TS: the call was made through an import of a relative module and the
   * target is the function that module exports.
   */
  moduleExport?: true;
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
  /** Line of the call in `sourceFile` that passes the tainted argument. */
  callLine?: number;
  /** Method in `sourceFile` that makes that call. */
  callMethod?: string;
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
  hops:   Array<{ file: string; line: number; method: string; kind: 'source' | 'wrapper_return' | 'field_write' | 'field_read' | 'sink_call' | 'callback' | 'sink' }>;
  confidence: number;
  /**
   * The callee argument position the tainted value enters through, when the
   * path ends in a call into the sink's method (cognium-dev#637).
   */
  calleeArgPositions?: number[];
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
/**
 * Escape a string for safe interpolation into a `new RegExp(...)`. A method
 * parameter name can be a Python starred parameter (`*args`, `**kwargs`), and
 * `*` is a regex quantifier — an unescaped interpolation throws "Nothing to
 * repeat" and fails the whole project analysis closed (cognium-dev#458). Such a
 * key never matches a `\b`-anchored expression, so escaping fixes the crash
 * without changing any resolved flow.
 */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isJavaIdent(s: string): boolean {
  if (!s) return false;
  const first = s[0]!;
  if (first !== '_' && !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) return false;
  for (let i = 1; i < s.length; i++) {
    const c = s[i]!;
    if (c === '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) continue;
    return false;
  }
  return true;
}

/** Single-statement body `fieldName = paramName` for a one-param static setter. */
function parseJavaStaticFieldAssignment(inner: string): { field: string; param: string } | null {
  let s = inner.trim();
  if (s.endsWith(';')) s = s.slice(0, -1).trim();
  const eq = s.indexOf('=');
  if (eq < 0) return null;
  const field = s.slice(0, eq).trim();
  const param = s.slice(eq + 1).trim();
  if (!isJavaIdent(field) || !isJavaIdent(param)) return null;
  if (s.slice(eq + 1).includes('=')) return null;
  return { field, param };
}

/** Body that is only `return fieldName` or `return this.fieldName`. */
function parseJavaStaticGetterReturn(inner: string): string | null {
  let s = inner.trim();
  if (!s.startsWith('return')) return null;
  s = s.slice('return'.length).trim();
  if (s.endsWith(';')) s = s.slice(0, -1).trim();
  if (s.startsWith('this.')) s = s.slice(5);
  if (!isJavaIdent(s)) return null;
  return s;
}

/** Body `return OtherType.staticMethod()`. */
function parseJavaStaticDelegateReturn(inner: string): { type: string; method: string } | null {
  let s = inner.trim();
  if (!s.startsWith('return')) return null;
  s = s.slice('return'.length).trim();
  if (s.endsWith(';')) s = s.slice(0, -1).trim();
  const paren = s.indexOf('(');
  if (paren < 0 || !s.endsWith(')')) return null;
  const call = s.slice(0, paren).trim();
  const dot = call.lastIndexOf('.');
  if (dot < 0) return null;
  const type = call.slice(0, dot);
  const method = call.slice(dot + 1);
  if (!isJavaIdent(type) || !isJavaIdent(method)) return null;
  if (s.slice(paren + 1, -1).trim() !== '') return null;
  return { type, method };
}

/** Field annotations that mark a framework-injected field (Spring, JSR-330, Jakarta). */
const JAVA_INJECT_ANNOTATIONS = new Set(['Autowired', 'Inject', 'Resource']);

/** A project class or interface, with the file that declares it. */
interface ProjectType {
  file: string;
  type: TypeInfo;
  fqn: string;
}

/** `GetMapping("/x")` → `GetMapping`; `lombok.RequiredArgsConstructor` → `RequiredArgsConstructor`. */
function annotationName(annotation: string): string {
  const paren = annotation.indexOf('(');
  const bare = (paren >= 0 ? annotation.slice(0, paren) : annotation).trim();
  return bare.slice(bare.lastIndexOf('.') + 1);
}

/**
 * The type a declaration names, without type arguments: `Repo<User>` → `Repo`,
 * `com.x.Repo` stays qualified. Null for arrays, unions, function types and
 * anything else that is not one named type.
 */
function declaredTypeName(text: string): string | null {
  const s = text.trim();
  const lt = s.indexOf('<');
  if (lt >= 0 && !s.endsWith('>')) return null;
  const t = (lt >= 0 ? s.slice(0, lt) : s).trim();
  return /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(t) ? t : null;
}

/**
 * Java fields a class receives by dependency injection, as receiver
 * expression (`repo`, `this.repo`) → declared type. A field counts when it is
 * annotated `@Autowired` / `@Inject` / `@Resource`, when a constructor takes a
 * parameter of its type (constructor injection, with or without
 * `@Autowired`), or when Lombok generates that constructor
 * (`@RequiredArgsConstructor` for final fields, `@AllArgsConstructor`).
 */
function javaInjectedFields(type: TypeInfo): Map<string, string> {
  const out = new Map<string, string>();
  const classAnnotations = new Set(type.annotations.map(annotationName));
  const lombokRequired = classAnnotations.has('RequiredArgsConstructor');
  const lombokAll = classAnnotations.has('AllArgsConstructor');
  const ctorParamTypes = new Set<string>();
  for (const m of type.methods) {
    if (m.name !== type.name) continue;
    for (const p of m.parameters) {
      const t = p.type ? declaredTypeName(p.type) : null;
      if (t) ctorParamTypes.add(t);
    }
  }
  for (const f of type.fields) {
    if (!f.type || f.modifiers.includes('static')) continue;
    const t = declaredTypeName(f.type);
    if (!t) continue;
    const injected = f.annotations.some(a => JAVA_INJECT_ANNOTATIONS.has(annotationName(a)))
      || ctorParamTypes.has(t)
      || lombokAll
      || (lombokRequired && f.modifiers.includes('final'));
    if (!injected) continue;
    out.set(f.name, f.type);
    out.set(`this.${f.name}`, f.type);
  }
  return out;
}

/**
 * TypeScript constructor parameters a class keeps as members, as receiver
 * expression (`this.svc`) → declared type: parameter properties
 * (`constructor(private svc: PingService)`, `private readonly`, `public`,
 * `protected`, `readonly`) and parameters the constructor body assigns
 * (`this.svc = svc`). The IR does not record parameter modifiers, so this reads
 * the constructor's source text.
 */
function tsInjectedProperties(type: TypeInfo, lines: string[] | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!lines) return out;
  const ctor = type.methods.find(m => m.name === 'constructor');
  if (!ctor) return out;
  const text = lines.slice(ctor.start_line - 1, ctor.end_line).join('\n');
  for (const p of ctor.parameters) {
    if (!p.type || !/^[A-Za-z_$][\w$]*$/.test(p.name)) continue;
    const name = escapeRegExp(p.name);
    const property = new RegExp(
      `(?:^|[\\s(,])(?:public|private|protected|readonly)\\s+(?:readonly\\s+)?${name}\\s*\\??\\s*:`);
    if (property.test(text)) out.set(`this.${p.name}`, p.type);
    const assigned = new RegExp(`\\bthis\\.([A-Za-z_$][\\w$]*)\\s*=\\s*${name}\\s*(?=[;}\\n]|$)`, 'g');
    for (const m of text.matchAll(assigned)) out.set(`this.${m[1]}`, p.type);
  }
  return out;
}

/** `a/b/./c/../d` → `a/b/d`, keeping a leading `/`. */
function normalizeModulePath(p: string): string {
  const parts: string[] = [];
  for (const part of p.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') parts.pop();
    else parts.push(part);
  }
  return (p.startsWith('/') ? '/' : '') + parts.join('/');
}

/** File path without a JS/TS extension. */
function withoutScriptExtension(file: string): string {
  return file.replace(/\.(?:d\.)?[cm]?[jt]sx?$/, '');
}

/**
 * Can the module specifier `spec`, imported in `fromFile`, name `file`? A
 * relative specifier must resolve to it (`./ping.service`, `./ping.service.js`,
 * `./ping` for `ping/index.ts`); any other (a path alias such as
 * `src/ping/ping.service` or `@app/ping.service`) must end in its base name.
 */
function moduleSpecifierNames(spec: string, fromFile: string, file: string): boolean {
  const target = withoutScriptExtension(file);
  const bare = withoutScriptExtension(spec);
  if (spec.startsWith('.')) {
    const slash = fromFile.lastIndexOf('/');
    const base = normalizeModulePath(slash >= 0 ? `${fromFile.slice(0, slash)}/${bare}` : bare);
    return target === base || target === `${base}/index`;
  }
  const last = bare.slice(bare.lastIndexOf('/') + 1);
  return last !== '' && (target === last || target.endsWith(`/${last}`));
}

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
  private sourceLines?: Map<string, string[]>;

  // Cache: method FQN -> taint info
  private methodTaintInfo: Map<string, MethodTaintInfo> = new Map();

  /**
   * The same summaries keyed `${file}#${methodFqn}`. JS/TS module functions
   * share the FQN `<module>.<name>` across files, so a lookup by FQN alone can
   * return another file's function of the same name.
   */
  private methodTaintInfoByFile: Map<string, MethodTaintInfo> = new Map();

  // Cache: `${typeFqn}.${fieldName}` -> field taint info
  private fieldTaintInfo: Map<string, FieldTaintInfo> = new Map();

  /** cognium-dev#638 step 4 — `ClassName.staticField` written from a real source. */
  private csharpStaticFieldWriters: Map<
    string,
    { file: string; line: number; type: string; methodName: string }
  > = new Map();

  /** cognium-dev#1455 — Java static field set from a cross-file param (`remember(v)`). */
  private javaStaticFieldWriters: Record<
    string,
    { file: string; line: number; type: string; methodName: string }
  > = {};

  /** `${typeFqn}.${fieldName}` → static getter method FQN (e.g. `ShadowState.last`). */
  private javaStaticFieldGetters: Record<string, string> = {};

  /** Wrapper static getter FQN → canonical getter FQN it delegates to. */
  private javaStaticGetterDelegates: Record<string, string> = {};

  // Resolved calls cache
  private resolvedCalls: Map<string, ResolvedCall> = new Map();

  /** JS/TS file → the `<module>` method it exports as default (null: none found). */
  private jsDefaultExportNames: Map<string, string | null> = new Map();

  /** Per file: class → injected receiver expression → declared type (see `injectedReceiverType`). */
  private injectedReceivers: Map<string, Map<TypeInfo, Map<string, string>>> = new Map();

  /** Project classes and interfaces by FQN and by simple name, built on first use. */
  private projectTypeIndex?: { byFqn: Map<string, ProjectType[]>; byName: Map<string, ProjectType[]> };

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
  /**
   * Raw source lines per file. Optional: the JS/TS parameter-to-sink check reads a
   * def's right-hand side from them (the DFG carries none) to stop at literal-only
   * values; without them the check still runs, only less precisely.
   */
  setSourceLines(lines: Map<string, string[]>): void {
    if (this.sourceLines !== lines) {
      // TypeScript injected receivers are read from source text: drop any
      // binding resolved before it was available.
      this.injectedReceivers.clear();
      this.resolvedCalls.clear();
    }
    this.sourceLines = lines;
    this.jsDefaultExportNames.clear();
    for (const [path, ir] of this.fileIRs) {
      this.analyzeJavaStaticFieldPairs(ir, path);
    }
  }

  addFile(filePath: string, ir: CircleIR): void {
    this.projectTypeIndex = undefined;
    this.injectedReceivers.delete(filePath);
    this.fileIRs.set(filePath, ir);
    this.symbolTable.addFromIR(ir, filePath);
    this.typeHierarchy.addFromIR(ir, filePath);

    // Analyze methods for taint propagation characteristics
    this.analyzeMethodTaint(ir, filePath);

    // Analyze cross-instance field bindings (constructor + setter writers)
    this.analyzeFieldTaint(ir, filePath);
    this.analyzeCSharpStaticFieldWriters(ir, filePath);
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

    // JS/TS: a call made through an import of a relative module resolves to
    // the function that module exports, before any name-based guess.
    const lang = this.fileIRs.get(fromFile)?.meta.language;
    if (lang === 'javascript' || lang === 'typescript') {
      resolved = this.resolveJsImportedCall(call, fromFile);
    }

    if (!resolved) {
      // Try to resolve based on receiver type; else a static or same-class call.
      resolved = call.receiver
        ? this.resolveWithReceiver(call, fromFile)
        : this.resolveStaticOrLocal(call, fromFile);
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

    // An injected receiver (`repo.find(q)` on a constructor-injected field,
    // `this.svc.ping(h)` on a parameter property) is typed by its declaration.
    // When that type is known not to hold the method in the project, no other
    // class's method of the same name is the target either.
    const injected = this.resolveInjectedReceiver(call, fromFile);
    if (injected !== undefined) return injected ?? undefined;

    // Preflight (#74 follow-up / Java cross-file E): the Java extractor
    // already populates `receiver_type_fqn` for invocations whose receiver
    // type can be resolved via imports/locals/fields. Honour it before
    // falling through to context-derived inference (which only handles a
    // few common abbreviations and constructor-defined locals).
    let receiverType: string | undefined =
      call.receiver_type_fqn ?? this.inferReceiverType(receiver, fromFile);

    if (!receiverType && call.receiver_type) {
      receiverType = this.symbolTable.resolveTypeName(call.receiver_type, fromFile);
    }

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

    // A JDK receiver (`System.getProperty`, `props.getProperty` on a
    // `java.util.Properties`, `Integer.parseInt`) is not a project method that
    // happens to share the name: OWASP's `System.getProperty("os.name")` resolved to the project's
    // `PropertiesManager.getProperty` and made a `config_param` source (#976).
    // Only a project type of that simple name may shadow it, and that case was
    // resolved above.
    const lang = this.fileIRs.get(fromFile)?.meta.language;
    if (receiverType ? isJdkType(receiverType, lang) : isJdkClassReceiver(receiver, lang)) return undefined;

    // JS/TS: `signer.getAddress()` on a receiver of unknown type is a method of
    // that object, not a module-level function that happens to share the name
    // (juice-shop: the ethers Signer resolved to routes/address.ts getAddress and
    // made req.body a source in the frontend, #992). Only a receiver bound by an
    // import (`import * as addr from './address'`) may reach a module function.
    if (!receiverType && (lang === 'javascript' || lang === 'typescript')) {
      const byName = this.resolveByMethodName(call, fromFile);
      if (byName && byName.targetClass === '<module>' && !this.isImportBinding(fromFile, receiver)) return undefined;
      return byName;
    }

    // Fallback: search by method name
    return this.resolveByMethodName(call, fromFile);
  }

  /** Is `name` bound by an import in `file` (alias, default or namespace import)? */
  private isImportBinding(file: string, name: string): boolean {
    const ir = this.fileIRs.get(file);
    return (ir?.imports ?? []).some(i => (i.alias ?? i.imported_name) === name);
  }

  /**
   * JS/TS: resolve a call made through the caller's import of a relative
   * module to the function that module exports:
   *   - `const { fn } = require('./h')` / `import { fn as go } from './h'`,
   *     then `fn(…)` / `go(…)`: the export `fn`;
   *   - `const ping = require('./h')` / `import ping from './h'`, then
   *     `ping(…)`: the module's default export (`module.exports = function`,
   *     `export default function`);
   *   - `const h = require('./h')`, `import * as h from './h'` or
   *     `import h from './h'`, then `h.fn(…)`: the export `fn`.
   * Re-exports (`export * from`, `export { fn } from`) are followed up to
   * three hops. Undefined when the call is not made through such an import
   * or the function is not found; resolution then falls back to the
   * name-based search.
   */
  private resolveJsImportedCall(call: CallInfo, fromFile: string): ResolvedCall | undefined {
    const ir = this.fileIRs.get(fromFile);
    if (!ir) return undefined;
    const receiver = call.receiver ?? null;
    if (receiver !== null && !/^[A-Za-z_$][\w$]*$/.test(receiver)) return undefined;
    const binding = receiver ?? call.method_name;
    const imp = (ir.imports ?? []).find(i =>
      !i.is_type_only && !!i.from_package && i.from_package.startsWith('.')
      && (i.alias ?? i.imported_name) === binding);
    if (!imp?.from_package) return undefined;
    const wholeModule = imp.is_wildcard || imp.imported_name === 'default';
    let symbol: string;
    if (receiver === null) symbol = wholeModule ? 'default' : imp.imported_name;
    else if (wholeModule) symbol = call.method_name;
    else return undefined; // a named import used as an object: left to the type-based paths
    const targetFile = this.resolveJsModuleFile(fromFile, imp.from_package);
    if (!targetFile) return undefined;
    const found = this.findJsExportedFunction(targetFile, symbol, 0, new Set());
    if (!found) return undefined;
    const pkg = found.ir.meta.package || '';
    const typeFqn = pkg ? `${pkg}.<module>` : '<module>';
    return {
      call,
      sourceFile: fromFile,
      targetFile: found.file,
      targetMethod: `${typeFqn}.${found.method.name}`,
      targetClass: typeFqn,
      resolution: 'exact',
      moduleExport: true,
    };
  }

  /**
   * Bind a call made through an injected receiver to the receiver's declared
   * type (Java, TypeScript). The target is the declared class, the nearest
   * project superclass declaring the method, or, for an interface or an
   * abstract method, the one project class that implements it.
   *
   * Returns `undefined` when the receiver is not an injected one, or when the
   * declared type cannot be decided (several project types share its name, an
   * interface has several implementations): the general resolution then runs
   * as before. Returns `null` when the declared type is known and does not
   * hold the method in the project (a library type, an interface with no
   * implementation, a method inherited from a library base class).
   */
  private resolveInjectedReceiver(call: CallInfo, fromFile: string): ResolvedCall | null | undefined {
    const ir = this.fileIRs.get(fromFile);
    if (!ir) return undefined;
    const lang = ir.meta.language;
    if (lang !== 'java' && lang !== 'typescript') return undefined;
    const declared = this.injectedReceiverType(call, fromFile, ir);
    if (!declared) return undefined;
    const declaredType = this.resolveDeclaredType(declared, fromFile, ir);
    if (declaredType === undefined || declaredType === null) return declaredType;

    let owner = declaredType.type.kind === 'interface'
      ? undefined
      : this.typeDeclaringMethod(declaredType, call.method_name, 0);
    const abstractMethod = owner?.type.methods.find(m => m.name === call.method_name)?.modifiers.includes('abstract');
    let dispatched = false;
    if (!owner || abstractMethod) {
      if (owner === undefined && declaredType.type.kind !== 'interface') return null;
      const lookup = declaredType.type.kind === 'interface'
        ? this.typeHierarchy.getAllImplementations(declaredType.fqn)
        : this.typeHierarchy.getAllSubtypes(declaredType.fqn);
      const concrete = new Map<string, ProjectType>();
      for (const fqn of lookup) {
        const types = this.projectTypes().byFqn.get(fqn) ?? [];
        if (types.length !== 1) return undefined;
        const t = types[0];
        if (t.type.kind !== 'class') continue;
        const impl = this.typeDeclaringMethod(t, call.method_name, 0);
        if (impl && !impl.type.methods.find(m => m.name === call.method_name)?.modifiers.includes('abstract')) {
          concrete.set(impl.fqn, impl);
        }
      }
      if (concrete.size === 0) return null;
      if (concrete.size > 1) return undefined;
      owner = [...concrete.values()][0];
      dispatched = true;
    }

    const targetMethod = `${owner.fqn}.${call.method_name}`;
    return {
      call,
      sourceFile: fromFile,
      targetFile: owner.file,
      targetMethod,
      targetClass: owner.fqn,
      resolution: dispatched ? 'polymorphic' : 'exact',
      ...(dispatched ? { candidates: [targetMethod] } : {}),
      injected: true,
    };
  }

  /**
   * The project file a relative JS/TS module specifier names, trying the
   * TypeScript and JavaScript extensions and `index` files. A `.js` / `.mjs`
   * / `.cjs` / `.jsx` specifier may name its TypeScript source.
   */
  private resolveJsModuleFile(fromFile: string, spec: string): string | undefined {
    const parts = fromFile.split('/');
    parts.pop();
    for (const seg of spec.split('/')) {
      if (seg === '' || seg === '.') continue;
      if (seg === '..') {
        if (parts.length > 1 || (parts.length === 1 && parts[0] !== '')) parts.pop();
      } else {
        parts.push(seg);
      }
    }
    const base = parts.join('/');
    const stem = base.replace(/\.(?:[mc]?js|jsx)$/, '');
    const exts = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
    const candidates = [base, ...exts.map(e => stem + e), ...exts.map(e => `${base}/index${e}`)];
    return candidates.find(c => this.fileIRs.has(c));
  }

  /**
   * The module-level function `file` exports as `symbol` (`default` for the
   * default export), following re-exports and re-exported imports.
   */
  private findJsExportedFunction(
    file: string,
    symbol: string,
    depth: number,
    visited: Set<string>,
  ): { file: string; ir: CircleIR; method: MethodInfo } | undefined {
    const ir = this.fileIRs.get(file);
    const key = `${file}#${symbol}`;
    if (!ir || visited.has(key)) return undefined;
    visited.add(key);
    const lang = ir.meta.language;
    if (lang !== 'javascript' && lang !== 'typescript') return undefined;
    const name = symbol === 'default' ? this.jsDefaultExportName(file, ir) : symbol;
    const method = name
      ? ir.types.find(t => t.name === '<module>')?.methods.find(m => m.name === name)
      : undefined;
    if (method) return { file, ir, method };
    if (depth >= 3) return undefined;
    for (const imp of ir.imports ?? []) {
      if (!imp.from_package?.startsWith('.') || imp.is_type_only) continue;
      const reExport = imp.is_wildcard && imp.alias === null;
      if (!reExport && (name === undefined || (imp.alias ?? imp.imported_name) !== name)) continue;
      const next = this.resolveJsModuleFile(file, imp.from_package);
      if (!next || next === file) continue;
      const nextSymbol = reExport ? symbol : imp.is_wildcard ? 'default' : imp.imported_name;
      const found = this.findJsExportedFunction(next, nextSymbol, depth + 1, visited);
      if (found) return found;
    }
    return undefined;
  }

  /**
   * Name of the `<module>` method a JS/TS file exports as its default:
   * `default` for an anonymous one, else the name given by
   * `export default function f` / `export default f` /
   * `module.exports = function f` / `module.exports = f` /
   * `export { f as default }`.
   */
  private jsDefaultExportName(file: string, ir: CircleIR): string | undefined {
    const methods = ir.types.find(t => t.name === '<module>')?.methods ?? [];
    if (methods.some(m => m.name === 'default')) return 'default';
    const lines = this.sourceLines?.get(file);
    if (!lines) return undefined;
    if (this.jsDefaultExportNames.has(file)) return this.jsDefaultExportNames.get(file) ?? undefined;
    const name = this.readJsDefaultExportName(lines, methods);
    this.jsDefaultExportNames.set(file, name ?? null);
    return name;
  }

  /** The default export named by a top-level statement of `lines`, among `methods`. */
  private readJsDefaultExportName(lines: readonly string[], methods: readonly MethodInfo[]): string | undefined {
    const known = (name: string | undefined): name is string => !!name && methods.some(x => x.name === name);
    for (const raw of lines) {
      const line = raw.trim().replace(/;$/, '');
      const fn = /^(?:export\s+default|module\.exports\s*=)\s*(?:async\s+)?function[\s*]*([A-Za-z_$][\w$]*)/.exec(line)?.[1];
      if (known(fn)) return fn;
      const bare = /^(?:export\s+default|module\.exports\s*=)\s*([A-Za-z_$][\w$]*)$/.exec(line)?.[1];
      if (known(bare)) return bare;
      const list = /^export\s*\{([^}]*)\}$/.exec(line)?.[1];
      for (const entry of list?.split(',') ?? []) {
        const alias = /^([A-Za-z_$][\w$]*)\s+as\s+default$/.exec(entry.trim())?.[1];
        if (known(alias)) return alias;
      }
    }
    return undefined;
  }

  /**
   * The declared type of `call.receiver` when it is an injected member of the
   * class the call is in (see `javaInjectedFields` / `tsInjectedProperties`).
   * A bare Java name that a local or parameter of the enclosing method hides
   * is not the field.
   */
  private injectedReceiverType(call: CallInfo, fromFile: string, ir: CircleIR): string | undefined {
    const receiver = call.receiver;
    if (!receiver) return undefined;
    const line = call.location.line;
    let owner: TypeInfo | undefined;
    for (const t of ir.types) {
      if (line < t.start_line || line > t.end_line) continue;
      if (!owner || t.end_line - t.start_line < owner.end_line - owner.start_line) owner = t;
    }
    if (!owner) return undefined;

    let byType = this.injectedReceivers.get(fromFile);
    if (!byType) {
      byType = new Map();
      for (const t of ir.types) {
        if (t.kind !== 'class') continue;
        const receivers = ir.meta.language === 'java'
          ? javaInjectedFields(t)
          : tsInjectedProperties(t, this.sourceLines?.get(fromFile));
        if (receivers.size > 0) byType.set(t, receivers);
      }
      this.injectedReceivers.set(fromFile, byType);
    }
    const declared = byType.get(owner)?.get(receiver);
    if (!declared) return undefined;

    if (ir.meta.language === 'java' && !receiver.startsWith('this.')) {
      if (call.receiver_type && declaredTypeName(call.receiver_type) !== declaredTypeName(declared)) return undefined;
      const method = owner.methods.find(m => line >= m.start_line && line <= m.end_line);
      if (method && (this.getFileIndex(ir).defsByMethod.get(method) ?? [])
        .some(d => d.variable === receiver && (d.kind === 'local' || d.kind === 'param'))) return undefined;
    }
    return declared;
  }

  /**
   * The project type a declaration's type text names, seen from `fromFile`.
   * `null` when it names a type outside the project; `undefined` when it
   * cannot be decided.
   *
   * Java: an explicit import, then the file's own package, then wildcard
   * imports; an explicitly imported or qualified name that is not a project
   * type is a library type. Last, a simple name only one project type has.
   * TypeScript: the class an import binding names, in the file its module
   * specifier names; or a class the file declares itself. A name bound by an
   * import of a module outside the project is a library type.
   */
  private resolveDeclaredType(typeText: string, fromFile: string, ir: CircleIR): ProjectType | null | undefined {
    const name = declaredTypeName(typeText);
    if (!name) return undefined;
    const index = this.projectTypes();
    const unique = (types: ProjectType[] | undefined): ProjectType | null | undefined =>
      !types || types.length === 0 ? null : types.length === 1 ? types[0] : undefined;

    if (ir.meta.language === 'java') {
      const explicit = ir.imports.find(i => !i.is_wildcard && i.from_package && i.imported_name === name);
      const candidates: string[] = [];
      if (name.includes('.')) {
        candidates.push(name);
      } else if (explicit) {
        candidates.push(`${explicit.from_package}.${name}`);
      } else {
        const pkg = ir.meta.package || '';
        candidates.push(pkg ? `${pkg}.${name}` : name);
        for (const i of ir.imports) {
          if (i.is_wildcard && i.from_package) candidates.push(`${i.from_package}.${name}`);
        }
      }
      for (const fqn of candidates) {
        const found = index.byFqn.get(fqn);
        if (found && found.length > 0) return found.length === 1 ? found[0] : undefined;
      }
      // A package-qualified or imported name that is not a project type is a
      // library type. A nested type (`Outer.Inner`, `import a.Outer.Inner`) is
      // not indexed under that name, so it stays undecided.
      const qualifier = name.includes('.') ? name.slice(0, name.lastIndexOf('.')) : explicit?.from_package;
      if (qualifier) return /(?:^|\.)[A-Z][\w$]*$/.test(qualifier) ? undefined : null;
      return unique(index.byName.get(name));
    }

    const binding = ir.imports.find(i => (i.alias ?? i.imported_name) === name);
    if (binding) {
      const spec = binding.from_package ?? '';
      const sameName = index.byName.get(binding.imported_name) ?? [];
      const named = sameName.filter(t => moduleSpecifierNames(spec, fromFile, t.file));
      if (named.length > 0) return unique(named);
      if (sameName.length === 0) return null;
      // The specifier names no file that declares the class: a re-exporting
      // index module (relative) takes the one project class of that name; a
      // path alias the scan cannot map stays undecided.
      return spec.startsWith('.') && sameName.length === 1 ? sameName[0] : undefined;
    }
    const local = (index.byName.get(name) ?? []).filter(t => t.file === fromFile);
    return local.length === 1 ? local[0] : local.length === 0 ? null : undefined;
  }

  /**
   * `type` itself when it declares `methodName`, else the nearest project
   * superclass that does (at most four levels up).
   */
  private typeDeclaringMethod(type: ProjectType, methodName: string, depth: number): ProjectType | undefined {
    if (type.type.methods.some(m => m.name === methodName)) return type;
    if (!type.type.extends || depth >= 4) return undefined;
    const ir = this.fileIRs.get(type.file);
    if (!ir) return undefined;
    const parent = this.resolveDeclaredType(type.type.extends, type.file, ir);
    return parent ? this.typeDeclaringMethod(parent, methodName, depth + 1) : undefined;
  }

  /** Project classes and interfaces, indexed by FQN and by simple name. */
  private projectTypes(): { byFqn: Map<string, ProjectType[]>; byName: Map<string, ProjectType[]> } {
    if (this.projectTypeIndex) return this.projectTypeIndex;
    const byFqn = new Map<string, ProjectType[]>();
    const byName = new Map<string, ProjectType[]>();
    for (const [file, ir] of this.fileIRs) {
      for (const type of ir.types) {
        if (type.kind !== 'class' && type.kind !== 'interface') continue;
        const pkg = type.package || ir.meta.package || '';
        const entry: ProjectType = { file, type, fqn: pkg ? `${pkg}.${type.name}` : type.name };
        for (const [map, key] of [[byFqn, entry.fqn], [byName, type.name]] as const) {
          const list = map.get(key);
          if (list) list.push(entry); else map.set(key, [entry]);
        }
      }
    }
    this.projectTypeIndex = { byFqn, byName };
    return this.projectTypeIndex;
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

    const newExpr = /^new\s+([A-Za-z_][\w.$]*)\s*(?:<[^>]*>)?\s*\(/.exec(receiver.trim());
    if (newExpr) {
      return this.symbolTable.resolveTypeName(newExpr[1], fromFile);
    }

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
        this.methodTaintInfoByFile.set(`${filePath}#${methodFqn}`, taintInfo);
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
    for (const type of ir.types) {
      const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;
      for (const field of type.fields ?? []) {
        if (!field.annotations?.some(a => JAVA_INJECT_ANNOTATIONS.has(a))) continue;
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

    // Java: methods with `interprocedural_param` sources propagate that parameter
    // cross-file (e.g. `remember(String v)` storing into a static field).
    if (ir.meta.language === 'java') {
      for (const src of ir.taint.sources) {
        if (src.type !== 'interprocedural_param' || !src.variable) continue;
        if (src.line < method.start_line || src.line > method.end_line) continue;
        const idx = method.parameters.findIndex(p => p.name === src.variable);
        if (idx >= 0) taintedParams.add(idx);
      }
    }

    const isJs = ir.meta.language === 'javascript' || ir.meta.language === 'typescript';
    for (const sink of ir.taint.sinks) {
      if (sink.line < method.start_line || sink.line > method.end_line) continue;

      // Find the call(s) at the sink line — match by line number.
      // JS/TS (#1120): only the sink call itself, at its dangerous positions —
      // in `fs.writeFileSync(file, JSON.stringify(data))` the parameter `data`
      // is written, not used as a path.
      const callsAtSink = ir.calls.filter(c => c.location.line === sink.line
        && (!isJs || !sink.method || this.callMatchesSink(sink, c)));
      for (const call of callsAtSink) {
        for (const arg of call.arguments) {
          if (isJs && sink.argPositions && sink.argPositions.length > 0
              && !sink.argPositions.includes(arg.position)) continue;
          // Argument that's a direct variable reference.
          const candidates: string[] = [];
          if (arg.variable) candidates.push(arg.variable);
          if (arg.expression) {
            // Heuristic: scan the expression for whole-word param-name tokens.
            // Catches concatenations / nested expressions like `prefix + url`.
            for (const [name] of paramNameToIndex) {
              const re = new RegExp(`\\b${escapeRegExp(name)}\\b`);
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
  /**
   * Optional wall-clock deadline for the three project-wide walks
   * (cognium-dev#366). Returns true once the caller's budget is spent.
   *
   * `CrossFilePass` already had a budget, but it was only evaluated BETWEEN
   * phases, so a single phase ran unbounded and the documented "bounded"
   * contract did not hold — which is what makes a large multi-module repo look
   * like a sync hang to a consumer whose own `Promise.race` timeout cannot
   * interrupt synchronous work. These walks are the O(F·T·M) ones called out
   * at the top of this file, so the check goes in their OUTER per-file loops:
   * frequent enough to bound the work, cheap enough not to matter (one
   * `Date.now()` per file).
   *
   * When the deadline fires the walk returns what it has found so far, which
   * is the pre-existing `budgetExceeded` semantic — partial results, kept.
   */
  findCrossFileTaintFlows(deadline?: () => boolean): CrossFileTaintFlow[] {
    const flows: CrossFileTaintFlow[] = [];
    // Deduplicate: same source + target sink should only emit one flow
    const seen = new Set<string>();

    for (const [filePath, ir] of this.fileIRs) {
      if (deadline?.()) break;
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
        const sourceVar = source.variable ?? this.getLocalDefVarAt(ir, source.line)
          ?? this.annotatedParamName(ir, source);

        // Expand the source variable to the set of locals DFG-derived from
        // it (cognium-dev #146). The variable-connectivity gate below then
        // accepts a call arg that references the source var OR any variable
        // rebound from it. Without this, a source whose value is passed
        // through an intermediate binding before the cross-file call is
        // dropped — e.g. Rust actix `handle(q: web::Query<…>)` where the
        // source variable is the param `q` but the call passes
        // `cmd` from `let cmd = q.get("cmd").unwrap()`. Java/TS already
        // pass because their property-source detection records the LHS of
        // the assignment as `source.variable`; Rust's param-based source
        // records the extractor param, so the derivation must be followed
        // via `dfg.chains`. Computed once per source (independent of the
        // call being tested).
        const reachable = sourceVar
          ? this.collectTaintReachable(ir, sourceVar, source.line, filePath)
          : undefined;

        // Find calls at or after the source line
        for (const call of ir.calls) {
          if (call.location.line < source.line) continue;
          // A source with no variable (`parse(fs.readFileSync(p))`) can reach
          // only the call it is nested in, on its own line — not every later
          // cross-file call in the file (dogfood 2026-10-31: one principles.md
          // read in security-scan/scanner.ts reached readFileSync in 12 files).
          if (!reachable && call.location.line !== source.line) continue;

          const resolved = this.resolveCall(call, filePath);
          if (!resolved || resolved.targetFile === filePath) continue;

          let carriedPositions: number[] | undefined;
          // Variable-connectivity gate: when we know the source variable, the
          // call's arguments must reference it — or a variable DFG-derived
          // from it (#146) — directly or by expression.
          if (reachable) {
            carriedPositions = this.carriedArgPositions(ir, call, reachable);
            if (!carriedPositions) continue;
          }

          // The method the value ends in: the callee itself, or, for C# and for a
          // call through an injected receiver, the methods at the end of a pure
          // forwarder chain (cognium-dev#637; a controller → service → repository).
          const startIR = this.fileIRs.get(resolved.targetFile);
          const terminals: Array<{ file: string; method: string; positions: number[] }> =
            startIR?.meta.language === 'csharp' || resolved.injected
              ? this.forwarderChainTerminals(resolved.targetFile, resolved.targetMethod,
                  carriedPositions ?? call.arguments.map((_, i) => i), 0, new Set())
              : [{ file: resolved.targetFile, method: resolved.targetMethod,
                   positions: carriedPositions ?? call.arguments.map((_, i) => i) }];

          for (const term of terminals) {
          // Only proceed if the target file has any YAML-matched sinks at all.
          // Skipping sink-free files prevents the cartesian explosion of flows into
          // utility modules (AST helpers, string utilities, etc.) that have no
          // dangerous operations.
          const targetIR = this.fileIRs.get(term.file);
          if (!targetIR || targetIR.taint.sinks.length === 0) continue;

          // Find the target method in the target file so we can locate sinks within it.
          // `resolved.targetMethod` is a FQN like "ClassName.methodName"; we match on
          // the suffix after the last dot.
          const shortName = term.method.split('.').pop() ?? term.method;
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
            // JS/TS: the carried parameter must reach the sink's own arguments, not just
            // any line of the callee (dogfood 2026-11-01: a route value bound as a `?`
            // parameter was credited to `db.prepare(<constant SQL>)` in the same method).
            // Every parameter is tried, not only `term.positions`: the caller-side carried
            // positions can miss the real carrier (juice-shop `downloadToFile(imageUrl, dest)`
            // reported [1] only), and this check must not lose a flow on that.
            if ((targetIR.meta.language === 'javascript' || targetIR.meta.language === 'typescript')
                && !this.jsParamReachesSinkArgs(targetIR, targetMethod, targetMethod.parameters.map((_, i) => i), sink, term.file)) continue;
            // Java, through an injected receiver: the same check on the carried
            // parameters, so a service method whose sink is fed by something
            // else (a constant, a field) is not credited with the caller's value.
            if (resolved.injected && targetIR.meta.language === 'java'
                && !this.jsParamReachesSinkArgs(targetIR, targetMethod, term.positions, sink, term.file)) continue;
            const key = `${filePath}:${source.line}→${term.file}:${sink.line}`;
            if (seen.has(key)) continue;
            seen.add(key);

            flows.push({
              sourceFile: filePath,
              sourceLine: source.line,
              sourceType: source.type,
              targetFile: term.file,
              targetLine: sink.line,           // actual sink line in target file
              targetMethod: term.method,
              flowType: 'call_arg',
              taintedArgPositions: term.positions,
              callLine: call.location.line,
              ...(call.in_method ? { callMethod: call.in_method } : {}),
            });
          }
          }
        }
      }
    }

    return flows;
  }

  /**
   * The argument positions of `call` that carry a value of `reachable` (the
   * source variable and the locals DFG-derived from it), or undefined when
   * none does or the DFG proves the carried variable was reassigned away from
   * the source before the call.
   */
  private carriedArgPositions(
    ir: CircleIR,
    call: CallInfo,
    reachable: { names: Set<string>; defIds: Set<number> },
  ): number[] | undefined {
    // Name-based acceptance (#146): find which reachable variable
    // name the call carries (bare arg or inside an expression like
    // `&a` / `"p" + a`), so the #266 clobber check can key on it.
    let matchedName: string | undefined;
    for (const arg of call.arguments) {
      if (arg.variable && reachable.names.has(arg.variable)) {
        matchedName = arg.variable;
        break;
      }
      if (arg.expression) {
        for (const v of reachable.names) {
          if (new RegExp(`\\b${escapeRegExp(v)}\\b`).test(arg.expression)) {
            matchedName = v;
            break;
          }
        }
        if (matchedName) break;
      }
    }
    if (!matchedName) return undefined;
    // The arguments that carry the source (cognium-dev#637): the
    // callee reach check follows only those parameters.
    const names = [...reachable.names];
    const carried = call.arguments.flatMap((arg, i) =>
      (arg.variable && reachable.names.has(arg.variable)) ||
      names.some(v => arg.expression && new RegExp(`\\b${escapeRegExp(v)}\\b`).test(arg.expression))
        ? [i] : []);

    // Redefinition override (cognium-dev #266): the name-based gate
    // cannot distinguish a source-named variable from a later
    // same-named redefinition to an untainted value
    // (`a = req.getParameter(); a = "safe"; helper.run(a)`). When
    // the DFG *positively* proves the matched variable's reaching
    // def at the call line is such a redefinition — a known def_id
    // NOT in the source's reachable def set — reject the flow.
    // Fires only when the DFG can prove it; empty/imprecise DFG
    // (e.g. Python) → no rejection, #146 name decision stands.
    if (this.taintClobbered(ir, call.location.line, matchedName, reachable.defIds)) return undefined;
    return carried;
  }

  /**
   * JS/TS: does a value in one of the parameters at `positions` of `method` reach the
   * arguments of `sink`? Names derived from those parameters by def-use chains are matched
   * against the sink call's dangerous arguments (`argPositions`, else all). Conservative:
   * true when the sink call or the parameter defs cannot be found, so it only drops a
   * flow whose sink call is present and mentions none of those names.
   */
  private jsParamReachesSinkArgs(
    ir: CircleIR,
    method: MethodInfo,
    positions: number[],
    sink: TaintSink,
    file: string,
  ): boolean {
    const params = positions.map(i => method.parameters[i]?.name).filter((n): n is string => !!n);
    if (params.length === 0) return true;
    const calls = (this.getFileIndex(ir).callsByLine.get(sink.line) ?? [])
      .filter(c => c.method_name === sink.method
        && (sink.callColumn === undefined || c.location.column === undefined || c.location.column === sink.callColumn));
    if (calls.length === 0) return true;
    const names = this.jsNamesFromParams(ir, method, params, file);
    const res = [...names].map(n => new RegExp(`(?<![\\w$.])${escapeRegExp(n)}(?![\\w$])`));
    return calls.some(c => c.arguments
      .filter(a => !sink.argPositions || sink.argPositions.length === 0 || sink.argPositions.includes(a.position))
      .some(a => (a.variable && names.has(a.variable)) || res.some(re => re.test(a.expression ?? ''))));
  }

  /**
   * JS/TS: the parameter names `params` of `method` and the locals derived from
   * them by def-use chains inside the method. The walk does not pass through a
   * def whose value is literal-only (`const where = options.id ? 'WHERE id = ?'
   * : ''`): the parameter decides which literal, but the value carries none of it.
   */
  private jsNamesFromParams(
    ir: CircleIR,
    method: { start_line: number; end_line: number },
    params: string[],
    file: string,
  ): Set<string> {
    const names = new Set<string>(params);
    const seeds = ir.dfg.defs
      .filter(d => params.includes(d.variable) && d.line >= method.start_line && d.line <= method.end_line)
      .map(d => d.id);
    if (seeds.length === 0) return names;
    const lines = this.sourceLines?.get(file);
    const defById = new Map(ir.dfg.defs.map(d => [d.id, d]));
    const visited = new Set<number>(seeds);
    const frontier = [...seeds];
    while (frontier.length > 0) {
      const cur = frontier.shift()!;
      for (const ch of ir.dfg.chains ?? []) {
        if (ch.from_def !== cur || visited.has(ch.to_def)) continue;
        visited.add(ch.to_def);
        const d = defById.get(ch.to_def);
        if (!d || (lines && literalOnlyAssignment(lines[d.line - 1] ?? '', d.variable))) continue;
        if (d.variable) names.add(d.variable);
        frontier.push(ch.to_def);
      }
    }
    return names;
  }

  /** Sink call on this line (method + optional column), same filter as `jsParamReachesSinkArgs`. */
  private callMatchesSink(
    sink: TaintSink,
    call: { method_name?: string; location?: { column?: number } },
  ): boolean {
    return call.method_name === sink.method
      && (sink.callColumn === undefined
        || call.location?.column === undefined
        || call.location.column === sink.callColumn);
  }

  /** Arguments the sink marks dangerous (`argPositions`, else all). */
  private dangerousSinkArguments(
    sink: TaintSink,
    call: { arguments?: Array<{ position: number }> },
  ): Array<{ position: number; variable?: string; expression?: string }> {
    const args = call.arguments ?? [];
    if (!sink.argPositions || sink.argPositions.length === 0) return args;
    return args.filter(a => sink.argPositions!.includes(a.position));
  }

  /**
   * The methods a value ends in after a chain of pure forwarders (C#,
   * cognium-dev#637; Java and TypeScript from a call through an injected
   * receiver). A callee that holds a sink is its own terminal. One that holds no
   * sink only passes the tainted parameter, as a bare argument, to calls that each
   * resolve exactly (or through an injected receiver) to a method in another
   * file; those are followed (depth <= 4, a visited set stops cycles). Anything
   * else — a transformed argument, an unresolved call, a forwarder with no
   * onward call — contributes no terminal.
   */
  private forwarderChainTerminals(
    file: string,
    methodFqn: string,
    positions: number[],
    depth: number,
    visited: Set<string>,
  ): Array<{ file: string; method: string; positions: number[] }> {
    const ir = this.fileIRs.get(file);
    if (!ir) return [];
    const shortName = methodFqn.split('.').pop() ?? methodFqn;
    const method = ir.types.flatMap(t => t.methods).find(m => m.name === shortName);
    if (!method) return [];
    const idx = this.getFileIndex(ir);
    const here = [{ file, method: methodFqn, positions }];
    if ((idx.sinksByMethod.get(method) ?? []).length > 0) return here;
    if (depth >= 4) return [];
    const key = `${file}#${methodFqn}`;
    if (visited.has(key)) return [];
    visited.add(key);
    const names = positions.map(i => method.parameters[i]?.name).filter((n): n is string => !!n);
    if (names.length === 0) return [];
    const out: Array<{ file: string; method: string; positions: number[] }> = [];
    for (const call of idx.callsByMethod.get(method) ?? []) {
      const carried = call.arguments.flatMap((a, i) =>
        names.some(n => new RegExp(`(?<![\\w.])${escapeRegExp(n)}(?!\\w)`).test(a.expression ?? '')) ? [i] : []);
      if (carried.length === 0) continue;
      if (!carried.every(i => names.includes((call.arguments[i].expression ?? '').trim()))) continue;
      const r = this.resolveCall(call, file);
      if (!r || (r.resolution !== 'exact' && !r.injected) || r.targetFile === file) continue;
      out.push(...this.forwarderChainTerminals(r.targetFile, r.targetMethod, carried, depth + 1, visited));
    }
    visited.delete(key);
    return out;
  }

  /**
   * JS/TS: taint a module function hands back to its caller through a
   * callback.
   *
   *   // app.js
   *   withHost(req.query.host, (h) => exec(`ping ${h}`));
   *   // host.js
   *   exports.withHost = (value, cb) => { cb(value.trim()); };
   *
   * The caller passes a source to a function in another file, and that
   * function calls one of its own parameters with a value derived from the
   * tainted parameter. The function the caller passed in that position (an
   * inline function, or a function of the caller's file named there) receives
   * the value in the matching parameter; a sink inside it whose dangerous
   * arguments read that parameter, directly or through a derived local, is
   * reported. A callee that calls back with a constant or an unrelated value
   * carries nothing.
   */
  findJsCallbackTaintPaths(deadline?: () => boolean): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();
    const wordRe = (n: string): RegExp => new RegExp(`(?<![\\w$.])${escapeRegExp(n)}(?![\\w$])`);
    for (const [filePath, ir] of this.fileIRs) {
      if (deadline?.()) break;
      if (ir.meta.language !== 'javascript' && ir.meta.language !== 'typescript') continue;
      if (ir.taint.sinks.length === 0) continue;
      const lines = this.sourceLines?.get(filePath);
      if (!lines) continue;
      const idx = this.getFileIndex(ir);
      for (const source of ir.taint.sources) {
        if (source.type === 'interprocedural_param') continue;
        const sourceVar = source.variable ?? this.getLocalDefVarAt(ir, source.line);
        if (!sourceVar) continue;
        const reachable = this.collectTaintReachable(ir, sourceVar, source.line, filePath);
        for (const call of ir.calls) {
          if (call.location.line < source.line || call.arguments.length < 2) continue;
          const carried = this.carriedArgPositions(ir, call, reachable);
          if (!carried) continue;
          const resolved = this.resolveCall(call, filePath);
          if (!resolved || resolved.targetFile === filePath) continue;
          const targetIR = this.fileIRs.get(resolved.targetFile);
          if (!targetIR || (targetIR.meta.language !== 'javascript' && targetIR.meta.language !== 'typescript')) continue;
          const shortName = resolved.targetMethod.split('.').pop() ?? resolved.targetMethod;
          const ownerName = resolved.targetClass.split('.').pop();
          const callee = targetIR.types.find(t => t.name === ownerName)?.methods.find(m => m.name === shortName)
            ?? targetIR.types.flatMap(t => t.methods).find(m => m.name === shortName);
          if (!callee) continue;
          const tainted = carried.map(i => callee.parameters[i]?.name).filter((n): n is string => !!n);
          if (tainted.length === 0) continue;
          const derived = this.jsNamesFromParams(targetIR, callee, tainted, resolved.targetFile);
          const derivedRes = [...derived].map(wordRe);
          const calleeCalls = this.getFileIndex(targetIR).callsByMethod.get(callee) ?? [];
          const calleeLines = this.sourceLines?.get(resolved.targetFile);
          const tables = calleeLines
            ? constLookupTables(calleeLines.join('\n'), targetIR.meta.language)
            : new Set<string>();

          for (let j = 0; j < callee.parameters.length && j < call.arguments.length; j++) {
            const cbName = callee.parameters[j]?.name;
            if (!cbName || carried.includes(j) || !/^[A-Za-z_$][\w$]*$/.test(cbName)) continue;
            const fn = this.jsCallbackFunction(ir, lines, call, j);
            if (!fn) continue;
            for (const cbCall of calleeCalls) {
              if (cbCall.receiver || cbCall.method_name !== cbName) continue;
              for (const arg of cbCall.arguments) {
                const carriesValue = (!!arg.variable && derived.has(arg.variable))
                  || derivedRes.some(re => re.test(arg.expression ?? ''));
                if (!carriesValue) continue;
                // `cb(cond ? 'a' : 'b')`, `cb(String(…))` of one, or `cb(TABLE[key])`
                // on a constant table: the parameter picks the value, it is not in it.
                const expr = (arg.expression ?? '').trim();
                const inner = /^String\s*\(([\s\S]*)\)$/.exec(expr)?.[1]?.trim() ?? expr;
                if (LITERAL_RHS.test(inner) || isConstTableLookup(inner, tables)) continue;
                const param = fn.params[arg.position];
                if (!param) continue;
                const names = [...this.jsNamesFromParams(ir, fn, [param], filePath)].map(wordRe);
                for (const sink of ir.taint.sinks) {
                  if (sink.line < fn.start_line || sink.line > fn.end_line) continue;
                  const sinkCalls = (idx.callsByLine.get(sink.line) ?? []).filter(c => this.callMatchesSink(sink, c));
                  const reads = sinkCalls.some(c => this.dangerousSinkArguments(sink, c)
                    .some(a => names.some(re => re.test(a.expression ?? ''))));
                  if (!reads) continue;
                  const key = `${filePath}:${source.line}→${filePath}:${sink.line}:${sink.type}`;
                  if (seen.has(key)) continue;
                  seen.add(key);
                  const hops: InterproceduralTaintPath['hops'] = [
                    { file: filePath, line: source.line, method: '', kind: 'source' },
                    { file: filePath, line: call.location.line, method: call.in_method ?? '', kind: 'sink_call' },
                    { file: resolved.targetFile, line: cbCall.location.line, method: resolved.targetMethod, kind: 'callback' },
                    { file: filePath, line: sink.line, method: fn.name, kind: 'sink' },
                  ];
                  paths.push({
                    source: { file: filePath, line: source.line, type: source.type },
                    sink: { file: filePath, line: sink.line, type: sink.type, cwe: sink.cwe },
                    hops,
                    confidence: Math.max(0.3, Math.pow(0.85, hops.length - 1)),
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
   * The function a JS/TS call passes as its argument `j`: an inline arrow
   * function or function expression (its line range found in `lines` from
   * the call's line), or the name of a function declared in the caller's
   * file. Parameter names keep their positions; a destructuring pattern is ''.
   */
  private jsCallbackFunction(
    ir: CircleIR,
    lines: readonly string[],
    call: CallInfo,
    j: number,
  ): { name: string; start_line: number; end_line: number; params: string[] } | undefined {
    const expr = (call.arguments[j]?.expression ?? '').trim();
    if (/^[A-Za-z_$][\w$]*$/.test(expr)) {
      const m = ir.types.find(t => t.name === '<module>')?.methods.find(x => x.name === expr);
      return m ? { name: m.name, start_line: m.start_line, end_line: m.end_line, params: m.parameters.map(p => p.name) } : undefined;
    }
    const head = /^(?:async\s+)?(?:function\b[^(]*\(([^)]*)\)|\(([^)]*)\)\s*(?::[^=]*)?=>|([A-Za-z_$][\w$]*)\s*=>)/.exec(expr);
    if (!head) return undefined;
    const list = head[1] ?? head[2] ?? head[3] ?? '';
    const params = list.split(',').map(raw => {
      let p = raw.trim();
      if (p.startsWith('...')) p = p.slice(3);
      const cut = p.search(/[=:?]/);
      if (cut >= 0) p = p.slice(0, cut);
      p = p.trim();
      return /^[A-Za-z_$][\w$]*$/.test(p) ? p : '';
    });
    const first = expr.split('\n')[0].trim();
    const from = call.location.line - 1;
    for (let i = from; i < Math.min(lines.length, from + 50); i++) {
      if (!(lines[i] ?? '').includes(first)) continue;
      return { name: '', start_line: i + 1, end_line: i + expr.split('\n').length, params };
    }
    return undefined;
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
  findInterproceduralTaintPaths(deadline?: () => boolean): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();

    type Origin = {
      file: string;
      line: number;
      type: string;
      hopChain: InterproceduralTaintPath['hops'];
      /**
       * Caller-side def ids that carry this taint (source def + DFG-derived
       * defs). Used by the #266 reassignment-clobber check. Undefined when
       * the caller DFG can't provide it (e.g. Python's empty DFG) — the
       * check then no-ops and taint stands.
       */
      defIds?: Set<number>;
    };

    // Cache: method FQN → { ir, method }
    const methodIndex = this.buildMethodIndex();

    this.primeJavaStaticFieldWriters(methodIndex, deadline);

    for (const [callerFile, callerIR] of this.fileIRs) {
      if (deadline?.()) break;   // cognium-dev#366 — bound the O(F·T·M) walk
      const callerIdx = this.getFileIndex(callerIR);
      for (const type of callerIR.types) {
        for (const method of type.methods) {
          // 1. Seed tainted vars with real sources inside this method.
          const tainted = new Map<string, Origin>();
          for (const src of callerIR.taint.sources) {
            if (src.line < method.start_line || src.line > method.end_line) continue;
            if (!src.variable) continue;
            if (src.type === 'interprocedural_param') continue;
            tainted.set(src.variable, {
              file: callerFile,
              line: src.line,
              type: src.type,
              hopChain: [{ file: callerFile, line: src.line, method: method.name, kind: 'source' }],
              defIds: this.collectTaintReachable(callerIR, src.variable, src.line, callerFile).defIds,
            });
          }

          // 2. Walk calls in M in line order (pre-indexed; sorted ASC).
          const callsInMethod = callerIdx.callsByMethod.get(method) ?? [];

          for (const call of callsInMethod) {
            const resolved = this.resolveCall(call, callerFile);
            if (!resolved) continue;

            const callee = this.calleeTaintInfo(resolved);
            if (!callee) continue;

            // 2a. If callee returns a source and is NOT a sanitizer, mark every
            //     local def on this caller line as tainted (the assignment LHS).
            const calleeNode0 = this.calleeNodeOf(methodIndex, resolved);
            if (callee.returnsSource && !callee.sanitizes && callee.sourceType &&
                !(calleeNode0 && this.sourcesOnlySteerBranches(callee.file, calleeNode0.ir, calleeNode0.method))) {
              const calleeNode = calleeNode0;
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
                  defIds: this.forwardReachableDefs(callerIR, [def.id], callerFile),
                });
              }
            }

            // 2b. For each tainted arg passed to a callee param that propagates
            //     to a sink, emit a multi-hop path.
            if (callee.taintedParams.length === 0 || callee.sanitizes) continue;

            for (let argIdx = 0; argIdx < call.arguments.length; argIdx++) {
              if (!callee.taintedParams.includes(argIdx)) continue;

              const arg = call.arguments[argIdx];
              const matched = this.matchTaintedArg(arg, tainted,
                callerIR.meta.language === 'javascript' || callerIR.meta.language === 'typescript');
              if (!matched) continue;

              // #266: skip when the matched var's value was reassigned away
              // from the source before this call (DFG-proven clobber). Keyed
              // on the matched name so it covers expression args too.
              if (this.taintClobbered(callerIR, call.location.line, matched.var, matched.origin.defIds)) {
                continue;
              }

              const calleeNode = this.calleeNodeOf(methodIndex, resolved);
              if (!calleeNode) continue;

              this.noteJavaStaticFieldWriteFromParam(
                resolved.targetMethod,
                calleeNode,
                matched,
                argIdx,
              );

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
                  calleeArgPositions: [argIdx],
                });
              }
            }
          }

          // 2b.5 — cognium-dev#590: wrapper-return marks the assignment LHS tainted,
          //     but caller-body sinks often consume a derived local (`sql = "…" + x`).
          //     Extend the tainted set with DFG-reachable names before sink matching.
          if (tainted.size > 0) {
            this.extendInterproceduralTaintedVars(callerIR, callerFile, tainted);
          }

          // 2c. Caller-body sinks: after marking locals tainted via wrapper-return,
          //     check whether any sink in the CALLER'S OWN method body consumes a
          //     tainted variable. This closes the canonical Jenkins shape where the
          //     final sink (e.g. `Paths.get(p)`, `Runtime.exec(cmd)`) lives in the
          //     caller's file rather than in a cross-file callee.
          if (tainted.size > 0) {
            const sinksInCaller = callerIdx.sinksByMethod.get(method) ?? [];
            const isJs = callerIR.meta.language === 'javascript' || callerIR.meta.language === 'typescript';
            for (const sink of sinksInCaller) {
              const callsAtSink = (callerIdx.callsByLine.get(sink.line) ?? [])
                .filter(c => this.callMatchesSink(sink, c));
              for (const sinkCall of callsAtSink) {
                for (const arg of this.dangerousSinkArguments(sink, sinkCall)) {
                  const matched = this.matchTaintedArg(arg, tainted, isJs);
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
  findFieldBindingTaintPaths(deadline?: () => boolean): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();
    if (this.fieldTaintInfo.size === 0) return paths;

    const fieldExprRe = /^(\w+)\.(\w+)$/;
    const methodIndex = this.buildMethodIndex();

    for (const [callerFile, callerIR] of this.fileIRs) {
      if (deadline?.()) break;   // cognium-dev#366 — bound the O(F·T·M) walk
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
            const callsAtSink = (callerIdx.callsByLine.get(sink.line) ?? [])
              .filter(c => this.callMatchesSink(sink, c));
            for (const sinkCall of callsAtSink) {
              for (const arg of this.dangerousSinkArguments(sink, sinkCall)) {
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
            const callee = this.calleeTaintInfo(resolved);
            if (!callee || callee.sanitizes || callee.taintedParams.length === 0) continue;

            for (let argIdx = 0; argIdx < call.arguments.length; argIdx++) {
              if (!callee.taintedParams.includes(argIdx)) continue;
              const matched = this.matchTaintedArg(call.arguments[argIdx], tainted);
              if (!matched) continue;
              const calleeNode = this.calleeNodeOf(methodIndex, resolved);
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
   * Cross-file C# flows through a static field (`A.stored = req…` in file A,
   * `data = A.stored` → sink in file B). cognium-dev#638 `_68`.
   */
  findCSharpStaticFieldTaintPaths(deadline?: () => boolean): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();
    if (this.csharpStaticFieldWriters.size === 0) return paths;

    for (const [readerFile, callerIR] of this.fileIRs) {
      if (deadline?.()) break;
      if (callerIR.meta.language !== 'csharp') continue;
      const callerIdx = this.getFileIndex(callerIR);

      for (const type of callerIR.types) {
        for (const method of type.methods) {
          type Origin = {
            file: string;
            line: number;
            type: string;
            hopChain: InterproceduralTaintPath['hops'];
          };
          const tainted = new Map<string, Origin>();

          const defsInMethod = (callerIdx.defsByMethod.get(method) ?? []).filter(
            d => d.kind === 'local' && !!d.variable,
          );

          for (const def of defsInMethod) {
            const usesAtLine = callerIdx.usesByLine.get(def.line) ?? [];
            const fieldKey = this.resolveCSharpStaticFieldReadKey(type, usesAtLine);
            if (!fieldKey) continue;
            const writer = this.csharpStaticFieldWriters.get(fieldKey);
            if (!writer) continue;

            const hopChain: InterproceduralTaintPath['hops'] = [
              { file: writer.file, line: writer.line, method: writer.methodName, kind: 'source' },
              { file: writer.file, line: writer.line, method: writer.methodName, kind: 'field_write' },
              { file: readerFile, line: def.line, method: method.name, kind: 'field_read' },
            ];
            tainted.set(def.variable!, {
              file: writer.file,
              line: writer.line,
              type: writer.type,
              hopChain,
            });
          }

          if (tainted.size === 0) continue;

          const sinksInCaller = callerIdx.sinksByMethod.get(method) ?? [];
          for (const sink of sinksInCaller) {
            const callsAtSink = callerIdx.callsByLine.get(sink.line) ?? [];
            for (const sinkCall of callsAtSink) {
              for (const arg of sinkCall.arguments ?? []) {
                const matched = this.matchTaintedArg(arg, tainted);
                if (!matched) continue;
                const key = `csf:${matched.origin.file}:${matched.origin.line}→${readerFile}:${sink.line}`;
                if (seen.has(key)) continue;
                seen.add(key);
                const hops: InterproceduralTaintPath['hops'] = [
                  ...matched.origin.hopChain,
                  { file: readerFile, line: sink.line, method: method.name, kind: 'sink' },
                ];
                const decay = Math.max(0.3, Math.pow(0.85, Math.max(hops.length - 1, 0)));
                paths.push({
                  source: {
                    file: matched.origin.file,
                    line: matched.origin.line,
                    type: matched.origin.type,
                  },
                  sink: {
                    file: readerFile,
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

    return paths;
  }

  private primeJavaStaticFieldWriters(
    methodIndex: Map<string, { ir: CircleIR; method: MethodInfo }>,
    deadline?: () => boolean,
  ): void {
    type Origin = {
      file: string;
      line: number;
      type: string;
      hopChain: InterproceduralTaintPath['hops'];
      defIds?: Set<number>;
    };

    for (const [callerFile, callerIR] of this.fileIRs) {
      if (deadline?.()) break;
      const callerIdx = this.getFileIndex(callerIR);
      for (const type of callerIR.types) {
        for (const method of type.methods) {
          const tainted = new Map<string, Origin>();
          for (const src of callerIR.taint.sources) {
            if (src.line < method.start_line || src.line > method.end_line) continue;
            if (!src.variable) continue;
            tainted.set(src.variable, {
              file: callerFile,
              line: src.line,
              type: src.type,
              hopChain: [{ file: callerFile, line: src.line, method: method.name, kind: 'source' }],
              defIds: this.collectTaintReachable(callerIR, src.variable, src.line, callerFile).defIds,
            });
          }
          for (const call of callerIdx.callsByMethod.get(method) ?? []) {
            const resolved = this.resolveCall(call, callerFile);
            if (!resolved) continue;
            const callee = this.calleeTaintInfo(resolved);
            if (!callee || callee.taintedParams.length === 0 || callee.sanitizes) continue;
            const calleeNode = this.calleeNodeOf(methodIndex, resolved);
            if (!calleeNode) continue;

            for (let argIdx = 0; argIdx < call.arguments.length; argIdx++) {
              if (!callee.taintedParams.includes(argIdx)) continue;
              const matched = this.matchTaintedArg(call.arguments[argIdx], tainted);
              if (!matched) continue;
              if (this.taintClobbered(callerIR, call.location.line, matched.var, matched.origin.defIds)) {
                continue;
              }
              this.noteJavaStaticFieldWriteFromParam(
                resolved.targetMethod,
                calleeNode,
                matched,
                argIdx,
              );
            }
          }
        }
      }
    }
  }

  private analyzeJavaStaticFieldPairs(ir: CircleIR, filePath: string): void {
    if (ir.meta.language !== 'java') return;
    const lines = this.sourceLines?.get(filePath);
    if (!lines) return;
    const pkg = ir.meta.package || '';

    for (const type of ir.types) {
      const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;
      const pairs = new Map<string, { setter?: string; getter?: string }>();

      for (const m of type.methods) {
        if (!m.modifiers.includes('static')) continue;
        const body = lines.slice(m.start_line - 1, m.end_line).join('\n');
        const open = body.indexOf('{');
        const close = body.lastIndexOf('}');
        if (open < 0 || close <= open) continue;
        const inner = body.slice(open + 1, close).replace(/\/\/[^\n]*/g, '').trim();

        if (m.parameters.length === 1) {
          const stm = parseJavaStaticFieldAssignment(inner);
          if (stm && stm.param === m.parameters[0].name) {
            const entry = pairs.get(stm.field) ?? {};
            entry.setter = m.name;
            pairs.set(stm.field, entry);
            continue;
          }
        }
        if (m.parameters.length === 0) {
          const field = parseJavaStaticGetterReturn(inner);
          if (field) {
            const entry = pairs.get(field) ?? {};
            entry.getter = m.name;
            pairs.set(field, entry);
          }
        }
      }

      for (const [fieldName, { getter }] of pairs) {
        if (!getter) continue;
        const getterFqn = `${typeFqn}.${getter}`;
        this.javaStaticFieldGetters[`${typeFqn}.${fieldName}`] = getterFqn;
      }

      for (const m of type.methods) {
        if (!m.modifiers.includes('static') || m.parameters.length !== 0) continue;
        const body = lines.slice(m.start_line - 1, m.end_line).join('\n');
        const open = body.indexOf('{');
        const close = body.lastIndexOf('}');
        if (open < 0 || close <= open) continue;
        const inner = body.slice(open + 1, close).replace(/\/\/[^\n]*/g, '').trim();
        const dm = parseJavaStaticDelegateReturn(inner);
        if (!dm) continue;
        const delegateTypeFqn = pkg ? `${pkg}.${dm.type}` : dm.type;
        const delegateFqn = `${delegateTypeFqn}.${dm.method}`;
        this.javaStaticGetterDelegates[`${typeFqn}.${m.name}`] = delegateFqn;
      }
    }
  }

  private noteJavaStaticFieldWriteFromParam(
    targetMethod: string,
    calleeNode: { ir: CircleIR; method: MethodInfo },
    matched: { var: string; origin: { file: string; line: number; type: string } },
    argIdx: number,
  ): void {
    if (calleeNode.ir.meta.language !== 'java') return;
    const m = calleeNode.method;
    if (!m.modifiers.includes('static') || m.parameters.length !== 1) return;
    if (argIdx !== 0) return;

    const filePath = this.filePathForIr(calleeNode.ir);
    const lines = filePath ? (this.sourceLines?.get(filePath) ?? []) : [];
    const body = lines.slice(m.start_line - 1, m.end_line).join('\n');
    const open = body.indexOf('{');
    const close = body.lastIndexOf('}');
    if (open < 0 || close <= open) return;
    const inner = body.slice(open + 1, close).replace(/\/\/[^\n]*/g, '').trim();
    const stm = parseJavaStaticFieldAssignment(inner);
    if (!stm || stm.param !== m.parameters[0].name) return;

    const typeFqn = targetMethod.replace(/\.[^.]+$/, '');
    const fieldKey = `${typeFqn}.${stm.field}`;
    const getterFqn = this.javaStaticFieldGetters[fieldKey];
    if (!getterFqn) return;

    this.javaStaticFieldWriters[fieldKey] = {
      file: matched.origin.file,
      line: matched.origin.line,
      type: matched.origin.type,
      methodName: m.name,
    };

    const promoteReturnsSource = (fqn: string) => {
      const info = this.methodTaintInfo.get(fqn);
      if (info) {
        info.returnsSource = true;
        info.sourceType = matched.origin.type;
      }
    };
    promoteReturnsSource(getterFqn);
    for (const wrapper of Object.keys(this.javaStaticGetterDelegates)) {
      const target = this.javaStaticGetterDelegates[wrapper];
      if (target === getterFqn) promoteReturnsSource(wrapper);
    }
  }

  findJavaStaticFieldTaintPaths(deadline?: () => boolean): InterproceduralTaintPath[] {
    const paths: InterproceduralTaintPath[] = [];
    const seen = new Set<string>();
    if (Object.keys(this.javaStaticFieldWriters).length === 0) return paths;

    for (const [readerFile, callerIR] of this.fileIRs) {
      if (deadline?.()) break;
      if (callerIR.meta.language !== 'java') continue;
      const callerIdx = this.getFileIndex(callerIR);

      for (const type of callerIR.types) {
        for (const method of type.methods) {
          type Origin = {
            file: string;
            line: number;
            type: string;
            hopChain: InterproceduralTaintPath['hops'];
          };
          const tainted = new Map<string, Origin>();

          const defsInMethod = (callerIdx.defsByMethod.get(method) ?? []).filter(
            d => d.kind === 'local' && !!d.variable,
          );

          for (const def of defsInMethod) {
            const usesAtLine = callerIdx.usesByLine.get(def.line) ?? [];
            const fieldKey = this.resolveJavaStaticFieldReadKey(callerIR, type, usesAtLine);
            if (!fieldKey) continue;
            const writer = this.javaStaticFieldWriters[fieldKey];
            if (!writer) continue;

            const hopChain: InterproceduralTaintPath['hops'] = [
              { file: writer.file, line: writer.line, method: writer.methodName, kind: 'source' },
              { file: writer.file, line: writer.line, method: writer.methodName, kind: 'field_write' },
              { file: readerFile, line: def.line, method: method.name, kind: 'field_read' },
            ];
            tainted.set(def.variable!, {
              file: writer.file,
              line: writer.line,
              type: writer.type,
              hopChain,
            });
          }

          if (tainted.size === 0) continue;

          const sinksInCaller = callerIdx.sinksByMethod.get(method) ?? [];
          for (const sink of sinksInCaller) {
            const callsAtSink = callerIdx.callsByLine.get(sink.line) ?? [];
            for (const sinkCall of callsAtSink) {
              for (const arg of sinkCall.arguments ?? []) {
                const matched = this.matchTaintedArg(arg, tainted);
                if (!matched) continue;
                const key = `jsf:${matched.origin.file}:${matched.origin.line}→${readerFile}:${sink.line}`;
                if (seen.has(key)) continue;
                seen.add(key);
                paths.push({
                  source: {
                    file: matched.origin.file,
                    line: matched.origin.line,
                    type: matched.origin.type,
                  },
                  sink: {
                    file: readerFile,
                    line: sink.line,
                    type: sink.type,
                    cwe: sink.cwe,
                  },
                  hops: [
                    ...matched.origin.hopChain,
                    { file: readerFile, line: sink.line, method: method.name, kind: 'sink' },
                  ],
                  confidence: 0.7,
                });
              }
            }
          }
        }
      }
    }

    return paths;
  }

  private resolveJavaStaticFieldReadKey(
    callerIR: CircleIR,
    containingType: { name: string; fields?: Array<{ name: string; modifiers?: string[] }> },
    usesAtLine: DFGUse[],
  ): string | null {
    const names = usesAtLine.filter(u => u.def_id === null && u.variable).map(u => u.variable!);
    const pkg = callerIR.meta.package || '';
    const typeFqn = pkg ? `${pkg}.${containingType.name}` : containingType.name;
    for (const name of names) {
      const field = containingType.fields?.find(f => f.name === name);
      if (!field?.modifiers?.includes('static')) continue;
      const key = `${typeFqn}.${name}`;
      if (Object.hasOwn(this.javaStaticFieldWriters, key)) return key;
    }
    for (let i = 0; i < names.length; i++) {
      for (let j = 0; j < names.length; j++) {
        if (i === j) continue;
        const key = `${names[i]}.${names[j]}`;
        if (Object.hasOwn(this.javaStaticFieldWriters, key)) return key;
      }
    }
    return null;
  }

  private filePathForIr(ir: CircleIR): string | undefined {
    for (const [path, candidate] of this.fileIRs) {
      if (candidate === ir) return path;
    }
    return ir.meta.file || undefined;
  }

  private analyzeCSharpStaticFieldWriters(ir: CircleIR, filePath: string): void {
    if (ir.meta.language !== 'csharp') return;
    for (const type of ir.types) {
      const staticFields = new Set(
        (type.fields ?? [])
          .filter(f => f.modifiers?.includes('static'))
          .map(f => f.name),
      );
      if (staticFields.size === 0) continue;
      for (const src of ir.taint.sources ?? []) {
        if (src.type === 'interprocedural_param') continue;
        if (!src.variable) continue;
        const fieldName = src.variable.replace(/^this\./, '');
        if (!staticFields.has(fieldName)) continue;
        const method = type.methods.find(
          m => src.line >= m.start_line && src.line <= m.end_line,
        );
        const key = `${type.name}.${fieldName}`;
        this.csharpStaticFieldWriters.set(key, {
          file: filePath,
          line: src.line,
          type: src.type,
          methodName: method?.name ?? '',
        });
      }
    }
  }

  private resolveCSharpStaticFieldReadKey(
    containingType: { name: string; fields?: Array<{ name: string; modifiers?: string[] }> },
    usesAtLine: DFGUse[],
  ): string | null {
    const extUses = usesAtLine.filter(u => u.def_id === null && u.variable);
    const names = extUses.map(u => u.variable!);
    for (let i = 0; i < names.length; i++) {
      for (let j = 0; j < names.length; j++) {
        if (i === j) continue;
        const key = `${names[i]}.${names[j]}`;
        if (this.csharpStaticFieldWriters.has(key)) return key;
      }
    }
    for (const name of names) {
      const field = containingType.fields?.find(f => f.name === name);
      if (!field?.modifiers?.includes('static')) continue;
      const key = `${containingType.name}.${name}`;
      if (this.csharpStaticFieldWriters.has(key)) return key;
    }
    return null;
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
  /**
   * After cross-file wrapper-return seeding (step 2a), add same-file locals
   * DFG-derived from that assignment so caller-body sinks see `sql` as well
   * as `invoice` (cognium-dev#590). In-method sources already reach derived
   * names via `findCrossFileTaintFlows` / `collectTaintReachable`; extending
   * those here duplicates paths and emits `external_taint_escape` on calls
   * that bypass pass-level suppressions (cognium-dev#412).
   */
  private extendInterproceduralTaintedVars(
    callerIR: CircleIR,
    callerFile: string,
    tainted: Map<string, {
      file: string;
      line: number;
      type: string;
      hopChain: InterproceduralTaintPath['hops'];
      defIds?: Set<number>;
    }>,
  ): void {
    for (const [varName, origin] of [...tainted.entries()]) {
      const wrapperHop = origin.hopChain.find(
        h => h.kind === 'wrapper_return' && h.file === callerFile,
      );
      if (!wrapperHop) continue;
      const anchorLine = wrapperHop.line;

      const reachable = this.collectTaintReachable(callerIR, varName, anchorLine, callerFile);
      for (const derived of reachable.names) {
        if (derived === varName || tainted.has(derived)) continue;
        tainted.set(derived, { ...origin, defIds: reachable.defIds });
      }
    }
  }

  private matchTaintedArg(
    arg: { variable?: string | null; expression?: string },
    tainted: Map<string, { file: string; line: number; type: string; hopChain: InterproceduralTaintPath['hops']; defIds?: Set<number> }>,
    /** JS/TS: a name after a single `.` is a property (`args.output`), not the tainted local `output` (a spread `...output` still is). */
    jsMember = false,
  ): { var: string; origin: { file: string; line: number; type: string; hopChain: InterproceduralTaintPath['hops']; defIds?: Set<number> } } | null {
    if (tainted.size === 0) return null;

    // JS/TS (#1137): `name.length` is a number, so an argument that uses the
    // tainted name only as `name.length` carries no taint across the call.
    const lengthOnly = (tv: string): string | undefined => arg.expression?.replace(
      new RegExp(`(?<![\\w$.])${escapeRegExp(tv)}\\s*\\??\\.\\s*length(?![\\w$(\\[])`, 'g'), '0');

    // Direct variable reference
    if (arg.variable && tainted.has(arg.variable)) {
      const rest = jsMember ? lengthOnly(arg.variable) : undefined;
      if (rest === undefined || rest === arg.expression
          || new RegExp(`(?<![\\w$])${escapeRegExp(arg.variable)}(?![\\w$])`).test(rest)) {
        return { var: arg.variable, origin: tainted.get(arg.variable)! };
      }
    }

    // Whole-word scan inside the expression (handles `prefix + url`, `url.trim()`, etc.)
    if (arg.expression) {
      for (const [tv, origin] of tainted) {
        const re = jsMember
          ? new RegExp(`(?<![\\w$])(?<!(?:^|[^.])\\.)${escapeRegExp(tv)}(?![\\w$])`)
          : new RegExp(`\\b${escapeRegExp(tv)}\\b`);
        if (re.test(jsMember ? lengthOnly(tv)! : arg.expression)) return { var: tv, origin };
      }
    }

    return null;
  }

  /**
   * Index methods by FQN for quick lookup during chain construction, and by
   * `${file}#${fqn}` (see `methodTaintInfoByFile`).
   */
  private buildMethodIndex(): Map<string, { ir: CircleIR; method: MethodInfo }> {
    const idx = new Map<string, { ir: CircleIR; method: MethodInfo }>();
    for (const [file, ir] of this.fileIRs) {
      const pkg = ir.meta.package || '';
      for (const type of ir.types) {
        const typeFqn = pkg ? `${pkg}.${type.name}` : type.name;
        for (const method of type.methods) {
          idx.set(`${typeFqn}.${method.name}`, { ir, method });
          idx.set(`${file}#${typeFqn}.${method.name}`, { ir, method });
        }
      }
    }
    return idx;
  }

  /** Taint summary of the method a call resolved to, in the file it resolved to. */
  private calleeTaintInfo(resolved: ResolvedCall): MethodTaintInfo | undefined {
    return this.methodTaintInfoByFile.get(`${resolved.targetFile}#${resolved.targetMethod}`)
      ?? this.methodTaintInfo.get(resolved.targetMethod);
  }

  /** The method a call resolved to, in the file it resolved to. */
  private calleeNodeOf(
    methodIndex: Map<string, { ir: CircleIR; method: MethodInfo }>,
    resolved: ResolvedCall,
  ): { ir: CircleIR; method: MethodInfo } | undefined {
    return methodIndex.get(`${resolved.targetFile}#${resolved.targetMethod}`)
      ?? methodIndex.get(resolved.targetMethod);
  }

  /** Return the first local-def variable name at a given line, if any. */
  private getLocalDefVarAt(ir: CircleIR, line: number): string | undefined {
    for (const def of ir.dfg.defs) {
      if (def.line === line && def.kind === 'local' && def.variable) return def.variable;
    }
    return undefined;
  }

  /**
   * The parameter an annotated-parameter source binds (`@RequestParam q in
   * search`, `@Query host in ping`). Such a source names no variable and sits
   * on the signature line, which defines no local, so without it the source
   * could reach only a call on that same line. Undefined unless the method
   * the source names declares that parameter around the source line.
   */
  private annotatedParamName(ir: CircleIR, source: TaintSource): string | undefined {
    const m = /^@[\w$.]+ ([A-Za-z_$][\w$]*) in ([A-Za-z_$][\w$]*)$/.exec(source.location ?? '');
    if (!m) return undefined;
    const [, param, methodName] = m;
    const declared = ir.types.some(t => t.methods.some(method =>
      method.name === methodName
      && source.line >= method.start_line && source.line <= method.end_line
      && method.parameters.some(p => p.name === param)));
    return declared ? param : undefined;
  }

  /**
   * Collect the set of variable names DFG-reachable from `sourceVar` within
   * a single file — the source variable itself plus every local whose
   * definition transitively consumes it via def-use chains (cognium-dev
   * #146). Bounded forward BFS over `dfg.chains`.
   *
   * Used by the cross-file variable-connectivity gate so a tainted value
   * that is rebound before the cross-file call still connects. Example
   * (Rust actix): the source variable is the extractor param `q`, but the
   * call passes `cmd` from `let cmd = q.get("cmd").unwrap()`; the chain
   * `q → cmd` makes `cmd` reachable.
   *
   * Soundness guard: the walk does NOT follow a derivation whose def is
   * produced on a line carrying a *cross-file-resolvable call*. Such a
   * value crossed a file boundary and may have been transformed or
   * sanitized (e.g. `String safe = sanitizer.sanitizeUrl(raw)` — the
   * wrapper-sanitizer negative control). Verifying whether that call
   * preserves taint is the job of `findInterproceduralTaintPaths`, which
   * is sanitizer-aware; this coarse pass must stay conservative and stop
   * at the boundary. Same-file / stdlib accessor calls (`q.get(...)`,
   * `.unwrap()`) do not resolve cross-file, so genuine taint derivatives
   * are still followed.
   */
  private collectTaintReachable(
    ir: CircleIR,
    sourceVar: string,
    sourceLine: number,
    filePath: string,
  ): { names: Set<string>; defIds: Set<number> } {
    // Seed with the source's OWN def — line-anchored so a later same-named
    // redefinition is not treated as the source (cognium-dev #266). Prefer
    // the def named sourceVar at the source line; fall back to the earliest
    // def with that name (still the source in the reassign-to-untainted
    // shape, since the redefinition comes later).
    const defs = ir.dfg.defs;
    let seedDefs = defs.filter(d => d.variable === sourceVar && d.line === sourceLine);
    if (seedDefs.length === 0) {
      const named = defs
        .filter(d => d.variable === sourceVar)
        .sort((a, b) => a.line - b.line);
      if (named.length > 0) seedDefs = [named[0]];
    }

    const defIds = this.forwardReachableDefs(ir, seedDefs.map(d => d.id), filePath);
    const names = new Set<string>([sourceVar]);
    for (const d of defs) {
      if (d.variable && defIds.has(d.id)) names.add(d.variable);
    }
    return { names, defIds };
  }

  /**
   * Forward-reachable def set from a seed set of def ids, following
   * `dfg.chains` (cognium-dev #146/#266). Stops at any def produced on a
   * line carrying a cross-file-resolvable call (potential sanitizer
   * boundary — the #146 soundness guard). Returns the seed ∪ all
   * transitively derived def ids. Empty/absent DFG → just the seed.
   */
  private forwardReachableDefs(
    ir: CircleIR,
    seedDefIds: number[],
    filePath: string,
  ): Set<number> {
    const defIds = new Set<number>(seedDefIds);
    const chains = ir.dfg.chains;
    if (!chains || chains.length === 0 || seedDefIds.length === 0) return defIds;

    const lineByDefId = new Map<number, number>();
    for (const d of ir.dfg.defs) lineByDefId.set(d.id, d.line);

    const crossFileCallLines = new Set<number>();
    for (const call of ir.calls) {
      const resolved = this.resolveCall(call, filePath);
      if (resolved && resolved.targetFile !== filePath) {
        crossFileCallLines.add(call.location.line);
      }
    }

    const frontier = [...seedDefIds];
    const visited = new Set<number>(frontier);
    while (frontier.length > 0) {
      const cur = frontier.shift()!;
      for (const ch of chains) {
        if (ch.from_def !== cur || visited.has(ch.to_def)) continue;
        visited.add(ch.to_def);
        const toLine = lineByDefId.get(ch.to_def);
        if (toLine !== undefined && crossFileCallLines.has(toLine)) continue;
        defIds.add(ch.to_def);
        frontier.push(ch.to_def);
      }
    }
    return defIds;
  }

  /**
   * Def-precise clobber check for the interprocedural walker (cognium-dev
   * #266). Given a bare-variable call arg matched to a tainted var whose
   * caller-side taint reaches `taintDefIds`, returns true when the DFG
   * proves the arg's reaching def at the call line is NOT one of those
   * defs — i.e. the variable was reassigned to a non-tainted value between
   * the taint point and the call (`a = source(); a = "safe"; run(a)`).
   *
   * Conservative: returns false whenever the proof is unavailable (no bare
   * variable, no precise reaching def, empty def set / DFG), so it only
   * removes flows the DFG positively disproves — recall risk stays minimal
   * for the shared interprocedural pass, and empty-DFG languages (Python)
   * are unaffected.
   */
  /**
   * Def-precise clobber check for the cross-file gates (cognium-dev #266).
   * Given the matched taint variable `varName` carried by a call at
   * `callLine` and the source's reachable def set `taintDefIds`, returns
   * true when the DFG proves `varName`'s reaching def at the call is NOT
   * one of those defs — i.e. the variable was reassigned to a non-tainted
   * value between the taint point and the call
   * (`a = source(); a = "safe"; run(a)` / `run(&a)`). Keyed on the variable
   * name (not `arg.variable`) so it also covers expression args
   * (Rust `&a`, `"p" + a`, …).
   *
   * Conservative: returns false whenever the proof is unavailable (no
   * precise reaching def, empty def set / DFG), so it only removes flows
   * the DFG positively disproves — recall risk stays minimal for the
   * shared cross-file passes, and empty-DFG languages (Python) are
   * unaffected.
   */
  private taintClobbered(
    ir: CircleIR,
    callLine: number,
    varName: string,
    taintDefIds: Set<number> | undefined,
  ): boolean {
    if (!taintDefIds || taintDefIds.size === 0) return false;
    const use = ir.dfg.uses.find(
      u => u.line === callLine && u.variable === varName && u.def_id !== null,
    );
    if (!use || use.def_id === null) return false;
    return !taintDefIds.has(use.def_id);
  }

  /**
   * True when every real source inside `method` lands in a local that is only
   * ever read in a branch condition (`if (...)`, `while (...)`) after it is
   * assigned, so no source value can reach what the method returns (#914).
   *
   * OWASP `Utils.getOSCommandString(append)` reads
   * `String osName = System.getProperty("os.name");` only to choose between
   * `"cmd.exe /c " + append` and `append`. Without this, `returnsSource`
   * marks the method's return as `env_input` and every caller's
   * `exec(... getOSCommandString("ls ") ...)` became a command_injection path.
   *
   * Java / JS / TS when the source text is available; otherwise false
   * (the method keeps `returnsSource`).
   */
  private sourcesOnlySteerBranches(file: string, ir: CircleIR, method: MethodInfo): boolean {
    const lang = ir.meta.language;
    if (lang !== 'java' && lang !== 'javascript' && lang !== 'typescript') return false;
    const lines = this.sourceLines?.get(file);
    if (!lines) return false;
    const real = ir.taint.sources.filter(s =>
      s.type !== 'interprocedural_param' && s.line >= method.start_line && s.line <= method.end_line);
    if (real.length === 0) return false;
    for (const src of real) {
      if (lang === 'java') {
        if (!this.javaSourceOnlySteersBranches(lines, method, src)) return false;
      } else if (!this.jsTsSourceOnlySteersBranches(lines, method, src)) {
        return false;
      }
    }
    return true;
  }

  /** #914 — local assigned from a source, then only read in branch conditions. */
  private javaSourceOnlySteersBranches(
    lines: string[],
    method: MethodInfo,
    src: TaintSource,
  ): boolean {
    const v = src.variable;
    if (!v || !/^[A-Za-z_$][\w$]*$/.test(v)) return false;
    const decl = new RegExp(`^\\s*(?:final\\s+)?[\\w<>\\[\\].]+\\s+${v}\\s*=[^;]*;\\s*$`);
    if (!decl.test(stripJavaLiterals(lines[src.line - 1] ?? ''))) return false;
    const mention = new RegExp(`(?<![\\w$.])${v.replace(/\$/g, '\\$')}(?![\\w$])`);
    for (let l = src.line + 1; l <= method.end_line; l++) {
      const text = withoutLeadingConditions(stripJavaLiterals(lines[l - 1] ?? ''));
      if (mention.test(text)) return false;
    }
    return true;
  }

  /**
   * #1136 — JS/TS counterpart of #914: a read used only to steer a branch
   * (including inline `if (guard(read(...))) push(path)`) does not taint the
   * helper's return for cross-file chaining.
   */
  private jsTsSourceOnlySteersBranches(
    lines: string[],
    method: MethodInfo,
    src: TaintSource,
  ): boolean {
    const v = src.variable;
    if (v && /^[A-Za-z_$][\w$]*$/.test(v)) {
      const decl = new RegExp(`^\\s*(?:const|let|var)\\s+${v.replace(/\$/g, '\\$')}\\s*=`);
      if (decl.test(stripJavaLiterals(lines[src.line - 1] ?? ''))) {
        const mention = new RegExp(`(?<![\\w$.])${v.replace(/\$/g, '\\$')}(?![\\w$])`);
        for (let l = src.line + 1; l <= method.end_line; l++) {
          const text = withoutLeadingConditions(stripJavaLiterals(lines[l - 1] ?? ''));
          if (mention.test(text)) return false;
        }
        return true;
      }
    }
    const anchor = this.jsTsBranchOnlyAnchor(lines, src);
    if (!anchor) return false;
    for (let l = method.start_line; l <= method.end_line; l++) {
      const text = stripJavaLiterals(lines[l - 1] ?? '');
      if (!text.includes(anchor)) continue;
      const outsideCond = withoutLeadingConditions(text);
      if (outsideCond.includes(anchor)) return false;
    }
    return true;
  }

  /** Stable substring for an inline read (e.g. `readFileSync`) on the source line. */
  private jsTsBranchOnlyAnchor(lines: string[], src: TaintSource): string | undefined {
    const line = stripJavaLiterals(lines[src.line - 1] ?? '');
    const readCall = line.match(/\b(readFileSync|readFile|readSync)\s*\(/);
    if (readCall) return readCall[1];
    if (src.location) {
      const m = src.location.match(/\b(readFileSync|readFile|readSync)\b/);
      if (m) return m[1];
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
    this.methodTaintInfoByFile.clear();
    this.fieldTaintInfo.clear();
    this.resolvedCalls.clear();
    this.jsDefaultExportNames.clear();
  }

  /** Expose field-taint summary (for tests + diagnostics). */
  getFieldTaintInfo(typeFqn: string, fieldName: string): FieldTaintInfo | undefined {
    return this.fieldTaintInfo.get(`${typeFqn}.${fieldName}`);
  }
}

/** A Java line with comments and string / char literals blanked. */
function stripJavaLineComment(text: string): string {
  const idx = text.indexOf('//');
  return idx >= 0 ? text.slice(0, idx) : text;
}

function stripJavaLiterals(text: string): string {
  return text
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)'/g, "''")
    .split('\n')
    .map(stripJavaLineComment)
    .join('\n');
}

/**
 * The line with the parenthesised condition of every `if` / `else if` /
 * `while` it opens removed, so what remains is what the line does with
 * data. An unbalanced condition (it wraps to the next line) is left in
 * place, which only makes the caller more conservative.
 */
function withoutLeadingConditions(text: string): string {
  let out = text;
  for (;;) {
    const m = /\b(?:if|while)\s*\(/.exec(out);
    if (!m) return out;
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let close = -1;
    for (let i = open; i < out.length; i++) {
      if (out[i] === '(') depth++;
      else if (out[i] === ')' && --depth === 0) { close = i; break; }
    }
    if (close < 0) return out;
    out = out.slice(0, m.index) + out.slice(close + 1);
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

/** java.lang classes callers name unqualified, plus anything qualified under java./javax. */
const JAVA_LANG_CLASSES: ReadonlySet<string> = new Set([
  'System', 'Math', 'StrictMath', 'Integer', 'Long', 'Short', 'Byte', 'Double', 'Float',
  'Boolean', 'Character', 'String', 'StringBuilder', 'StringBuffer', 'Objects', 'Thread',
  'Runtime', 'Class', 'ClassLoader', 'Enum', 'Process', 'ProcessBuilder', 'Number',
]);

/** A resolved receiver type in the JDK (`java.lang.System`, `java.util.Properties`). */
function isJdkType(fqn: string, language: string | undefined): boolean {
  return (language === undefined || language === 'java') && /^javax?\.[a-z]/.test(fqn);
}

function isJdkClassReceiver(receiver: string, language: string | undefined): boolean {
  if (language !== undefined && language !== 'java') return false;
  if (/^javax?\.[a-z]/.test(receiver)) return true;
  return JAVA_LANG_CLASSES.has(receiver);
}

// A JS literal: quoted string, a template literal without `${…}`, number, boolean, null, undefined.
const JS_LITERAL = '(?:\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*"|`[^`$\\\\]*`|-?\\d+(?:\\.\\d+)?|true|false|null|undefined)';
const LITERAL_RHS = new RegExp(`^(?:${JS_LITERAL}|[^?;]+\\?\\s*${JS_LITERAL}\\s*:\\s*${JS_LITERAL})$`);

/**
 * True when the line assigns `variable` a literal-only value: a literal, or a
 * conditional whose two branches are literals (`x = cond ? 'a' : ''`).
 */
function literalOnlyAssignment(line: string, variable: string): boolean {
  const m = new RegExp(`(?:^|[^\\w$.])${escapeRegExp(variable)}\\s*(?::[^=]+)?=(?!=)\\s*(.+?);?\\s*$`).exec(line);
  return m !== null && LITERAL_RHS.test(m[1]!.trim());
}
