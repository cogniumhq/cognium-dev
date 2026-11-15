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


/** cognium-dev#626 — in-place Java argv container passed as a call argument. */
const ARGV_CONTAINER_ARG_RE =
  /^\s*(?:Arrays\s*\.\s*asList|List\s*\.\s*of|Collections\s*\.\s*singletonList)\s*\(|^\s*new\s+String\s*\[\s*\]\s*\{/;

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
  /**
   * Source text of the file. JS/TS only: lets call resolution see that a
   * receiver is declared as a built-in collection (see
   * `isBuiltinCollectionReceiver`).
   */
  sourceCode?: string;
}

/**
 * Perform inter-procedural taint analysis.
 *
 * Accepts either a CodeGraph (preferred) or the legacy (types, calls, dfg, ...)
 * signature for backward compatibility.
 */
// Go calls that consume a tainted value without it leaving the program. Kept
// narrow and literal: language builtins and conversions; error construction
// from the standard library, pkg/errors and grpc status; string formatting
// that RETURNS a string (Fprintf is deliberately absent — its writer may be an
// http.ResponseWriter, which the xss sink governs); logging verbs (a log
// sink is modelled separately as log_injection, so an escape on a logger is
// a duplicate, not a detection); and pure functions from stdlib packages
// gated on the package receiver so a same-named method on a project type
// still falls through. Anything not listed is still an escape.
const GO_BUILTIN_CALLS = new Set([
  'len', 'cap', 'make', 'new', 'append', 'copy', 'delete', 'close', 'panic',
  'recover', 'print', 'println', 'min', 'max', 'clear',
  'string', 'int', 'int8', 'int16', 'int32', 'int64', 'uint', 'uint8', 'uint16',
  'uint32', 'uint64', 'float32', 'float64', 'bool', 'byte', 'rune', 'error',
]);
// Matched by NAME on any receiver, so only verbs that are unambiguous: a
// method called Errorf/Sprintf/Warnf on a project type is still formatting or
// logging. Error CONSTRUCTION names (`New`, `Is`, `Wrap`, `Join` …) are NOT
// here — `client.New(socketPath)` is a genuine unknown call and must escape —
// they are covered by the receiver-gated packages below.
const GO_ERROR_AND_LOG_CALLS = new Set([
  'Errorf',
  // string formatting that returns a string
  'Sprintf', 'Sprint', 'Sprintln',
  // logging verbs (stdlib log, klog/glog, logrus, zap, zerolog)
  'Print', 'Printf', 'Println', 'Fatal', 'Fatalf', 'Fatalln', 'Panic', 'Panicf',
  'Panicln', 'Debug', 'Debugf', 'Debugln', 'Debugw', 'Info', 'Infof', 'Infoln',
  'Infow', 'InfoS', 'Warn', 'Warnf', 'Warnln', 'Warnw', 'Warning', 'Warningf',
  'Warningln', 'Error', 'Errorln', 'Errorw', 'ErrorS', 'Trace', 'Tracef',
  'V', 'WithError', 'WithField', 'WithFields', 'WithValues', 'Msg', 'Msgf',
]);
// Error-construction receivers whose every method is non-escaping.
// Error construction / inspection receivers: stdlib errors, pkg/errors and
// xerrors (all imported as `errors`), grpc `status`, multierr. NOT `fmt`:
// fmt.Fprintf(w, …) to an http.ResponseWriter is the reflected-XSS shape, and
// on Go today the escape is the only signal on it.
const GO_ERROR_PACKAGES = new Set(['errors', 'status', 'xerrors', 'multierr', 'multierror']);
// Pure stdlib packages: a call through one of these returns a derived value.
const GO_PURE_PACKAGES = new Set([
  'strings', 'strconv', 'bytes', 'unicode', 'utf8', 'path', 'filepath', 'math',
  'sort', 'slices', 'maps', 'time', 'regexp', 'url', 'hex', 'base64',
]);

// C# — the #455 gate ported (cognium-dev#474). Same failure shape as Go: once a
// real sink is correctly credited as safe, the catch-all
// `external_taint_escape` (CWE-20) reports the tainted value "escaping" into
// the safe call instead, so fixing a false positive converts it rather than
// removing it. #272's now-clean safe mirrors all emit escapes.
//
// Discipline copied deliberately from the Go gate: receiver-gate the static
// BCL classes, and match by NAME only for verbs that are unambiguous.
//
// `Write` / `WriteLine` / `WriteAsync` are NOT name-matched. `Response.Write`
// and ASP.NET Core `Response.WriteAsync` are the reflected-XSS sinks (#503),
// exactly the hazard that keeps `fmt` out of the Go gate — so console and
// trace writing is reached through the receiver list below instead.
const CSHARP_PURE_STATIC_RECEIVERS = new Set([
  // formatting / conversion / parsing — return a derived value
  'string', 'String', 'Convert', 'Encoding', 'BitConverter', 'Math',
  'Int16', 'Int32', 'Int64', 'UInt16', 'UInt32', 'UInt64', 'Double', 'Single',
  'Decimal', 'Boolean', 'Byte', 'SByte', 'Char', 'Guid', 'DateTime',
  'DateTimeOffset', 'TimeSpan', 'Enum', 'Array', 'Buffer', 'Nullable',
  'CultureInfo', 'StringComparer', 'Comparer', 'EqualityComparer',
  // logging / diagnostics receivers
  'Console', 'Debug', 'Trace', 'Logger', 'logger', '_logger', 'Log',
]);
// Unambiguous derived-value and logging verbs. A method with one of these
// names on any receiver has not sent the value out of the program.
const CSHARP_NON_ESCAPE_METHODS = new Set([
  // string / value derivation
  'ToString', 'ToArray', 'ToList', 'ToCharArray', 'GetHashCode', 'Equals',
  'CompareTo', 'Trim', 'TrimStart', 'TrimEnd', 'Substring', 'Split', 'Join',
  'Concat', 'PadLeft', 'PadRight', 'ToLower', 'ToUpper', 'ToLowerInvariant',
  'ToUpperInvariant', 'StartsWith', 'EndsWith', 'Contains', 'IndexOf',
  'LastIndexOf', 'Insert', 'Remove', 'Normalize', 'Append', 'AppendLine',
  'AppendFormat', 'TryParse', 'Parse',
  // structured logging (Microsoft.Extensions.Logging, Serilog, NLog, log4net)
  'LogInformation', 'LogWarning', 'LogError', 'LogDebug', 'LogTrace',
  'LogCritical', 'Information', 'Warning', 'Verbose', 'Fatal', 'BeginScope',
  // Collection stores. A value put into a container has not left the program —
  // the same reasoning that puts Go's `append` in GO_BUILTIN_CALLS. Measured
  // on the 10 scored Juliet C# families these were 1,296 of the 2,368 escape
  // rows remaining after the first pass of this gate (#474): `Add` 864,
  // `AddLast` 432.
  //
  // Project methods are deliberately NOT gated, matching the Go gate's rule
  // that an unknown call must still escape: Juliet's own `BadSink` /
  // `GoodB2GSink` / `Action` dispatches account for a further 840 rows and are
  // left alone, because "the callee is defined in this file" is a different
  // claim needing its own change.
  'Add', 'AddLast', 'AddFirst', 'AddRange', 'TryAdd', 'Insert', 'Push',
  'Enqueue',
  // Collection lookups (cognium-dev#665). Using a value as a key into an
  // in-memory map hands nothing out of the program; it is the allowlist
  // shape (`if (!Catalog.TryGetValue(sku, out var price)) return …`).
  'TryGetValue', 'ContainsKey', 'ContainsValue', 'GetValueOrDefault',
  // Encoders (cognium-dev#518). Encoding a value hands back a string; nothing
  // has left the program at `Uri.EscapeDataString(input)`.
  'EscapeDataString', 'EscapeUriString', 'UrlEncode', 'UrlPathEncode',
  'HtmlEncode', 'HtmlAttributeEncode', 'JavaScriptStringEncode',
]);

function isCSharpNonEscapeCall(call: CallInfo): boolean {
  const name = call.method_name;
  const recv = (call.receiver ?? '').split('.').pop() ?? '';
  if (CSHARP_PURE_STATIC_RECEIVERS.has(recv)) return true;
  if (CSHARP_NON_ESCAPE_METHODS.has(name)) return true;
  // The inherited controller helper `Content(body, contentType)` writes the
  // response body; the `Content` xss sink judges it by its content type
  // (cognium-dev#580), so a plain-text or JSON body is not an escape either.
  if (name === 'Content' && (call.receiver === null || call.receiver === 'this' || call.receiver === 'base')) return true;
  return false;
}

// Java (#468, slice): JDK exception / error types. Constructing one wraps the
// value into an object that has not left the program, the counterpart of the
// error-construction rows in the Go (#455) and C# (#474) gates. Formatters,
// StringBuilder, loggers and project-defined exception classes are gated in
// `isJavaNonEscapeCall`; an unknown callee still escapes.
const JAVA_LANG_EXCEPTION_TYPES = new Set([
  'Exception', 'RuntimeException', 'IllegalArgumentException',
  'IllegalStateException', 'UnsupportedOperationException',
  'NullPointerException', 'IndexOutOfBoundsException', 'NumberFormatException',
  'Error', 'AssertionError',
]);

// Java (#468, slice 4): in-memory string accumulators. Wrapping a tainted value in a
// `StringBuilder` / `StringBuffer` keeps it in-process; publishing `toString()` still escapes.
const JAVA_LANG_STRING_ACCUMULATOR_TYPES = new Set(['StringBuilder', 'StringBuffer']);

// Java (#468, slice 2): JDK static formatters. Building a string sends the
// value nowhere, the counterpart of the formatter row in the Go gate (#455).
// Receiver-gated: only the exact JDK class, written bare (and not shadowed by a
// declared or differently-imported class of that name) or fully qualified.
// Instance `.format(...)` on any other receiver still escapes.
const JAVA_FORMATTER_CLASSES: ReadonlyMap<string, string> = new Map([
  ['String', 'java.lang'],
  ['MessageFormat', 'java.text'],
]);

// Java (#468, slice 5): logging verbs. A tainted value written to a logger has
// not left the program under the #455 gate — `log_injection` governs the sink.
// Matched by method name on any receiver (SLF4J, Log4j, java.util.logging, …).
const JAVA_LOGGER_METHODS = new Set([
  'severe', 'warning', 'config', 'fine', 'finer', 'finest', 'logp', 'logrb',
  'log', 'trace', 'debug', 'info', 'warn', 'error', 'fatal',
  'Log', 'LogInformation', 'LogWarning', 'LogError', 'LogDebug', 'LogTrace',
  'LogCritical', 'Information', 'Warning', 'Verbose', 'Fatal', 'BeginScope',
]);

function isJavaLoggerCall(call: CallInfo): boolean {
  return JAVA_LOGGER_METHODS.has(call.method_name);
}

/**
 * #468 S2: drop duplicate `log_injection` on gated loggers for SLF4J/Log4j-style
 * calls, but keep `java.util.logging.Logger` flows for flow-sanitize recall (#947).
 */
export function isJavaLoggerLogInjectionDuplicate(call: CallInfo): boolean {
  if (!isJavaLoggerCall(call)) return false;
  const fqn = call.receiver_type_fqn ?? '';
  const recv = call.receiver ?? '';
  const target = call.resolution?.target ?? '';
  if (fqn.startsWith('java.util.logging.') || target.startsWith('java.util.logging.')) {
    return false;
  }
  if (recv.includes('java.util.logging.') || /\bjava\.util\.logging\.Logger\b/.test(recv)) {
    return false;
  }
  if (/^Logger\.getLogger\b/.test(recv) || /^java\.util\.logging\.Logger\.getLogger\b/.test(recv)) {
    return false;
  }
  return true;
}

/**
 * #468 S2: suppress `log_injection` only when it duplicates a gated SLF4J/Log4j
 * escape — not when a bare tainted argument still reaches the logger (issue-216).
 */
export function shouldSuppressGatedLoggerLogInjection(
  flow: { sink_type: string; sink_line: number; path: Array<{ variable?: string }> },
  callsAtSink: readonly CallInfo[],
): boolean {
  if (flow.sink_type !== 'log_injection') return false;
  const duplicateCalls = callsAtSink.filter(c => isJavaLoggerLogInjectionDuplicate(c));
  if (duplicateCalls.length === 0) return false;
  // Log4j message lookup substitution — `${…}` in the format string (cognium-dev#1247).
  for (const call of duplicateCalls) {
    for (const arg of call.arguments) {
      const expr = (arg.expression ?? '').trim();
      if (/\$\{/.test(expr) && /\+/.test(expr)) return false;
    }
  }
  const sinkVar = flow.path.length > 0 ? flow.path[flow.path.length - 1]?.variable : undefined;
  if (sinkVar && /^[A-Za-z_$][\w$]*$/.test(sinkVar)) {
    const escaped = sinkVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?:^|[^A-Za-z0-9_$])${escaped}(?:[^A-Za-z0-9_$]|$)`);
    for (const call of duplicateCalls) {
      for (const arg of call.arguments) {
        const expr = (arg.expression ?? '').trim();
        if (expr === sinkVar) return false;
        if (re.test(expr) && expr.length <= sinkVar.length + 2) return false;
      }
    }
  }
  return true;
}

// Java (#468, slice 3): `java.util.Objects` null checks. They validate or return
// the reference and do not send the value outside the program.
const JAVA_OBJECTS_CLASS: ReadonlyMap<string, string> = new Map([['Objects', 'java.util']]);
const JAVA_OBJECTS_NULL_CHECK_METHODS = new Set([
  'requireNonNull',
  'requireNonNullElse',
  'requireNonNullElseGet',
]);

function isJavaStaticFormatterCall(
  call: CallInfo,
  declaredTypeNames: ReadonlySet<string>,
  imports: ReadonlyArray<{ imported_name: string; from_package: string | null; alias: string | null; is_wildcard: boolean }>,
  calls: readonly CallInfo[],
): boolean {
  if (call.method_name !== 'format' || !call.receiver) return false;
  // A formatter that is itself an argument of another call (`queue.publish(
  // MessageFormat.format(..., v))`) keeps its escape: the enclosing call has no
  // tainted variable of its own to report, so this call is where the value
  // leaves.
  const needle = `${call.receiver}.format(`;
  for (const other of calls) {
    if (other === call || other.method_name === 'format') continue;
    if (other.arguments.some(a => a.expression.includes(needle))) return false;
  }
  return isJdkClassReceiver(call.receiver, JAVA_FORMATTER_CLASSES, declaredTypeNames, imports);
}

function isJavaObjectsNullCheckCall(
  call: CallInfo,
  declaredTypeNames: ReadonlySet<string>,
  imports: ReadonlyArray<{ imported_name: string; from_package: string | null; alias: string | null; is_wildcard: boolean }>,
): boolean {
  if (!call.receiver || !JAVA_OBJECTS_NULL_CHECK_METHODS.has(call.method_name)) return false;
  return isJdkClassReceiver(call.receiver, JAVA_OBJECTS_CLASS, declaredTypeNames, imports);
}

/**
 * Is `receiver` the JDK class named in `classes` (simple name → package)?
 * Fully qualified it must be exactly `<pkg>.<Class>`; written bare it must not
 * be shadowed by a class declared in this file or by an import (or alias) of
 * that simple name from another package. A `java.lang` class is implicit; any
 * other package must be imported (explicitly or by wildcard), otherwise the
 * bare name may be a same-package class.
 */
function isJdkClassReceiver(
  receiver: string,
  classes: ReadonlyMap<string, string>,
  declaredTypeNames: ReadonlySet<string>,
  imports: ReadonlyArray<{ imported_name: string; from_package: string | null; alias: string | null; is_wildcard: boolean }>,
): boolean {
  const dot = receiver.lastIndexOf('.');
  const simple = dot < 0 ? receiver : receiver.slice(dot + 1);
  const pkg = classes.get(simple);
  if (pkg === undefined) return false;
  if (dot >= 0) return receiver === `${pkg}.${simple}`;
  if (declaredTypeNames.has(simple)) return false;
  for (const imp of imports) {
    if (imp.alias === simple) return false;
    if (!imp.is_wildcard && imp.imported_name === simple && imp.from_package !== pkg) return false;
  }
  if (pkg === 'java.lang') return true;
  return imports.some(imp =>
    imp.from_package === pkg && (imp.imported_name === simple || imp.is_wildcard));
}

// Java (#807): `java.lang.Character` classification predicates. Each returns a
// boolean about its argument and keeps no reference to it, so a tainted char or
// code point tested with `Character.isLetter(ch)` has not left the program —
// the counterpart of the Go const-regexp `MatchString` row (#349). Same
// receiver gate as the formatters: a declared or differently-imported
// `Character` class still escapes.
const JAVA_CHARACTER_CLASS: ReadonlyMap<string, string> = new Map([['Character', 'java.lang']]);
const JAVA_CHARACTER_PREDICATES = new Set([
  'isLetter', 'isDigit', 'isLetterOrDigit', 'isAlphabetic', 'isWhitespace',
  'isSpaceChar', 'isUpperCase', 'isLowerCase', 'isTitleCase', 'isISOControl',
  'isDefined', 'isIdeographic', 'isMirrored', 'isJavaIdentifierStart',
  'isJavaIdentifierPart', 'isUnicodeIdentifierStart', 'isUnicodeIdentifierPart',
  'isIdentifierIgnorable', 'isHighSurrogate', 'isLowSurrogate', 'isSurrogate',
  'isSurrogatePair', 'isValidCodePoint', 'isBmpCodePoint',
  'isSupplementaryCodePoint',
]);
// #814: metadata queries on a code point (name / general category) do not retain
// the char; same receiver gate as the boolean predicates (#807).
const JAVA_CHARACTER_METADATA = new Set(['getName', 'getType', 'getNumericValue']);

function isJavaCharacterPredicateCall(
  call: CallInfo,
  declaredTypeNames: ReadonlySet<string>,
  imports: ReadonlyArray<{ imported_name: string; from_package: string | null; alias: string | null; is_wildcard: boolean }>,
): boolean {
  if (!call.receiver) return false;
  if (!JAVA_CHARACTER_PREDICATES.has(call.method_name) && !JAVA_CHARACTER_METADATA.has(call.method_name)) {
    return false;
  }
  return isJdkClassReceiver(call.receiver, JAVA_CHARACTER_CLASS, declaredTypeNames, imports);
}

function isJavaNonEscapeCall(
  call: CallInfo,
  declaredTypeNames: ReadonlySet<string>,
  imports: ReadonlyArray<{ imported_name: string; from_package: string | null; alias: string | null; is_wildcard: boolean }>,
  calls: readonly CallInfo[],
): boolean {
  if (isJavaStaticFormatterCall(call, declaredTypeNames, imports, calls)) return true;
  if (isJavaObjectsNullCheckCall(call, declaredTypeNames, imports)) return true;
  if (isJavaLoggerCall(call)) return true;
  if (isJavaCharacterPredicateCall(call, declaredTypeNames, imports)) return true;
  // Only a constructor call `new X(...)`: no receiver, and the resolved target
  // is `X.<init>` (the extractor does not set `is_constructor` for Java).
  if (call.receiver) return false;
  const isCtor = call.is_constructor === true ||
    (call.resolution?.target ?? '').endsWith('.<init>');
  if (!isCtor) return false;
  const written = call.method_name;
  const simple = written.split('.').pop() ?? written;
  // Fully-qualified spelling: only `java.lang.<X>`; anything else is a project
  // or library class.
  if (written.includes('.')) {
    return written.startsWith('java.lang.') &&
      (JAVA_LANG_EXCEPTION_TYPES.has(simple) || JAVA_LANG_STRING_ACCUMULATOR_TYPES.has(simple) ||
        /(Exception|Error)$/.test(simple));
  }
  // An explicit import of the same simple name from another package, or a class
  // declared in this file, shadows the java.lang type.
  if (call.receiver_type_fqn && !call.receiver_type_fqn.startsWith('java.lang.')) return false;
  if (declaredTypeNames.has(simple)) return false;
  return JAVA_LANG_EXCEPTION_TYPES.has(simple) || JAVA_LANG_STRING_ACCUMULATOR_TYPES.has(simple);
}

/**
 * Go: `<re>.MatchString(subject)` where `<re>` is a plain identifier whose every
 * definition in the file is `regexp.MustCompile(<one string literal>)`. The call
 * returns a bool and neither retains nor writes its subject, so a tainted subject
 * has not left the program (#349). A pattern built from a variable, a receiver
 * that is a parameter / field / reassigned or shadowed name, or a string-returning
 * matcher (`FindString`) is not covered and keeps its escape.
 */
function isGoConstRegexMatchCall(call: CallInfo, graph: CodeGraph, calls: readonly CallInfo[]): boolean {
  if (call.method_name !== 'MatchString' || call.arguments.length !== 1) return false;
  const re = call.receiver ?? '';
  if (!/^[A-Za-z_]\w*$/.test(re)) return false;
  const defs = graph.defsByVar.get(re);
  if (!defs || defs.length === 0) return false;
  return defs.every(def =>
    def.kind === 'local' &&
    calls.some(c =>
      c.location.line === def.line &&
      c.method_name === 'MustCompile' &&
      c.receiver === 'regexp' &&
      c.arguments.length === 1 &&
      typeof c.arguments[0].literal === 'string' &&
      /^(?:`[^`]*`|"(?:[^"\\]|\\.)*")$/.test(c.arguments[0].expression.trim())));
}

function isGoNonEscapeCall(call: CallInfo): boolean {
  const name = call.method_name;
  const recv = (call.receiver ?? '').split('.').pop() ?? '';
  if (!call.receiver && GO_BUILTIN_CALLS.has(name)) return true;
  if (GO_ERROR_PACKAGES.has(recv)) return true;
  if (GO_PURE_PACKAGES.has(recv)) return true;
  if (GO_ERROR_AND_LOG_CALLS.has(name)) return true;
  return false;
}

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
  const declaredTypeNames = new Set<string>(types.map(t => t.name));

  // Build call graph edges with receiver type resolution
  const lang = graph.ir.meta.language;
  // Java: overloads get one node each, and calls bind by arity and argument
  // types (see `resolveJavaCallTargets`).
  const isJava = lang === 'java';

  // Build method nodes from type information
  const methodNodes = buildMethodNodes(types, isJava);
  const collectionReceiver = (lang === 'typescript' || lang === 'javascript') && typeof options.sourceCode === 'string'
    ? makeBuiltinCollectionReceiverTest(options.sourceCode)
    : null;
  const callEdges = buildCallEdges(calls, methodNodes, types, collectionReceiver, isJava);

  // Identify initially tainted parameters (from sources)
  const taintedMethods = new Set<string>();
  const taintedReturns = new Map<string, string>();

  // Mark methods containing sources as tainted (using FQN)
  for (const source of sources) {
    const methodInfo = findMethodAtLine(types, source.line);
    if (methodInfo) {
      taintedMethods.add(nodeKeyOf(methodNodes, methodInfo));
    }
  }

  // Build taint map from DFG via CodeGraph (eliminates O(N) scan per source)
  const seedIds = new Set<number>();
  for (const source of sources) {
    for (const def of graph.defsAtLine(source.line)) {
      seedIds.add(def.id);
    }
    // Bash positional params ($1..$9, $@, $*) live as synthetic param defs at
    // line 0; the source emits at the use line. Seed by variable name against
    // line-0 param defs so cross-procedure taint actually starts.
    if (source.variable) {
      for (const def of graph.defsAtLine(0)) {
        if (def.kind === 'param' && def.variable === source.variable) {
          seedIds.add(def.id);
        }
      }
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
    // Safe DOM text methods — set textContent, not innerHTML (XSS-safe)
    'text', 'textContent', 'innerText', 'createTextNode',
    'addClass', 'removeClass', 'toggleClass',
    'parseInt', 'parseFloat', 'Number', 'String', 'Boolean',
    // Pure serializers (JSON.stringify, qs/querystring.stringify) return a
    // string to the caller; the value has not left the program (#670).
    'stringify',
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
    // Go database/sql query methods — when parameterised (?, $N, :name),
    // these are safe boundaries; the sql_injection check governs the unsafe
    // shape. Without this, parameterised queries fall through to
    // external_taint_escape. (cognium-dev #102 FP-19a)
    'Query', 'QueryRow', 'QueryContext', 'QueryRowContext',
    'Exec', 'ExecContext', 'Prepare', 'PrepareContext',
    // Go html/template escape helpers — explicit safe utilities.
    // Belt-and-suspenders with the sanitizer config so external_taint_escape
    // is suppressed regardless of class-prefix matching. (cognium-dev #102 FP-27)
    'EscapeString', 'HTMLEscapeString', 'JSEscapeString', 'URLQueryEscaper',
    // Go os/exec — when isSafeGoExecCommandCall has already cleared the
    // command_injection sink (fixed program literal, non-shell), the call
    // should not fall through to external_taint_escape on the variadic args.
    // Genuine command_injection is still emitted via the configured sink.
    // (cognium-dev #102 FP-25)
    'Command', 'CommandContext',
  ]);

  // Structured ORM / query-builder finder methods (JS/TS ecosystem — Prisma,
  // Sequelize, TypeORM, Mongoose, Strapi, knex, drizzle). The driver binds
  // values positionally, so a tainted value in a `where`/filter object is
  // parameterised, not injected — exactly the Go `Query`/`Exec` case above.
  // These names have raw/unsafe siblings (`queryRaw`, `$queryRawUnsafe`,
  // `whereRaw`, `raw`, `find`) which are intentionally NOT listed and still
  // fall through to the escape/injection check. Suppresses only the
  // low-confidence CWE-668 `external_taint_escape` fallback — genuine
  // sql/nosql sinks are governed by their configured patterns. (cognium-ai#279 R-1)
  const ormQueryBuilderMethods = new Set([
    'findMany', 'findFirst', 'findUnique', 'findUniqueOrThrow', 'findFirstOrThrow',
    'findOne', 'findAll', 'findByPk', 'findAndCountAll', 'findBy', 'findOneBy',
    'where', 'andWhere', 'orWhere', 'whereIn', 'whereNot', 'first', 'bind',
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

  // Bash: functions defined in this script (their positional defs carry
  // `bash-fn:<name>`).
  const bashScriptFunctions = new Set<string>();
  if (graph.ir.meta.language === 'bash') {
    for (const d of graph.ir.dfg.defs) {
      if (d.kind === 'param' && d.expression?.startsWith('bash-fn:')) {
        bashScriptFunctions.add(d.expression.slice('bash-fn:'.length));
      }
    }
  }

  // Java: the calls are visited until no parameter gains taint, and only the
  // last visit reports sinks, so a callee declared above its caller (or a
  // helper moved within the file) is analysed as if declared below it. Other
  // languages keep the single visit in source order.
  const maxCallPasses = isJava ? 10 : 1;
  let emit = !isJava;
  for (let pass = 0; ; pass++) {
    let grew = false;
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
            continue;
          }
        }
        // cognium-dev#626: a Java argv container built in place —
        // `launchCommand(Arrays.asList("/bin/sh", "-c", "make " + step))` — carries
        // every tainted variable named inside it. For a call expression `variable`
        // is the callee name, so the check above never sees `step`.
        if (graph.ir.meta.language === 'java' && ARGV_CONTAINER_ARG_RE.test(arg.expression ?? '')) {
          const inCode = (arg.expression ?? '').replace(/"(?:[^"\\]|\\.)*"/g, ' ');
          const carried = graph.usesAtLine(call.location.line).find(u =>
            u.def_id !== null && taintedDefIds.has(u.def_id) &&
            new RegExp(`(?<![\\p{L}\\p{N}_.])${u.variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\p{L}\\p{N}_])`, 'u').test(inCode));
          if (carried) {
            taintedArgPositions.push(arg.position);
            taintedArgVars.push(carried.variable);
          }
        }
      }

      // Resolve callee by receiver type when available (nested / inner classes).
      // A method of a built-in Map/Set receiver (`this.cache.set(k, v)`) is
      // never a method of a class in this file, whatever its name.
      const builtinReceiver = collectionReceiver !== null && collectionReceiver(call.receiver);
      const targets: MethodNode[] = builtinReceiver ? [] : resolveCallTargets(call, methodNodes, types, isJava);

      if (targets.length === 0) {
        if (!emit) continue;
        // External method call - check if tainted data is escaping
        // Skip collection methods (data manipulation), sanitizer methods (data cleaning),
        // and safe utility methods (validation, normalization)
        if (taintedArgPositions.length > 0 &&
            !collectionMethods.has(call.method_name) &&
            !sanitizerMethods.has(call.method_name) &&
            !safeUtilityMethods.has(call.method_name) &&
            !ormQueryBuilderMethods.has(call.method_name)) {
          // Bash specialization: every external utility (ping, whois, curl, nc,
          // …) is an unknown call, but an unquoted tainted positional yields
          // word-splitting/arg-injection that is concretely CWE-78 command
          // injection — not a generic CWE-668 escape. Re-classify, except for a
          // small allowlist of side-effect-free builtins.
          const isBash = graph.ir.meta.language === 'bash';
          // Go: a value consumed by a builtin, wrapped into an error, formatted
          // into a string, logged, or run through a pure stdlib helper has not
          // left the program. Measured on 203 Go repositories these shapes were
          // 78% of ALL Go taint flows (9469 escapes vs 2742 classical), with
          // `len` alone at 709 — so a handler file with a single request read
          // produced a page of CWE-668 before any real sink was reached.
          if (graph.ir.meta.language === 'go' && isGoNonEscapeCall(call)) {
            continue;
          }
          // Go: a bool test of the value against a constant-pattern regexp (#349).
          if (graph.ir.meta.language === 'go' && isGoConstRegexMatchCall(call, graph, calls)) {
            continue;
          }
          // C# — same gate, same reason (#474, sibling of #455/#468).
          if (graph.ir.meta.language === 'csharp' && isCSharpNonEscapeCall(call)) {
            continue;
          }
          // Java — JDK exception construction, static formatters (#468, minimal slices)
          // and Character predicates (#807).
          if (graph.ir.meta.language === 'java' && isJavaNonEscapeCall(call, declaredTypeNames, graph.ir.imports ?? [], calls)) {
            continue;
          }
          const bashSafeBuiltins = new Set([
            'echo', 'printf', 'test', '[', '[[', 'true', 'false', ':',
            'declare', 'local', 'export', 'readonly', 'typeset',
          ]);
          if (isBash && bashSafeBuiltins.has(call.method_name)) {
            continue;
          }
          // Bash: a function defined in this script is not an external utility.
          // Its arguments reach its own positional parameters through the DFG
          // (call-argument chains), so a real sink inside its body still fires.
          if (isBash && bashScriptFunctions.has(call.method_name)) {
            continue;
          }

          // Bash argv-terminator gate (#216 FP #4): when `--` appears as an
          // argument before every tainted position AND every tainted positional
          // is double-quoted, both flag-injection and word-splitting are
          // impossible. Common pattern: `grep -- "$pattern" file`. The two
          // conditions are conjunctive — quoting alone permits `-e payload`
          // flag injection, `--` alone permits word-splitting on unquoted
          // expansion.
          if (isBash && taintedArgPositions.length > 0) {
            const terminatorPos = call.arguments
              .filter(a => a.expression === '--')
              .map(a => a.position)
              .reduce<number | null>((min, p) => (min === null || p < min ? p : min), null);
            const earliestTainted = Math.min(...taintedArgPositions);
            if (terminatorPos !== null && terminatorPos < earliestTainted) {
              const allTaintedQuoted = taintedArgPositions.every(p => {
                const a = call.arguments[p];
                if (!a) return false;
                const expr = a.expression.trim();
                return expr.startsWith('"') && expr.endsWith('"');
              });
              if (allTaintedQuoted) {
                continue;
              }
            }
          }

          // Bash SQL CLI re-classification (#216 FP #5): SQL client utilities
          // (sqlite3, mysql, psql, mariadb) take SQL strings as positional
          // args, not shell commands. When taint reaches the fallback (e.g.
          // via variable indirection that bypasses the per-utility builtin
          // sink in `bash.ts`), classify as CWE-89 sql_injection instead of
          // CWE-78 command_injection. The flow IS a vulnerability; only the
          // type label is corrected.
          const bashSqlCliTools = new Set(['sqlite3', 'mysql', 'psql', 'mariadb']);
          const isBashSqlCli = isBash && bashSqlCliTools.has(call.method_name);

          const sink: TaintSink = isBashSqlCli
            ? {
                type: 'sql_injection',
                cwe: 'CWE-89',
                location: `Tainted data (${taintedArgVars.join(', ')}) interpolated into SQL query passed to ${call.method_name}`,
                line: call.location.line,
                confidence: 0.7,
                method: call.method_name,
                argPositions: taintedArgPositions,
              }
            : isBash
            ? {
                type: 'command_injection',
                cwe: 'CWE-78',
                location: `Tainted data (${taintedArgVars.join(', ')}) passed unquoted to shell utility ${call.method_name}`,
                line: call.location.line,
                confidence: 0.6,
                method: call.method_name,
                argPositions: taintedArgPositions,
              }
            : {
                // Create an "external_taint_escape" sink for this call
                // This represents tainted data being passed to code we can't analyze
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
        for (const targetMethod of targets) {
          // Mark corresponding parameters as tainted
          for (const pos of taintedArgPositions) {
            if (pos < targetMethod.parameters.length) {
              targetMethod.parameters[pos].sourceLine = call.location.line;
              // Its param defs are already seeded once the parameter is tainted.
              if (targetMethod.parameters[pos].isTainted) continue;
              targetMethod.parameters[pos].isTainted = true;
              grew = true;
              const paramName = targetMethod.parameters[pos].name;
              for (const def of graph.ir.dfg.defs) {
                if (
                  def.kind === 'param' &&
                  def.variable === paramName &&
                  def.line >= targetMethod.startLine &&
                  def.line <= targetMethod.endLine
                ) {
                  taintedDefIds.add(def.id);
                }
              }
            }
          }
          taintedMethods.add(targetMethod.fqn);
          if (!emit) continue;

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
    }
    if (emit) break;
    if (!grew || pass + 1 >= maxCallPasses) emit = true;
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
  /** Each declaration's node (Java: one per overload; elsewhere the FQN's last declaration). */
  byInfo: Map<MethodInfo, MethodNode>;
}

/**
 * Build method nodes from type information.
 * Uses fully qualified names (FQN) as keys for precise method resolution.
 */
function buildMethodNodes(types: TypeInfo[], javaOverloads = false): MethodNodeMaps {
  const byFqn = new Map<string, MethodNode>();
  const byName = new Map<string, MethodNode>();
  const byInfo = new Map<MethodInfo, MethodNode>();

  for (const type of types) {
    // Java: a name declared more than once in the type is keyed by its erased
    // parameter types, `pkg.C.m(String)`, so no overload replaces another.
    // A name declared once keeps the plain `pkg.C.m` key.
    const nameCount = new Map<string, number>();
    if (javaOverloads) {
      for (const m of type.methods) nameCount.set(m.name, (nameCount.get(m.name) ?? 0) + 1);
    }
    for (const method of type.methods) {
      let fqn = buildMethodFQN(type.package, type.name, method.name);
      if (javaOverloads) {
        if ((nameCount.get(method.name) ?? 0) > 1) {
          fqn += `(${method.parameters.map(p => p.type === null ? '?' : javaErasure(p.type).text).join(',')})`;
        }
        // Two declarations with one key (same-named nested types, or a
        // parse that lost the types): keep both, the later one by line.
        if (byFqn.has(fqn)) fqn += `@${method.start_line}`;
      }

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
      byInfo.set(method, node);

      // Store with simple name for fallback (first occurrence wins)
      if (!byName.has(method.name)) {
        byName.set(method.name, node);
      }
    }
  }

  // Elsewhere a later declaration of one FQN replaces the earlier one.
  if (!javaOverloads) {
    for (const [info, node] of byInfo) {
      if (byFqn.get(node.fqn) !== node) byInfo.delete(info);
    }
  }

  return { byFqn, byName, byInfo };
}

/** The node key of the method a `findMethodAtLine` context names. */
function nodeKeyOf(maps: MethodNodeMaps, ctx: MethodContext): string {
  return maps.byInfo.get(ctx.method)?.fqn
    ?? buildMethodFQN(ctx.packageName, ctx.className, ctx.methodName);
}

/**
 * The same-file methods a call may bind to. Java: see
 * `resolveJavaCallTargets`. Elsewhere: the one node `resolveMethodCall`
 * names, if any.
 */
function resolveCallTargets(
  call: CallInfo,
  methodNodes: MethodNodeMaps,
  types: TypeInfo[],
  isJava: boolean,
): MethodNode[] {
  if (isJava) return resolveJavaCallTargets(call, methodNodes, types);
  const fqn = resolveMethodCall(call, methodNodes, types);
  const node = fqn ? methodNodes.byFqn.get(fqn) : getMethodNode(methodNodes, call.method_name);
  return node ? [node] : [];
}

/**
 * Java call resolution (C5 follow-up F4). The owner type is chosen as
 * before (the receiver's declared type; else, with a receiver, the first type
 * declaring the name; else the innermost type around the call that declares
 * it, then the first type declaring it). Among that type's methods of the
 * name:
 *   1. those whose arity fits the call (a trailing varargs parameter takes
 *      any number of arguments, including none);
 *   2. of those, the ones every known argument type can be passed to
 *      (`javaArgDefinitelyIncompatible`);
 *   3. if exactly one candidate takes every argument at its exact erased
 *      type, that one.
 * Whatever is still ambiguous is kept whole, so taint reaches every
 * overload the call could be, never just the one declared last. A step that
 * would leave nothing falls back to the step before it (our types are a
 * syntactic approximation, and dropping every candidate would hide flows).
 * The result does not depend on the order of the declarations.
 */
function resolveJavaCallTargets(
  call: CallInfo,
  methodNodes: MethodNodeMaps,
  types: TypeInfo[],
): MethodNode[] {
  const name = call.method_name;
  const declares = (t: TypeInfo): boolean => t.methods.some(m => m.name === name);
  let owners: TypeInfo[] = [];
  if (call.receiver_type) {
    const rt = call.receiver_type;
    owners = types.filter(t => declares(t) && (t.name === rt || (t.package !== null && `${t.package}.${t.name}` === rt)));
  }
  if (owners.length === 0 && call.receiver) {
    const first = types.find(declares);
    if (first) owners = [first];
  }
  if (owners.length === 0) {
    const line = call.location.line;
    const around = types
      .filter(t => declares(t) && line >= t.start_line && line <= t.end_line)
      .sort((a, b) => (a.end_line - a.start_line) - (b.end_line - b.start_line));
    const first = around[0] ?? types.find(declares);
    if (first) owners = [first];
  }
  const candidates: MethodInfo[] = owners.flatMap(t => t.methods.filter(m => m.name === name));
  const chosen = selectJavaOverloads(candidates, call, types);
  const out: MethodNode[] = [];
  for (const m of chosen) {
    const node = methodNodes.byInfo.get(m);
    if (node && !out.includes(node)) out.push(node);
  }
  return out;
}

function selectJavaOverloads(candidates: MethodInfo[], call: CallInfo, types: TypeInfo[]): MethodInfo[] {
  if (candidates.length <= 1) return candidates;
  const n = call.arguments.length;
  const byArity = candidates.filter(m => javaArityFits(m, n));
  if (byArity.length === 0) return candidates;
  if (byArity.length === 1) return byArity;
  const argTypes = call.arguments.map(a => a.type ?? null);
  const applicable = byArity.filter(m => argTypes.every((t, i) => !javaArgDefinitelyIncompatibleAt(t, m, i, n, types)));
  if (applicable.length === 0) return byArity;
  if (applicable.length === 1) return applicable;
  const exact = applicable.filter(m => m.parameters.length === n && argTypes.every((t, i) => {
    const p = m.parameters[i]?.type;
    return t !== null && p !== null && p !== undefined && javaErasure(t).text === javaErasure(p).text;
  }));
  return exact.length === 1 ? exact : applicable;
}

/** A trailing parameter is varargs when spelled `T...`, or untyped (the default extractor reports a varargs parameter with no type). */
function javaIsVarargs(m: MethodInfo): boolean {
  const last = m.parameters[m.parameters.length - 1];
  return last !== undefined && (last.type === null || last.type.trimEnd().endsWith('...'));
}

function javaArityFits(m: MethodInfo, n: number): boolean {
  const k = m.parameters.length;
  return k === n || (javaIsVarargs(m) && n >= k - 1);
}

function javaArgDefinitelyIncompatibleAt(
  argType: string | null,
  m: MethodInfo,
  i: number,
  n: number,
  types: TypeInfo[],
): boolean {
  if (argType === null) return false;
  const k = m.parameters.length;
  const varargs = javaIsVarargs(m);
  if (varargs && i >= k - 1) {
    const raw = m.parameters[k - 1].type;
    if (raw === null) return false;
    const arrayType = raw.trimEnd().replace(/\.\.\.$/, '[]');
    const elemType = raw.trimEnd().replace(/\.\.\.$/, '');
    // One argument in the varargs slot may be the array itself.
    if (n === k && !javaArgDefinitelyIncompatible(argType, arrayType, types)) return false;
    return javaArgDefinitelyIncompatible(argType, elemType, types);
  }
  const p = m.parameters[i]?.type ?? null;
  return p === null ? false : javaArgDefinitelyIncompatible(argType, p, types);
}

const JAVA_PRIMITIVES = new Set(['byte', 'short', 'char', 'int', 'long', 'float', 'double', 'boolean']);
const JAVA_BOX: Record<string, string> = {
  byte: 'Byte', short: 'Short', char: 'Character', int: 'Integer',
  long: 'Long', float: 'Float', double: 'Double', boolean: 'Boolean',
};
const JAVA_UNBOX: Record<string, string> = Object.fromEntries(Object.entries(JAVA_BOX).map(([p, b]) => [b, p]));
const JAVA_WIDENS: Record<string, readonly string[]> = {
  byte: ['short', 'int', 'long', 'float', 'double'],
  short: ['int', 'long', 'float', 'double'],
  char: ['int', 'long', 'float', 'double'],
  int: ['long', 'float', 'double'],
  long: ['float', 'double'],
  float: ['double'],
  double: [],
  boolean: [],
};
const NUMBER_SUPERS = ['Number', 'Object', 'Comparable', 'Serializable', 'Constable', 'ConstantDesc'];
/**
 * Final JDK types whose every supertype is known: an argument of one of
 * these static types can be passed only to a parameter typed as one of its
 * supertypes, and no other class can be passed to a parameter of one of them.
 */
const JAVA_FINAL_SUPERS: Record<string, readonly string[]> = {
  String: ['String', 'Object', 'CharSequence', 'Comparable', 'Serializable', 'Constable', 'ConstantDesc'],
  Integer: ['Integer', ...NUMBER_SUPERS],
  Long: ['Long', ...NUMBER_SUPERS],
  Short: ['Short', 'Number', 'Object', 'Comparable', 'Serializable', 'Constable'],
  Byte: ['Byte', 'Number', 'Object', 'Comparable', 'Serializable', 'Constable'],
  Float: ['Float', ...NUMBER_SUPERS],
  Double: ['Double', ...NUMBER_SUPERS],
  Boolean: ['Boolean', 'Object', 'Comparable', 'Serializable', 'Constable'],
  Character: ['Character', 'Object', 'Comparable', 'Serializable', 'Constable'],
  Class: ['Class', 'Object', 'Serializable', 'Type', 'GenericDeclaration', 'AnnotatedElement', 'TypeDescriptor', 'OfField'],
};

/** A Java type spelled in source, erased: no annotations, type arguments or package; `...` read as `[]`. */
function javaErasure(raw: string): { base: string; dims: number; text: string } {
  let t = raw.replace(/@[\w.]+(?:\([^)]*\))?\s*/g, '').replace(/\bfinal\s+/g, '').trim();
  let prev = '';
  while (prev !== t) { prev = t; t = t.replace(/<[^<>]*>/g, ''); }
  t = t.replace(/\.\.\.$/, '[]').replace(/\s+/g, '');
  const dims = (t.match(/\[\]/g) ?? []).length;
  const qualified = t.replace(/\[\]/g, '');
  const base = qualified.slice(qualified.lastIndexOf('.') + 1);
  return { base, dims, text: base + '[]'.repeat(dims) };
}

/**
 * `true` only when an argument of static type `argType` certainly cannot be
 * passed to a parameter of type `paramType` (no subtyping, widening, boxing
 * or unboxing makes it fit). Anything this cannot decide (an unknown class,
 * a type variable, a supertype declared in another file) is compatible.
 */
function javaArgDefinitelyIncompatible(argType: string, paramType: string, types: TypeInfo[]): boolean {
  const a = javaErasure(argType);
  const p = javaErasure(paramType);
  if (!a.base || !p.base) return false;
  const declared = new Map<string, TypeInfo>();
  for (const t of types) if (!declared.has(t.name)) declared.set(t.name, t);
  // A type variable (or anything else we cannot read) decides nothing.
  const opaque = (b: string): boolean =>
    !JAVA_PRIMITIVES.has(b) && !(b in JAVA_FINAL_SUPERS) && !declared.has(b) && /^[A-Z][A-Z0-9]?$/.test(b);
  if (opaque(a.base) || opaque(p.base)) return false;
  if (a.base === 'null' && a.dims === 0) return p.dims === 0 && JAVA_PRIMITIVES.has(p.base);
  if (a.dims !== p.dims) {
    // An array goes to Object / Cloneable / Serializable, or to a shallower
    // array of one of those.
    if (a.dims > p.dims && ['Object', 'Cloneable', 'Serializable'].includes(p.base)) return false;
    return true;
  }
  if (a.dims > 0) {
    if (JAVA_PRIMITIVES.has(a.base) || JAVA_PRIMITIVES.has(p.base)) return a.base !== p.base;
    return javaArgDefinitelyIncompatible(a.base, p.base, types);
  }
  if (a.base === p.base) return false;
  const aPrim = JAVA_PRIMITIVES.has(a.base);
  const pPrim = JAVA_PRIMITIVES.has(p.base);
  if (aPrim && pPrim) return !JAVA_WIDENS[a.base].includes(p.base);
  if (aPrim) return !JAVA_FINAL_SUPERS[JAVA_BOX[a.base]].includes(p.base);
  if (pPrim) {
    const unboxed = JAVA_UNBOX[a.base];
    if (unboxed) return unboxed !== p.base && !JAVA_WIDENS[unboxed].includes(p.base);
    return true;
  }
  if (a.base in JAVA_FINAL_SUPERS) return !JAVA_FINAL_SUPERS[a.base].includes(p.base);
  if (p.base === 'Object') return false;
  if (p.base in JAVA_FINAL_SUPERS) return true;
  // A class or interface declared in this file: incompatible only when its
  // whole supertype closure is declared here too and does not hold the
  // parameter type.
  const start = declared.get(a.base);
  if (!start) return false;
  const seen = new Set<string>();
  const queue: TypeInfo[] = [start];
  while (queue.length > 0) {
    const t = queue.pop()!;
    if (seen.has(t.name)) continue;
    seen.add(t.name);
    for (const sup of [t.extends, ...t.implements]) {
      if (!sup) continue;
      const sb = javaErasure(sup).base;
      if (sb === p.base) return false;
      const st = declared.get(sb);
      if (!st) return false;   // a supertype from elsewhere could be anything
      queue.push(st);
    }
  }
  return !seen.has(p.base);
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
 * Dogfood 2026-10-31 (cognium-ai circle-ir-ai/src/cache/file-cache.ts) —
 * method resolution is by NAME on any receiver, so in a class with its own
 * `get` / `set`, `this.memoryCache.set(hash, entry)` on a
 * `Map<string, CacheEntry<T>>` field resolved to the class's `set` method and
 * produced a path_traversal flow into that method's `fs.writeFileSync`.
 *
 * Returns a test for "this receiver is declared in this file as a built-in
 * Map / WeakMap / Set / WeakSet". The receiver must be a plain identifier or a
 * `this.x` member (resolved against its last property name), and only a
 * declaration that positively says so counts: `x: Map<…>` / `ReadonlyMap` /
 * `Set<…>` / `ReadonlySet`, or `x = new Map(…)` / `new Set(…)`. Any other
 * receiver keeps the name-based resolution, so a `this.helper.run(x)` into a
 * project class is unaffected.
 */
function makeBuiltinCollectionReceiverTest(
  sourceCode: string,
): (receiver: string | null | undefined) => boolean {
  const memo = new Map<string, boolean>();
  return (receiver) => {
    const raw = (receiver ?? '').trim();
    const m = /^(?:this\.)?([A-Za-z_$][\w$]*)$/.exec(raw);
    if (!m || raw === 'this') return false;
    const name = m[1];
    const hit = memo.get(name);
    if (hit !== undefined) return hit;
    const n = name.replace(/[$]/g, '\\$&');
    const coll = '(?:Readonly)?(?:Weak)?(?:Map|Set)';
    const ctor = new RegExp(`(?<![\\w$.])${n}\\s*(?::[^=;]*)?=\\s*new\\s+(?:Weak)?(?:Map|Set)\\s*(?:<[^;]*>)?\\s*\\(`);
    const typed = new RegExp(`(?<![\\w$.])${n}\\s*[?!]?\\s*:\\s*${coll}\\s*<`);
    const thisCtor = new RegExp(`\\bthis\\.${n}\\s*=\\s*new\\s+(?:Weak)?(?:Map|Set)\\s*(?:<[^;]*>)?\\s*\\(`);
    const result = ctor.test(sourceCode) || typed.test(sourceCode) || thisCtor.test(sourceCode);
    memo.set(name, result);
    return result;
  };
}

/**
 * Build call edges from call information.
 * Uses receiver type information for precise method resolution.
 */
function buildCallEdges(
  calls: CallInfo[],
  methodNodes: MethodNodeMaps,
  types: TypeInfo[],
  collectionReceiver: ((receiver: string | null | undefined) => boolean) | null = null,
  isJava = false,
): CallEdge[] {
  const edges: CallEdge[] = [];

  for (const call of calls) {
    if (collectionReceiver !== null && collectionReceiver(call.receiver)) continue;
    // Find the caller method
    const callerMethod = call.in_method;
    if (!callerMethod) continue;

    // Resolve the call target(s) using receiver type (Java: every overload
    // the call may bind to gets an edge).
    const calleeKeys = isJava
      ? resolveJavaCallTargets(call, methodNodes, types).map(n => n.fqn)
      : [resolveMethodCall(call, methodNodes, types)].filter((k): k is string => k !== null);

    for (const calleeMethod of calleeKeys) {
      edges.push({
        callerMethod,
        calleeMethod,
        callLine: call.location.line,
        taintedArgs: [],
      });
    }
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

    const fqn = nodeKeyOf(methodNodes, methodCtx);

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
