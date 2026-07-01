/**
 * SinkFilterPass
 *
 * Applies the four-stage sink filtering pipeline to eliminate false positives,
 * followed by language-specific XPath/XSS suppression.
 *
 * Filter stages (applied in order):
 *   1. Dead code — remove sinks on unreachable lines
 *   2. Clean array elements — strong updates via constant propagation
 *   3. Clean variables — arguments proven non-tainted by constant propagation
 *   4. Sanitized sinks — sinks wrapped by a recognised sanitizer call
 *   5. Python XPath FP reduction
 *   6. JavaScript setAttribute FP reduction (safe attribute names)
 *   7. JavaScript XSS FP reduction
 *
 * Depends on: taint-matcher, constant-propagation, language-sources
 */

import type { TaintSource, TaintSink, TaintSanitizer, TypeInfo, MethodInfo } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { LanguageSourcesResult } from './language-sources-pass.js';
import { JS_TAINTED_PATTERNS } from './language-sources-pass.js';
import { LIBRARY_API_SURFACE_TAG } from '../library-api-surface-downgrade.js';

/**
 * Common XSS sanitizer patterns for JavaScript/TypeScript.
 * These indicate the assigned value has been sanitized before use.
 */
const JS_XSS_SANITIZERS = [
  /\bDOMPurify\.sanitize\s*\(/,
  /\bsanitizeHtml\s*\(/,
  /\bsanitize\s*\(/,
  /\bescapeHtml\s*\(/,
  /\bescapeHTML\s*\(/,
  /\bhtmlEscape\s*\(/,
  /\bxss\s*\(/,              // xss library
  /\bxssFilters\./,          // xss-filters library
  /\bvalidator\.escape\s*\(/,
  /\b(?:he|entities)\.encode\s*\(/,
  /\bencodeURIComponent\s*\(/,
  /\bencodeURI\s*\(/,
  /\bcreateSafeHTML\s*\(/,
  /\btrustAsHtml\s*\(/,      // Angular
  /\bbypassSecurityTrust/,   // Angular
];

// ---------------------------------------------------------------------------
// Stage 16 — JS log_injection (CWE-117) sanitizer patterns.
// (cognium-dev #216 sanitizer-wrapped FP — Sprint 52)
// ---------------------------------------------------------------------------
//
// Common CRLF-stripping / log-sanitization helpers. Used by Stage 16 both as
// an inline check on the sink line AND as a backward-scan check via the
// `isAssignedFromSanitizerPattern` helper.
const JS_LOG_INJECTION_SANITIZERS = [
  /\bstripCrlf\s*\(/,
  /\bstripCRLF\s*\(/,
  /\bremoveNewlines\s*\(/,
  /\bsanitizeLogValue\s*\(/,
  // Inline CRLF-stripping regex literal: .replace(/[\r\n]/g, '')
  /\.replace\(\s*\/\[\s*\\r\s*\\n\s*\]\/[gimsu]*\s*,\s*['"`]['"`]\s*\)/,
  // Inline CRLF sequence: .replace(/\r\n/g, '')
  /\.replace\(\s*\/\\r\\n\/[gimsu]*\s*,\s*['"`]['"`]\s*\)/,
];

// ---------------------------------------------------------------------------
// Stage 17 — Python ldap_injection (CWE-90) regex-strip wrapper recognition.
// (cognium-dev #216 sanitizer-wrapped FP — Sprint 52)
// ---------------------------------------------------------------------------
//
// Built-in Python LDAP sanitizer call-site names. Augmented at scan time with
// derived wrapper functions detected via `findPythonLdapStripWrappers`.
const PY_BUILTIN_LDAP_SANITIZERS = ['escape_filter_chars', 'filter_format'];

// Python `def name(param):` followed (within a few lines) by
// `return re.sub(r"[<class>]", "", param)` where the character class contains
// at least three of the LDAP filter metacharacters from RFC 4515.
const PY_LDAP_METACHARS = ['(', ')', '=', '*', '\\'];
const PY_DEF_RE = /^\s*def\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*:\s*$/;
const PY_LDAP_STRIP_RETURN_RE =
  /^\s*return\s+re\.sub\(\s*r?["']\[([^"'\]]+)\]["']\s*,\s*r?["']["']\s*,\s*([A-Za-z_]\w*)\s*\)\s*$/;

// ---------------------------------------------------------------------------
// Stage 18 — Python xxe (CWE-611) parser-variable / wrapper recognition.
// (cognium-dev #216 sanitizer-wrapped FP — Sprint 52)
// ---------------------------------------------------------------------------
//
// `XMLParser(...resolve_entities=False...)` constructor — when present in the
// 30 lines above an xxe sink (same enclosing scope), the parser is hardened
// and the sink is safe.
const PY_XML_PARSER_HARDENED_RE =
  /\bXMLParser\s*\([^)]*\bresolve_entities\s*=\s*False\b[^)]*\)/;

// ---------------------------------------------------------------------------
// Stage 19 — Python sql_injection regex-allowlist-quoter wrapper suppression.
// (cognium-dev #215 — Sprint 53; Python port of Java Stage 15 #191)
// ---------------------------------------------------------------------------
//
// Python f-string SQL where identifier interpolations route through an
// in-file helper that validates with `re.fullmatch(allowlist, name)`
// + `raise`, and values flow through bind placeholders (?, %s, :name),
// is a parameterized query with an identifier-interpolation wrapper.
// Helper is the sanitizer; bind placeholder proves values do not concat.
const PY_SQL_EXEC_METHODS = new Set<string>(['execute', 'executemany']);
// Recognises Python `re.fullmatch(r"<regex>", …)` / `re.match(r"^<…>$", …)`
// — fullmatch is implicitly anchored; match requires explicit `^…$`.
const PY_INLINE_FULLMATCH_RE =
  /\bre\s*\.\s*fullmatch\s*\(\s*r?"((?:[^"\\]|\\.)*)"/g;
const PY_INLINE_MATCH_ANCHORED_RE =
  /\bre\s*\.\s*match\s*\(\s*r?"\^((?:[^"\\]|\\.)*)\$"/g;
// Bind placeholders: `?` (sqlite3/odbc), `%s` (psycopg2/mysqlclient),
// `:name` (named placeholders). All proof of bind-arg routing.
const PY_BIND_PLACEHOLDER_RE = /\?|%s|:[A-Za-z_]\w*/;

// ---------------------------------------------------------------------------
// Stage 9 — Java code_injection (CWE-094) FP reduction allowlists.
// (cognium-dev #155, #156, #159, #160 — Sprint 42)
// ---------------------------------------------------------------------------

// #155 — non-script data parsers misclassified as code-injection sinks.
const DATA_PARSER_TYPES = new Set<string>([
  'Parser',                 // commonmark, airline, picocli, jcommander
  'CommandLine', 'JCommander',
  'DateParser', 'FastDateFormat', 'FastDatePrinter',
  'ResultParser',
  'DateFormat', 'SimpleDateFormat',
  'NumberFormat', 'DecimalFormat',
  'OptionParser', 'CmdLineParser',
]);

// #156 — compiled-template classes; risk lives at the compile step,
// not the render step.
const COMPILED_TEMPLATE_TYPES = new Set<string>([
  'Template',               // Freemarker, Velocity
  'JetTemplate',            // Jetbrick
  'ITemplate',              // Rythm
  'VelocityTemplate', 'BeetlTemplate',
]);

// #159 — reflection methods whose first arg, when literal /
// annotation-accessor / empty, makes the call statically resolvable.
const REFLECTION_LITERAL_METHODS = new Set<string>([
  'forName', 'loadClass',
  'getMethod', 'getDeclaredMethod',
  'getConstructor', 'getDeclaredConstructor',
  'parseExpression',
  'invoke',                 // no further args = no payload injection
]);

// Java declaration regex template; receiver name is interpolated.
// Receiver is pre-validated by /^[A-Za-z_]\w*$/ so regex metacharacter
// injection is impossible.
const JAVA_DECL_RE_TEMPLATE =
  '(?:\\b(?:final|public|private|protected|static)\\s+)*' +
  '([A-Z]\\w*(?:\\.[A-Z]\\w*)?(?:<[^>]*>)?)\\s+RECV\\b\\s*[=;,)]';

// ---------------------------------------------------------------------------
// Stage 10 — Java command_injection (CWE-78) FP reduction.
// (cognium-dev #167, #170 — Sprint 43)
// ---------------------------------------------------------------------------

// #170 — protocol-client wire-method names (overlap with the
// genuine OS-exec method names; this set is consulted only when
// the file also imports a protocol-client package).
const PROTOCOL_WIRE_METHODS = new Set<string>([
  'executeCommand', 'execute', 'dispatch',
  'send', 'publish', 'command', 'run',
]);

// #170 — packages whose presence indicates a protocol-client file.
// Conservative list: well-known JVM Redis / MQ / DB drivers.
const PROTOCOL_CLIENT_PACKAGES: readonly string[] = [
  'redis.clients.jedis',
  'io.lettuce',
  'org.springframework.data.redis',
  'org.springframework.data.mongodb',
  'org.springframework.amqp',
  'com.rabbitmq',
  'org.apache.kafka',
  'org.eclipse.paho',
];

// Defense-in-depth: even inside a protocol-client file, do not
// suppress a sink whose receiver is explicitly an OS-exec class.
const OS_EXEC_RECEIVER_RE =
  /\b(?:Runtime|ProcessBuilder|DefaultExecutor|Executor|Exec|Launcher|ProcStarter|ProcessExecutor|RuntimeUtil)\s*[.(]/;

// ---------------------------------------------------------------------------
// Stage 11 — Java command_injection (CWE-78) FP reduction.
// (cognium-dev #179 Sink 1 — Sprint 44)
// ---------------------------------------------------------------------------

// #179 Sink 1 — argv-form ProcessBuilder constructor shapes.
// Java's ProcessBuilder(List<String>) and ProcessBuilder(String...)
// overloads pass argv directly to fork(2): no shell, no metacharacter
// expansion. Only single-string-variable construction remains exploitable.
//
// Matches any of:
//   new ProcessBuilder(Arrays.asList(...))
//   new ProcessBuilder(List.of(...))
//   new ProcessBuilder(Collections.singletonList(...))
//   new ProcessBuilder(new ArrayList<...>(...))
//   new ProcessBuilder(new String[]{ ... })
//   new ProcessBuilder("...", ...)        (varargs ≥2 args; first is string literal)
const PROCESS_BUILDER_ARGV_FORM_RE =
  /\bnew\s+ProcessBuilder\s*\(\s*(?:Arrays\.asList\b|List\.of\b|Collections\.singletonList\b|new\s+ArrayList\b|new\s+String\s*\[\s*\]\s*\{|"[^"]*"\s*,)/;

// ---------------------------------------------------------------------------
// Stage 12 — Java throw-statement FP suppression.
// (cognium-dev #157 — Sprint 45)
// ---------------------------------------------------------------------------
//
// `throw new <SomeException|Error>(...)` is structurally never a runtime
// sink: it constructs the exception object then unwinds the stack. No
// SQL execution, no command exec, no XSS, no path I/O happens. Drops any
// sink whose own line begins with `throw new <Word>(Exception|Error)`.
// Sink-type-agnostic: a throw is never a runtime sink regardless of CWE.
const JAVA_THROW_STATEMENT_RE = /^\s*throw\s+new\s+\w+(?:Exception|Error)\b/;

// ---------------------------------------------------------------------------
// Stage 9e — Java code_injection (CWE-094) library-API surface tag.
// (cognium-dev #161 — Sprint 47)
// ---------------------------------------------------------------------------
//
// JEXL engine entry points (`JexlEngine.createExpression`,
// `Expression.evaluate`) and template-engine compile methods
// (`Handlebars.compile`, `Pebble.compile`, `Velocity` configure,
// …) are the *library API surface*. The library cannot know whether
// the supplied script string came from a trusted source — that
// trust call belongs to the caller. Tagging downgrades from HIGH/
// CRITICAL → MEDIUM rather than suppressing.
const JEXL_ENGINE_TYPES = new Set<string>(['JexlEngine', 'Jexl', 'JxltEngine']);
const JEXL_EXPRESSION_TYPE_RE = /(?:Jexl)?(?:Expression|Script|Template)(?:Script)?$/;
const TEMPLATE_COMPILE_RECEIVER_TYPES = new Set<string>([
  'Handlebars', 'Mustache', 'MustacheFactory', 'DefaultMustacheFactory',
  'Pebble', 'PebbleEngine', 'PebbleEngineBuilder',
  'VelocityEngine', 'Velocity',
  'Configuration',
  'Freemarker', 'FreeMarker',
  'TemplateEngine', 'SpringTemplateEngine',
  'Thymeleaf',
]);

// ---------------------------------------------------------------------------
// Stage 9f — Java code_injection (CWE-094) SPI loader tag.
// (cognium-dev #165 — Sprint 47)
// ---------------------------------------------------------------------------
//
// `Class.forName(<var>)` whose enclosing method also calls
// `getResources("META-INF/services/...")` is an SPI loader. The
// service class names come from a resource file packaged with the
// JAR, not from request data. Library-API surface — tag + downgrade.
const SPI_GET_RESOURCES_RE =
  /\.getResources\s*\(\s*["'][^"']*META-INF\/services\/[^"']*["']\s*\)/;

// ---------------------------------------------------------------------------
// Stage 9g — Java code_injection (CWE-094) ClassLoader override tag.
// (cognium-dev #168 — Sprint 47)
// ---------------------------------------------------------------------------
//
// `ClassLoader.loadClass(String)` / `findClass(String)` inside a
// subclass of ClassLoader/URLClassLoader/SecureClassLoader (or
// inside a `CachingProvider` SPI) is implementing the JDK / JSR
// API contract. Trust call belongs to the framework caller, not
// the implementation. Tag + downgrade.
const CLASSLOADER_PARENT_TYPES = new Set<string>([
  'ClassLoader', 'URLClassLoader', 'SecureClassLoader',
]);
const CLASSLOADER_NAME_RE = /(?:CachingProvider|ClassLoader|SpiLoader)$/;
const LOADCLASS_OVERRIDE_METHOD_RE =
  /\b(?:public|protected)\s+(?:[\w<>?,\s]+\s+)?(?:loadClass|findClass)\s*\(\s*String\b/;
const JAVA_CLASS_DECL_RE =
  /\bclass\s+([A-Z]\w*)\b(?:\s+extends\s+([A-Z][\w.]*))?(?:\s+implements\s+([A-Z][\w.,<>\s?]*))?/;

// ---------------------------------------------------------------------------
// Stage 13 — Java sql_injection SQL builder wrapper suppression.
// (cognium-dev #163 — Sprint 47)
// ---------------------------------------------------------------------------
//
// Inside `*Dialect` / `*SqlBuilder` / `*Quoter` / `*QueryBuilder`
// classes, a `.wrap(...)` / `.quote(...)` / `.escape(...)` /
// `.identifier(...)` call returns an already-quoted SQL fragment.
// Concat into a larger SQL string is the standard codegen idiom;
// the wrapper is the sanitizer.
const SQL_BUILDER_CLASS_RE =
  /(?:Dialect|SqlBuilder|Quoter|Wrapper|SqlGenerator|QueryBuilder)$/;
const SQL_BUILDER_WRAPPER_CALL_RE = /\.(?:wrap|quote|escape|identifier)\s*\(/;

// ---------------------------------------------------------------------------
// Stage 14 — Java sql_injection SQL-extraction-method suppression.
// (cognium-dev #177 — Sprint 47)
// ---------------------------------------------------------------------------
//
// Methods that *return* a SQL string (`String getInsertSql(Insert)`,
// `String toSql(Expression)`, `String extractQueryString(Statement)`)
// from a typed AST/builder input are SQL *codegen*, not SQL *execution*.
// The taint engine sees the returned string flowing into a downstream
// concat, but at this site there is no statement execution.
const SQL_EXTRACTION_RETURN_RE = /^(?:String|CharSequence|Optional\s*<\s*String\s*>)$/;
const SQL_EXTRACTION_NAME_RE =
  /^(?:get|extract|build).*(?:[Ss]ql|[Qq]uery)|^toSql|.*Statement.*ToString$|.*Query.*String$/;
const SQL_EXTRACTION_PRIMITIVE_INPUT_RE = /^(?:String|CharSequence)$/;

// ---------------------------------------------------------------------------
// Stage 15 — Java sql_injection regex-allowlist-quoter wrapper suppression.
// (cognium-dev #191 / FP-77 — Sprint 49)
// ---------------------------------------------------------------------------
//
// Generalises Stage 13: a SQL string assembled from string literals +
// in-file helper-method calls (where the helper validates its argument
// with an inline regex allowlist + throw) AND containing a `?`
// placeholder for value binding is a parameterized query with an
// identifier-interpolation wrapper. The wrapper is the sanitizer; the
// `?` placeholder proves user values flow through bind args, not concat.
//
// Stage 13 required a `*Dialect|*SqlBuilder|*Quoter|*QueryBuilder`
// class-name suffix; FP-77 cases (utility classes like
// `SafeSqlIdentifierQuote`) don't carry that suffix. Stage 15 drops the
// class-name gate and instead inspects the helper's body for the
// regex-allowlist+throw shape that proves the parameter is validated.
const SQL_EXEC_METHODS = new Set<string>([
  'prepareStatement', 'prepareCall',
  'execute', 'executeQuery', 'executeUpdate', 'executeLargeUpdate',
  'addBatch',
]);
const JAVA_SQL_ASSIGN_RE_TEMPLATE =
  '\\b(?:String|CharSequence|final\\s+String|var)\\s+SQLVAR\\b\\s*=\\s*(.+?);';
// Recognises Java `String.matches("regex")` — implicitly anchored ^…$.
const JAVA_INLINE_MATCHES_RE = /\.\s*matches\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)/g;

function resolveJavaReceiverType(
  receiver: string,
  sinkLine: number,
  sourceLines: string[],
): string | null {
  if (!receiver || !/^[A-Za-z_]\w*$/.test(receiver)) return null;
  const start = Math.max(0, sinkLine - 31);
  const declRe = new RegExp(JAVA_DECL_RE_TEMPLATE.replace('RECV', receiver));
  for (let i = sinkLine - 2; i >= start; i--) {
    const ln = sourceLines[i] ?? '';
    const m = ln.match(declRe);
    if (m) {
      const raw = m[1].replace(/<[^>]*>/g, '').trim();
      const parts = raw.split('.');
      return parts[parts.length - 1] ?? null;
    }
  }
  return null;
}

/**
 * Backward-scan for the enclosing `class X extends Y implements Z`
 * declaration. Returns null when no class declaration is found within
 * the file up to `sinkLine`. Used by Stage 9g (#168) and Stage 13 (#163).
 */
function findEnclosingClassDecl(
  sinkLine: number,
  sourceLines: string[],
): { name: string; extendsType: string | null; implementsTypes: string[] } | null {
  const end = Math.min(sourceLines.length, sinkLine);
  for (let i = end - 1; i >= 0; i--) {
    const ln = sourceLines[i] ?? '';
    const m = ln.match(JAVA_CLASS_DECL_RE);
    if (!m) continue;
    const implementsTypes = m[3]
      ? m[3].split(',').map(s => s.replace(/<[^>]*>/g, '').trim()).filter(Boolean)
          .map(s => { const parts = s.split('.'); return parts[parts.length - 1] ?? s; })
      : [];
    const extendsRaw = m[2] ?? null;
    const extendsType = extendsRaw
      ? (() => { const p = extendsRaw.split('.'); return p[p.length - 1] ?? extendsRaw; })()
      : null;
    return { name: m[1], extendsType, implementsTypes };
  }
  return null;
}

/**
 * Backward-scan for the enclosing method signature that overrides
 * `loadClass(String)` or `findClass(String)`. Heuristic textual match.
 * Stops at a class-body open brace at column 0 (no enclosing method).
 */
function isInsideLoadClassOverride(
  sinkLine: number,
  sourceLines: string[],
): boolean {
  const limit = Math.max(0, sinkLine - 200);
  for (let i = sinkLine - 2; i >= limit; i--) {
    const ln = sourceLines[i] ?? '';
    if (LOADCLASS_OVERRIDE_METHOD_RE.test(ln)) return true;
    // Stop scanning if we hit a class declaration without finding the method.
    if (/\bclass\s+[A-Z]\w*\b/.test(ln)) return false;
  }
  return false;
}

/**
 * Find the IR `MethodInfo` whose line range contains `sinkLine`. Returns
 * null when no method declaration covers the line. Used by Stage 14 (#177).
 */
function findEnclosingMethodFromIr(
  types: TypeInfo[],
  sinkLine: number,
): MethodInfo | null {
  for (const t of types) {
    if (sinkLine < t.start_line || sinkLine > t.end_line) continue;
    for (const m of t.methods) {
      if (sinkLine >= m.start_line && sinkLine <= m.end_line) return m;
    }
  }
  return null;
}

/**
 * Stage 15 (#191) — split a Java string-concat RHS into top-level
 * `+`-separated tokens. Respects double-quoted strings and parenthesis
 * depth so commas / `+` characters inside string literals or nested
 * call argument lists do not split.
 */
function splitJavaConcatTokens(rhs: string): string[] {
  const tokens: string[] = [];
  let cur = '';
  let depth = 0;
  let inString = false;
  let i = 0;
  while (i < rhs.length) {
    const ch = rhs[i] ?? '';
    if (inString) {
      cur += ch;
      if (ch === '\\' && i + 1 < rhs.length) {
        cur += rhs[i + 1] ?? '';
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i++;
      continue;
    }
    if (ch === '"') { inString = true; cur += ch; i++; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; cur += ch; i++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth--; cur += ch; i++; continue; }
    if (ch === '+' && depth === 0) {
      tokens.push(cur.trim());
      cur = '';
      i++;
      continue;
    }
    cur += ch;
    i++;
  }
  if (cur.trim()) tokens.push(cur.trim());
  return tokens;
}

/**
 * Stage 15 (#191) — true when the regex literal would compile to a
 * strict-anchored allowlist: under `String.matches()` the regex is
 * implicitly anchored `^…$`, so any pattern that — after stripping
 * `[…]` character classes and escape sequences — contains no bare
 * `.` (any-char) and no `|` (alternation) admits only the listed
 * characters. Mirrors `propagator.ts:isStrictAnchoredRegex` minus the
 * `^…$` requirement (which is implicit for `String.matches`).
 */
function isImplicitlyAnchoredAllowlistRegex(re: string): boolean {
  if (re === '') return false;
  const stripped = re.replace(/\[(?:[^\]\\]|\\.)*\]/g, '');
  const cleaned = stripped.replace(/\\./g, '');
  if (cleaned.includes('.')) return false;
  if (cleaned.includes('|')) return false;
  return true;
}

/**
 * Stage 15 (#191) — locate a Java method body in source text by name.
 * Returns the body lines (between the opening `{` and the matching
 * `}` at the same brace depth) or null when not found / not bracketed.
 *
 * Heuristic textual scan — does not parse generics; sufficient for the
 * regex-allowlist guard recognition we need.
 */
function findJavaMethodBody(
  methodName: string,
  sourceLines: string[],
): string[] | null {
  if (!/^[A-Za-z_]\w*$/.test(methodName)) return null;
  const sigRe = new RegExp(
    `\\b(?:public|private|protected|static|final|synchronized|\\s)+[\\w<>?,\\s\\[\\]]+?\\b${methodName}\\s*\\(`,
  );
  for (let i = 0; i < sourceLines.length; i++) {
    const ln = sourceLines[i] ?? '';
    if (!sigRe.test(ln)) continue;
    // Scan forward for the opening `{` (may be on same or following line).
    let braceLine = -1;
    for (let j = i; j < Math.min(sourceLines.length, i + 4); j++) {
      if ((sourceLines[j] ?? '').includes('{')) { braceLine = j; break; }
    }
    if (braceLine < 0) continue;
    // Collect body lines until brace depth returns to 0.
    let depth = 0;
    const body: string[] = [];
    for (let j = braceLine; j < sourceLines.length; j++) {
      const ln2 = sourceLines[j] ?? '';
      body.push(ln2);
      for (const ch of ln2) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (depth <= 0 && j > braceLine) return body;
    }
    return null;
  }
  return null;
}

/**
 * Stage 15 (#191) — true if the Java method body contains an inline
 * `var.matches("strict-anchored-regex")` call AND a `throw` statement
 * appears later in the body. The two need not be in the same `if`; the
 * combination proves the parameter is validated and any non-allowlisted
 * input terminates execution before reaching the return.
 */
function javaBodyHasInlineRegexAllowlistThrow(bodyLines: string[]): boolean {
  const text = bodyLines.join('\n');
  if (!/\bthrow\s+/.test(text)) return false;
  JAVA_INLINE_MATCHES_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = JAVA_INLINE_MATCHES_RE.exec(text)) !== null) {
    if (isImplicitlyAnchoredAllowlistRegex(m[1] ?? '')) return true;
  }
  return false;
}

function isJavaLiteralOrAnnotationAccessor(expr: string): boolean {
  const e = expr.trim();
  if (e === '') return true;                                       // no args
  if (/^"(?:[^"\\]|\\.)*"$/.test(e)) return true;                  // string literal
  if (/^[A-Za-z_]\w*\s*\.\s*(?:value|name|key)\s*\(\s*\)$/.test(e)) return true; // ann.value()
  return false;
}

/**
 * Extract the top-level argument list from a Java method call. Allows one
 * level of nested parens so `ann.value()` is captured whole. Returns null
 * when the call can't be located. Returns `[]` for empty arg lists.
 */
function extractJavaCallArgs(method: string, line: string): string[] | null {
  const re = new RegExp(`\\b${method}\\s*\\(([^()]*(?:\\([^()]*\\)[^()]*)*)\\)`);
  const m = line.match(re);
  if (!m) return null;
  const argsText = m[1].trim();
  if (argsText === '') return [];
  return argsText.split(',').map(s => s.trim());
}

/**
 * Returns true if the file imports any class from `packagePrefix`.
 * Bounded scan — Java imports live in the first ~80 lines. Conservative:
 * matches both regular and static imports.
 */
function hasJavaImportFromPackage(
  packagePrefix: string,
  sourceLines: string[],
): boolean {
  if (!/^[A-Za-z_][\w.]*$/.test(packagePrefix)) return false;
  const limit = Math.min(sourceLines.length, 80);
  const re = new RegExp(
    `^\\s*import\\s+(?:static\\s+)?${packagePrefix.replace(/\./g, '\\.')}\\b`,
  );
  for (let i = 0; i < limit; i++) {
    if (re.test(sourceLines[i] ?? '')) return true;
  }
  return false;
}

export interface SinkFilterResult {
  /** Merged sources: taint-matcher + language-sources. */
  sources: TaintSource[];
  /** Filtered sinks. */
  sinks: TaintSink[];
  sanitizers: TaintSanitizer[];
}

export class SinkFilterPass implements AnalysisPass<SinkFilterResult> {
  readonly name = 'sink-filter';
  readonly category = 'security' as const;

  run(ctx: PassContext): SinkFilterResult {
    const { graph, language } = ctx;
    const { calls, dfg } = graph.ir;

    const taintMatcher = ctx.getResult<TaintMatcherResult>('taint-matcher');
    const constProp    = ctx.getResult<ConstantPropagatorResult>('constant-propagation');
    const langSources  = ctx.getResult<LanguageSourcesResult>('language-sources');

    // Merge sources and sinks from both upstream passes.
    const sources: TaintSource[] = [...taintMatcher.sources, ...langSources.additionalSources];

    // Build merged sinks, deduplicating JS DOM sinks that may overlap with config sinks.
    const sinks: TaintSink[] = [...taintMatcher.sinks];
    for (const s of langSources.additionalSinks) {
      if (!sinks.some(x => x.line === s.line && x.cwe === s.cwe && x.type === s.type)) {
        sinks.push(s);
      }
    }
    const sanitizers: TaintSanitizer[] = [
      ...taintMatcher.sanitizers,
      ...(langSources.additionalSanitizers ?? []),
    ];

    // Stage 1 — dead code
    let filtered = sinks.filter(sink => !constProp.unreachableLines.has(sink.line));

    // Stage 2 — clean array elements
    filtered = filterCleanArraySinks(filtered, calls, constProp.taintedArrayElements, constProp.symbols);

    // Stage 3 — clean variables
    filtered = filterCleanVariableSinks(
      filtered, calls, constProp.tainted, constProp.symbols,
      dfg, constProp.sanitizedVars, constProp.synchronizedLines, language,
    );

    // Stage 4 — sanitized sinks
    filtered = filterSanitizedSinks(filtered, sanitizers, calls);

    // Stage 5 — Python XPath FP reduction
    if (language === 'python') {
      const { pyTaintedVars, pySanitizedVars } = langSources;
      const sourceLines = ctx.code.split('\n');
      // cognium-dev#104 (Sprint 22) — OOP field-path sources (`self.<field>`)
      // emitted by `findOopFieldReadSources` aren't captured in
      // `pyTaintedVars` (which is built by intra-procedural textual scanning).
      // Collect OOP field-path source variables so xpath sinks reachable
      // via constructor-injected fields aren't pruned as "no tainted var on
      // line" in OOP shapes such as
      //   class Q: __init__(self, q): self.q = q
      //          def find(self, tree): return tree.xpath(f"...{self.q}...")
      const oopFieldVars = new Set<string>();
      for (const s of sources) {
        if (s.variable && s.variable.startsWith('self.')) {
          oopFieldVars.add(s.variable);
        }
      }
      filtered = filtered.filter(sink => {
        if (sink.type !== 'xpath_injection') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        const taintedVarOnLine = [...pyTaintedVars.keys()].find(v =>
          new RegExp(`\\b${v}\\b`).test(sinkLineText)
        );
        // OOP escape — if the sink line references `self.<field>` for one
        // of the constructor-injected OOP sources, accept it (#104).
        const oopVarOnLine = [...oopFieldVars].find(v =>
          sinkLineText.includes(v)
        );
        if (oopVarOnLine) return true;
        if (!taintedVarOnLine) return false;
        if (pySanitizedVars.has(taintedVarOnLine)) return false;
        if (new RegExp(`\\.xpath\\s*\\([^)]*\\b\\w+\\s*=\\s*\\b${taintedVarOnLine}\\b`).test(sinkLineText)) return false;
        return true;
      });
    }

    // Build call-by-line index for Stages 6–7.
    const callsByLine = new Map<number, typeof calls>();
    for (const call of calls) {
      const existing = callsByLine.get(call.location.line) ?? [];
      existing.push(call);
      callsByLine.set(call.location.line, existing);
    }

    // Stage 6 — JavaScript setAttribute FP reduction
    // Only flag setAttribute when the attribute name is dangerous (on*, style, srcdoc).
    if (['javascript', 'typescript'].includes(language)) {
      filtered = filtered.filter(sink => {
        if (sink.method !== 'setAttribute') return true;
        const callsAtSink = callsByLine.get(sink.line) ?? [];
        const setAttrCalls = callsAtSink.filter(c => c.method_name === 'setAttribute');
        for (const call of setAttrCalls) {
          const firstArg = call.arguments[0];
          if (!firstArg) continue;
          // If first arg is a string literal, check if it's a dangerous attribute
          const attrName = firstArg.literal ?? (
            firstArg.expression && !firstArg.variable && isStringLiteralExpression(firstArg.expression)
              ? firstArg.expression.trim().replace(/^['"]|['"]$/g, '')
              : null
          );
          if (attrName != null) {
            const lower = String(attrName).toLowerCase();
            if (/^on\w+$/.test(lower) || lower === 'style' || lower === 'srcdoc') return true;
            return false; // Safe attribute like 'title', 'class', 'id', etc.
          }
          // Attribute name is dynamic — keep as dangerous (conservative)
          return true;
        }
        return true;
      });
    }

    // Stage 7 — JavaScript XSS FP reduction
    if (['javascript', 'typescript'].includes(language)) {
      const { jsTaintedVars } = langSources;
      const sourceLines = ctx.code.split('\n');

      filtered = filtered.filter(sink => {
        if (sink.type !== 'xss') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';

        // 6a. If a sanitizer is used on this line, suppress the finding
        if (JS_XSS_SANITIZERS.some(p => p.test(sinkLineText))) return false;

        // 6b. If the RHS is a pure string literal, suppress (e.g., `.innerHTML = "<div>Hello</div>"`)
        //     Match: `.innerHTML = "..."` or `.innerHTML = '...'` or `.innerHTML = `...``
        const assignmentMatch = sinkLineText.match(/\.(?:innerHTML|outerHTML)\s*=\s*(.+)/);
        if (assignmentMatch) {
          // Strip trailing semicolon and whitespace
          const rhs = assignmentMatch[1].trim().replace(/;$/, '').trim();
          // Pure double-quoted string literal
          if (/^"[^"]*"$/.test(rhs)) return false;
          // Pure single-quoted string literal
          if (/^'[^']*'$/.test(rhs)) return false;
          // Template literal without interpolation
          if (/^`[^`]*`$/.test(rhs) && !rhs.includes('${')) return false;
          // Empty string
          if (rhs === '""' || rhs === "''" || rhs === '``') return false;
        }

        // 6c. Validation-guard heuristic: suppress .href / location sinks inside validated blocks.
        // If nearby lines (within 5 lines above) contain a conditional validation pattern
        // (if + includes/startsWith/indexOf/test/match/endsWith), suppress the sink.
        if (/\.href\s*=|location\s*=/.test(sinkLineText)) {
          const guardPatterns = /\b(?:includes|startsWith|endsWith|indexOf|test|match)\s*\(/;
          const startLine = Math.max(0, sink.line - 6);
          for (let i = startLine; i < sink.line - 1; i++) {
            const line = sourceLines[i] ?? '';
            if (/\bif\s*\(/.test(line) && guardPatterns.test(line)) {
              return false;
            }
          }
        }

        // 6d. If known tainted vars exist, require one on this line to keep the sink
        if (jsTaintedVars.size > 0) {
          if ([...jsTaintedVars.keys()].some(v => new RegExp(`\\b${v}\\b`).test(sinkLineText))) return true;
          if (JS_TAINTED_PATTERNS.some(p => p.pattern.test(sinkLineText))) return true;
          return false;
        }

        // 6d. No tainted vars tracked — check if line has any obvious taint source patterns
        //     If none found and RHS looks like a variable, keep the sink (conservative)
        if (JS_TAINTED_PATTERNS.some(p => p.pattern.test(sinkLineText))) return true;

        // 6e. Check if RHS is a known constant from constant propagation
        if (assignmentMatch) {
          const rhsClean = assignmentMatch[1].trim().replace(/;$/, '').trim();
          // If RHS is just an identifier, check if it's a known constant
          const identMatch = rhsClean.match(/^(\w+)$/);
          if (identMatch) {
            const varName = identMatch[1];
            const symbolInfo = constProp.symbols.get(varName);
            if (symbolInfo && symbolInfo.type === 'string') return false;
          }
        }

        // Default: keep the sink (conservative when no taint info available)
        return true;
      });
    }

    // Stage 8 — JavaScript open_redirect / crlf / header_injection FP reduction.
    // Suppresses res.redirect(url) and res.setHeader(...) sinks when an
    // allowlist/validation guard appears within 6 lines above the sink, OR
    // when the sink call's tainted argument is a literal (CORS '*' etc).
    // (cognium-dev #99, #132)
    if (['javascript', 'typescript'].includes(language)) {
      const sourceLines = ctx.code.split('\n');
      // #132 — `has` covers Set/Map allowlist primitive: ALLOWED.has(url).
      const guardPatterns = /\b(?:includes|startsWith|endsWith|indexOf|test|match|has)\s*\(/;
      filtered = filtered.filter(sink => {
        if (sink.type !== 'open_redirect' && sink.type !== 'crlf') {
          return true;
        }
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        // 8a. Conditional-allowlist guard: if (allowed.includes(x)) res.redirect(x);
        const startLine = Math.max(0, sink.line - 7);
        for (let i = startLine; i < sink.line - 1; i++) {
          const line = sourceLines[i] ?? '';
          if (/\bif\s*\(/.test(line) && guardPatterns.test(line)) {
            return false;
          }
        }
        // 8b. Sanitized via encodeURIComponent/encodeURI on the sink line.
        if (/\bencodeURIComponent\s*\(|\bencodeURI\s*\(/.test(sinkLineText)) {
          return false;
        }
        // 8c. setHeader literal value: res.setHeader('Name', '*') / 'literal'.
        // Match e.g. `res.setHeader('X-Foo', '*')` where 2nd arg is a literal.
        const setHeaderMatch = sinkLineText.match(/setHeader\s*\(\s*[^,]+,\s*(['"`])([^'"`]*)\1\s*\)/);
        if (setHeaderMatch) {
          return false;
        }
        // 8d. Express/Koa `res.cookie(name, value, [opts])` is CRLF-safe by
        // construction: the cookie helper serializes via `cookie.serialize()`
        // which URL-encodes CR (%0D) / LF (%0A). The raw-header path
        // `setHeader('Set-Cookie', tainted)` is still flagged via 8c-or-default.
        // (cognium-dev #132)
        if (sink.method === 'cookie' && sink.type === 'crlf') {
          return false;
        }
        return true;
      });
    }

    // Stage 9 — Java code_injection (CWE-094) FP reduction.
    // (cognium-dev #155, #156, #159, #160 — Sprint 42)
    //
    // Conservative-bias default: any code_injection sink whose receiver
    // type or arg shape doesn't match one of the four known-safe shapes
    // below continues to fire. Recall on tainted Class.forName /
    // SpEL / template-compile is unchanged.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'code_injection') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        const receiverMatch = sinkLineText.match(/\b(\w+)\s*\.\s*(\w+)\s*\(/);
        const receiver = receiverMatch?.[1];
        const method = sink.method ?? receiverMatch?.[2];

        // 9a — #155: non-script data parsers (commonmark, hutool, zxing,
        // CLI arg parsers, SimpleDateFormat, DecimalFormat, …).
        if (method === 'parse' && receiver) {
          const recvType = resolveJavaReceiverType(receiver, sink.line, sourceLines);
          if (recvType && DATA_PARSER_TYPES.has(recvType)) return false;
        }

        // 9b — #156: compiled-template render/process. Risk lives at the
        // compile step, not the render step.
        if (
          (method === 'render' || method === 'process' ||
           method === 'merge' || method === 'renderTo') && receiver
        ) {
          const recvType = resolveJavaReceiverType(receiver, sink.line, sourceLines);
          if (recvType && COMPILED_TEMPLATE_TYPES.has(recvType)) return false;
        }

        // 9c — #159: reflection / SpEL with literal / annotation-accessor
        // first arg. Static-resolvable target is not code injection.
        // Special case for `invoke`: `method.invoke(target)` with no
        // further args has no payload (target is just the receiver).
        if (method && REFLECTION_LITERAL_METHODS.has(method)) {
          const args = extractJavaCallArgs(method, sinkLineText);
          if (args !== null) {
            if (method === 'invoke') {
              if (args.length <= 1) return false;
            } else {
              const firstArg = args[0] ?? '';
              if (isJavaLiteralOrAnnotationAccessor(firstArg)) return false;
            }
          }
        }

        // 9d — #160: no-arg Constructor#newInstance(). Empty arg list
        // means the constructor was statically resolved.
        if (method === 'newInstance' &&
            /\.\s*newInstance\s*\(\s*\)/.test(sinkLineText)) {
          return false;
        }

        return true;
      });
    }

    // Stage 9f — Java xxe (CWE-611) FP reduction on non-XML parsers.
    // (cognium-dev #181 — follow-up to #155.)
    //
    // The taint matcher's receiver-fuzzy lookup maps any receiver name
    // ending in `parser` (e.g. CommonMark's `PARSER`) to the XML parser
    // classes `SAXParser` / `XMLReader` / `DocumentBuilder`, then the
    // xxe sink rule (`{ method: 'parse', class: 'DocumentBuilder' }`)
    // accepts the call as a sink. Markdown / CLI-arg / date / number
    // parsers do not perform XML parsing and have no external-entity
    // surface. Mirrors stage 9a but for xxe: when the resolvable receiver
    // type is a known non-XML data-parser class, drop the xxe sink.
    // Recall on real `DocumentBuilder.parse(...)` / `SAXParser.parse(...)`
    // / `XMLReader.parse(...)` is unchanged — those classes are NOT in
    // DATA_PARSER_TYPES so the gate never trips on them.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'xxe') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        const receiverMatch = sinkLineText.match(/\b(\w+)\s*\.\s*(\w+)\s*\(/);
        const receiver = receiverMatch?.[1];
        const method = sink.method ?? receiverMatch?.[2];
        if (method === 'parse' && receiver) {
          const recvType = resolveJavaReceiverType(receiver, sink.line, sourceLines);
          if (recvType && DATA_PARSER_TYPES.has(recvType)) return false;
        }
        return true;
      });
    }

    // Stage 10 — Java command_injection (CWE-78) FP reduction.
    // (cognium-dev #167, #170 — Sprint 43)
    //
    // Conservative-bias default: any command_injection sink whose file
    // imports don't match a known non-OS-exec package continues to fire.
    // Recall on real Runtime / ProcessBuilder / commons-exec sinks
    // unchanged.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'command_injection') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';

        // 10a — #167: picocli `new CommandLine(...)` collides with
        // Apache Commons Exec `CommandLine` in the existing
        // CWE_78_RECEIVER_ALLOWLIST at taint-matcher.ts. picocli's
        // annotation-driven dispatch never invokes a shell.
        if (sink.method === 'CommandLine' &&
            /\bnew\s+CommandLine\s*\(/.test(sinkLineText) &&
            hasJavaImportFromPackage('picocli', sourceLines)) {
          return false;
        }

        // 10b — #170: protocol-client wire-command methods called
        // inside Jedis / Lettuce / Kafka / Rabbit / Mongo / Paho /
        // Spring-Data classes. Receiver is implicit `this` so the
        // existing CWE_78_RECEIVER_ALLOWLIST gate falls through.
        if (sink.method && PROTOCOL_WIRE_METHODS.has(sink.method)) {
          for (const pkg of PROTOCOL_CLIENT_PACKAGES) {
            if (hasJavaImportFromPackage(pkg, sourceLines)) {
              // Defense-in-depth: a protocol-client file that ALSO
              // calls Runtime.exec etc. must keep firing.
              if (!OS_EXEC_RECEIVER_RE.test(sinkLineText)) {
                return false;
              }
            }
          }
        }

        return true;
      });
    }

    // Stage 11 — Java command_injection (CWE-78) FP reduction.
    // (cognium-dev #179 Sink 1 — Sprint 44)
    //
    // new ProcessBuilder(List<String>) / new ProcessBuilder(String...)
    // pass argv directly to fork(2). The kernel treats each element as
    // a literal argv slot — no shell, no metacharacter expansion. Only
    // the single-bare-variable form remains a sink (case 6/8 in B.1).
    //
    // sink.method === 'ProcessBuilder' uniquely identifies the
    // ProcessBuilder constructor sink (the other PB sinks use
    // method='start' / method='command'). The line-text regex then
    // verifies the constructor-call shape carries argv-form arguments.
    //
    // Sprint 93 (#189) adds `start` to the suppression cover: after the
    // `new X(...)` receiver-type resolution landed, chained
    // `new ProcessBuilder(...).start()` now correctly resolves the
    // `start()` receiver to `ProcessBuilder`, which activates the
    // pre-existing `class: 'ProcessBuilder', method: 'start'` sink
    // pattern. When the `.start()` call site is on the SAME line as an
    // argv-form ProcessBuilder ctor, the same argv-form logic proves
    // the exec is non-injectable and the `start` sink is dropped too.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'command_injection') return true;
        if (sink.method !== 'ProcessBuilder' && sink.method !== 'start') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        if (!/\bnew\s+ProcessBuilder\s*\(/.test(sinkLineText)) return true;
        if (PROCESS_BUILDER_ARGV_FORM_RE.test(sinkLineText)) return false;
        return true;
      });
    }

    // Stage 12 — Java throw-statement FP suppression.
    // (cognium-dev #157 — Sprint 45)
    //
    // A `throw new <SomeException|Error>(...)` line is structurally
    // never a runtime sink: the expression constructs the exception
    // object, then the next bytecode unwinds the stack. No SQL, no
    // exec, no XSS, no path I/O happens. Suppression is sink-type-
    // agnostic — a real sink anywhere else in the same method
    // continues to fire. Only sinks whose OWN line is the throw
    // statement are dropped.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        if (JAVA_THROW_STATEMENT_RE.test(sinkLineText)) return false;
        return true;
      });
    }

    // Stage 9e/9f/9g — Java code_injection library-API surface tagging.
    // (cognium-dev #161 / #165 / #168 — Sprint 47)
    //
    // Adds the `library-api-surface:caller-responsibility` tag to
    // sinks that sit at the library API boundary. The central
    // `applyLibraryApiSurfaceDowngrade` hook downgrades tagged
    // findings to MEDIUM/warning. Sinks are NOT suppressed — they
    // still surface so callers can audit the call chain.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      for (const sink of filtered) {
        if (sink.type !== 'code_injection') continue;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        const receiverMatch = sinkLineText.match(/\b(\w+)\s*\.\s*(\w+)\s*\(/);
        const receiver = receiverMatch?.[1];
        const method = sink.method ?? receiverMatch?.[2];

        let shouldTag = false;

        // 9e — #161: JEXL / template-engine library entry points.
        if (method === 'createExpression' && receiver) {
          const recvType = resolveJavaReceiverType(receiver, sink.line, sourceLines);
          if (recvType && JEXL_ENGINE_TYPES.has(recvType)) shouldTag = true;
        }
        if (!shouldTag && method === 'evaluate' && receiver) {
          const recvType = resolveJavaReceiverType(receiver, sink.line, sourceLines);
          if (recvType && JEXL_EXPRESSION_TYPE_RE.test(recvType)) shouldTag = true;
        }
        if (!shouldTag && method === 'compile' && receiver) {
          const recvType = resolveJavaReceiverType(receiver, sink.line, sourceLines);
          if (recvType && TEMPLATE_COMPILE_RECEIVER_TYPES.has(recvType)) shouldTag = true;
        }

        // 9f — #165: Class.forName(<var>) inside an SPI loader.
        if (!shouldTag && method === 'forName') {
          const start = Math.max(0, sink.line - 31);
          const end = Math.min(sourceLines.length, sink.line + 30);
          for (let i = start; i < end; i++) {
            if (SPI_GET_RESOURCES_RE.test(sourceLines[i] ?? '')) {
              shouldTag = true;
              break;
            }
          }
        }

        // 9g — #168: ClassLoader/findClass/loadClass override.
        if (!shouldTag && method && (method === 'loadClass' || method === 'findClass' || method === 'forName')) {
          const enclosing = findEnclosingClassDecl(sink.line, sourceLines);
          if (enclosing) {
            const extendsClassLoader =
              enclosing.extendsType !== null && CLASSLOADER_PARENT_TYPES.has(enclosing.extendsType);
            const implementsSpi = enclosing.implementsTypes.some(t => /CachingProvider$/.test(t));
            const nameLooksLikeLoader = CLASSLOADER_NAME_RE.test(enclosing.name);
            if (extendsClassLoader || implementsSpi || nameLooksLikeLoader) shouldTag = true;
          }
          if (!shouldTag && isInsideLoadClassOverride(sink.line, sourceLines)) {
            shouldTag = true;
          }
        }

        if (shouldTag) {
          const existing = sink.tags ?? [];
          if (!existing.includes(LIBRARY_API_SURFACE_TAG)) {
            sink.tags = [...existing, LIBRARY_API_SURFACE_TAG];
          }
        }
      }
    }

    // Stage 9h — Java code_injection polymorphic-dispatch suppression.
    // (cognium-dev #164 — Sprint 47)
    //
    // Dispatch over a `private static final X[] PARSERS = { new A(),
    // new B(), … };` array literal is closed-set dispatch. Each
    // element is a literal `new` of a code-known type; attacker
    // input cannot insert a new element at runtime.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'code_injection') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        const receiverMatch = sinkLineText.match(/\b(\w+)\s*\.\s*(\w+)\s*\(/);
        const receiver = receiverMatch?.[1];
        if (!receiver) return true;

        // Backward-scan for an array-literal declaration whose elements
        // are all `new X()` constructions. Also accept the iteration
        // variable shape: `for (X p : PARSERS) p.parse(...)`.
        // We accept the suppression when either:
        //  (a) receiver itself is declared as `X` in a for-each over
        //      a `private static final X[] NAME = { new ..., new ... };`
        //  (b) receiver appears as `NAME[<idx>]` and NAME is the array.
        const start = Math.max(0, sink.line - 200);
        let arrayName: string | null = null;
        const foreachRe = new RegExp(`\\bfor\\s*\\(\\s*\\w[\\w<>?]*\\s+${receiver}\\s*:\\s*(\\w+)\\b`);
        for (let i = sink.line - 1; i >= start; i--) {
          const ln = sourceLines[i] ?? '';
          const fm = ln.match(foreachRe);
          if (fm) { arrayName = fm[1]; break; }
        }
        if (!arrayName) {
          const methodNameMatch = sinkLineText.match(/\.(\w+)\s*\(/);
          const methodNameRe = methodNameMatch ? methodNameMatch[1] : '\\w+';
          const idxRe = new RegExp(`\\b(\\w+)\\s*\\[[^\\]]+\\]\\s*\\.\\s*${methodNameRe}\\s*\\(`);
          const im = sinkLineText.match(idxRe);
          if (im) arrayName = im[1];
        }
        if (!arrayName) return true;

        // Look for `private static final X[] arrayName = { ... };` OR
        // `private static final X[] arrayName = new X[] { ... };`.
        // Detection of the `{` is deferred to the body-collection step
        // so both forms collapse to the same downstream init-parse.
        const declRe = new RegExp(
          `\\bprivate\\s+static\\s+final\\s+(?:[\\w<>?,\\s]+)\\[\\s*\\]\\s+${arrayName}\\s*=`,
        );
        let declStart = -1;
        for (let i = 0; i < sink.line; i++) {
          if (declRe.test(sourceLines[i] ?? '')) { declStart = i; break; }
        }
        if (declStart < 0) return true;

        // Collect text until matching `};` (bounded).
        let body = '';
        for (let i = declStart; i < Math.min(sourceLines.length, declStart + 40); i++) {
          body += (sourceLines[i] ?? '') + '\n';
          if (/\}\s*;/.test(sourceLines[i] ?? '')) break;
        }
        // Accept both `= { ... }` and `= new X[] { ... }`.
        const initMatch = body.match(/=\s*(?:new\s+[\w<>?,\s]+\[\s*\]\s*)?\{([\s\S]*?)\}\s*;/);
        if (!initMatch) return true;
        const elements = initMatch[1].split(',').map(s => s.trim()).filter(Boolean);
        if (elements.length === 0) return true;
        const allNewLiterals = elements.every(e => /^new\s+[A-Z]\w*\s*\([^)]*\)$/.test(e));
        if (allNewLiterals) return false;
        return true;
      });
    }

    // Stage 13 — Java sql_injection SQL-builder-wrapper suppression.
    // (cognium-dev #163 — Sprint 47)
    //
    // Inside a `*Dialect` / `*SqlBuilder` / `*Quoter` / `*QueryBuilder`
    // class, a wrapper/quoter call (`.wrap(`, `.quote(`, `.escape(`,
    // `.identifier(`) appearing within ±10 lines of the sink means the
    // SQL fragment was assembled via the dialect's quoting helper —
    // the wrapper IS the sanitizer. Narrow gate: requires BOTH the
    // class-name suffix AND a wrapper call nearby.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'sql_injection') return true;
        const enclosing = findEnclosingClassDecl(sink.line, sourceLines);
        if (!enclosing) return true;
        if (!SQL_BUILDER_CLASS_RE.test(enclosing.name)) return true;
        const lo = Math.max(0, sink.line - 11);
        const hi = Math.min(sourceLines.length, sink.line + 10);
        for (let i = lo; i < hi; i++) {
          if (SQL_BUILDER_WRAPPER_CALL_RE.test(sourceLines[i] ?? '')) return false;
        }
        return true;
      });
    }

    // Stage 14 — Java sql_injection SQL-extraction-method suppression.
    // (cognium-dev #177 — Sprint 47)
    //
    // Three-clause gate on the enclosing method:
    //   (1) return type is String / CharSequence / Optional<String>
    //   (2) method name matches a get/extract/toSql SQL-getter shape
    //   (3) primary parameter type is NOT a String primitive (i.e.
    //       input is an AST / builder / Statement object)
    // All three → this is SQL codegen, not SQL execution. Suppress.
    if (language === 'java') {
      const types = graph.ir.types ?? [];
      if (types.length > 0) {
        filtered = filtered.filter(sink => {
          if (sink.type !== 'sql_injection') return true;
          const enclosing = findEnclosingMethodFromIr(types, sink.line);
          if (!enclosing) return true;
          const ret = (enclosing.return_type ?? '').replace(/\s+/g, ' ').trim();
          if (!SQL_EXTRACTION_RETURN_RE.test(ret)) return true;
          if (!SQL_EXTRACTION_NAME_RE.test(enclosing.name)) return true;
          const firstParamType = enclosing.parameters[0]?.type ?? null;
          if (firstParamType === null) return true;
          const simpleType = firstParamType.replace(/<[^>]*>/g, '').trim();
          if (SQL_EXTRACTION_PRIMITIVE_INPUT_RE.test(simpleType)) return true;
          return false;
        });
      }
    }

    // Stage 15 — Java sql_injection regex-allowlist-quoter suppression.
    // (cognium-dev #191 / FP-77 — Sprint 49)
    //
    // Gate (all must hold to drop the sink):
    //   (a) sink is a JDBC exec method (prepareStatement / execute*)
    //   (b) sink argument is a single variable (the SQL string)
    //   (c) variable is assigned within 30 lines above from a
    //       string-concat RHS whose tokens are ONLY string literals and
    //       method calls (no bare-variable concat)
    //   (d) at least one literal token contains a `?` placeholder
    //       (parameterized value binding signal)
    //   (e) at least one method-call token names an in-file Java method
    //       whose body contains an inline `.matches("strict-anchored")`
    //       call plus a `throw` (regex-allowlist guard)
    //
    // Together (a)–(e) prove the SQL is parameterized for values with
    // identifier interpolation routed through a validated quoter.
    // Stage 13 (#163) handles the same shape inside `*Dialect` /
    // `*SqlBuilder` classes — this stage drops the class-name gate.
    if (language === 'java') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'sql_injection') return true;
        const method = sink.method ?? '';
        if (!SQL_EXEC_METHODS.has(method)) return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        // Sink-call arg: take the first parenthesised arg of the method.
        const callArgs = extractJavaCallArgs(method, sinkLineText);
        if (!callArgs || callArgs.length === 0) return true;
        const sqlVar = callArgs[0]?.trim() ?? '';
        let rhs: string | null = null;
        if (/^[A-Za-z_]\w*$/.test(sqlVar)) {
          // Indirect form: SQL assigned to a named variable above the sink.
          // Scan backward for the SQL variable's assignment.
          const lo = Math.max(0, sink.line - 31);
          const assignRe = new RegExp(
            JAVA_SQL_ASSIGN_RE_TEMPLATE.replace('SQLVAR', sqlVar),
          );
          for (let i = sink.line - 2; i >= lo; i--) {
            const ln = sourceLines[i] ?? '';
            const m = ln.match(assignRe);
            if (m) { rhs = m[1] ?? null; break; }
          }
        } else if (/"[^"]*"/.test(sqlVar) && sqlVar.includes('+')) {
          // Inline form (cognium-dev #214): SQL concat passed directly to the
          // exec method. Treat the arg expression itself as the RHS and run
          // gates (c)–(e) against it.
          rhs = sqlVar;
        }
        if (!rhs) return true;
        const tokens = splitJavaConcatTokens(rhs);
        if (tokens.length < 2) return true; // single token = not a concat shape
        let hasPlaceholder = false;
        const methodCallNames: string[] = [];
        for (const tk of tokens) {
          if (/^"(?:[^"\\]|\\.)*"$/.test(tk)) {
            if (tk.includes('?')) hasPlaceholder = true;
            continue;
          }
          const callMatch = tk.match(/^([A-Za-z_]\w*)\s*\(/);
          if (callMatch) { methodCallNames.push(callMatch[1] ?? ''); continue; }
          // Any token that is neither a string literal nor a method call
          // (e.g. a bare identifier) disqualifies this gate.
          return true;
        }
        if (!hasPlaceholder) return true;
        if (methodCallNames.length === 0) return true;
        for (const mname of methodCallNames) {
          const body = findJavaMethodBody(mname, sourceLines);
          if (body && javaBodyHasInlineRegexAllowlistThrow(body)) return false;
        }
        return true;
      });
    }

    // Stage 16 — JS log_injection (CWE-117) sanitizer suppression.
    // (cognium-dev #216 sanitizer-wrapped FP — Sprint 52)
    //
    // Gate (any suppresses the sink):
    //   (a) sink line contains an inline call to a known CRLF-stripping
    //       helper (stripCrlf, sanitizeLogValue, .replace(/[\r\n]/g, ''))
    //   (b) sink line references a variable assigned within 30 lines
    //       above from a sanitizer-pattern RHS
    if (['javascript', 'typescript'].includes(language)) {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'log_injection') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        if (JS_LOG_INJECTION_SANITIZERS.some(p => p.test(sinkLineText))) return false;
        const varNames = extractSourceIdentifiers(sinkLineText);
        for (const v of varNames) {
          if (isAssignedFromSanitizerPattern(sourceLines, sink.line, v, JS_LOG_INJECTION_SANITIZERS)) {
            return false;
          }
        }
        return true;
      });
    }

    // Stage 17 — Python ldap_injection (CWE-90) regex-strip wrapper
    // recognition. (cognium-dev #216 sanitizer-wrapped FP — Sprint 52)
    //
    // Scan file for module-level wrapper functions whose body is
    //   return re.sub(r"[<class>]", "", <param>)
    // where the character class contains at least three of the LDAP filter
    // metacharacters ( ) = * \. Treat such wrappers (plus the built-in
    // `escape_filter_chars` / `filter_format`) as LDAP sanitizers.
    //
    // Gate (any suppresses the sink):
    //   (a) sink line contains a direct call to a known LDAP sanitizer
    //   (b) sink line references a variable assigned within 30 lines above
    //       from a known LDAP sanitizer call
    if (language === 'python') {
      const sourceLines = ctx.code.split('\n');
      const wrappers = findPythonLdapStripWrappers(sourceLines);
      const allLdapSanitizers = [...PY_BUILTIN_LDAP_SANITIZERS, ...wrappers];
      if (allLdapSanitizers.length > 0) {
        const ldapPatterns = allLdapSanitizers.map(
          name => new RegExp(`\\b${escapeRegex(name)}\\s*\\(`),
        );
        filtered = filtered.filter(sink => {
          if (sink.type !== 'ldap_injection') return true;
          const sinkLineText = sourceLines[sink.line - 1] ?? '';
          if (ldapPatterns.some(p => p.test(sinkLineText))) return false;
          const varNames = extractSourceIdentifiers(sinkLineText);
          for (const v of varNames) {
            if (isAssignedFromSanitizerPattern(sourceLines, sink.line, v, ldapPatterns)) {
              return false;
            }
          }
          return true;
        });
      }
    }

    // Stage 18 — Python xxe (CWE-611) parser-variable / wrapper recognition.
    // (cognium-dev #216 sanitizer-wrapped FP — Sprint 52)
    //
    // When an xxe sink (fromstring/parse/etc.) appears within the same
    // enclosing function as an `XMLParser(...resolve_entities=False...)`
    // constructor, the parser is hardened and the sink is safe. Covers:
    //   - wrapper functions (`def safe_parse(...): parser = XMLParser(...);
    //     return ET.fromstring(b, parser)`) — sink inside wrapper body
    //   - class methods (`def parse_direct(self): parser = XMLParser(...);
    //     return ET.fromstring(self.xml, parser)`)
    //
    // Scope safety: the backward scan stops at the first `def` line so the
    // safe parser in a sibling/preceding function never suppresses an unsafe
    // sink in a different function. Recall lock: `XMLParser(resolve_entities
    // =True)` does NOT match the hardened regex, so /wrong /fake routes
    // (which build their own unsafe parsers) still fire.
    if (language === 'python') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'xxe') return true;
        const lookback = 30;
        const lo = Math.max(0, sink.line - 1 - lookback);
        for (let i = sink.line - 2; i >= lo; i--) {
          const ln = sourceLines[i] ?? '';
          if (PY_XML_PARSER_HARDENED_RE.test(ln)) return false;
          // Function boundary: stop scanning when we leave the sink's
          // enclosing def, so a hardened parser in a sibling function never
          // suppresses an unsafe sink in this function.
          if (/^\s*def\s+\w+\s*\(/.test(ln)) break;
        }
        return true;
      });
    }

    // Stage 19 — Python sql_injection regex-allowlist-quoter wrapper
    // suppression. (cognium-dev #215 — Sprint 53; port of Java Stage 15)
    //
    // Gate (all must hold to drop the sink):
    //   (a) sink method is cursor.execute / cursor.executemany
    //   (b) sink first arg is an f-string (`f"…{x}…"`) with ≥1 interpolation
    //   (c) every `{…}` interpolation is a literal OR a bare identifier
    //       whose assignment within 30 lines above is `<helper>(<arg>)`
    //       — an in-file helper call
    //   (d) the f-string literal segments contain a bind placeholder
    //       (`?`, `%s`, or `:name`)
    //   (e) at least one such helper's body contains `re.fullmatch(<allowlist>,…)`
    //       (or anchored `re.match(^…$,…)`) AND a `raise` statement
    //
    // Together (a)–(e) prove the SQL is parameterized for values with
    // identifier interpolation routed through a validated quoter.
    if (language === 'python') {
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'sql_injection') return true;
        const method = sink.method ?? '';
        if (!PY_SQL_EXEC_METHODS.has(method)) return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        // Find the f-string first argument: f"…" or f'…'
        const fstrMatch = sinkLineText.match(/\bf"((?:[^"\\]|\\.)*)"|\bf'((?:[^'\\]|\\.)*)'/);
        if (!fstrMatch) return true;
        const fstrBody = fstrMatch[1] ?? fstrMatch[2] ?? '';
        const { literals, interps } = splitPyFstringTokens(fstrBody);
        if (interps.length === 0) return true;
        // Gate (d): bind placeholder in literal segments
        if (!literals.some(lit => PY_BIND_PLACEHOLDER_RE.test(lit))) return true;
        // Gate (c) + (e): every interpolation must be a literal or
        // resolve through an in-file helper with the regex-allowlist+raise
        // shape. At least one helper match is required.
        let sawHelperWithGuard = false;
        for (const interp of interps) {
          const t = interp.trim();
          if (t === '') return true;
          // Literal-shape interp: bare number / quoted string — accept.
          if (/^-?\d+$/.test(t) || /^"(?:[^"\\]|\\.)*"$/.test(t) || /^'(?:[^'\\]|\\.)*'$/.test(t)) {
            continue;
          }
          // Direct in-line helper call: `{helper(arg)}` — extract name.
          let helperName: string | null = null;
          const directCall = t.match(/^([A-Za-z_]\w*)\s*\(/);
          if (directCall) {
            helperName = directCall[1] ?? null;
          } else if (/^[A-Za-z_]\w*$/.test(t)) {
            // Bare identifier — scan backward for assignment from helper call.
            helperName = findPythonAssignedHelperCall(t, sink.line, sourceLines);
            if (helperName === null) return true;
          } else {
            // Any other expression shape (attribute access, arithmetic,
            // method chain) disqualifies — too permissive otherwise.
            return true;
          }
          const body = findPythonFunctionBody(helperName, sourceLines);
          if (body && pythonBodyHasInlineRegexAllowlistRaise(body)) {
            sawHelperWithGuard = true;
          }
        }
        if (!sawHelperWithGuard) return true;
        return false;
      });
    }

    return { sources, sinks: filtered, sanitizers };
  }
}

// ---------------------------------------------------------------------------
// Sprint 52 helpers — shared sanitizer-assignment backward scan utilities.
// ---------------------------------------------------------------------------

/**
 * Escape regex metacharacters in an identifier or literal for use inside a
 * RegExp template. Identifiers from `def NAME(...)` matches are already
 * `[A-Za-z_]\w*`-restricted, but kept defensively.
 */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Reserved keywords across JS/TS/Python that should not be treated as
 * source-identifier candidates by `extractSourceIdentifiers`.
 */
const RESERVED_KEYWORDS = new Set<string>([
  // JS/TS
  'if', 'else', 'return', 'const', 'let', 'var', 'function', 'class', 'new',
  'this', 'for', 'while', 'do', 'break', 'continue', 'switch', 'case',
  'default', 'try', 'catch', 'finally', 'throw', 'typeof', 'instanceof',
  'in', 'of', 'await', 'async', 'import', 'export', 'from', 'as', 'void',
  'null', 'undefined', 'true', 'false', 'super', 'extends', 'static',
  // Python
  'def', 'lambda', 'yield', 'pass', 'with', 'global', 'nonlocal', 'and',
  'or', 'not', 'is', 'None', 'True', 'False', 'raise', 'except', 'elif',
  'self', 'cls', 'print',
  // Common stdlib roots that show up everywhere and would balloon scans.
  'console', 'req', 'res', 'request', 'response',
]);

/**
 * Extract identifier-shaped tokens from a source line. Skips keywords and
 * single-character names. Used by Stages 16-17 to find candidate variables
 * whose assignment lines should be scanned backward.
 */
function extractSourceIdentifiers(text: string): string[] {
  const out: string[] = [];
  const re = /\b([A-Za-z_]\w+)\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    if (!RESERVED_KEYWORDS.has(name)) out.push(name);
  }
  return out;
}

/**
 * Scan upward from `sinkLine` (1-based) for an assignment to `varName`. If
 * the RHS of that assignment matches any of the supplied sanitizer regexes,
 * return true. Stops at the first assignment found (no `varName` reassignment
 * tracking — a benign reassignment after a tainted one is the common shape,
 * so first-assignment-found-above-the-sink is the precision-correct choice).
 *
 * Shared by Stages 16 (JS log_injection) and 17 (Python ldap_injection).
 */
function isAssignedFromSanitizerPattern(
  sourceLines: string[],
  sinkLine: number,
  varName: string,
  sanitizerPatterns: RegExp[],
  lookback: number = 30,
): boolean {
  const escapedVar = escapeRegex(varName);
  // Match `[<keyword>?] varName = <rhs>` for both JS (`const|let|var`) and
  // Python (bare assignment) shapes.
  const assignRe = new RegExp(
    `(?:\\b(?:const|let|var|final|String)\\s+)?\\b${escapedVar}\\s*=\\s*(.+)`,
  );
  // Scope boundary: stop at a function declaration so a sibling function's
  // assignment to the same variable name never crosses scope.
  const fnBoundaryRe = /^\s*(?:def\s+\w+\s*\(|function\s+\w+\s*\(|\w+\s*[:=]\s*(?:async\s+)?\(?[^)]*\)?\s*=>)/;
  const lo = Math.max(0, sinkLine - 1 - lookback);
  for (let i = sinkLine - 2; i >= lo; i--) {
    const ln = sourceLines[i] ?? '';
    const m = ln.match(assignRe);
    if (m) {
      const rhs = (m[1] ?? '').trim();
      return sanitizerPatterns.some(p => p.test(rhs));
    }
    if (fnBoundaryRe.test(ln)) break;
  }
  return false;
}

/**
 * Find module-level Python functions whose body is a single
 * `return re.sub(r"[<class>]", "", param)` line where the character class
 * contains at least three of the LDAP filter metacharacters `( ) = * \`.
 *
 * Returns the function names. Conservative scan window: looks at the first
 * three non-blank lines after the `def` to find the `return re.sub(...)`.
 */
function findPythonLdapStripWrappers(sourceLines: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < sourceLines.length; i++) {
    const defMatch = sourceLines[i].match(PY_DEF_RE);
    if (!defMatch) continue;
    const fnName = defMatch[1];
    const param = defMatch[2];
    // Scan next non-blank/comment line for the return re.sub(...) pattern.
    for (let j = i + 1; j < Math.min(i + 4, sourceLines.length); j++) {
      const body = sourceLines[j];
      if (/^\s*$/.test(body) || /^\s*#/.test(body)) continue;
      const ret = body.match(PY_LDAP_STRIP_RETURN_RE);
      if (!ret) break;
      const charClass = ret[1];
      const argName = ret[2];
      if (argName !== param) break;
      const metaCount = PY_LDAP_METACHARS.filter(c => charClass.includes(c)).length;
      if (metaCount >= 3) out.push(fnName);
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Stage 19 (#215) Python helpers — f-string interp split, function body
// scan via indent depth, and inline regex-allowlist+raise recognition.
// ---------------------------------------------------------------------------

/**
 * Stage 19 (#215) — split a Python f-string body into literal segments and
 * brace interpolations. Returns parallel arrays. Conservative: only flat
 * `{<expr>}` interpolations are recognised (no nested f-strings, no
 * format-specs after `:` since `:` overlaps with named-bind placeholders).
 * Escape sequence `{{`/`}}` is preserved as literal text.
 */
function splitPyFstringTokens(body: string): { literals: string[]; interps: string[] } {
  const literals: string[] = [];
  const interps: string[] = [];
  let i = 0;
  let cur = '';
  while (i < body.length) {
    const ch = body[i] ?? '';
    if (ch === '{' && body[i + 1] === '{') {
      cur += '{';
      i += 2;
      continue;
    }
    if (ch === '}' && body[i + 1] === '}') {
      cur += '}';
      i += 2;
      continue;
    }
    if (ch === '{') {
      literals.push(cur);
      cur = '';
      i++;
      let depth = 1;
      let expr = '';
      while (i < body.length && depth > 0) {
        const ch2 = body[i] ?? '';
        if (ch2 === '{') { depth++; expr += ch2; i++; continue; }
        if (ch2 === '}') {
          depth--;
          if (depth === 0) { i++; break; }
          expr += ch2;
          i++;
          continue;
        }
        expr += ch2;
        i++;
      }
      // Strip any trailing format-spec (after `:` at depth 0) — but only
      // when there's a non-trivial spec so we don't false-strip identifiers
      // containing `:` (which shouldn't happen syntactically anyway).
      const colonIdx = expr.indexOf(':');
      const interp = colonIdx >= 0 ? expr.substring(0, colonIdx) : expr;
      interps.push(interp);
      continue;
    }
    cur += ch;
    i++;
  }
  literals.push(cur);
  return { literals, interps };
}

/**
 * Stage 19 (#215) — find the helper-name assigned to `varName` within 30
 * lines above `sinkLine` (1-based). Returns the helper function name if
 * the RHS is a bare `helper(<arg>)` call, otherwise null.
 */
function findPythonAssignedHelperCall(
  varName: string,
  sinkLine: number,
  sourceLines: string[],
): string | null {
  if (!/^[A-Za-z_]\w*$/.test(varName)) return null;
  const lo = Math.max(0, sinkLine - 31);
  const assignRe = new RegExp(
    `^\\s*${varName}\\s*=\\s*([A-Za-z_]\\w*)\\s*\\(`,
  );
  for (let i = sinkLine - 2; i >= lo; i--) {
    const ln = sourceLines[i] ?? '';
    const m = ln.match(assignRe);
    if (m) return m[1] ?? null;
  }
  return null;
}

/**
 * Stage 19 (#215) — locate a Python function body by name using indent
 * depth. Returns the body lines (between the `def` and the first line whose
 * indent is ≤ the `def` line's indent) or null when not found.
 *
 * Conservative textual scan — does not handle decorators across multiple
 * lines or nested functions with the same name. Sufficient for the
 * regex-allowlist guard recognition.
 */
function findPythonFunctionBody(
  funcName: string,
  sourceLines: string[],
): string[] | null {
  if (!/^[A-Za-z_]\w*$/.test(funcName)) return null;
  const sigRe = new RegExp(`^(\\s*)def\\s+${funcName}\\s*\\(`);
  for (let i = 0; i < sourceLines.length; i++) {
    const ln = sourceLines[i] ?? '';
    const m = ln.match(sigRe);
    if (!m) continue;
    const baseIndent = (m[1] ?? '').length;
    const body: string[] = [];
    for (let j = i + 1; j < sourceLines.length; j++) {
      const ln2 = sourceLines[j] ?? '';
      if (ln2.trim() === '') { body.push(ln2); continue; }
      const indentMatch = ln2.match(/^(\s*)/);
      const indent = (indentMatch?.[1] ?? '').length;
      if (indent <= baseIndent) break;
      body.push(ln2);
    }
    return body;
  }
  return null;
}

/**
 * Stage 19 (#215) — true if the Python function body contains
 *   `re.fullmatch(r"<strict-anchored-regex>", …)`  OR
 *   `re.match(r"^<…>$", …)`
 * AND a `raise` statement. The two need not be in the same `if`; the
 * combination proves the parameter is validated and any non-allowlisted
 * input terminates execution before the function returns.
 */
function pythonBodyHasInlineRegexAllowlistRaise(bodyLines: string[]): boolean {
  // Strip inline `# …` comments from each line so words like "raise" or
  // `re.fullmatch` appearing in commentary don't trigger a false guard
  // detection. Conservative: this does not handle `#` inside string
  // literals, but the surrounding code already operates on textual lines
  // and the false-suppression risk from a `#` inside a string is bounded
  // by the other gates (must also have anchored regex + bind placeholder).
  const stripped = bodyLines.map(ln => ln.replace(/#.*$/, ''));
  const text = stripped.join('\n');
  if (!/\braise\s+/.test(text)) return false;
  PY_INLINE_FULLMATCH_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PY_INLINE_FULLMATCH_RE.exec(text)) !== null) {
    if (isImplicitlyAnchoredAllowlistRegex(m[1] ?? '')) return true;
  }
  PY_INLINE_MATCH_ANCHORED_RE.lastIndex = 0;
  while ((m = PY_INLINE_MATCH_ANCHORED_RE.exec(text)) !== null) {
    if (isImplicitlyAnchoredAllowlistRegex(m[1] ?? '')) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helpers (moved verbatim from analyzer.ts)
// ---------------------------------------------------------------------------

import type { CircleIR } from '../../types/index.js';

type Symbols = Map<string, { value: string | number | boolean | null; type: string; sourceLine: number }>;

/**
 * Evaluate a simple arithmetic expression containing only digits, spaces, and
 * the operators +, -, *, /, and parentheses. Uses a recursive descent parser
 * so no dynamic code execution (Function / eval) is needed.
 */
function evalArithmetic(input: string): number | null {
  let pos = 0;
  const len = input.length;

  function peek(): string { return input[pos] ?? ''; }
  function consume(): string { return input[pos++] ?? ''; }
  function skipWs(): void { while (pos < len && input[pos] === ' ') pos++; }

  function parseNumber(): number | null {
    skipWs();
    const chars: string[] = [];
    if (peek() === '-') { chars.push(consume()); }
    while (pos < len && /[\d.]/.test(input[pos]!)) chars.push(consume());
    if (chars.length === 0 || (chars.length === 1 && chars[0] === '-')) return null;
    const n = parseFloat(chars.join(''));
    return isFinite(n) ? n : null;
  }

  function parseFactor(): number | null {
    skipWs();
    if (peek() === '(') {
      consume(); // '('
      const val = parseExpr();
      skipWs();
      if (peek() === ')') consume();
      return val;
    }
    return parseNumber();
  }

  function parseTerm(): number | null {
    let left = parseFactor();
    if (left === null) return null;
    while (true) {
      skipWs();
      const op = peek();
      if (op !== '*' && op !== '/') break;
      consume();
      const right = parseFactor();
      if (right === null) return null;
      left = op === '*' ? left * right : (right === 0 ? null : left / right);
      if (left === null) return null;
    }
    return left;
  }

  function parseExpr(): number | null {
    let left = parseTerm();
    if (left === null) return null;
    while (true) {
      skipWs();
      const op = peek();
      if (op !== '+' && op !== '-') break;
      consume();
      const right = parseTerm();
      if (right === null) return null;
      left = op === '+' ? left + right : left - right;
    }
    return left;
  }

  if (!/^[\d\s+\-*/().]+$/.test(input)) return null;
  const result = parseExpr();
  skipWs();
  return pos === input.length ? result : null;
}

function evaluateSimpleExpression(expr: string, symbols: Symbols): string {
  let evaluated = expr;
  for (const [name, val] of symbols) {
    if (val.type === 'int' || val.type === 'float') {
      const regex = new RegExp(`\\b${name}\\b`, 'g');
      evaluated = evaluated.replace(regex, String(val.value));
    }
  }
  const result = evalArithmetic(evaluated);
  if (result !== null && !isNaN(result)) return String(Math.floor(result));
  return expr;
}

function isStringLiteralExpression(expr: string): boolean {
  const trimmed = expr.trim();
  if (trimmed.length < 2) return false;
  const quote = trimmed[0];
  if (quote !== '"' && quote !== "'") return false;
  // Walk to find where the leading quoted string ends, honoring backslash escapes.
  // If the closing quote is the last character, this is a pure string literal.
  // Otherwise it's a compound expression like `"a" + u + "b"` that just happens to
  // begin and end with a quote — those must NOT be treated as literal (cognium-dev#63).
  let i = 1;
  while (i < trimmed.length) {
    const c = trimmed[i];
    if (c === '\\') { i += 2; continue; }
    if (c === quote) return i === trimmed.length - 1;
    i++;
  }
  return false; // unterminated string literal — be conservative
}

function filterCleanArraySinks(
  sinks: CircleIR['taint']['sinks'],
  calls: CircleIR['calls'],
  taintedArrayElements: Map<string, Set<string>>,
  symbols: Symbols,
): CircleIR['taint']['sinks'] {
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const callsAtSink = callsByLine.get(sink.line) ?? [];
    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        const arrayAccessMatch = arg.expression?.match(/^(\w+)\[(\d+|[^[\]]+)\]$/);
        if (arrayAccessMatch) {
          const arrayName = arrayAccessMatch[1];
          let indexStr = arrayAccessMatch[2];
          indexStr = evaluateSimpleExpression(indexStr, symbols);
          const taintedIndices = taintedArrayElements.get(arrayName);
          if (taintedIndices !== undefined) {
            const isTainted = taintedIndices.has(indexStr) || taintedIndices.has('*');
            if (!isTainted) return false;
          }
        }
      }
    }
    return true;
  });
}

export function filterCleanVariableSinks(
  sinks: CircleIR['taint']['sinks'],
  calls: CircleIR['calls'],
  taintedVars: Set<string>,
  symbols: Symbols,
  dfg?: CircleIR['dfg'],
  sanitizedVars?: Set<string>,
  synchronizedLines?: Set<number>,
  language?: string,
): CircleIR['taint']['sinks'] {
  const fieldNames = new Set<string>();
  if (dfg) {
    for (const def of dfg.defs) {
      if (def.kind === 'field') fieldNames.add(def.variable);
    }
  }

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const callsAtSink = callsByLine.get(sink.line) ?? [];
    const isInSynchronizedBlock = synchronizedLines?.has(sink.line) ?? false;

    // Only evaluate the call that matched the sink pattern — not nested inner calls at the
    // same line (e.g. System.getProperty("user.dir") inside r.exec(args,...,new File(...))).
    // sink.method is set by findSinks to call.method_name; language-sources sinks also carry it.
    const relevantCalls = sink.method
      ? callsAtSink.filter(c => c.method_name === sink.method)
      : callsAtSink;

    // Whether to trust sink.argPositions for narrowing the cleanness check. In shell-like
    // languages, flag-vs-positional ambiguity makes statically declared argument positions
    // unreliable (e.g. `rm -rf "$DIR"` has the path at position 1, but `rm "$DIR"` at
    // position 0). For typed languages (JS/TS, Java, Python, Go, Rust) the declared
    // positions reliably correspond to dangerous arguments.
    const trustArgPositions = language !== 'bash' && language !== 'shell';

    for (const call of relevantCalls) {
      let allArgsAreClean = true;
      let dangerousArgCount = 0;
      const methodName = call.in_method;

      for (const arg of call.arguments) {
        // Restrict cleanness check to the dangerous argument positions for this sink (e.g.
        // SQL sinks like `db.query(query, callback)` are dangerous only at arg[0]; a callback
        // variable at arg[1] must not cause the whole sink to appear "dirty"). Mirrors the
        // pattern used by taint-propagation.ts when matching tainted args to sinks. Skipped
        // for bash/shell where argPositions is unreliable (see comment above the loop).
        if (trustArgPositions && sink.argPositions && sink.argPositions.length > 0 && !sink.argPositions.includes(arg.position)) continue;
        dangerousArgCount++;

        // Skip the command-name argument in shell calls (e.g., arg[0]="curl" for `curl -s URL`).
        // The command name itself has literal=null and expression matching the method name.
        // Only applies to Bash — in other languages a variable can legitimately share its name
        // with the function (e.g., Rust `html(html)` where `html` is a tainted local variable).
        if (language === 'bash' && arg.expression === call.method_name && !arg.variable && arg.literal == null) continue;

        if (arg.variable && !arg.expression?.includes('[')) {
          const varName = arg.variable;
          const scopedName = methodName ? `${methodName}:${varName}` : varName;

          if (fieldNames.has(varName) && !isInSynchronizedBlock) { allArgsAreClean = false; continue; }
          if (sanitizedVars?.has(scopedName) || sanitizedVars?.has(varName)) continue;
          if (taintedVars.has(scopedName) || taintedVars.has(varName)) { allArgsAreClean = false; continue; }

          const symbolValue = symbols.get(scopedName) ?? symbols.get(varName);
          if (symbolValue && symbolValue.type !== 'unknown') continue;

          allArgsAreClean = false;
        } else {
          if (arg.literal != null) continue;
          if (arg.expression && !arg.variable && isStringLiteralExpression(arg.expression)) continue;
          allArgsAreClean = false;
        }
      }

      if (allArgsAreClean && dangerousArgCount > 0) return false;
    }

    return true;
  });
}

export function filterSanitizedSinks(
  sinks: CircleIR['taint']['sinks'],
  sanitizers: CircleIR['taint']['sanitizers'],
  calls: CircleIR['calls'],
): CircleIR['taint']['sinks'] {
  if (!sanitizers || sanitizers.length === 0) return sinks;

  const sanitizersByLine = new Map<number, typeof sanitizers>();
  for (const san of sanitizers) {
    const existing = sanitizersByLine.get(san.line) ?? [];
    existing.push(san);
    sanitizersByLine.set(san.line, existing);
  }

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const lineSanitizers = sanitizersByLine.get(sink.line);
    if (!lineSanitizers || lineSanitizers.length === 0) return true;

    for (const san of lineSanitizers) {
      if (san.sanitizes.includes(sink.type as typeof san.sanitizes[number])) {
        const lineCalls = callsByLine.get(sink.line) ?? [];
        for (const call of lineCalls) {
          for (const arg of call.arguments) {
            const expr = arg.expression || '';
            const sanMethodMatch = san.method.match(/(?:(\w+)\.)?(\w+)\(\)/);
            if (sanMethodMatch) {
              const sanMethodName = sanMethodMatch[2];
              const sanClassName  = sanMethodMatch[1];
              if (sanClassName) {
                if (expr.includes(`${sanClassName}.${sanMethodName}(`)) return false;
              } else if (expr.includes(`${sanMethodName}(`)) {
                return false;
              }
            }
          }
        }
      }
    }
    return true;
  });
}
