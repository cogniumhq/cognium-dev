/**
 * Taint source/sink matcher
 *
 * Matches method calls and annotations against taint configurations.
 */

import type { CallInfo, TypeInfo, TaintSource, TaintSink, TaintSanitizer, Taint, SourceType, SinkType, SupportedLanguage } from '../types/index.js';
import type { TaintConfig, SourcePattern, SinkPattern, SanitizerPattern } from '../types/config.js';
import type { TypeHierarchyResolver } from '../resolution/type-hierarchy.js';
import { getDefaultConfig } from './config-loader.js';

/**
 * Python tainted access patterns (regex-based).
 * Handles request.args['id'], request.GET['key'] etc. (subscript access — not call nodes).
 */
const PYTHON_TAINTED_PATTERNS: Array<{ pattern: RegExp; sourceType: SourceType }> = [
  { pattern: /\brequest\.args\b/,         sourceType: 'http_param'  },
  { pattern: /\brequest\.form\b/,         sourceType: 'http_body'   },
  { pattern: /\brequest\.json\b/,         sourceType: 'http_body'   },
  { pattern: /\brequest\.data\b/,         sourceType: 'http_body'   },
  { pattern: /\brequest\.files?\b/,       sourceType: 'file_input'  },
  { pattern: /\brequest\.headers?\b/,     sourceType: 'http_header' },
  { pattern: /\brequest\.cookies\b/,      sourceType: 'http_cookie' },
  { pattern: /\brequest\.GET\b/,          sourceType: 'http_param'  },
  { pattern: /\brequest\.POST\b/,         sourceType: 'http_body'   },
  { pattern: /\brequest\.META\b/,         sourceType: 'http_header' },
  { pattern: /\brequest\.FILES\b/,        sourceType: 'file_input'  },
  { pattern: /\brequest\.query_params\b/, sourceType: 'http_param'  },
  { pattern: /\brequest\.path_params\b/,  sourceType: 'http_param'  },
];

/**
 * Analyze code for taint sources, sinks, and sanitizers.
 *
 * When `code` is provided, each emitted TaintSource/TaintSink is annotated with
 * its trimmed source-line text in the `code` field. Consumers (LLM enrichment
 * pipelines, SARIF reporters) can then render the offending line without
 * re-reading the file.
 */
export function analyzeTaint(
  calls: CallInfo[],
  types: TypeInfo[],
  config: TaintConfig = getDefaultConfig(),
  typeHierarchy?: TypeHierarchyResolver,
  language?: SupportedLanguage,
  code?: string,
): Taint {
  const sourceLines = code !== undefined ? code.split('\n') : undefined;
  const sources = findSources(calls, types, config.sources, sourceLines, language);
  const sinks = findSinks(calls, config.sinks, typeHierarchy, language, sourceLines);
  const sanitizers = findSanitizers(calls, types, config.sanitizers, sourceLines);

  return { sources, sinks, sanitizers };
}

/**
 * Attach trimmed source-line text to each TaintSource / TaintSink at its
 * recorded line. Idempotent — only fills `code` when missing. Used by passes
 * that emit sources/sinks outside of `analyzeTaint()` (e.g. LanguageSourcesPass).
 */
export function attachSourceLineCode(
  sources: TaintSource[],
  sinks: TaintSink[],
  code: string,
): void {
  const lines = code.split('\n');
  for (const s of sources) {
    if (s.code === undefined) {
      s.code = lines[s.line - 1]?.trim();
    }
  }
  for (const s of sinks) {
    if (s.code === undefined) {
      s.code = lines[s.line - 1]?.trim();
    }
  }
}

/**
 * Find taint sources in method calls and annotated parameters.
 */
function findSources(
  calls: CallInfo[],
  types: TypeInfo[],
  patterns: SourcePattern[],
  sourceLines?: string[],
  language?: SupportedLanguage,
): TaintSource[] {
  const sources: TaintSource[] = [];

  // Check method calls
  for (const call of calls) {
    for (const pattern of patterns) {
      // Honor language restriction on source patterns (added Sprint 9):
      // some Axum extractors (`Path<T>`, `Json<T>`) collide with stdlib
      // names in other languages (e.g. Python `pathlib.Path(raw)` was
      // being matched as the Rust Axum `Path` extractor → spurious
      // `http_path` source). Skip when language is known and excluded.
      if (
        pattern.languages &&
        pattern.languages.length > 0 &&
        language !== undefined &&
        !pattern.languages.includes(language)
      ) {
        continue;
      }
      if (matchesSourcePattern(call, pattern)) {
        sources.push({
          type: pattern.type,
          location: formatCallLocation(call),
          severity: pattern.severity,
          line: call.location.line,
          confidence: 1.0,
          in_method: call.in_method ?? undefined,
        });
      }
    }
  }

  // Check annotated parameters
  for (const type of types) {
    for (const method of type.methods) {
      for (const param of method.parameters) {
        for (const pattern of patterns) {
          if (pattern.annotation && pattern.param_tainted) {
            if (matchesAnnotation(param.annotations, pattern.annotation)) {
              // Use parameter line if available, fallback to method start line
              const paramLine = param.line ?? method.start_line;
              sources.push({
                type: pattern.type,
                location: `@${pattern.annotation} ${param.name} in ${method.name}`,
                severity: pattern.severity,
                line: paramLine,
                confidence: 1.0,
                in_method: method.name,
              });
            }
          }
        }
      }
    }
  }

  // Check methods/constructors with a method-level annotation that taints ALL params.
  // E.g. Jenkins @DataBoundConstructor: every constructor parameter is user-controlled
  // because Jenkins wires them from form/JSON binding at construction time.
  for (const type of types) {
    for (const method of type.methods) {
      for (const pattern of patterns) {
        if (!pattern.method_annotation) continue;
        if (!matchesAnnotation(method.annotations, pattern.method_annotation)) continue;
        for (const param of method.parameters) {
          const paramLine = param.line ?? method.start_line;
          sources.push({
            type: pattern.type,
            location: `@${pattern.method_annotation} ${param.name} in ${method.name}`,
            severity: pattern.severity,
            line: paramLine,
            confidence: 1.0,
            in_method: method.name,
          });
        }
      }
    }
  }

  // Rust web framework extractors: Axum/Actix/Rocket parameter types that carry HTTP input.
  // The parameter type after Tree-sitter extraction may be the bare name
  // (`Path<String>`) or the qualified name (`web::Path<String>` for actix,
  // `axum::extract::Path<T>` for axum). cognium-dev #71.
  //
  // Source-type assignment is sink-coverage aware (see findings.ts
  // canSourceReachSink): `http_body` does not cover `path_traversal`/`ssrf`,
  // so `Form`/`Query`/`Path` extractors are modelled as `http_param` (which
  // covers the full sink set the issue lists). `Json`/`Multipart`/`Body`/
  // `Bytes` remain `http_body` — they're typically deserialized payloads.
  const RUST_EXTRACTOR_KIND = /(?:^|::)(Json|Form|Query|Path|Extension|Multipart|Body|Bytes)(?:<|$)/;
  for (const type of types) {
    for (const method of type.methods) {
      for (const param of method.parameters) {
        if (!param.type) continue;
        const kindMatch = RUST_EXTRACTOR_KIND.exec(param.type);
        if (!kindMatch) continue;
        const kind = kindMatch[1];
        // `Extension<T>` carries shared app state, not HTTP input — skip.
        if (kind === 'Extension') continue;
        const sourceType: 'http_param' | 'http_body' =
          (kind === 'Form' || kind === 'Query' || kind === 'Path') ? 'http_param' : 'http_body';
        const paramLine = param.line ?? method.start_line;
        const alreadyExists = sources.some(
          s => s.line === paramLine && s.variable === param.name,
        );
        if (alreadyExists) continue;
        sources.push({
          type: sourceType,
          location: `${param.type} ${param.name} in ${method.name}`,
          severity: 'high',
          line: paramLine,
          confidence: 1.0,
          variable: param.name,
          in_method: method.name,
        });
      }
    }
  }

  // Inter-procedural: treat certain method parameters as potential taint sources
  // This handles cases where tainted data flows from another class/method.
  //
  // NB (#128): the `interprocedural_param` emission is intentionally
  // *not* gated here — downstream passes (constant propagation,
  // constructor-field tracking in `language-sources-pass.ts`) need the
  // raw seed sources to correctly track taint through DTO chains
  // (`new User(input)` → `user.getName()` → SQL sink). The
  // entry-point classification gate lives at the flow-construction
  // boundary in `interprocedural-pass.ts` instead, where it can drop
  // speculative flows without breaking the propagator's seed set.
  for (const type of types) {
    for (const method of type.methods) {
      // Skip private methods (can only be called from within the class)
      if (method.modifiers.includes('private')) continue;

      // Skip standard methods that are unlikely to receive tainted data
      const skipMethods = ['toString', 'hashCode', 'equals', 'compareTo'];
      if (skipMethods.includes(method.name)) continue;

      for (const param of method.parameters) {
        // Check if parameter type could carry tainted data
        // For typed languages (Java), check the type
        // For untyped languages (JavaScript), treat all params as potentially tainted
        const isTaintable = param.type
          ? isInterproceduralTaintableType(param.type)
          : true; // JavaScript/Python - no type means any value

        if (isTaintable) {
          // Use parameter line if available, fallback to method start line
          const paramLine = param.line ?? method.start_line;
          sources.push({
            type: 'interprocedural_param',
            location: `${param.type || 'any'} ${param.name} in ${method.name}`,
            severity: 'medium',
            line: paramLine,
            confidence: param.type ? 0.7 : 0.5, // Lower confidence for untyped params
            in_method: method.name,
          });
        }
      }
    }
  }

  // JavaScript/Node.js: Detect Express request property access patterns as sources
  // This handles patterns like db.query("SELECT * FROM users WHERE id = " + req.params.id)
  // Get property-based source patterns
  const propertyPatterns = patterns.filter(p => p.property && p.object && p.property_tainted);
  const hasPropertyPatterns = propertyPatterns.length > 0;

  for (const call of calls) {
    for (const arg of call.arguments) {
      if (arg.expression) {
        const taintCheck = isJavaScriptTaintedArgument(arg.expression, hasPropertyPatterns ? patterns : undefined);
        if (taintCheck.isTainted && taintCheck.sourceType) {
          // Check if we already have a source at this line
          const alreadyExists = sources.some(s => s.line === call.location.line && s.type === taintCheck.sourceType);
          if (!alreadyExists) {
            sources.push({
              type: taintCheck.sourceType,
              location: `${arg.expression} in ${call.in_method || 'anonymous'}`,
              severity: 'high',
              line: call.location.line,
              confidence: 1.0,
              in_method: call.in_method ?? undefined,
            });
          }
        }
      }
    }
  }

  // Python/Flask/Django: Detect request property access patterns as sources.
  // Handles subscript access like request.args['id'] which is NOT a call node —
  // instead it appears as an argument expression inside the actual sink call.
  for (const call of calls) {
    for (const arg of call.arguments) {
      if (!arg.expression) continue;
      for (const { pattern, sourceType } of PYTHON_TAINTED_PATTERNS) {
        if (pattern.test(arg.expression)) {
          const alreadyExists = sources.some(
            s => s.line === call.location.line && s.type === sourceType
          );
          if (!alreadyExists) {
            sources.push({
              type: sourceType,
              location: `${arg.expression} in ${call.in_method || 'anonymous'}`,
              severity: 'high',
              line: call.location.line,
              confidence: 1.0,
              in_method: call.in_method ?? undefined,
            });
          }
          break;
        }
      }
    }
  }

  // Deduplicate sources by line+type, keeping highest confidence
  const sourceMap = new Map<string, TaintSource>();
  for (const source of sources) {
    const key = `${source.line}:${source.type}`;
    const existing = sourceMap.get(key);
    if (!existing || source.confidence > existing.confidence) {
      sourceMap.set(key, source);
    }
  }

  const result = Array.from(sourceMap.values());
  if (sourceLines) {
    for (const s of result) {
      s.code = sourceLines[s.line - 1]?.trim();
    }
  }

  // Rust: method-call sources (e.g. `req.match_info()`, `req.uri()`) land on
  // the source-line without a `variable` field — `detectExpressionScanFlows`
  // (taint-propagation-pass.ts) needs the variable name to scan downstream
  // sink-line arguments. Recover it from the surrounding `let <var> = ...`
  // binding, which is the idiomatic shape in actix/axum/rocket handlers.
  // cognium-dev #71.
  if (language === 'rust' && sourceLines) {
    const LET_BINDING = /^\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::\s*[^=]+)?=/;
    for (const s of result) {
      if (s.variable && s.variable.length > 0) continue;
      const lineText = sourceLines[s.line - 1] ?? '';
      const m = LET_BINDING.exec(lineText);
      if (m) s.variable = m[1];
    }
  }

  // Java: YAML/call-pattern source emission (above) records the call site but
  // not the binding identifier. Variable-scoped sanitizer detectors
  // (`isReassignedToLiteralBetween`, allowlist-bounded variable checks,
  // expression-scan sourcesWithVar gate) all short-circuit when
  // `source.variable` is undefined. Recover the LHS from the source line so
  // they keep working for Java tainted-variable patterns. cognium-dev #101.
  //
  // Covers:
  //   `String x = req.getParameter(...)`         → x
  //   `int id = Integer.parseInt(req.getParameter("id"))` → id  (parseInt
  //                                                              sanitizer
  //                                                              clears
  //                                                              downstream)
  //   `final List<String> xs = req.getParameter(...)` → xs
  //   `x = req.getParameter(...)`                → x  (no type)
  //
  // SKIPPED — RHS is `new <Ctor>(...)`: when a source call is nested inside a
  // constructor, the LHS holds the constructor's result, not the source's
  // tainted value. Example (Zip-Slip, cognium-dev #52):
  //   `File outFile = new File(destDir, entry.getName());`
  // Here `outFile` is a File handle, not the tainted entry name; binding
  // `entry.getName()` to `outFile` would break the same-line source→sink
  // flow detection that #52 depends on. The regex rejects `= new ` via the
  // `(?!new\b)` lookahead after the `=`.
  //
  // Conservative: when no clear LHS, leave variable undefined (no regression
  // vs. today's behaviour). `==` is excluded via `(?!=)`.
  if (language === 'java' && sourceLines) {
    // `(?!=)` rejects `==` so the LHS regex doesn't fire on equality
    // comparisons.
    const JAVA_ASSIGN_LHS = /^\s*(?:(?:final|public|private|protected|static|synchronized|volatile|transient)\s+)*(?:[A-Za-z_][\w.]*(?:\s*<[^=]*>)?(?:\s*\[\s*\])*\s+)?([A-Za-z_]\w*)\s*=(?!=)/;
    for (const s of result) {
      if (s.variable && s.variable.length > 0) continue;
      const lineText = sourceLines[s.line - 1] ?? '';
      const m = JAVA_ASSIGN_LHS.exec(lineText);
      if (!m) continue;
      // RHS guard — refuse to bind when the source is nested inside a
      // constructor call. Done in JS (not via regex lookahead) because the
      // post-`=` `\s*` would backtrack to zero and defeat the lookahead.
      const rhs = lineText.slice(m[0].length).trimStart();
      if (/^new\b/.test(rhs)) continue;
      s.variable = m[1];
    }
  }

  // Go: method-call sources (`r.URL.Query().Get("h")`,
  // `r.Header.Get("X-Forwarded-For")`) land on the source line without a
  // `variable` field, so `detectExpressionScanFlows` cannot match the
  // bound identifier in downstream concatenated sink arguments
  // (`exec.Command("sh", "-c", "ping " + host)`). Recover the LHS from
  // the surrounding Go assignment shape. cognium-dev #53.
  //
  // Covers:
  //   `host := r.URL.Query().Get("h")`         → host  (short-var)
  //   `var host = r.URL.Query().Get("h")`      → host  (typed declaration)
  //   `var host string = r.URL.Query().Get("h")` → host (with explicit type)
  //   `host = r.URL.Query().Get("h")`          → host  (reassignment)
  //   `host, ok := r.URL.Query()["h"]`         → host  (first ident of multi-LHS)
  //
  // `(?!=)` rejects `==` so the regex doesn't fire on equality. A leading
  // tuple `name, ok := ...` keeps only the first identifier because that
  // is the value-binding; the rest are status / error idiomatic Go.
  if (language === 'go' && sourceLines) {
    const GO_ASSIGN_LHS = /^\s*(?:var\s+)?([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)*\s*(?::\s*[A-Za-z_][\w.]*\s*)?(?::?=)(?!=)/;
    for (const s of result) {
      if (s.variable && s.variable.length > 0) continue;
      const lineText = sourceLines[s.line - 1] ?? '';
      const m = GO_ASSIGN_LHS.exec(lineText);
      if (m) s.variable = m[1];
    }
  }

  return result;
}

/**
 * Check if a parameter type could carry tainted data in inter-procedural analysis.
 * These are types commonly used to pass user-controlled data between methods.
 */
function isInterproceduralTaintableType(typeName: string): boolean {
  // Normalize type name (remove generics)
  const baseType = typeName.split('<')[0].trim();

  // Types that are already handled by regular taint source patterns
  // These have specific methods that are taint sources (getParameter, getCookies, etc.)
  // and should NOT be treated as interprocedural sources
  const excludedTypes = [
    // Servlet framework - taint comes from specific methods, not the parameter itself
    'HttpServletRequest', 'HttpServletResponse',
    'ServletRequest', 'ServletResponse',
    'HttpSession', 'ServletContext',
    // Spring framework
    'Model', 'ModelMap', 'ModelAndView',
    'WebRequest', 'NativeWebRequest',
    // Other framework types
    'FilterChain', 'RequestDispatcher',
  ];

  if (excludedTypes.includes(baseType)) {
    return false;
  }

  // Types that could carry tainted user data
  const taintableTypes = [
    // Most generic
    'Object',
    // Java Strings
    'String', 'CharSequence', 'StringBuilder', 'StringBuffer',
    // Java Collections
    'Collection', 'List', 'Set', 'Map', 'Queue', 'Deque',
    'ArrayList', 'LinkedList', 'HashSet', 'TreeSet', 'HashMap', 'TreeMap',
    'LinkedHashMap', 'LinkedHashSet', 'Vector', 'Stack',
    'ConcurrentHashMap', 'CopyOnWriteArrayList',
    // Arrays (handled by suffix check below)
    // Streams
    'Stream', 'Optional',
    // Iterators
    'Iterator', 'Iterable',
    // Rust types
    '&str', 'str', '&String', '&mut str', '&mut String',
    'Vec', '&Vec', '&[u8]', '&[String]',
    'Option', 'Result',
  ];

  if (taintableTypes.includes(baseType)) {
    return true;
  }

  // Check for array types
  if (typeName.endsWith('[]')) {
    const elementType = typeName.slice(0, -2);
    // String arrays, Object arrays, and byte arrays are commonly tainted
    if (elementType === 'String' || elementType === 'Object' || elementType === 'byte') {
      return true;
    }
  }

  return false;
}

/**
 * Check if a SQL query call uses parameterized query pattern.
 * Parameterized queries are safe because user input is passed as bound
 * parameters, not concatenated into the query string.
 *
 * Recognized patterns:
 * - db.query(sql, [params], callback)  — Node.js mysql/pg
 * - db.query(sql, [params])            — Node.js mysql2
 * - knex.raw(sql, [params])            — Knex.js
 * - db.Query("SELECT ... WHERE id = ?", input)  — Go database/sql
 * - cursor.execute("SELECT ... WHERE id = %s", (param,))  — Python DB-API
 * - jdbcTemplate.query("SELECT ... WHERE id = ?", mapper)  — Java Spring
 * - stmt.executeQuery("SELECT ... WHERE id = ?")           — Java PreparedStatement
 */
function isParameterizedQueryCall(call: CallInfo, pattern: SinkPattern): boolean {
  // Only applies to SQL injection sinks
  if (pattern.type !== 'sql_injection') return false;

  // Check arg[0] — the query string — for placeholder patterns.
  // If the query is a string literal containing SQL placeholders and no
  // concatenation, it's a parameterized query regardless of how the params
  // are passed (array, varargs, tuple, etc.).
  const queryArg = call.arguments.find(a => a.position === 0);
  if (queryArg) {
    const queryText = queryArg.literal ?? queryArg.expression ?? '';
    // SQL placeholders: ?, $1, $2, :name, %s
    // The ? can appear mid-string ("WHERE id = ? AND") or at end ("WHERE id = ?")
    const hasPlaceholders = /(\?(?:\s|,|$|\))|\$\d+|:\w+|%s)/.test(queryText);
    // String concatenation indicators (unsafe even with placeholders)
    const hasConcatenation = /\+\s*[^+]/.test(queryText) || queryText.includes('${');
    if (hasPlaceholders && !hasConcatenation && call.arguments.length >= 2) {
      return true;
    }
  }

  // Existing check: second arg is array literal [params] (Node.js pattern)
  if (call.arguments.length >= 2) {
    const secondArg = call.arguments.find(a => a.position === 1);
    if (secondArg?.expression) {
      const expr = secondArg.expression.trim();
      if (expr.startsWith('[')) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if a Python subprocess.* call is safe-by-shape: arg[0] is a list
 * literal AND `shell=True` is NOT present. In that shape Python invokes
 * `execve(argv)` directly with no shell interpolation, so a tainted element
 * inside the list cannot escape into shell metacharacters.
 *
 * Cases:
 *   subprocess.run(["ping", "-c", host])                  → safe  (list, default shell=False)
 *   subprocess.run(["ping", "-c", host], shell=False)     → safe  (list, explicit shell=False)
 *   subprocess.run(["ping", "-c", host], shell=True)      → unsafe (shell=True with list — Python
 *                                                                  passes argv[0] as the shell command,
 *                                                                  so behaviour is surprising but per
 *                                                                  CWE-78 keep flagging)
 *   subprocess.run("ping " + host)                        → unsafe (single-string form: a tainted
 *                                                                  command name is a real attack vector)
 *   subprocess.run("ping " + host, shell=True)            → unsafe (classic shell injection)
 *
 * Only applies to the `subprocess` class — `os.system`, `os.exec*` etc. have
 * their own semantics and are handled by their own sink entries.
 */
function isSafePythonSubprocessCall(call: CallInfo, pattern: SinkPattern, language: SupportedLanguage | undefined): boolean {
  if (language !== 'python') return false;
  if (pattern.type !== 'command_injection') return false;
  if (pattern.class !== 'subprocess') return false;

  // arg[0] must be a list literal (Python `[...]`).
  const arg0 = call.arguments.find(a => a.position === 0);
  if (!arg0) return false;
  const expr0 = (arg0.literal ?? arg0.expression ?? '').trim();
  if (!expr0.startsWith('[')) return false;

  // shell=True (any kwarg form) disqualifies the safe-shape skip.
  for (const a of call.arguments) {
    const e = (a.expression ?? '').trim();
    if (/^shell\s*=\s*True\b/.test(e)) return false;
  }

  return true;
}

/**
 * Check if a Go `exec.Command(...)` / `exec.CommandContext(...)` call is
 * safe-by-shape: arg[0] (program) is a string literal AND that literal is
 * NOT a shell program. In that shape Go invokes `execve(program, argv)`
 * directly with no shell interpolation, so tainted subsequent arguments
 * are just argv elements and cannot escape into shell metacharacters.
 *
 * Cases:
 *   exec.Command("ping", "-c", "1", host)           → safe (non-shell program)
 *   exec.Command("git", "clone", taintedURL)        → safe (non-shell program)
 *   exec.Command("/bin/sh", "-c", taintedCmd)       → unsafe (shell program via basename)
 *   exec.Command("sh", "-c", taintedCmd)            → unsafe (shell program, Sprint 23 #53 lock)
 *   exec.Command("bash", "-c", taintedCmd)          → unsafe (shell program)
 *   exec.Command(taintedProg, "-c", "code")         → unsafe (program itself tainted)
 *
 * Sprint 23 widened the exec.Command argPositions to `[]` in the Go plugin
 * so all variadic positions are scanned (#53 shell-shape recall). That
 * widening regressed precision on fixed-argv calls. This shape filter
 * restores precision while preserving #53.
 *
 * cognium-dev #102 FP-25.
 */
function isSafeGoExecCommandCall(call: CallInfo, pattern: SinkPattern, language: SupportedLanguage | undefined): boolean {
  if (language !== 'go') return false;
  if (pattern.type !== 'command_injection') return false;
  if (pattern.class !== 'exec') return false;
  if (pattern.method !== 'Command' && pattern.method !== 'CommandContext') return false;

  // CommandContext shifts: arg[0]=ctx, arg[1]=program
  const programArgPos = pattern.method === 'CommandContext' ? 1 : 0;
  const programArg = call.arguments.find(a => a.position === programArgPos);
  if (!programArg) return false;

  // Prefer the unquoted `literal` field when present — it's non-null only
  // for string-literal arguments. If absent, fall back to the raw
  // `expression` text (which may still be a quoted literal). A bare
  // identifier (e.g. `taintedProg`) sets `literal=null` and `expression`
  // to the identifier text with no surrounding quote — keep dangerous.
  let program: string;
  if (programArg.literal !== null && programArg.literal !== undefined) {
    program = String(programArg.literal).split('/').pop() ?? String(programArg.literal);
  } else {
    const expr = (programArg.expression ?? '').trim();
    if (!(expr.startsWith('"') || expr.startsWith('`') || expr.startsWith("'"))) {
      return false;  // unknown / variable program — assume dangerous
    }
    const stripped = expr.slice(1, -1);
    program = stripped.split('/').pop() ?? stripped;
  }

  // Shell programs interpret subsequent args as shell — keep dangerous.
  const SHELL_PROGRAMS = new Set([
    'sh', 'bash', 'zsh', 'dash', 'ash', 'ksh',
    'cmd', 'cmd.exe', 'powershell', 'pwsh',
    'powershell.exe', 'pwsh.exe',
  ]);
  if (SHELL_PROGRAMS.has(program)) return false;

  // Non-shell program literal: subsequent args are argv elements, not
  // shell metacharacters. Sink is safe.
  return true;
}

/**
 * Check if a Rust `Command::new(...).arg(...).args(...).spawn().output()`
 * chain is safe-by-shape: the program (bound at `Command::new("prog")`) is a
 * string literal AND not a shell program. In that shape Rust invokes
 * `execvp(program, argv)` directly without spawning a shell, so tainted argv
 * elements passed via `.arg()` / `.args()` cannot escape into shell
 * metacharacters.
 *
 * Cases:
 *   Command::new("ls")                                  → safe (constructor, non-shell literal)
 *   Command::new("ls").args(&[user_input])              → safe (chained, literal program)
 *   Command::new("ls").arg(user_input).spawn()          → safe (chained, literal program)
 *   Command::new("sh").arg("-c").arg(taintedCmd)        → unsafe (shell program)
 *   Command::new(taintedProg)                           → unsafe (program itself tainted)
 *   let cmd = Command::new("ls"); cmd.args(&[x]);       → unsafe-by-default
 *                                                         (binding tracking out
 *                                                         of scope; safe only
 *                                                         via direct chain)
 *
 * Only suppresses when the program literal can be read DIRECTLY from the call
 * or its receiver chain text — variable-bound receivers stay dangerous.
 *
 * cognium-dev #115 FP-21.
 */
function isSafeRustCommandCall(call: CallInfo, pattern: SinkPattern, language: SupportedLanguage | undefined): boolean {
  if (language !== 'rust') return false;
  if (pattern.type !== 'command_injection') return false;
  // Two source rules emit Rust Command sinks (config-loader.ts):
  //   (a) `{ method: 'arg'|'args'|'new'|'spawn'|'output', class: 'Command', ... }`
  //       — the per-class rules (rust.json + L1798).
  //   (b) `{ method: 'spawn', languages: [...'rust'], ... }` (L662) — a
  //       class-less universal-spawn rule that fires for Rust too.
  // Allow both shapes through to the per-method shape checks below.
  if (pattern.class !== undefined && pattern.class !== 'Command') return false;

  const SHELL_PROGRAMS = new Set([
    'sh', 'bash', 'zsh', 'dash', 'ash', 'ksh',
    'cmd', 'cmd.exe', 'powershell', 'pwsh',
    'powershell.exe', 'pwsh.exe',
  ]);

  // Extract a program literal from text containing `Command::new("...")`
  // or `Command::new('...')` (anywhere in the receiver chain — Rust builder
  // patterns can put any number of `.arg()` calls between the constructor
  // and the eventual sink method).
  // Returns the basename, or null if no literal.
  const PROGRAM_RE = /\bCommand\s*::\s*new\s*\(\s*(?:r?"([^"]*)"|'([^']*)')/;
  const extractProgram = (text: string): string | null => {
    const m = PROGRAM_RE.exec(text);
    if (!m) return null;
    const lit = m[1] ?? m[2] ?? '';
    return lit.split('/').pop() ?? lit;
  };

  if (pattern.method === 'new') {
    // Constructor: arg[0] is the program. Check the literal directly.
    const programArg = call.arguments.find(a => a.position === 0);
    if (!programArg) return false;
    let program: string;
    if (programArg.literal !== null && programArg.literal !== undefined) {
      program = String(programArg.literal).split('/').pop() ?? String(programArg.literal);
    } else {
      const expr = (programArg.expression ?? '').trim();
      if (!(expr.startsWith('"') || expr.startsWith("'"))) {
        return false;  // non-literal program — keep dangerous
      }
      const stripped = expr.slice(1, -1);
      program = stripped.split('/').pop() ?? stripped;
    }
    return !SHELL_PROGRAMS.has(program);
  }

  if (
    pattern.method === 'arg' ||
    pattern.method === 'args' ||
    pattern.method === 'spawn' ||
    pattern.method === 'output'
  ) {
    // Chained call: receiver text should start with `Command::new("literal")`.
    // If the receiver is a bare identifier (variable-bound), we cannot prove
    // safety without binding tracking — keep dangerous.
    const receiverText = call.receiver ?? '';
    const program = extractProgram(receiverText);
    if (program === null) return false;
    return !SHELL_PROGRAMS.has(program);
  }

  return false;
}

/**
 * Match a Java class-literal expression: `Foo.class`, `com.example.Foo.class`,
 * `User<T>.class` (loose), `Foo[].class`. Does NOT match `Class.forName(...)`,
 * `getClass()`, locals, or any non-literal expression — those remain dangerous
 * for typed-overload deserialization sinks.
 */
const CLASS_LITERAL_RE = /^(?:[A-Za-z_][\w]*\.)*[A-Z][\w]*(?:\[\])*\.class$/;

/**
 * Check if a call's argument at `position` is a fixed-at-compile-time class
 * literal (e.g. `User.class`). Used by SinkPattern.safe_if_class_literal_at to
 * suppress typed deserialization overloads. The untyped 1-arg form and the
 * dynamic-class form (`Class.forName(x)`) never match.
 */
function argIsClassLiteral(call: CallInfo, position: number): boolean {
  const arg = call.arguments.find(a => a.position === position);
  if (!arg) return false;
  const expr = (arg.literal ?? arg.expression ?? '').trim();
  if (!expr) return false;
  return CLASS_LITERAL_RE.test(expr);
}

/**
 * CWE-78 (OS Command Injection) receiver-class allowlist (#129).
 *
 * Unscoped catch-all sinks in `configs/sinks/command.yaml` (e.g. `exec`,
 * `executeCommand`, `runCommand`, `system`, `shell`) match ANY receiver
 * with the method name. On Java OSS top-25, `redis/jedis`'s
 * `UnifiedJedis.executeCommand` (RESP protocol over TCP — NOT shell)
 * produced 1,680 of 1,968 high CWE-78 findings (85.4% FP rate).
 *
 * This allowlist gates emission of `command_injection` sinks behind a
 * known set of OS-command-invoking receiver classes. Calls whose
 * `receiver_type` is statically resolved to a non-allowlist class are
 * suppressed. Calls whose receiver_type is unresolved (dynamic
 * dispatch — typical for JS `child_process.exec`, Python
 * `subprocess.run`, Go `exec.Command`) fall through to preserve recall.
 *
 * Class-scoped sinks for the real OS APIs already exist in command.yaml
 * (Runtime.exec, ProcessBuilder.command, DefaultExecutor.execute,
 * Launcher.launch, etc.); this gate adds the inverse — suppressing
 * non-OS receivers from the unscoped catch-all patterns.
 */
const CWE_78_RECEIVER_ALLOWLIST: ReadonlySet<string> = new Set([
  // java.lang.*
  'Runtime', 'ProcessBuilder', 'Process',
  // Apache Commons Exec
  'CommandLine', 'DefaultExecutor', 'Executor',
  // Gradle
  'Exec',
  // Jenkins
  'Launcher', 'ProcStarter',
  // Spring
  'ProcessExecutor',
  // hutool
  'RuntimeUtil',
]);

/**
 * Find taint sinks in method calls.
 * Deduplicates sinks at the same location+line+cwe, keeping highest confidence.
 */
function findSinks(
  calls: CallInfo[],
  patterns: SinkPattern[],
  typeHierarchy?: TypeHierarchyResolver,
  language?: SupportedLanguage,
  sourceLines?: string[],
): TaintSink[] {
  // Use a map to deduplicate by location+line+cwe
  const sinkMap = new Map<string, TaintSink>();

  for (const call of calls) {
    for (const pattern of patterns) {
      if (matchesSinkPattern(call, pattern, typeHierarchy, language)) {
        // Skip parameterized queries (safe pattern for SQL injection)
        if (isParameterizedQueryCall(call, pattern)) {
          continue;
        }

        // Skip Python subprocess.* calls in safe shape: list arg[0] without
        // shell=True. Python invokes execve() directly with no shell
        // interpolation, so tainted list elements can never escape into
        // shell metacharacters. cognium-dev #48 pt1.
        if (isSafePythonSubprocessCall(call, pattern, language)) {
          continue;
        }

        // Skip Go exec.Command/CommandContext calls in safe shape: arg[0]
        // (program) is a non-shell string literal. Go invokes execve()
        // directly so subsequent argv elements cannot escape into shell
        // metacharacters. Preserves Sprint 23 #53 shell-shape recall
        // (sh/bash/zsh/etc.) while restoring fixed-argv precision.
        // cognium-dev #102 FP-25.
        if (isSafeGoExecCommandCall(call, pattern, language)) {
          continue;
        }

        // Skip Rust Command::new("prog").arg/args/spawn/output calls in
        // safe shape: program literal is a non-shell binary. Rust invokes
        // execvp() directly so subsequent argv elements cannot escape into
        // shell metacharacters. cognium-dev #115 FP-21.
        if (isSafeRustCommandCall(call, pattern, language)) {
          continue;
        }

        // Skip typed deserialization overloads where the target type is a
        // compile-time class literal (e.g. `ObjectMapper.readValue(json,
        // User.class)`). Jackson/Gson/FastJson cannot deserialize arbitrary
        // gadgets when the type is fixed; the dangerous shape is the untyped
        // 1-arg form or a dynamic-class second arg (`Class.forName(x)`).
        if (
          pattern.safe_if_class_literal_at !== undefined &&
          argIsClassLiteral(call, pattern.safe_if_class_literal_at)
        ) {
          continue;
        }

        // #129 — CWE-78 receiver-class allowlist gate.
        // Suppress command_injection emissions on receivers known NOT
        // to invoke OS commands. Constructors check method_name (which
        // equals the class being constructed). Non-constructor calls
        // check receiver_type only when statically resolved;
        // unresolved receivers fall through to preserve recall for
        // dynamic-language module-binding calls (child_process.exec,
        // subprocess.run, os/exec.Command).
        if (pattern.type === 'command_injection') {
          if (call.is_constructor) {
            if (!CWE_78_RECEIVER_ALLOWLIST.has(call.method_name)) {
              continue;
            }
          } else {
            const receiverClass = call.receiver_type;
            if (receiverClass && !CWE_78_RECEIVER_ALLOWLIST.has(receiverClass)) {
              continue;
            }
          }
        }

        const location = formatCallLocation(call);
        const key = `${location}:${call.location.line}:${pattern.cwe}`;
        const confidence = calculateSinkConfidence(call, pattern);

        const existing = sinkMap.get(key);
        if (!existing || confidence > existing.confidence) {
          sinkMap.set(key, {
            type: pattern.type,
            cwe: pattern.cwe,
            location,
            line: call.location.line,
            confidence,
            method: call.method_name,
            argPositions: pattern.arg_positions,
          });
        }
      }
    }
  }

  const result = Array.from(sinkMap.values());
  if (sourceLines) {
    for (const s of result) {
      s.code = sourceLines[s.line - 1]?.trim();
    }
  }
  return result;
}

/**
 * Check if a call matches a source pattern.
 */
function matchesSourcePattern(call: CallInfo, pattern: SourcePattern): boolean {
  // Method-based matching
  if (pattern.method) {
    if (call.method_name !== pattern.method) {
      return false;
    }

    // If class is specified, check receiver
    if (pattern.class && pattern.class !== 'constructor') {
      // Prefer IR-resolved receiver type when available (Java/TS plugins).
      if (call.receiver_type && call.receiver_type === pattern.class) {
        // resolved type matches — accept
      } else if (call.receiver_type_fqn && call.receiver_type_fqn.endsWith('.' + pattern.class)) {
        // FQN tail matches
      } else if (!call.receiver) {
        // Bare function call: accept when import resolution produced a fully
        // qualified target whose tail is `<pattern.class>.<pattern.method>`.
        // Handles Python `from urllib.request import urlopen; urlopen(x)`
        // where `call.resolution.target === 'urllib.request.urlopen'`.
        const target = call.resolution?.target;
        const expectedTail = `${pattern.class}.${pattern.method}`;
        if (target && (target === expectedTail || target.endsWith('.' + expectedTail))) {
          // Resolved bare-import alias matches the class-qualified pattern.
        } else {
          // A bare function call with no receiver can never match a class-qualified method.
          // Without this guard, ANY call named `get()` matches ALL Map/HashMap/Properties
          // patterns, producing false positives for unrelated local functions (e.g. a
          // metric helper `const get = (name) => acc.find(...)`).
          return false;
        }
      } else if (!receiverMightBeClass(call.receiver, pattern.class)) {
        // The receiver might be a variable name, not the class name
        // For now, we do a simple match - in a full implementation,
        // we'd need type inference
        return false;
      }
    }

    return pattern.return_tainted === true;
  }

  return false;
}

/**
 * Check if a call's arguments contain tainted Express/Node.js property access patterns.
 * This handles patterns like req.params.id, req.query.name, req.body.data
 * Also handles binary expressions like 'str' + req.params.id
 */
function isJavaScriptTaintedArgument(
  argExpression: string,
  sourcePatterns?: SourcePattern[]
): { isTainted: boolean; sourceType: SourceType | null } {
  // Build patterns from config if provided - both exact and contained matches
  const exactPatterns: Array<{ pattern: RegExp; sourceType: SourceType }> = [];
  const containedPatterns: Array<{ pattern: RegExp; sourceType: SourceType }> = [];

  if (sourcePatterns) {
    // Use config-based property patterns
    for (const sp of sourcePatterns) {
      if (sp.property && sp.object && sp.property_tainted) {
        // Create regex for exact match (direct argument)
        const exactRegex = new RegExp(`^${sp.object}\\.${sp.property}\\b`);
        exactPatterns.push({ pattern: exactRegex, sourceType: sp.type });
        // Create regex for contained match (binary expressions like 'str' + req.params.id)
        const containedRegex = new RegExp(`\\b${sp.object}\\.${sp.property}\\b`);
        containedPatterns.push({ pattern: containedRegex, sourceType: sp.type });
      }
    }
  }

  // Fallback hardcoded patterns (for backwards compatibility)
  if (exactPatterns.length === 0) {
    const basePatterns = [
      { base: 'req\\.params', sourceType: 'http_param' as SourceType },
      { base: 'req\\.query', sourceType: 'http_param' as SourceType },
      { base: 'req\\.body', sourceType: 'http_body' as SourceType },
      { base: 'req\\.headers', sourceType: 'http_header' as SourceType },
      { base: 'req\\.cookies', sourceType: 'http_cookie' as SourceType },
      { base: 'req\\.url', sourceType: 'http_path' as SourceType },
      { base: 'req\\.path', sourceType: 'http_path' as SourceType },
      { base: 'req\\.originalUrl', sourceType: 'http_path' as SourceType },
      { base: 'req\\.file', sourceType: 'file_input' as SourceType },
      { base: 'req\\.files', sourceType: 'file_input' as SourceType },
      { base: 'request\\.params', sourceType: 'http_param' as SourceType },
      { base: 'request\\.query', sourceType: 'http_param' as SourceType },
      { base: 'request\\.body', sourceType: 'http_body' as SourceType },
      { base: 'request\\.headers', sourceType: 'http_header' as SourceType },
      { base: 'process\\.env', sourceType: 'env_input' as SourceType },
      { base: 'process\\.argv', sourceType: 'io_input' as SourceType },
      { base: 'ctx\\.query', sourceType: 'http_param' as SourceType },
      { base: 'ctx\\.params', sourceType: 'http_param' as SourceType },
      { base: 'ctx\\.request', sourceType: 'http_body' as SourceType },
    ];

    for (const { base, sourceType } of basePatterns) {
      exactPatterns.push({ pattern: new RegExp(`^${base}\\b`), sourceType });
      containedPatterns.push({ pattern: new RegExp(`\\b${base}\\b`), sourceType });
    }
  }

  // First check exact patterns (direct argument like req.params.id)
  for (const { pattern, sourceType } of exactPatterns) {
    if (pattern.test(argExpression)) {
      return { isTainted: true, sourceType };
    }
  }

  // Then check contained patterns (binary expressions like 'str' + req.params.id)
  for (const { pattern, sourceType } of containedPatterns) {
    if (pattern.test(argExpression)) {
      return { isTainted: true, sourceType };
    }
  }

  return { isTainted: false, sourceType: null };
}

/**
 * Receivers that are known NOT to be dangerous for a given method name.
 *
 * This prevents classless sink patterns (e.g. generic "exec()" for
 * Runtime.getRuntime().exec()) from matching unrelated APIs that happen
 * to share the same method name (e.g. RegExp.exec(), db.exec()).
 *
 * Keys are method names; values are lowercase receiver prefixes/names
 * that should be excluded from matching.
 */
const SAFE_RECEIVERS_BY_METHOD: Record<string, Set<string>> = {
  // RegExp.exec(), Pattern.exec() — not command/code execution
  exec: new Set([
    'regex', 'regexp', 'pattern', 're', 'rx', 'match', 'matcher',
    // Database APIs — db.exec() is SQL, not command injection
    'db', 'database', 'sqlite', 'conn', 'connection', 'client',
    'pool', 'knex', 'prisma', 'sequelize', 'transaction', 'tx',
    'stmt', 'statement', 'cursor',
  ]),

  // query() is only a SQL sink when receiver is a database handle — not URL builders,
  // DOM selectors, GraphQL clients, DNS resolvers, etc.
  query: new Set([
    'uri', 'url', 'builder', 'uribuilder', 'uricomponents', 'uricomponentsbuilder',
    'servleturicomponentsbuilder', 'httpurl', 'urlbuilder', 'webclient',
    'request', 'req', 'router', 'route', 'app', 'express',
    'parser', 'selector', 'jquery', 'dom', 'document', 'element',
    'xmlpath', 'xpath', 'dns', 'resolver',
    'graphql', 'apollo', 'querybuilder', 'criteria',
  ]),

  // authenticate() — safe on auth framework objects (token verification, not code exec)
  authenticate: new Set([
    'auth', 'authenticator', 'authmanager', 'authprovider',
    'authenticationmanager', 'authservice', 'oauth', 'token',
    'jwt', 'passport', 'session', 'security', 'credentials',
    'identityprovider', 'ldap', 'saml', 'oidc',
  ]),

  // add() is extremely generic — safe on collections, UI containers, builders, etc.
  add: new Set([
    'list', 'set', 'map', 'collection', 'array', 'queue', 'deque',
    'stack', 'vector', 'builder', 'panel', 'container', 'group',
    'layout', 'menu', 'toolbar', 'model', 'registry', 'context',
    'config', 'options', 'params', 'headers', 'attributes',
    'listeners', 'handlers', 'filters', 'interceptors', 'validators',
    'extensions', 'plugins', 'modules', 'components', 'children',
    'items', 'elements', 'entries', 'rows', 'columns', 'fields',
    'properties', 'descriptors', 'nodes', 'actions', 'results',
    'errors', 'warnings', 'messages', 'notifications', 'events',
    'subscribers', 'observers', 'providers', 'services', 'beans',
    'tasks', 'jobs', 'workers', 'threads', 'schedulers',
  ]),
};

/**
 * Check if a receiver is known to be safe (non-dangerous) for a given
 * method name and sink type.  Used to suppress false positives from
 * classless sink patterns.
 */
function isKnownSafeReceiverForMethod(receiver: string, method: string, sinkType: string): boolean {
  // fromXML/unmarshal are deserialization sinks (CWE-502), NOT command injection (CWE-78).
  // Suppress command_injection on any receiver — the deserialization sink pattern handles it.
  const lowerMethod = method.toLowerCase();
  if ((lowerMethod === 'fromxml' || lowerMethod === 'unmarshal') && sinkType === 'command_injection') {
    return true;
  }

  const safeReceivers = SAFE_RECEIVERS_BY_METHOD[method];
  if (!safeReceivers) return false;

  const lowerReceiver = receiver.toLowerCase();
  // Check direct match or prefix match (e.g. "regexPattern" starts with "regex")
  for (const safe of safeReceivers) {
    if (lowerReceiver === safe || lowerReceiver.startsWith(safe)) {
      return true;
    }
  }
  return false;
}

/**
 * Known false-positive FQN doppelgangers per sink type. A receiver whose
 * resolved fully-qualified type starts with one of these prefixes is
 * dropped from sink matching even when the method name and simple class
 * name would otherwise match.
 *
 * Rationale — Java in particular has multiple libraries that reuse the
 * same simple class name as the JDBC API but with completely different
 * semantics. JSqlParser (`net.sf.jsqlparser.*`) ships a
 * `Statement` type with `execute(StatementVisitor)` and `accept(...)`
 * methods that are visitor-pattern dispatch over an in-memory SQL AST —
 * not database execution. The simple-name pattern `Statement.execute()`
 * cannot tell them apart, so without this filter every JSqlParser
 * visitor call becomes a critical `sql_injection` finding.
 *
 * Prefixes are package-level (trailing dot) so they cover everything in
 * the namespace. Drops are silent — no finding is emitted, so downstream
 * consumers see consistent absence rather than a downgraded finding.
 *
 * `receiver_type_fqn` is populated by Java call extraction (see
 * `src/core/extractors/calls.ts`). When the FQN is unresolvable (e.g.
 * wildcard imports), the exclusion does not fire and the call is
 * processed by the normal heuristic path — conservative on both sides.
 */
const SINK_FQN_EXCLUSIONS: Partial<Record<SinkType, string[]>> = {
  sql_injection: [
    // JSqlParser AST library: Statement.execute(StatementVisitor),
    // Select.accept(SelectVisitor), Insert/Update/Delete.execute(...),
    // Expression.accept(ExpressionVisitor), etc.
    'net.sf.jsqlparser.',
  ],
};

/**
 * Check if a call matches a sink pattern.
 */
function matchesSinkPattern(
  call: CallInfo,
  pattern: SinkPattern,
  typeHierarchy?: TypeHierarchyResolver,
  language?: SupportedLanguage,
): boolean {
  // Language scoping: when the pattern declares a language list, only match
  // calls from a file in that language. Prevents cross-language name collisions
  // (e.g. Python/Rust `cursor.execute(sql)` matching Java `Executor.execute(Runnable)`).
  if (pattern.languages && pattern.languages.length > 0 && language !== undefined) {
    if (!pattern.languages.includes(language)) {
      return false;
    }
  }

  // Method name must match
  // Handle fully qualified names (e.g., "java.io.FileInputStream" should match "FileInputStream")
  const callMethodName = call.method_name;
  const patternMethod = pattern.method;

  // Direct match
  let methodMatches = callMethodName === patternMethod;

  // If not direct match, check if fully qualified name ends with pattern
  if (!methodMatches && callMethodName.includes('.')) {
    const simpleName = callMethodName.substring(callMethodName.lastIndexOf('.') + 1);
    methodMatches = simpleName === patternMethod;
  }

  if (!methodMatches) {
    return false;
  }

  // FQN doppelganger exclusion: drop the match if the receiver's resolved
  // fully-qualified type belongs to a library known to share simple class
  // names with the sink target without sharing the dangerous semantics.
  // Skipped when receiver_type_fqn is undefined/null (i.e. the simple-name
  // matcher remains the source of truth for unresolvable receivers).
  if (call.receiver_type_fqn) {
    const exclusions = SINK_FQN_EXCLUSIONS[pattern.type];
    if (exclusions) {
      for (const prefix of exclusions) {
        if (call.receiver_type_fqn.startsWith(prefix)) {
          return false;
        }
      }
    }
  }

  // Check class if specified
  if (pattern.class) {
    if (pattern.class === 'constructor') {
      // Constructor call - method name is the class name
      return true;
    }

    // Prefer the IR-resolved receiver type when the language plugin populates it
    // (Java/TS resolve simple types). Falls back to the receiver-name heuristic
    // when the type is unresolved.
    if (call.receiver_type && call.receiver_type === pattern.class) {
      // Resolved type matches — accept directly.
    } else if (call.receiver_type_fqn && call.receiver_type_fqn.endsWith('.' + pattern.class)) {
      // FQN tail matches simple class name.
    } else if (call.receiver && !receiverMightBeClass(call.receiver, pattern.class)) {
      // Heuristic match failed; fall back to TypeHierarchyResolver if available
      if (typeHierarchy && typeHierarchy.couldBeType(call.receiver, pattern.class)) {
        return true;
      }
      // Last-resort opt-in: when the sink declares allow_unresolved_receiver
      // and the call has an unresolved type with a dotted receiver expression
      // (e.g. `req.db.query`, `ctx.app.db.execute` — Express-style runtime
      // decoration), accept the match. Strictly gated to avoid widening the
      // FP surface on every sink. (cognium-dev #95)
      if (
        pattern.allow_unresolved_receiver &&
        !call.receiver_type &&
        !call.receiver_type_fqn &&
        call.receiver.includes('.')
      ) {
        return true;
      }
      return false;
    } else if (!call.receiver && !call.receiver_type) {
      // Bare function call: accept when import resolution produced a fully
      // qualified target whose tail is `<pattern.class>.<pattern.method>`.
      // Handles `from urllib.request import urlopen; urlopen(x)` against
      // sink pattern { method: 'urlopen', class: 'urllib.request' }.
      const target = call.resolution?.target;
      const expectedTail = `${pattern.class}.${pattern.method}`;
      if (target && (target === expectedTail || target.endsWith('.' + expectedTail))) {
        // accept
      } else {
        // If no receiver and no resolved type but class is required, don't match
        return false;
      }
    }
  }

  // If no class specified but the call has a receiver, check that the receiver
  // is not a known non-dangerous API.  Without this guard, classless patterns
  // such as the generic "exec()" command-injection entry (intended for
  // Runtime.getRuntime().exec()) match unrelated methods like RegExp.exec().
  if (!pattern.class && call.receiver) {
    if (isKnownSafeReceiverForMethod(call.receiver, call.method_name, pattern.type)) {
      return false;
    }
  }

  // If no class specified, match any receiver (or no receiver)
  return true;
}

/**
 * Check if an annotation list contains a specific annotation.
 */
function matchesAnnotation(annotations: string[], targetAnnotation: string): boolean {
  for (const ann of annotations) {
    // Handle both "RequestParam" and "RequestParam(value=...)" formats
    const annName = ann.split('(')[0].trim();
    if (annName === targetAnnotation) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a receiver variable might be an instance of a class.
 * This is a heuristic - full type inference would be more accurate.
 */
function receiverMightBeClass(receiver: string, className: string): boolean {
  // Suffix-wildcard pattern (e.g. `*Mapper`, `*Repository`) — matches any
  // identifier whose simple name ends in the suffix (case-insensitive).
  // Used by MyBatis ORM patterns (UserMapper, OrderMapper, …) and similar
  // framework conventions where the class name follows a fixed naming pattern
  // rather than a single hardcoded class.
  if (className.startsWith('*') && className.length > 1) {
    const suffix = className.slice(1).toLowerCase();
    // Simple-name view: drop trailing `()` chains and any dotted prefix
    // (e.g. `org.example.userMapper` → `userMapper`).
    let simpleReceiver = receiver;
    if (simpleReceiver.includes('.') && !simpleReceiver.endsWith(')')) {
      simpleReceiver = simpleReceiver.substring(simpleReceiver.lastIndexOf('.') + 1);
    }
    return simpleReceiver.toLowerCase().endsWith(suffix);
  }

  // Direct match
  if (receiver === className) {
    return true;
  }

  // Constructor-call receiver: `ClassName(args)` — Python `Path(raw)`,
  // JS `new URL(s)` (handled separately), etc. When the receiver is a
  // direct function call whose function name equals the target class
  // name, the resulting object is an instance of that class.
  // Required for the `pathlib.Path(x).resolve()` sanitizer to match
  // class: "Path" against receiver "Path(raw)" — Sprint 9 #48.2.
  if (receiver.endsWith(')')) {
    const ctorMatch = receiver.match(/^(\w+)\(/);
    if (ctorMatch) {
      const ctorName = ctorMatch[1];
      if (ctorName === className || ctorName.toLowerCase() === className.toLowerCase()) {
        return true;
      }
    }
  }

  // Chained method-call receiver: `<expr>.ClassName()` — e.g. Go
  // `w.Header()` where `http.ResponseWriter.Header()` returns
  // `http.Header`. Required for sinks like `{ class: 'Header', method:
  // 'Set' }` to match `w.Header().Set(k, v)`. (cognium-dev #111)
  const chainedCallSuffix = `.${className}()`;
  if (receiver.endsWith(chainedCallSuffix) ||
      receiver.toLowerCase().endsWith(chainedCallSuffix.toLowerCase())) {
    return true;
  }

  // Rust/C++ scoped receivers: extract the type name before ::
  // Handles both single-line and multi-line chained calls, e.g.:
  //   "Command::new(\"sh\").arg(\"-c\").arg(&input)"          (single-line)
  //   "Command::new(\"sh\")\n  .arg(\"-c\")\n  .arg(&input)"  (multi-line)
  if (receiver.includes('::')) {
    const scopePrefix = receiver.match(/^(\w+)::/);
    if (scopePrefix) {
      const typeName = scopePrefix[1];
      if (typeName === className || typeName.toLowerCase() === className.toLowerCase()) {
        return true;
      }
    }
  }

  // Handle fully qualified paths like "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate"
  // Check if the receiver ends with the class name (case insensitive)
  const lowerReceiver = receiver.toLowerCase();
  const lowerClass = className.toLowerCase();
  if (lowerReceiver.endsWith(lowerClass) || lowerReceiver.endsWith('.' + lowerClass)) {
    return true;
  }

  // Extract last part of dotted path (without method calls)
  if (receiver.includes('.') && !receiver.endsWith(')')) {
    const lastPart = receiver.substring(receiver.lastIndexOf('.') + 1);
    if (lastPart.toLowerCase() === lowerClass) {
      return true;
    }
    // Also check common naming patterns in the last part
    if (lastPart.toLowerCase().includes(lowerClass)) {
      return true;
    }
  }

  // Handle chained calls like "response.getWriter()" - extract last method call
  // and check if it returns the expected type
  if (receiver.includes('.') && receiver.endsWith(')')) {
    const methodCallMatch = receiver.match(/\.(\w+)\(\)$/);
    if (methodCallMatch) {
      const methodName = methodCallMatch[1];
      const returnTypeMappings: Record<string, string[]> = {
        'getWriter': ['PrintWriter'],
        'getOutputStream': ['OutputStream', 'ServletOutputStream'],
        'getReader': ['BufferedReader'],
        'getInputStream': ['InputStream', 'ServletInputStream'],
        'getConnection': ['Connection'],
        'createStatement': ['Statement'],
        'prepareStatement': ['PreparedStatement'],
        'getRuntime': ['Runtime'],
        'builder': ['Response', 'ResponseBuilder', 'HttpResponseBuilder'],
        'stdin': ['stdin', 'Stdin', 'BufReader'],
        'lock': ['stdin', 'Stdin', 'StdinLock', 'BufReader'],
      };
      const expectedTypes = returnTypeMappings[methodName];
      if (Array.isArray(expectedTypes) && expectedTypes.includes(className)) {
        return true;
      }
    }

    // Chained-call-with-args return-type heuristics for Go text/template
    // factories (cognium-dev#88). The standard idiom is e.g.
    //   `template.Must(template.New("p").Parse(src)).Execute(w, data)`
    // where the receiver is the chained `template.Must(...)` returning
    // *Template. The factory names are sufficiently specific that we only
    // recognise them in the `template.X(...)` form (receiver-prefix gated)
    // to avoid colliding with unrelated Parse/Clone/New methods.
    const goTemplateFactoryMatch = receiver.match(/\.(Must|New|Parse|ParseFiles|ParseGlob|ParseFS|Clone|Funcs|Option|Lookup|Delims)\(.+\)$/);
    if (goTemplateFactoryMatch && className === 'Template') {
      // Receiver must start with `template.` or `tmpl.` or an aliased template
      // package — keep this conservative by requiring the chain to contain
      // a literal `template.` segment.
      if (/(?:^|\b)template\./.test(receiver) || /(?:^|\b)tmpl\./.test(receiver)) {
        return true;
      }
    }
  }

  // Handle Rust scoped calls like "Response::builder()" — extract type before ::
  // and function name after :: for return-type heuristics (e.g., io::stdin() returns Stdin)
  if (receiver.includes('::') && receiver.endsWith(')')) {
    const scopedMatch = receiver.match(/^(\w+)::(\w+)\(.*\)$/);
    if (scopedMatch) {
      const typeName = scopedMatch[1];
      const funcName = scopedMatch[2];
      if (typeName === className || typeName.toLowerCase() === lowerClass) {
        return true;
      }
      // Check if the function name matches or returns the expected class
      if (funcName === className || funcName.toLowerCase() === lowerClass) {
        return true;
      }
    }
  }

  // Denylist: identifiers whose lowercased form is a well-known standalone JDK
  // type / generic concept name. For these, skip the loose substring/suffix
  // heuristics — only explicit `commonMappings` (below) should resolve them.
  // Prevents e.g. variable `executor` (j.u.c.Executor) wrongly matching pattern
  // class `DefaultExecutor` (Apache Commons Exec) just because
  // 'defaultexecutor'.includes('executor'). See issue #14.
  const ambiguousIdentifiers = new Set([
    'executor', 'pool', 'connection', 'manager',
    'handler', 'controller', 'task', 'thread', 'job',
    // Short Python DB abbreviation; would otherwise prefix-match obscure XSS
    // sink classes like XWiki's `CurrentTimePlugin` ('current'.startsWith('cur'))
    // via the CamelCase word prefix heuristic and produce an xss FP on every
    // `cur.execute(...)`. Resolved via commonMappings → ['Cursor']. See #65 / #48 pt3.
    'cur',
  ]);
  const isAmbiguous = ambiguousIdentifiers.has(lowerReceiver);

  // e.g., "request" might be HttpServletRequest
  // Match when receiver is contained in class name, but only if:
  //   (a) the receiver is ≥ 5 chars (avoids short generic names), OR
  //   (b) the receiver is 3-4 chars AND occupies ≥ 40% of the class name
  // This prevents "auth" (4/34=0.12) matching "DefaultOAuth2RequestAuthenticator"
  // while allowing "stmt" (4/9=0.44) to match "Statement".
  if (!isAmbiguous && lowerReceiver.length >= 3 && lowerClass.includes(lowerReceiver)) {
    if (lowerReceiver.length >= 5 || lowerReceiver.length / lowerClass.length >= 0.4) {
      return true;
    }
  }

  // Short-prefix/suffix heuristic: "stmt" might be StatementImpl (prefix),
  // "sink" might be CustomSink (suffix).
  // Require the receiver to cover ≥40% of the class name (mirroring the
  // `includes` heuristic at line 922) so short receivers like `cur` do not
  // loosely match unrelated long class names (e.g. `cur` vs
  // `CurrentTimePlugin` — the XWiki XSS sink that caused #65 / #48 pt3).
  // Receivers with explicit commonMappings entries (`ev`, `sb`, `pb`, etc.)
  // are still resolved by the commonMappings check below.
  if (!isAmbiguous && lowerReceiver.length >= 2) {
    if (lowerClass.startsWith(lowerReceiver) || lowerClass.endsWith(lowerReceiver)) {
      if (lowerReceiver.length / lowerClass.length >= 0.4) {
        return true;
      }
    }
  }

  // CamelCase word prefix heuristic: "req" might be CustomRequest (starts a word),
  // "lang" might be SimpleLanguage.  Check if the receiver matches the start of
  // any CamelCase segment and covers ≥ 40% of that word.
  // This prevents "auth" (4/13=0.31) matching "authenticator" while allowing
  // "req" (3/7=0.43) to match "request" and "lang" (4/8=0.50) to match "language".
  if (!isAmbiguous && lowerReceiver.length >= 3) {
    const words = className.replace(/([a-z])([A-Z])/g, '$1\0$2').toLowerCase().split('\0');
    for (const word of words) {
      if (word.startsWith(lowerReceiver) && lowerReceiver.length / word.length >= 0.4) {
        return true;
      }
    }
  }

  // Common abbreviations
  const commonMappings: Record<string, string[]> = {
    // HTTP/Servlet
    request: ['HttpServletRequest', 'ServletRequest'],
    response: ['HttpServletResponse', 'ServletResponse'],
    session: ['HttpSession'],

    // Database
    stmt: ['Statement', 'PreparedStatement'],
    conn: ['Connection'],
    em: ['EntityManager'],
    ps: ['PreparedStatement'],
    rs: ['ResultSet'],
    // `template` resolves to either Spring's JdbcTemplate (Java) or Go's
    // text/template `Template` — both are common idioms and the sink patterns
    // they participate in are language-scoped, so the joint mapping is safe.
    template: ['JdbcTemplate', 'Template'],
    tmpl: ['Template'],   // Go text/template idiom (cognium-dev#88)
    cur: ['Cursor'],         // Python DB-API cursor — see ambiguousIdentifiers note
    cursor: ['Cursor'],

    // I/O
    writer: ['PrintWriter'],
    out: ['PrintWriter', 'OutputStream'],
    reader: ['BufferedReader'],

    // Process/Runtime
    runtime: ['Runtime'],
    pb: ['ProcessBuilder'],

    // Scripting / Expression evaluation
    engine: ['ScriptEngine'],
    ev: ['ExpressionEvaluator', 'ScriptEvaluator', 'ClassBodyEvaluator'],
    evaluator: ['ExpressionEvaluator', 'ScriptEvaluator', 'ClassBodyEvaluator'],

    // LDAP
    ctx: ['Context', 'InitialContext', 'DirContext', 'InitialDirContext', 'LdapContext'],
    context: ['Context', 'InitialContext', 'DirContext', 'InitialDirContext', 'LdapContext'],
    dirCtx: ['DirContext', 'InitialDirContext'],
    ldapCtx: ['LdapContext'],
    idc: ['InitialDirContext'],
    ic: ['InitialContext'],
    dc: ['DirContext'],
    lc: ['LdapContext'],

    // XML/XPath
    xpath: ['XPath'],
    xp: ['XPath'],
    doc: ['Document', 'DocumentBuilder'],
    document: ['Document'],
    builder: ['DocumentBuilder', 'SAXParserFactory'],
    parser: ['SAXParser', 'XMLReader', 'DocumentBuilder'],
    saxParser: ['SAXParser'],
    xmlReader: ['XMLReader'],
    transformer: ['Transformer', 'TransformerFactory'],
    tf: ['TransformerFactory'],
    unmarshaller: ['Unmarshaller'],
    jaxb: ['Unmarshaller'],

    // HTTP Clients (SSRF)
    url: ['URL'],
    uri: ['URI'],
    client: ['HttpClient', 'WebClient'],
    httpClient: ['HttpClient'],
    webClient: ['WebClient'],
    restTemplate: ['RestTemplate'],
    rest: ['RestTemplate'],

    // Deserialization
    ois: ['ObjectInputStream'],
    objectInput: ['ObjectInputStream'],
    xstream: ['XStream'],
    mapper: ['ObjectMapper'],
    objectMapper: ['ObjectMapper'],

    // Files
    files: ['Files'],

    // Mail/MIME parts (JavaMail)
    part: ['Part', 'MimePart', 'BodyPart', 'MimeBodyPart'],
    bodyPart: ['BodyPart', 'MimeBodyPart'],
    mimePart: ['MimePart', 'MimeBodyPart'],
    mimeBodyPart: ['MimeBodyPart'],
    message: ['Message', 'MimeMessage'],
    mimeMessage: ['MimeMessage'],
    multipart: ['Multipart', 'MimeMultipart'],
    mp: ['Multipart', 'MimeMultipart'],

    // Zip/Archive
    zipEntry: ['ZipEntry'],
    entry: ['ZipEntry', 'TarArchiveEntry', 'JarEntry'],
    jarEntry: ['JarEntry'],

    // String builders/buffers (XSS via HTML construction)
    sb: ['StringBuilder', 'StringBuffer'],
    buffer: ['StringBuilder', 'StringBuffer'],
    result: ['StringBuilder', 'StringBuffer'],
    html: ['StringBuilder', 'StringBuffer'],
    output: ['StringBuilder', 'StringBuffer'],
    buf: ['StringBuilder', 'StringBuffer'],
    m_result: ['StringBuilder', 'StringBuffer'],
    stringBuffer: ['StringBuffer'],
    stringBuilder: ['StringBuilder'],

    // Maps/Collections (plugin parameters, config values)
    params: ['Map', 'HashMap', 'LinkedHashMap', 'TreeMap'],
    parameters: ['Map', 'HashMap'],
    args: ['Map', 'HashMap'],
    options: ['Map', 'HashMap'],
    config: ['Map', 'HashMap', 'Properties'],
    props: ['Properties', 'Map'],
    map: ['Map', 'HashMap', 'LinkedHashMap', 'TreeMap'],
    m_params: ['Map', 'HashMap'],

    // JavaScript/Node.js/Express mappings
    req: ['Request', 'HttpServletRequest'],
    res: ['Response', 'HttpServletResponse'],
    app: ['Express', 'Application'],
    router: ['Router'],
    fs: ['fs'],
    path: ['path'],
    http: ['http'],
    https: ['https'],
    child_process: ['child_process'],
    crypto: ['crypto'],
    exec: ['child_process'],
    spawn: ['child_process'],
    db: ['Connection', 'Pool', 'mysql'],
    pool: ['Pool', 'Connection'],
    mysql: ['mysql'],
    knex: ['knex'],
    prisma: ['prisma'],
    axios: ['axios'],
    fetch: ['fetch'],

    // Go idioms (single-letter receivers)
    r: ['Request'],
    w: ['ResponseWriter'],
  };

  const mappings = commonMappings[lowerReceiver];
  if (mappings && Array.isArray(mappings) && mappings.includes(className)) {
    return true;
  }

  // Try stripping trailing digits from receiver (e.g., XSTREAM2 → xstream → XStream)
  const strippedReceiver = lowerReceiver.replace(/\d+$/, '');
  if (strippedReceiver !== lowerReceiver && strippedReceiver.length >= 2) {
    const strippedMappings = commonMappings[strippedReceiver];
    if (strippedMappings && Array.isArray(strippedMappings) && strippedMappings.includes(className)) {
      return true;
    }
    // Also check if the stripped receiver matches via the heuristic checks above
    // (e.g., xstream2 → xstream → starts with 'xstream' which is the class XStream)
    if (lowerClass.startsWith(strippedReceiver) || strippedReceiver.startsWith(lowerClass)) {
      return true;
    }
  }

  return false;
}

/**
 * Format call location for human-readable output.
 */
function formatCallLocation(call: CallInfo): string {
  const parts: string[] = [];

  if (call.receiver) {
    parts.push(`${call.receiver}.${call.method_name}()`);
  } else {
    parts.push(`${call.method_name}()`);
  }

  if (call.in_method) {
    parts.push(`in ${call.in_method}`);
  }

  return parts.join(' ');
}

/**
 * Calculate confidence score for a sink match.
 */
function calculateSinkConfidence(call: CallInfo, pattern: SinkPattern): number {
  let confidence = 0.8; // Base confidence

  // Higher confidence if we have a receiver that matches
  if (pattern.class && call.receiver) {
    if (receiverMightBeClass(call.receiver, pattern.class)) {
      confidence += 0.1;
    }
  }

  // Higher confidence for critical severity patterns
  if (pattern.severity === 'critical') {
    confidence += 0.1;
  }

  return Math.min(confidence, 1.0);
}

/**
 * Check if a variable at a given position flows to a dangerous sink argument.
 */
export function isInDangerousPosition(
  argPosition: number,
  pattern: SinkPattern
): boolean {
  return pattern.arg_positions.includes(argPosition);
}

/**
 * Find sanitizers in method calls and annotated parameters.
 */
function findSanitizers(
  calls: CallInfo[],
  types: TypeInfo[],
  patterns: SanitizerPattern[],
  sourceLines?: string[]
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];

  // Build a set of method names with @sanitizer annotation (from Javadoc comments)
  const sanitizerMethods = new Set<string>();
  for (const type of types) {
    for (const method of type.methods) {
      if (method.annotations.includes('sanitizer')) {
        sanitizerMethods.add(method.name);
      }
    }
  }

  // Sprint 9 #79 (Phase L): derive wrapper sanitizers.
  // A method qualifies as a derived sanitizer when its body is exactly
  // `return <known_sanitizer>(<param>)` (optionally `await`-prefixed).
  // We require:
  //   1. Method body span ≤ 2 lines (signature + single return).
  //   2. Exactly one non-recursive call inside the method's line range.
  //   3. That call matches a configured sanitizer pattern with non-empty
  //      `removes`.
  //   4. The inner call's argument is exactly one of the wrapper's params.
  //   5. When source is available, the inner call's source line, after
  //      `return ` / `return await `, starts with the inner call's
  //      `[receiver.]method(` prefix and ends with `)` — rejecting
  //      unsafe shapes like `return x + shlex.quote(x)`.
  const wrapperSanitizers = new Map<string, SinkType[]>();
  for (const type of types) {
    for (const method of type.methods) {
      const bodySize = method.end_line - method.start_line;
      if (bodySize < 0 || bodySize > 2) continue;
      const paramNames = new Set(method.parameters.map(p => p.name));
      if (paramNames.size === 0) continue;

      const inside: CallInfo[] = [];
      for (const c of calls) {
        if (c.location.line < method.start_line || c.location.line > method.end_line) continue;
        if (c.method_name === method.name) continue; // recursion guard
        inside.push(c);
      }
      if (inside.length !== 1) continue;
      const innerCall = inside[0]!;

      let matched: SanitizerPattern | undefined;
      for (const pattern of patterns) {
        if (matchesSanitizerPattern(innerCall, pattern)) {
          matched = pattern;
          break;
        }
      }
      if (!matched || !matched.removes || matched.removes.length === 0) continue;

      let argOk = false;
      for (const arg of innerCall.arguments) {
        if (arg.variable && paramNames.has(arg.variable)) { argOk = true; break; }
      }
      if (!argOk) continue;

      if (sourceLines) {
        const lineText = sourceLines[innerCall.location.line - 1] ?? '';
        const stripped = lineText.trim();
        const returnMatch = stripped.match(/^return\s+(?:await\s+)?(.*)$/);
        if (!returnMatch) continue;
        const after = returnMatch[1]!.replace(/;\s*$/, '').trimEnd();
        const callPrefix = innerCall.receiver
          ? `${innerCall.receiver}.${innerCall.method_name}(`
          : `${innerCall.method_name}(`;
        if (!after.startsWith(callPrefix)) continue;
        if (!after.endsWith(')')) continue;
      }

      const existing = wrapperSanitizers.get(method.name);
      if (existing) {
        const set = new Set<SinkType>([...existing, ...matched.removes]);
        wrapperSanitizers.set(method.name, Array.from(set));
      } else {
        wrapperSanitizers.set(method.name, [...matched.removes]);
      }
    }
  }

  // Emit a derived-sanitizer entry at each call site to a wrapper method.
  for (const call of calls) {
    const removes = wrapperSanitizers.get(call.method_name);
    if (!removes) continue;
    sanitizers.push({
      type: 'derived_wrapper',
      method: formatSanitizerMethod(call),
      line: call.location.line,
      sanitizes: removes,
    });
  }

  // Check method calls for sanitizer methods
  for (const call of calls) {
    // Check if this call is to a method with @sanitizer annotation
    if (sanitizerMethods.has(call.method_name)) {
      sanitizers.push({
        type: 'javadoc_sanitizer',
        method: formatSanitizerMethod(call),
        line: call.location.line,
        sanitizes: ['xss', 'sql_injection', 'path_traversal', 'command_injection', 'ssrf'], // Generic sanitizer removes all
      });
      continue; // Skip pattern matching - already added as sanitizer
    }

    for (const pattern of patterns) {
      if (matchesSanitizerPattern(call, pattern)) {
        sanitizers.push({
          type: determineSanitizerType(pattern),
          method: formatSanitizerMethod(call),
          line: call.location.line,
          sanitizes: pattern.removes,
        });
      }
    }
  }

  // Check annotated parameters for sanitizer annotations
  for (const type of types) {
    for (const method of type.methods) {
      for (const param of method.parameters) {
        for (const pattern of patterns) {
          if (pattern.annotation && matchesAnnotation(param.annotations, pattern.annotation)) {
            sanitizers.push({
              type: 'annotation',
              method: `@${pattern.annotation} ${param.name} in ${method.name}`,
              line: method.start_line,
              sanitizes: pattern.removes,
            });
          }
        }
      }
    }
  }

  return sanitizers;
}

/**
 * Check if a call matches a sanitizer pattern.
 */
function matchesSanitizerPattern(call: CallInfo, pattern: SanitizerPattern): boolean {
  // Method-based matching
  if (pattern.method) {
    if (call.method_name !== pattern.method) {
      return false;
    }

    // If class is specified, check receiver
    if (pattern.class) {
      if (!call.receiver || !receiverMightBeClass(call.receiver, pattern.class)) {
        return false;
      }
    }

    return true;
  }

  return false;
}

/**
 * Determine the type of sanitizer based on pattern.
 */
function determineSanitizerType(pattern: SanitizerPattern): string {
  if (pattern.annotation) {
    return 'annotation';
  }
  if (pattern.method) {
    return 'method_call';
  }
  return 'unknown';
}

/**
 * Format sanitizer method for human-readable output.
 */
function formatSanitizerMethod(call: CallInfo): string {
  if (call.receiver) {
    return `${call.receiver}.${call.method_name}()`;
  }
  return `${call.method_name}()`;
}
