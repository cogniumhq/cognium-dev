/**
 * Taint source/sink matcher
 *
 * Matches method calls and annotations against taint configurations.
 */

import type { CallInfo, TypeInfo, TaintSource, TaintSink, TaintSanitizer, Taint, SourceType } from '../types/index.js';
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
 */
export function analyzeTaint(
  calls: CallInfo[],
  types: TypeInfo[],
  config: TaintConfig = getDefaultConfig(),
  typeHierarchy?: TypeHierarchyResolver,
): Taint {
  const sources = findSources(calls, types, config.sources);
  const sinks = findSinks(calls, config.sinks, typeHierarchy);
  const sanitizers = findSanitizers(calls, types, config.sanitizers);

  return { sources, sinks, sanitizers };
}

/**
 * Find taint sources in method calls and annotated parameters.
 */
function findSources(
  calls: CallInfo[],
  types: TypeInfo[],
  patterns: SourcePattern[]
): TaintSource[] {
  const sources: TaintSource[] = [];

  // Check method calls
  for (const call of calls) {
    for (const pattern of patterns) {
      if (matchesSourcePattern(call, pattern)) {
        sources.push({
          type: pattern.type,
          location: formatCallLocation(call),
          severity: pattern.severity,
          line: call.location.line,
          confidence: 1.0,
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
          });
        }
      }
    }
  }

  // Rust web framework extractors: Axum/Actix/Rocket parameter types that carry HTTP input.
  // e.g. Json<T>, Form<T>, Query<T>, Path<T>, Body, Bytes, Multipart
  const RUST_EXTRACTOR_TYPES = /^(?:Json|Form|Query|Path|Extension|Multipart)(?:<|$)|^(?:Body|Bytes)$/;
  for (const type of types) {
    for (const method of type.methods) {
      for (const param of method.parameters) {
        if (param.type && RUST_EXTRACTOR_TYPES.test(param.type)) {
          const paramLine = param.line ?? method.start_line;
          const alreadyExists = sources.some(s => s.line === paramLine && s.type === 'http_body');
          if (!alreadyExists) {
            sources.push({
              type: 'http_body',
              location: `${param.type} ${param.name} in ${method.name}`,
              severity: 'high',
              line: paramLine,
              confidence: 1.0,
            });
          }
        }
      }
    }
  }

  // Inter-procedural: treat certain method parameters as potential taint sources
  // This handles cases where tainted data flows from another class/method
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

  return Array.from(sourceMap.values());
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
 * Find taint sinks in method calls.
 * Deduplicates sinks at the same location+line+cwe, keeping highest confidence.
 */
function findSinks(calls: CallInfo[], patterns: SinkPattern[], typeHierarchy?: TypeHierarchyResolver): TaintSink[] {
  // Use a map to deduplicate by location+line+cwe
  const sinkMap = new Map<string, TaintSink>();

  for (const call of calls) {
    for (const pattern of patterns) {
      if (matchesSinkPattern(call, pattern, typeHierarchy)) {
        // Skip parameterized queries (safe pattern for SQL injection)
        if (isParameterizedQueryCall(call, pattern)) {
          continue;
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

  return Array.from(sinkMap.values());
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
      // A bare function call with no receiver can never match a class-qualified method.
      // Without this guard, ANY call named `get()` matches ALL Map/HashMap/Properties
      // patterns, producing false positives for unrelated local functions (e.g. a
      // metric helper `const get = (name) => acc.find(...)`).
      if (!call.receiver) {
        return false;
      }
      // The receiver might be a variable name, not the class name
      // For now, we do a simple match - in a full implementation,
      // we'd need type inference
      if (!receiverMightBeClass(call.receiver, pattern.class)) {
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
 * Check if a call matches a sink pattern.
 */
function matchesSinkPattern(call: CallInfo, pattern: SinkPattern, typeHierarchy?: TypeHierarchyResolver): boolean {
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

  // Check class if specified
  if (pattern.class) {
    if (pattern.class === 'constructor') {
      // Constructor call - method name is the class name
      return true;
    }

    // Check receiver - if pattern has class, receiver should match
    if (call.receiver && !receiverMightBeClass(call.receiver, pattern.class)) {
      // Heuristic match failed; fall back to TypeHierarchyResolver if available
      if (typeHierarchy && typeHierarchy.couldBeType(call.receiver, pattern.class)) {
        return true;
      }
      return false;
    }

    // If no receiver but class is required, don't match
    if (!call.receiver) {
      return false;
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
  // Direct match
  if (receiver === className) {
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

  // e.g., "request" might be HttpServletRequest
  // Match when receiver is contained in class name, but only if:
  //   (a) the receiver is ≥ 5 chars (avoids short generic names), OR
  //   (b) the receiver is 3-4 chars AND occupies ≥ 40% of the class name
  // This prevents "auth" (4/34=0.12) matching "DefaultOAuth2RequestAuthenticator"
  // while allowing "stmt" (4/9=0.44) to match "Statement".
  if (lowerReceiver.length >= 3 && lowerClass.includes(lowerReceiver)) {
    if (lowerReceiver.length >= 5 || lowerReceiver.length / lowerClass.length >= 0.4) {
      return true;
    }
  }

  // Short-prefix/suffix heuristic: "ev" might be ExpressionEvaluator (prefix),
  // "sink" might be CustomSink (suffix).
  // Only match if the class name starts or ends with the receiver (2+ chars).
  if (lowerReceiver.length >= 2) {
    if (lowerClass.startsWith(lowerReceiver) || lowerClass.endsWith(lowerReceiver)) {
      return true;
    }
  }

  // CamelCase word prefix heuristic: "req" might be CustomRequest (starts a word),
  // "lang" might be SimpleLanguage.  Check if the receiver matches the start of
  // any CamelCase segment and covers ≥ 40% of that word.
  // This prevents "auth" (4/13=0.31) matching "authenticator" while allowing
  // "req" (3/7=0.43) to match "request" and "lang" (4/8=0.50) to match "language".
  if (lowerReceiver.length >= 3) {
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
    template: ['JdbcTemplate'],

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
  patterns: SanitizerPattern[]
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
