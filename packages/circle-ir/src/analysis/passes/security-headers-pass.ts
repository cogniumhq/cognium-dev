/**
 * Pass #89: security-headers (category: security)
 *
 * Inspects HTTP response-header writes and handler presence to detect
 * clickjacking (CWE-1021) and CORS misconfiguration (CWE-346 / CWE-942).
 *
 * This pass does NOT use the taint source→sink machinery — it is a
 * call-site literal inspection problem, not a data-flow problem. It reads
 * `graph.ir.calls` and `graph.ir.types[].{annotations,methods[].annotations}`.
 *
 * Rule table is defined in `config-loader.ts` as `DEFAULT_HEADER_RULES`.
 * Adding a new rule there is enough to surface a finding — no pass code
 * changes are required.
 *
 * Supported header-write method names (cross-language):
 *   - Java:   setHeader, addHeader         (HttpServletResponse, HttpHeaders)
 *   - JS:     setHeader, set, header       (Express res.setHeader/set/header,
 *                                           Node http.ServerResponse)
 *   - Rust:   insert_header, insert        (Actix / Axum HeaderMap)
 *
 * Handler detection (heuristic, cross-language):
 *   - Java/Kotlin: annotations matching Controller|RequestMapping|GetMapping|...
 *   - JS/TS:       calls like app.get/post/put/..., router.get/..., server.use
 *   - Python:      decorators matching route|blueprint|api_view
 *   - Rust:        attribute macros matching get|post|put|delete|patch|route
 */

import type { CallInfo, SastFinding, CircleIR } from '../../types/index.js';
import type { HeaderRule } from '../../types/config.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TypeHierarchyResolver } from '../../resolution/type-hierarchy.js';
import { DEFAULT_HEADER_RULES } from '../config-loader.js';

export interface SecurityHeadersOptions {
  /** Override rule table (default: DEFAULT_HEADER_RULES). */
  rules?: HeaderRule[];
}

export interface SecurityHeadersPassResult {
  /** Whether the file was treated as an HTTP handler. */
  hasHandler: boolean;
  /** Headers written in the file (lowercased header name → call sites). */
  writtenHeaders: Map<string, CallInfo[]>;
}

/** Methods that write an HTTP response header with (name, value) arguments. */
const HEADER_WRITE_METHODS = new Set([
  'setHeader', 'addHeader',       // Java + Node
  'set', 'header',                // Express res.set / res.header
  'insert_header',                // Actix Web HttpResponse
  'insert',                       // Rust HeaderMap.insert (best-effort)
]);

/** Annotations / decorators indicating the file defines an HTTP handler. */
const HANDLER_ANNOTATION_RE =
  /\b(Controller|RestController|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestBody|RequestParam|PathVariable|route|blueprint|api_view|get|post|put|delete|patch|head|options)\b/i;

/** Java servlet HTTP handler method names (doGet, doPost, …). */
const SERVLET_HANDLER_METHODS = new Set([
  'doGet', 'doPost', 'doPut', 'doDelete', 'doHead', 'doOptions', 'doPatch',
  'service',
]);

/** Java servlet base class names. */
const SERVLET_BASE_CLASSES = new Set([
  'HttpServlet', 'GenericServlet', 'Servlet',
]);

/** Express / Koa route-registration receivers. */
const JS_ROUTER_RECEIVERS = new Set(['app', 'router', 'server', 'route']);
const JS_ROUTE_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'all', 'use', 'head', 'options',
]);

/**
 * Issue #50: Global security-middleware detection.
 *
 * When a file installs a well-known security-headers middleware, the
 * `missing-*` rules (which fire once per handler file) over-fire on
 * production code that delegates clickjacking / CSP / HSTS / X-Content-Type
 * defenses to a global filter chain or reverse proxy. We suppress those
 * rules when any of the following names appear as call targets, type names,
 * or annotations in the same file:
 *
 *   - Node/Express: helmet(), app.use(helmet.frameguard()), etc.
 *   - Spring (Java/Kotlin): httpSecurity.headers().frameOptions() chain,
 *     @EnableWebSecurity, SecurityFilterChain bean.
 *   - Flask/Python: Talisman(app), secure.Secure(), @app.after_request.
 *
 * Value-based rules (cors-wildcard-origin etc.) still fire — they inspect
 * actual header values and are not about middleware presence.
 */
const SECURITY_MIDDLEWARE_METHODS = new Set([
  // Node helmet (and sub-modules)
  'helmet',
  'frameguard',
  'contentSecurityPolicy',
  'hsts',
  'noSniff',
  'xssFilter',
  'referrerPolicy',
  'permittedCrossDomainPolicies',
  'dnsPrefetchControl',
  // Spring HttpSecurity builder chain
  'frameOptions',
  'headers',
  'httpStrictTransportSecurity',
  'contentTypeOptions',
  'xssProtection',
  // Flask / Python
  'Talisman',
  'Secure',
]);

const SECURITY_MIDDLEWARE_ANNOTATIONS_RE =
  /\b(EnableWebSecurity|SecurityFilterChain|after_request|before_request)\b/;

export class SecurityHeadersPass
  implements AnalysisPass<SecurityHeadersPassResult>
{
  readonly name = 'security-headers';
  readonly category = 'security' as const;

  private readonly rules: HeaderRule[];

  constructor(options: SecurityHeadersOptions = {}) {
    this.rules = options.rules ?? DEFAULT_HEADER_RULES;
  }

  run(ctx: PassContext): SecurityHeadersPassResult {
    const { graph } = ctx;
    const file = graph.ir.meta.file;
    const calls = graph.ir.calls;

    // -------------------------------------------------------------------
    // Step 1: collect all header writes, keyed by lowercased header name.
    //   writtenHeaders.get('x-frame-options') → list of setHeader(...) calls
    // -------------------------------------------------------------------
    const writtenHeaders = new Map<string, CallInfo[]>();
    for (const call of calls) {
      if (!HEADER_WRITE_METHODS.has(call.method_name)) continue;
      if (call.arguments.length < 1) continue;

      const nameLiteral = resolveHeaderName(call.arguments[0]);
      if (nameLiteral === null) continue;

      const key = nameLiteral.toLowerCase();
      let list = writtenHeaders.get(key);
      if (!list) { list = []; writtenHeaders.set(key, list); }
      list.push(call);
    }

    // -------------------------------------------------------------------
    // Step 2: decide whether this file defines an HTTP handler.
    //   Used to gate 'missing' rules with requiresHandler=true.
    // -------------------------------------------------------------------
    const hasHandler = detectHandler(graph, calls);

    // -------------------------------------------------------------------
    // Step 2b (issue #50): detect global security middleware so we can
    // suppress the noisy `missing-*` rules on files that delegate headers
    // to Helmet / SecurityFilterChain / Talisman / etc.
    // -------------------------------------------------------------------
    const hasGlobalMiddleware = detectGlobalSecurityMiddleware(graph, calls);

    // -------------------------------------------------------------------
    // Step 3: evaluate rules.
    // -------------------------------------------------------------------
    for (const rule of this.rules) {
      const headerKey = rule.header.toLowerCase();
      const writes = writtenHeaders.get(headerKey) ?? [];

      if (rule.kind === 'missing') {
        // Only fire if the header was never written in this file.
        if (writes.length > 0) continue;
        // Gate on handler detection when requested (default behavior for
        // 'missing' rules, since they are noisy on library files).
        if (rule.requiresHandler !== false && !hasHandler) continue;
        // Suppress when a global security middleware is installed in the
        // same file (issue #50).
        if (hasGlobalMiddleware) continue;

        ctx.addFinding({
          id: `${rule.rule_id}-${file}`,
          pass: this.name,
          category: this.category,
          rule_id: rule.rule_id,
          cwe: rule.cwe,
          severity: rule.severity,
          level: rule.level,
          message: rule.message,
          file,
          line: 1,
          fix: rule.fix,
        });
        continue;
      }

      // For value-based rules, inspect every call site.
      for (const call of writes) {
        const valueArg = call.arguments[1];
        if (!valueArg) continue;

        const valueLiteral = literalOf(valueArg);

        if (rule.kind === 'weak-value') {
          if (valueLiteral === null) continue; // dynamic — handled by 'unsafe-value'
          if (!rule.valuePattern) continue;
          if (!rule.valuePattern.test(valueLiteral)) continue;
        } else { // 'unsafe-value'
          // Only fire when the argument is NOT a string literal, i.e. dynamic.
          if (valueLiteral !== null) continue;
        }

        ctx.addFinding({
          id: `${rule.rule_id}-${file}-${call.location.line}`,
          pass: this.name,
          category: this.category,
          rule_id: rule.rule_id,
          cwe: rule.cwe,
          severity: rule.severity,
          level: rule.level,
          message: rule.message,
          file,
          line: call.location.line,
          fix: rule.fix,
          snippet: valueLiteral !== null
            ? `${rule.header}: ${valueLiteral}`
            : `${rule.header}: ${valueArg.expression}`,
          evidence: {
            header: rule.header,
            value: valueLiteral,
            expression: valueArg.expression,
            kind: rule.kind,
          },
        });
      }
    }

    // -------------------------------------------------------------------
    // Step 4: cross-header consistency (XFO ↔ CSP frame-ancestors).
    //   CSP frame-ancestors takes precedence over XFO in modern browsers.
    //   Flag mismatches where the two headers disagree.
    // -------------------------------------------------------------------
    checkXfoCspMismatch(writtenHeaders, file, ctx);

    return { hasHandler, writtenHeaders };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the string literal value from an argument, or return null if the
 * argument is dynamic. Strips surrounding quotes from the literal field.
 */
function literalOf(arg: { literal?: string | null; expression: string }): string | null {
  if (arg.literal !== null && arg.literal !== undefined && arg.literal !== '') {
    return stripQuotes(arg.literal);
  }
  // Fallback: check if the expression itself is a bare quoted string.
  const expr = arg.expression.trim();
  if (
    (expr.startsWith('"') && expr.endsWith('"')) ||
    (expr.startsWith("'") && expr.endsWith("'")) ||
    (expr.startsWith('`') && expr.endsWith('`'))
  ) {
    // Template literals with interpolation are not literals — reject.
    if (expr.startsWith('`') && expr.includes('${')) return null;
    return expr.slice(1, -1);
  }
  return null;
}

function stripQuotes(s: string): string {
  if (s.length < 2) return s;
  const first = s[0];
  const last = s[s.length - 1];
  if (
    (first === '"' && last === '"') ||
    (first === "'" && last === "'") ||
    (first === '`' && last === '`')
  ) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * Resolve the header-name argument to a string value. Handles:
 *  1. String literals: "X-Frame-Options"
 *  2. Java/framework constants: HttpHeaders.X_FRAME_OPTIONS → "X-Frame-Options"
 *     Converts SCREAMING_SNAKE_CASE to Header-Case. Works with any framework
 *     that follows Java constant naming conventions (Spring, Jakarta, Apache,
 *     Guava, etc.).
 */
function resolveHeaderName(arg: { literal?: string | null; expression: string }): string | null {
  // Try literal first.
  const lit = literalOf(arg);
  if (lit !== null) return lit;

  // Fallback: check if expression looks like a constant reference.
  // e.g. "HttpHeaders.X_FRAME_OPTIONS", "CONTENT_TYPE", "Header.X_FRAME_OPTIONS"
  const expr = arg.expression.trim();
  const dotIdx = expr.lastIndexOf('.');
  const fieldName = dotIdx >= 0 ? expr.slice(dotIdx + 1) : expr;

  // Must be SCREAMING_SNAKE_CASE: all uppercase letters, digits, underscores,
  // at least one underscore (to distinguish from simple variable names).
  if (!/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(fieldName)) return null;

  // Convert SCREAMING_SNAKE_CASE → Header-Case:
  //   X_FRAME_OPTIONS → X-Frame-Options
  //   ACCESS_CONTROL_ALLOW_ORIGIN → Access-Control-Allow-Origin
  return fieldName
    .split('_')
    .map(part => part.charAt(0) + part.slice(1).toLowerCase())
    .join('-');
}

/**
 * Detect XFO ↔ CSP frame-ancestors mismatches.
 *
 * When both X-Frame-Options and Content-Security-Policy (with frame-ancestors)
 * are set in the same file, CSP takes precedence in modern browsers. A mismatch
 * means the effective policy differs from what XFO declares, which is
 * a clickjacking misconfiguration (CWE-1021).
 *
 * Cases detected:
 *   - XFO=DENY but CSP frame-ancestors is not 'none'
 *   - XFO=SAMEORIGIN but CSP frame-ancestors allows external origins
 */
function checkXfoCspMismatch(
  writtenHeaders: Map<string, CallInfo[]>,
  file: string,
  ctx: PassContext,
): void {
  const xfoCalls = writtenHeaders.get('x-frame-options') ?? [];
  const cspCalls = writtenHeaders.get('content-security-policy') ?? [];
  if (xfoCalls.length === 0 || cspCalls.length === 0) return;

  for (const xfoCall of xfoCalls) {
    const xfoValue = literalOf(xfoCall.arguments[1])?.toUpperCase();
    if (!xfoValue) continue;

    for (const cspCall of cspCalls) {
      const cspValue = literalOf(cspCall.arguments[1]);
      if (!cspValue) continue;

      // Extract frame-ancestors directive from the CSP value.
      const faMatch = /frame-ancestors\s+([^;]+)/i.exec(cspValue);
      if (!faMatch) continue;
      const frameAncestors = faMatch[1].trim().toLowerCase();

      let mismatch = false;
      let message = '';

      if (xfoValue === 'DENY') {
        // XFO=DENY means no framing at all. CSP equivalent is frame-ancestors 'none'.
        if (frameAncestors !== "'none'" && frameAncestors !== 'none') {
          mismatch = true;
          message = `X-Frame-Options: DENY conflicts with CSP frame-ancestors: ${faMatch[1].trim()} — CSP takes precedence, framing is allowed`;
        }
      } else if (xfoValue === 'SAMEORIGIN') {
        // XFO=SAMEORIGIN means only same-origin. CSP equivalent is frame-ancestors 'self'.
        if (frameAncestors !== "'self'") {
          mismatch = true;
          message = `X-Frame-Options: SAMEORIGIN conflicts with CSP frame-ancestors: ${faMatch[1].trim()} — CSP takes precedence`;
        }
      }

      if (mismatch) {
        ctx.addFinding({
          id: `xfo-csp-mismatch-${file}-${xfoCall.location.line}`,
          pass: 'security-headers',
          category: 'security',
          rule_id: 'xfo-csp-mismatch',
          cwe: 'CWE-1021',
          severity: 'medium',
          level: 'warning',
          message,
          file,
          line: cspCall.location.line,
          fix: 'Ensure X-Frame-Options and CSP frame-ancestors express the same framing policy',
          evidence: {
            xfo: xfoValue,
            csp_frame_ancestors: frameAncestors,
          },
        });
      }
    }
  }
}

/**
 * Heuristic detection of whether the file contains an HTTP request handler.
 * Used to gate 'missing' rules so they don't fire on library / utility files.
 */
function detectHandler(
  graph: { ir: { types: Array<{
    annotations: string[];
    extends: string | null;
    methods: Array<{ name: string; annotations: string[] }>;
  }> } },
  calls: CallInfo[],
): boolean {
  // 1. Class or method annotations that look like controller/route markers.
  for (const type of graph.ir.types) {
    if (type.annotations.some(a => HANDLER_ANNOTATION_RE.test(a))) return true;
    for (const method of type.methods) {
      if (method.annotations.some(a => HANDLER_ANNOTATION_RE.test(a))) return true;
    }
  }

  // 2. Java servlet: class extends HttpServlet with doGet/doPost/service.
  for (const type of graph.ir.types) {
    const base = type.extends;
    if (base && SERVLET_BASE_CLASSES.has(base)) {
      if (type.methods.some(m => SERVLET_HANDLER_METHODS.has(m.name))) return true;
    }
  }

  // 3. Express / Koa / Node route registration: app.get('/x', …), router.post(…)
  for (const call of calls) {
    if (!JS_ROUTE_METHODS.has(call.method_name)) continue;
    if (!call.receiver) continue;
    if (!JS_ROUTER_RECEIVERS.has(call.receiver)) continue;
    // Router methods carry a route string as their first argument.
    const first = call.arguments[0];
    if (!first) continue;
    const literal = literalOf(first);
    if (literal !== null && literal.startsWith('/')) return true;
  }

  return false;
}

/**
 * Issue #50: Detect global security-headers middleware in the same file.
 *
 * Returns true if any of the well-known middleware call names appear,
 * or if a class/method carries an `@EnableWebSecurity` /
 * `SecurityFilterChain` / `@app.after_request` marker. When true, the
 * per-handler `missing-*` rules are suppressed because the middleware is
 * presumed to set the headers globally.
 *
 * Note: this is a conservative call-site heuristic. It deliberately
 * doesn't try to resolve imports — a Spring `headers()` call on something
 * unrelated would still suppress, but the false-suppression risk on
 * production code is far smaller than the false-positive cost of firing
 * a clickjacking warning on every handler in a Helmet-protected app.
 */
function detectGlobalSecurityMiddleware(
  graph: { ir: { types: Array<{
    annotations: string[];
    methods: Array<{ name: string; annotations: string[] }>;
  }> } },
  calls: CallInfo[],
): boolean {
  // 1. Call to any known security-middleware method (helmet(), Talisman(),
  //    httpSecurity.headers(), etc.).
  for (const call of calls) {
    if (SECURITY_MIDDLEWARE_METHODS.has(call.method_name)) return true;
    // Express idiom: app.use(helmet()) — helmet appears as the first arg
    // expression rather than the call's method_name.
    if (call.method_name === 'use' && call.arguments.length > 0) {
      const firstArg = call.arguments[0].expression ?? '';
      if (/\b(helmet|Talisman|secure)\b/.test(firstArg)) return true;
    }
  }

  // 2. Spring / Flask annotation markers on class or methods.
  for (const type of graph.ir.types) {
    if (type.annotations.some(a => SECURITY_MIDDLEWARE_ANNOTATIONS_RE.test(a))) return true;
    for (const method of type.methods) {
      if (method.annotations.some(a => SECURITY_MIDDLEWARE_ANNOTATIONS_RE.test(a))) return true;
      // Spring `@Bean SecurityFilterChain securityFilterChain(...)` declarations.
      if (/^security[A-Za-z]*FilterChain$/i.test(method.name)) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Cross-file CORS inheritance
// ---------------------------------------------------------------------------

/**
 * Detect CORS misconfigurations inherited through class hierarchy.
 *
 * When a parent servlet calls `setHeader("Access-Control-Allow-Origin", getXxx())`
 * with a virtual method as the value, child classes override that method to return
 * different values. Per-file analysis only sees the parent's call — the children
 * have 0 calls and produce 0 findings. This function resolves each child's
 * override return value and emits the appropriate CORS finding on the child file.
 */
export function checkInheritedCorsHeaders(
  fileAnalyses: Array<{ file: string; analysis: CircleIR }>,
  typeHierarchy: TypeHierarchyResolver,
  sourceLines: Map<string, string[]>,
): SastFinding[] {
  const findings: SastFinding[] = [];

  // Step 1: Find parent files with CORS header writes using a dynamic value.
  for (const { file: parentFile, analysis: parentIR } of fileAnalyses) {
    for (const call of parentIR.calls) {
      if (!HEADER_WRITE_METHODS.has(call.method_name)) continue;
      if (call.arguments.length < 2) continue;

      // Check arg[0] is the ACAO header.
      const headerName = resolveHeaderName(call.arguments[0]);
      if (headerName === null) continue;
      if (headerName.toLowerCase() !== 'access-control-allow-origin') continue;

      // Check arg[1] is dynamic (not a literal).
      const valueArg = call.arguments[1];
      const valueLiteral = literalOf(valueArg);
      if (valueLiteral !== null) continue; // Static value — handled by per-file pass.

      // Extract the virtual method name from the dynamic value expression.
      // e.g. "getAllowOriginValue(request)" → "getAllowOriginValue"
      const methodName = extractMethodName(valueArg);
      if (!methodName) continue;

      // Step 2: Find the parent class that contains this call.
      const parentClassName = findClassContainingMethod(parentIR, call, methodName);
      if (!parentClassName) continue;

      // Step 3: Find child classes via type hierarchy.
      const childFqns = typeHierarchy.getAllSubtypes(parentClassName);
      if (childFqns.length === 0) continue;

      // Step 4: For each child, resolve the override and emit a finding.
      for (const childFqn of childFqns) {
        const childType = typeHierarchy.getType(childFqn);
        if (!childType) continue;

        const childFile = childType.file;
        const lines = sourceLines.get(childFile);
        if (!lines) continue;

        // Find the override method in the child's IR.
        const childFA = fileAnalyses.find(f => f.file === childFile);
        if (!childFA) continue;

        const childIR = childFA.analysis;
        let overrideStartLine = 0;
        let overrideEndLine = 0;

        for (const type of childIR.types) {
          for (const method of type.methods) {
            if (method.name === methodName) {
              overrideStartLine = method.start_line;
              overrideEndLine = method.end_line;
              break;
            }
          }
          if (overrideStartLine > 0) break;
        }

        if (overrideStartLine === 0) continue; // No override — child inherits parent behavior.

        // Extract the return value from the override method's source lines.
        const returnValue = extractReturnValue(
          lines, overrideStartLine, overrideEndLine,
        );

        // Map return value to a CORS rule.
        const corsRule = mapReturnValueToCorsRule(returnValue);
        if (!corsRule) continue;

        findings.push({
          id: `${corsRule.ruleId}-${childFile}-${overrideStartLine}`,
          pass: 'security-headers',
          category: 'security',
          rule_id: corsRule.ruleId,
          cwe: corsRule.cwe,
          severity: corsRule.severity,
          level: 'error',
          message: corsRule.message,
          file: childFile,
          line: overrideStartLine,
          snippet: corsRule.snippet,
          evidence: {
            parentFile,
            parentMethod: methodName,
            childClass: childFqn,
            returnValue: returnValue.raw,
          },
        });
      }
    }
  }

  return findings;
}

/**
 * Extract a method name from a dynamic value argument.
 * Handles patterns like "getAllowOriginValue(request)", "this.getOrigin()", "getOrigin()".
 */
function extractMethodName(arg: { variable?: string | null; expression: string }): string | null {
  // Try variable field first (e.g. "getAllowOriginValue").
  if (arg.variable) {
    // If variable looks like a method name (not a parameter name), use it.
    const v = arg.variable;
    if (/^[a-zA-Z_]\w*$/.test(v) && v !== 'request' && v !== 'response' && v !== 'req' && v !== 'res') {
      return v;
    }
  }

  // Parse from expression: "getAllowOriginValue(request)" or "this.getOrigin()".
  const expr = arg.expression.trim();
  const match = /(?:\w+\.)?(\w+)\s*\(/.exec(expr);
  if (match) return match[1];

  return null;
}

/**
 * Find the class in the IR that (a) contains the header-write call site and
 * (b) defines the virtual method being invoked.
 */
function findClassContainingMethod(
  ir: CircleIR,
  call: CallInfo,
  methodName: string,
): string | null {
  const callLine = call.location.line;

  for (const type of ir.types) {
    // The call must be within the class's line range.
    if (callLine < type.start_line || callLine > type.end_line) continue;

    // The class must declare or inherit the virtual method.
    // We check if the class itself declares the method (abstract or concrete).
    const hasMethod = type.methods.some(m => m.name === methodName);
    if (hasMethod) return type.name;
  }

  // Fallback: return the class that contains the call site (even without the method).
  for (const type of ir.types) {
    if (callLine >= type.start_line && callLine <= type.end_line) return type.name;
  }

  return null;
}

interface ReturnValueInfo {
  kind: 'literal' | 'dynamic';
  value: string | null;  // The literal string value, if any.
  raw: string;            // The raw return expression.
}

/**
 * Extract the return value from a method's source lines.
 * Scans for `return` statements and classifies the returned expression.
 */
function extractReturnValue(
  lines: string[],
  startLine: number,
  endLine: number,
): ReturnValueInfo {
  const returnLiteralRe = /return\s+"([^"]*)"[;\s]*$/;
  const returnSingleQuoteRe = /return\s+'([^']*)'[;\s]*$/;

  for (let i = startLine - 1; i < Math.min(endLine, lines.length); i++) {
    const line = lines[i]?.trim();
    if (!line) continue;

    // Match: return "someValue";
    const literalMatch = returnLiteralRe.exec(line) || returnSingleQuoteRe.exec(line);
    if (literalMatch) {
      return { kind: 'literal', value: literalMatch[1], raw: literalMatch[1] };
    }

    // Match: return <dynamic expression>;
    if (/^\s*return\s+/.test(lines[i])) {
      const expr = lines[i].replace(/^\s*return\s+/, '').replace(/;\s*$/, '').trim();
      return { kind: 'dynamic', value: null, raw: expr };
    }
  }

  // No return found — treat as dynamic (may inherit parent behavior).
  return { kind: 'dynamic', value: null, raw: '<inherited>' };
}

interface CorsRuleMapping {
  ruleId: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  snippet: string;
}

/**
 * Map a resolved return value to the appropriate CORS misconfiguration rule.
 */
function mapReturnValueToCorsRule(returnValue: ReturnValueInfo): CorsRuleMapping | null {
  if (returnValue.kind === 'literal' && returnValue.value !== null) {
    const v = returnValue.value;

    if (v === 'null') {
      return {
        ruleId: 'cors-null-origin',
        cwe: 'CWE-346',
        severity: 'medium',
        message: 'Access-Control-Allow-Origin set to "null" — sandboxed or data: URIs can exploit this to bypass origin checks',
        snippet: `Access-Control-Allow-Origin: ${v}`,
      };
    }

    if (v === '*') {
      return {
        ruleId: 'cors-wildcard-origin',
        cwe: 'CWE-942',
        severity: 'medium',
        message: 'Access-Control-Allow-Origin set to wildcard "*" — any origin can read the response',
        snippet: `Access-Control-Allow-Origin: ${v}`,
      };
    }

    if (v.startsWith('http://')) {
      return {
        ruleId: 'cors-http-origin',
        cwe: 'CWE-346',
        severity: 'medium',
        message: `Access-Control-Allow-Origin allows insecure HTTP origin "${v}" — susceptible to MITM`,
        snippet: `Access-Control-Allow-Origin: ${v}`,
      };
    }

    // Other literal values (e.g. "https://example.com") — likely safe.
    return null;
  }

  // Dynamic/tainted return value — reflected origin.
  return {
    ruleId: 'cors-reflected-origin',
    cwe: 'CWE-346',
    severity: 'high',
    message: 'Access-Control-Allow-Origin reflects user-controlled value — any origin can read the response',
    snippet: `Access-Control-Allow-Origin: <dynamic: ${returnValue.raw}>`,
  };
}
