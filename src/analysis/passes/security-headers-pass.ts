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

import type { CallInfo } from '../../types/index.js';
import type { HeaderRule } from '../../types/config.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
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

/** Express / Koa route-registration receivers. */
const JS_ROUTER_RECEIVERS = new Set(['app', 'router', 'server', 'route']);
const JS_ROUTE_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'all', 'use', 'head', 'options',
]);

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
 * Heuristic detection of whether the file contains an HTTP request handler.
 * Used to gate 'missing' rules so they don't fire on library / utility files.
 */
function detectHandler(
  graph: { ir: { types: Array<{ annotations: string[]; methods: Array<{ annotations: string[] }> }> } },
  calls: CallInfo[],
): boolean {
  // 1. Class or method annotations that look like controller/route markers.
  for (const type of graph.ir.types) {
    if (type.annotations.some(a => HANDLER_ANNOTATION_RE.test(a))) return true;
    for (const method of type.methods) {
      if (method.annotations.some(a => HANDLER_ANNOTATION_RE.test(a))) return true;
    }
  }

  // 2. Express / Koa / Node route registration: app.get('/x', …), router.post(…)
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

  // 3. Any setHeader/addHeader call itself implies the file interacts
  //    with HTTP responses (but we don't want to let this alone bypass
  //    the 'missing' gate — otherwise rules would never fire when they
  //    should!). So DON'T count header writes here; they're counted
  //    at step 2 above via routing instead.

  return false;
}
