/**
 * Pass: info-disclosure-stacktrace (CWE-209, category: security)
 *
 * Detects exception stack traces / messages being returned to remote clients
 * via an HTTP response handler. This leaks framework internals, file paths,
 * SQL fragments, and class names — useful reconnaissance for an attacker.
 *
 * Detection per language:
 *   Java:
 *     - `e.printStackTrace(response.getWriter())` / `.printStackTrace(out)`
 *       where `out` is a response writer.
 *     - `response.getWriter().write(e.toString())`
 *     - `response.getWriter().println(e.getMessage())`
 *     - `new ResponseEntity<>(e.getStackTrace(), …)`
 *
 *   Python:
 *     - `return traceback.format_exc()` from a handler-like function
 *     - `flask.jsonify(error=traceback.format_exc())`
 *     - Bare `return str(e)` / `return {"error": str(e)}` in handler
 *
 *   JS/TS:
 *     - `res.send(err.stack)` / `res.json({error: err.stack})`
 *     - `res.json(err)` (whole error object)
 *     - `res.status(N).send(err.message + err.stack)` / similar
 *
 *   Go:
 *     - `http.Error(w, err.Error()+debug.Stack(), 500)` — narrow
 *     - `fmt.Fprintln(w, err)` in an HTTP handler
 *
 * Negative guard: if the consumer is a logger (`console.error`,
 * `logger.error`, `log.Error`), do NOT fire — logging stack traces
 * server-side is not a leak.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo, ArgumentInfo } from '../../types/index.js';

export interface InfoDisclosureStacktraceResult {
  findings: Array<{ line: number; api: string; language: string }>;
}

/** Receiver names that almost always indicate an HTTP response handle. */
const RESPONSE_RECEIVER_RE = /^(res|response|w|writer|ctx|c)$/i;

/** Logger receivers (negative guard). */
const LOGGER_RECEIVER_RE = /^(log|logger|slog|console|pino|winston|sentry)$/i;

/** Method names on a response that send data to the client. */
const RESPONSE_SEND_METHODS = new Set([
  'send', 'json', 'write', 'writeHead', 'end', 'sendFile',
  'println', 'print', 'getWriter',
  'Fprintln', 'Fprintf', 'Fprint',
]);

/** Expression heuristics for "this is an exception value".
 *
 * #133 — `.message` / `.getMessage()` are intentionally NOT matched. They
 * return a single-line developer-controlled human description (e.g.
 * `new Error('Validation failed')`), not a stack trace. The rule's
 * canonical CWE-209 scope is stack-trace disclosure; `.stack`,
 * `.toString()`, `.getStackTrace()`, full error object, and
 * `traceback.format_exc()` remain in scope.
 */
function isExceptionExpression(expr: string | undefined | null): boolean {
  if (!expr) return false;
  const e = expr.trim();
  // err.stack | e.toString() | e.getStackTrace() | e.getLocalizedMessage() | e.getCause()
  // traceback.format_exc() | debug.Stack() | str(e) | String(e)
  return (
    /\b(err|error|exc|exception|e|t|throwable)\.(stack|toString\(|getStackTrace\(|getLocalizedMessage\(|getCause\()/i.test(e) ||
    /\btraceback\.(format_exc|format_exception|print_exc)\b/i.test(e) ||
    /\bdebug\.Stack\(\)/.test(e) ||
    /\bstr\(\s*(err|error|exc|exception|e)\s*\)/i.test(e) ||
    /\bString\(\s*(err|error|exc|exception|e)\s*\)/i.test(e)
  );
}

/** #133 — Python file-handle open patterns:
 *   with open(...) as f:
 *   f = open(...)
 */
const PY_FILE_HANDLE_OPEN_RE =
  /^\s*(?:with\s+open\s*\([^)]*\)\s+as\s+(\w+)\s*:|(\w+)\s*=\s*open\s*\()/;

/**
 * #133 — True if `receiver` was produced by `open(...)` within the prior
 * 10 source lines. Used to suppress Python file-handle writes
 * (`f.write(API_KEY)`) which are not response leaks. Bounded backward
 * scan; conservative-bias when not resolvable.
 */
function isPythonFileHandle(
  receiver: string,
  callLine: number,
  sourceLines: string[],
): boolean {
  if (!receiver || !/^[A-Za-z_]\w*$/.test(receiver)) return false;
  const start = Math.max(0, callLine - 11);
  for (let i = callLine - 2; i >= start; i--) {
    const ln = sourceLines[i] ?? '';
    const m = ln.match(PY_FILE_HANDLE_OPEN_RE);
    if (!m) continue;
    const name = m[1] ?? m[2];
    if (name === receiver) return true;
  }
  return false;
}

/** True if an argument carries an exception-like value.
 *
 * #133 — When `arg.variable` matches an exception name (`err`, `error`,
 * …) the parser may have extracted it from a containing object literal
 * (e.g. `res.json({ ok: false, error: err.message })` → `variable="err"`).
 * In that case we must defer to `isExceptionExpression` on the full
 * expression text, NOT short-circuit to true on the bare variable
 * match. Only treat as a leak when the expression IS the bare variable
 * (e.g. `res.json(err)`) or is a stack-trace property access on it.
 */
function argIsException(arg: ArgumentInfo | undefined): boolean {
  if (!arg) return false;
  const expr = (arg.expression ?? '').trim();
  if (arg.variable && /^(err|error|exc|exception|e|t|throwable)$/i.test(arg.variable)) {
    // Bare exception variable: `res.json(err)`.
    if (!expr || expr === arg.variable) return true;
    // Containing expression — defer to isExceptionExpression for shape check.
    return isExceptionExpression(expr);
  }
  return isExceptionExpression(expr);
}

/** Detect Java: e.printStackTrace(out) where out is a response writer. */
function detectJavaPrintStackTrace(call: CallInfo): string | null {
  if (call.method_name !== 'printStackTrace') return null;
  // Receiver should look like an exception variable name.
  const rec = call.receiver ?? '';
  if (!/^(e|ex|exc|exception|err|error|t|throwable)$/i.test(rec)) return null;
  // Arg 0 should be a response writer expression.
  const arg0 = call.arguments.find((a) => a.position === 0);
  if (!arg0) return null;
  const expr = (arg0.expression ?? arg0.variable ?? '').trim();
  if (
    /\bresponse\.getWriter\(\)/.test(expr) ||
    /\bresp\.getWriter\(\)/.test(expr) ||
    /\bout\b/.test(expr) || // common name; conservative
    /\bgetWriter\(\)/.test(expr)
  ) {
    return 'e.printStackTrace(response.getWriter())';
  }
  return null;
}

/** Detect calls of the shape `response.send(err.stack)` / `.json(err)`. */
function detectResponseLeakCall(
  call: CallInfo,
  language?: string,
  sourceLines?: string[],
): string | null {
  const method = call.method_name ?? '';
  const receiver = call.receiver ?? '';

  if (!RESPONSE_SEND_METHODS.has(method)) return null;
  if (LOGGER_RECEIVER_RE.test(receiver)) return null;

  // #133 — Python file-handle write is not a response leak. When the
  // receiver was produced by `open(...)` within the prior 10 lines,
  // skip. Independent of receiver-name overlap; cannot regress real
  // response leaks (response writers are never produced by `open(...)`).
  if (
    language === 'python' &&
    (method === 'write' || method === 'writelines') &&
    sourceLines &&
    isPythonFileHandle(receiver, call.location.line, sourceLines)
  ) {
    return null;
  }

  // Accept either a bare known receiver name, or one whose tail is a known name
  // (e.g. `ctx.response`, `event.res`, `response.status(500)` chained returns).
  const recTail = receiver.split('.').pop() ?? receiver;
  const recHead = receiver.split('.')[0] ?? receiver;
  if (!RESPONSE_RECEIVER_RE.test(recTail) && !RESPONSE_RECEIVER_RE.test(recHead)) {
    // Allow chained: res.status(500).send(...) — receiver text often contains
    // `.status(` substring.
    if (!/(?:^|[.\s])(res|response)\.(?:status|set|header|cookie)\b/i.test(receiver)) {
      return null;
    }
  }

  // Any argument contains an exception expression?
  for (const a of call.arguments) {
    if (argIsException(a)) {
      return `${receiver || ''}${receiver ? '.' : ''}${method}(${(a.expression ?? a.variable ?? '').trim()})`;
    }
  }
  return null;
}

/** Detect Python: `return traceback.format_exc()` inside any function. */
function detectPythonTracebackReturn(ctx: PassContext): Array<{ line: number; api: string }> {
  const out: Array<{ line: number; api: string }> = [];
  const lines = ctx.code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i] ?? '';
    if (
      /\breturn\s+traceback\.format_exc\s*\(\s*\)/.test(ln) ||
      /\breturn\s+\{[^}]*traceback\.format_exc\s*\(\s*\)[^}]*\}/.test(ln) ||
      /\bjsonify\s*\([^)]*traceback\.format_exc\s*\(\s*\)/.test(ln)
    ) {
      out.push({ line: i + 1, api: 'return traceback.format_exc()' });
      continue;
    }
    // `return str(e)` in a handler context — conservative: require the
    // surrounding 5-line window to contain a Flask/FastAPI/Django marker.
    if (/\breturn\s+(?:str|repr)\s*\(\s*(?:e|err|error|exc|exception)\s*\)/.test(ln)) {
      const start = Math.max(0, i - 8);
      const end = Math.min(lines.length, i + 2);
      const window = lines.slice(start, end).join('\n');
      if (/@(?:app|router|blueprint)\.(?:route|get|post|put|delete|patch)\b/.test(window)) {
        out.push({ line: i + 1, api: 'return str(e) in handler' });
      }
    }
  }
  return out;
}

export class InfoDisclosureStacktracePass implements AnalysisPass<InfoDisclosureStacktraceResult> {
  readonly name = 'info-disclosure-stacktrace';
  readonly category = 'security' as const;

  run(ctx: PassContext): InfoDisclosureStacktraceResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: InfoDisclosureStacktraceResult['findings'] = [];

    // #133 — split lines once for downstream file-handle backward scan.
    const sourceLines = ctx.code.split('\n');

    if (language === 'python') {
      for (const f of detectPythonTracebackReturn(ctx)) {
        findings.push({ line: f.line, api: f.api, language });
        ctx.addFinding(this.makeFinding(file, f.line, f.api));
      }
    }

    for (const call of graph.ir.calls) {
      let api: string | null = null;

      if (language === 'java') {
        api = detectJavaPrintStackTrace(call);
        if (!api) api = detectResponseLeakCall(call, language, sourceLines);
      } else if (language === 'javascript' || language === 'typescript') {
        api = detectResponseLeakCall(call, language, sourceLines);
      } else if (language === 'go') {
        // http.Error(w, err.Error()+debug.Stack(), 500)
        // fmt.Fprintln(w, err)
        const method = call.method_name ?? '';
        const rec = call.receiver ?? '';
        if (rec === 'http' && method === 'Error') {
          const arg1 = call.arguments.find((a) => a.position === 1);
          if (argIsException(arg1)) api = 'http.Error(w, err.Error())';
        } else if (rec === 'fmt' && (method === 'Fprintln' || method === 'Fprintf' || method === 'Fprint')) {
          const arg0 = call.arguments.find((a) => a.position === 0);
          if (arg0 && /^(w|writer|resp|response)$/i.test((arg0.variable ?? arg0.expression ?? '').trim())) {
            for (const a of call.arguments) {
              if (a.position === 0) continue;
              if (argIsException(a)) { api = `fmt.${method}(w, err)`; break; }
            }
          }
        } else {
          api = detectResponseLeakCall(call, language, sourceLines);
        }
      } else if (language === 'python') {
        // Handle response leak shape too: e.g. `return jsonify(stack=...)`
        api = detectResponseLeakCall(call, language, sourceLines);
      }

      if (!api) continue;
      const line = call.location.line;
      findings.push({ line, api, language });
      ctx.addFinding(this.makeFinding(file, line, api));
    }

    return { findings };
  }

  private makeFinding(file: string, line: number, api: string) {
    return {
      id: `${this.name}-${file}-${line}`,
      pass: this.name,
      category: this.category,
      rule_id: this.name,
      cwe: 'CWE-209',
      severity: 'medium' as const,
      level: 'warning' as const,
      message:
        `Exception detail returned to client via \`${api}\`. ` +
        'Leaking stack traces / exception messages reveals framework internals, ' +
        'file paths, and class names — useful reconnaissance for an attacker.',
      file,
      line,
      fix:
        'Return a generic error response to the client (e.g. status 500 + a ' +
        'request id) and log the full exception server-side via your logger ' +
        '(e.g. `logger.error("…", e)` or `console.error(err)`).',
      evidence: { api },
    };
  }
}
