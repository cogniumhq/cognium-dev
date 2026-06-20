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

/** Expression heuristics for "this is an exception value". */
function isExceptionExpression(expr: string | undefined | null): boolean {
  if (!expr) return false;
  const e = expr.trim();
  // err.stack | err.message | e.toString() | e.getMessage() | e.getStackTrace()
  // exc.format_exc() | traceback.format_exc() | str(e)
  return (
    /\b(err|error|exc|exception|e|t|throwable)\.(stack|message|toString\(|getMessage\(|getStackTrace\(|getLocalizedMessage\(|getCause\()/i.test(e) ||
    /\btraceback\.(format_exc|format_exception|print_exc)\b/i.test(e) ||
    /\bdebug\.Stack\(\)/.test(e) ||
    /\bstr\(\s*(err|error|exc|exception|e)\s*\)/i.test(e) ||
    /\bString\(\s*(err|error|exc|exception|e)\s*\)/i.test(e)
  );
}

/** True if an argument carries an exception-like value. */
function argIsException(arg: ArgumentInfo | undefined): boolean {
  if (!arg) return false;
  if (arg.variable && /^(err|error|exc|exception|e|t|throwable)$/i.test(arg.variable)) {
    return true;
  }
  return isExceptionExpression(arg.expression);
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
function detectResponseLeakCall(call: CallInfo): string | null {
  const method = call.method_name ?? '';
  const receiver = call.receiver ?? '';

  if (!RESPONSE_SEND_METHODS.has(method)) return null;
  if (LOGGER_RECEIVER_RE.test(receiver)) return null;
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
        if (!api) api = detectResponseLeakCall(call);
      } else if (language === 'javascript' || language === 'typescript') {
        api = detectResponseLeakCall(call);
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
          api = detectResponseLeakCall(call);
        }
      } else if (language === 'python') {
        // Handle response leak shape too: e.g. `return jsonify(stack=...)`
        api = detectResponseLeakCall(call);
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
