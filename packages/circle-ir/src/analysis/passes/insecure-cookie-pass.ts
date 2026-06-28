/**
 * Pass: insecure-cookie (CWE-614, category: security)
 *
 * Pattern pass — flags cookie set operations that are missing the `Secure`
 * or `HttpOnly` flags. This is a configuration/absence vulnerability (the
 * cookie value itself does not need to be tainted), so it is detected by
 * inspecting call-site option literals rather than via taint flow.
 *
 * Detection per language:
 *   JavaScript / TypeScript:
 *     - Express `res.cookie(name, value, options)` — flag if options object
 *       (arg 2) is absent OR does not literally contain `secure: true` and
 *       `httpOnly: true`.
 *   Python:
 *     - Flask / Django / Starlette `response.set_cookie(name, value, **kw)`
 *       — flag if `secure=True` and `httponly=True` keyword args are not
 *       present in the call expression text.
 *   Java:
 *     - `new javax.servlet.http.Cookie("name", "value")` — flag the
 *       construction site if no `.setSecure(true)` AND `.setHttpOnly(true)`
 *       calls appear in the same source file (text-based heuristic; a
 *       full DFG-based version would require tracking the assigned
 *       variable through CFG).
 *
 * Excluded (intentionally not flagged):
 *   - `res.clearCookie(...)` — clears, not sets.
 *   - Cookie session middleware initialisation (`app.use(cookieSession(...))`).
 *
 * Out of scope (call site does not have enough information):
 *   - Spread-based options: `res.cookie('a', v, { ...secureDefaults, ... })`.
 *     We flag the call (RHS is opaque) unless `secure: true` and
 *     `httpOnly: true` appear literally. Users can suppress via config.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// ---------- JS / TS ----------
const COOKIE_RESPONSE_RECEIVERS = new Set([
  'res', 'response', 'reply',
]);
const SECURE_TRUE_RE   = /\bsecure\s*:\s*true\b/;
const HTTPONLY_TRUE_RE = /\bhttpOnly\s*:\s*true\b/i;

// ---------- Python ----------
const PY_SET_COOKIE_RECEIVERS = new Set([
  'response', 'resp', 'res',
]);
const PY_SECURE_TRUE_RE   = /\bsecure\s*=\s*True\b/;
const PY_HTTPONLY_TRUE_RE = /\bhttponly\s*=\s*True\b/i;

// ---------- Java ----------
const JAVA_SET_SECURE_TRUE_RE   = /\.setSecure\s*\(\s*true\s*\)/;
const JAVA_SET_HTTPONLY_TRUE_RE = /\.setHttpOnly\s*\(\s*true\s*\)/;

// ---------- Go ----------
// `http.SetCookie(w, &http.Cookie{..., Secure: true, HttpOnly: true})` —
// the struct literal text is in the second argument's expression. Sprint 56 #182 Slice B.
const GO_SECURE_TRUE_RE   = /\bSecure\s*:\s*true\b/;
const GO_HTTPONLY_TRUE_RE = /\bHttpOnly\s*:\s*true\b/;

// ---------- Rust ----------
// `format!("Set-Cookie: sid={}; Path=/; Secure; HttpOnly", ...)` /
// `write!(buf, "Set-Cookie: ...", ...)` / `writeln!(...)`. The Rust macro
// extractor surfaces method_name='format!'/'write!'/'writeln!' but does not
// populate `arguments`, so we text-scan the file source for the macro
// invocation containing a `Set-Cookie:` header literal and verify that the
// same invocation also contains `Secure` and `HttpOnly` tokens. Sprint 56 #182 Slice C.
// Multi-line matches are supported via the `s` flag (dotall).
const RUST_SET_COOKIE_MACRO_RE =
  /(format!|write!|writeln!)\s*\(([^()]*Set-Cookie[^()]*)\)/gis;

export interface InsecureCookieResult {
  insecureCookies: Array<{
    line: number;
    receiver: string;
    missingSecure: boolean;
    missingHttpOnly: boolean;
    optionsPresent: boolean;
  }>;
}

export class InsecureCookiePass implements AnalysisPass<InsecureCookieResult> {
  readonly name = 'insecure-cookie';
  readonly category = 'security' as const;

  run(ctx: PassContext): InsecureCookieResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const insecureCookies: InsecureCookieResult['insecureCookies'] = [];

    if (language === 'javascript' || language === 'typescript') {
      for (const call of graph.ir.calls) {
        const det = this.detectJs(call);
        if (!det) continue;
        insecureCookies.push(det);
        this.emit(ctx, file, det, 'js');
      }
    } else if (language === 'python') {
      for (const call of graph.ir.calls) {
        const det = this.detectPython(call);
        if (!det) continue;
        insecureCookies.push(det);
        this.emit(ctx, file, det, 'python');
      }
    } else if (language === 'java') {
      // Java text-based heuristic: detect `new Cookie(...)` constructor calls,
      // then look in the file source for `.setSecure(true)` and `.setHttpOnly(true)`
      // anywhere. Misses only when those setters exist in another file.
      const hasSetSecureTrue   = JAVA_SET_SECURE_TRUE_RE.test(code);
      const hasSetHttpOnlyTrue = JAVA_SET_HTTPONLY_TRUE_RE.test(code);
      for (const call of graph.ir.calls) {
        const det = this.detectJavaCookieCtor(call, hasSetSecureTrue, hasSetHttpOnlyTrue);
        if (!det) continue;
        insecureCookies.push(det);
        this.emit(ctx, file, det, 'java');
      }
    } else if (language === 'go') {
      for (const call of graph.ir.calls) {
        const det = this.detectGo(call);
        if (!det) continue;
        insecureCookies.push(det);
        this.emit(ctx, file, det, 'go');
      }
    } else if (language === 'rust') {
      const dets = this.detectRustSetCookieFormat(code);
      for (const det of dets) {
        insecureCookies.push(det);
        this.emit(ctx, file, det, 'rust');
      }
    }

    return { insecureCookies };
  }

  // ---------------- JS / TS ----------------
  private detectJs(call: CallInfo): InsecureCookieResult['insecureCookies'][number] | null {
    if (call.method_name !== 'cookie') return null;
    const receiver = call.receiver ?? '';
    if (!COOKIE_RESPONSE_RECEIVERS.has(receiver)) return null;

    // Must look like a setter call: at least (name, value) args.
    // `res.cookie('name')` (Express getter form) takes one arg — skip.
    if (call.arguments.length < 2) return null;

    const opts = call.arguments.find((a) => a.position === 2);
    const optsExpr = (opts?.expression ?? '').trim();
    const optionsPresent = optsExpr.length > 0;

    const missingSecure   = !SECURE_TRUE_RE.test(optsExpr);
    const missingHttpOnly = !HTTPONLY_TRUE_RE.test(optsExpr);
    if (!missingSecure && !missingHttpOnly) return null;

    return {
      line: call.location.line,
      receiver,
      missingSecure,
      missingHttpOnly,
      optionsPresent,
    };
  }

  // ---------------- Python ----------------
  private detectPython(call: CallInfo): InsecureCookieResult['insecureCookies'][number] | null {
    if (call.method_name !== 'set_cookie') return null;
    const receiver = call.receiver ?? '';
    if (!PY_SET_COOKIE_RECEIVERS.has(receiver)) return null;

    // Concatenate all argument expression text — keyword args may appear in
    // any position past the leading positional args.
    const argsBlob = call.arguments.map((a) => a.expression ?? '').join(', ');

    const missingSecure   = !PY_SECURE_TRUE_RE.test(argsBlob);
    const missingHttpOnly = !PY_HTTPONLY_TRUE_RE.test(argsBlob);
    if (!missingSecure && !missingHttpOnly) return null;

    return {
      line: call.location.line,
      receiver,
      missingSecure,
      missingHttpOnly,
      optionsPresent: call.arguments.length >= 2,
    };
  }

  // ---------------- Java ----------------
  private detectJavaCookieCtor(
    call: CallInfo,
    hasSetSecureTrue: boolean,
    hasSetHttpOnlyTrue: boolean,
  ): InsecureCookieResult['insecureCookies'][number] | null {
    // Java constructor: method_name === 'Cookie' for unqualified `new Cookie(...)`,
    // or a fully-qualified form like `javax.servlet.http.Cookie` /
    // `jakarta.servlet.http.Cookie` when the user writes
    // `new javax.servlet.http.Cookie(...)` without the import. OWASP Java
    // benchmark cases use the FQ shape exclusively (cognium-dev #118).
    const method = call.method_name ?? '';
    const isCookieCtor =
      method === 'Cookie' ||
      method.endsWith('.Cookie');
    if (!isCookieCtor) return null;
    const looksLikeCtor =
      call.is_constructor ||
      (!call.receiver && (call.receiver_type === 'Cookie' || (call.receiver_type ?? '').endsWith('.Cookie'))) ||
      (call.resolution?.target ?? '').endsWith('.<init>');
    if (!looksLikeCtor) return null;
    // Need at least (name, value).
    if (call.arguments.length < 2) return null;

    const missingSecure   = !hasSetSecureTrue;
    const missingHttpOnly = !hasSetHttpOnlyTrue;
    if (!missingSecure && !missingHttpOnly) return null;

    return {
      line: call.location.line,
      receiver: 'new Cookie',
      missingSecure,
      missingHttpOnly,
      optionsPresent: false,
    };
  }

  // ---------------- Go ----------------
  private detectGo(call: CallInfo): InsecureCookieResult['insecureCookies'][number] | null {
    // `http.SetCookie(w, &http.Cookie{...})` — Go extractor surfaces
    // method_name='SetCookie', receiver='http'. The struct-literal text
    // for the cookie is in the second argument's expression.
    if (call.method_name !== 'SetCookie') return null;
    if ((call.receiver ?? '') !== 'http') return null;
    if (call.arguments.length < 2) return null;

    const cookieArg = call.arguments.find((a) => a.position === 1);
    const cookieExpr = (cookieArg?.expression ?? '').trim();
    // Variable-form `http.SetCookie(w, cookie)` (where `cookie` is a previously
    // built variable) cannot be inspected at the call site. Skip unless the
    // expression looks like a struct literal (contains `{` and `}`). Mirrors
    // the existing JS spread-options known limitation.
    if (!cookieExpr.includes('{') || !cookieExpr.includes('}')) return null;

    const missingSecure   = !GO_SECURE_TRUE_RE.test(cookieExpr);
    const missingHttpOnly = !GO_HTTPONLY_TRUE_RE.test(cookieExpr);
    if (!missingSecure && !missingHttpOnly) return null;

    return {
      line: call.location.line,
      receiver: 'http.SetCookie',
      missingSecure,
      missingHttpOnly,
      optionsPresent: true,
    };
  }

  // ---------------- Rust ----------------
  private detectRustSetCookieFormat(code: string): InsecureCookieResult['insecureCookies'] {
    // Text-based: find `format!(...)` / `write!(...)` / `writeln!(...)` whose
    // body contains a `Set-Cookie:` header literal, then check the same body
    // for `Secure` and `HttpOnly` tokens.
    const out: InsecureCookieResult['insecureCookies'] = [];
    const re = new RegExp(RUST_SET_COOKIE_MACRO_RE.source, RUST_SET_COOKIE_MACRO_RE.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const macro = m[1] ?? '';
      const body  = m[2] ?? '';
      const missingSecure   = !/\bSecure\b/.test(body);
      const missingHttpOnly = !/\bHttpOnly\b/.test(body);
      if (!missingSecure && !missingHttpOnly) continue;
      // 1-based line number of the macro invocation start.
      const line = code.slice(0, m.index).split('\n').length;
      out.push({
        line,
        receiver: macro,
        missingSecure,
        missingHttpOnly,
        optionsPresent: true,
      });
    }
    return out;
  }

  private emit(
    ctx: PassContext,
    file: string,
    det: InsecureCookieResult['insecureCookies'][number],
    flavor: 'js' | 'python' | 'java' | 'go' | 'rust',
  ): void {
    const missing: string[] = [];
    if (det.missingSecure) {
      missing.push(
        flavor === 'js' ? '`secure: true`'
        : flavor === 'python' ? '`secure=True`'
        : flavor === 'java' ? '`setSecure(true)`'
        : flavor === 'go' ? '`Secure: true`'
        : '`Secure` attribute',
      );
    }
    if (det.missingHttpOnly) {
      missing.push(
        flavor === 'js' ? '`httpOnly: true`'
        : flavor === 'python' ? '`httponly=True`'
        : flavor === 'java' ? '`setHttpOnly(true)`'
        : flavor === 'go' ? '`HttpOnly: true`'
        : '`HttpOnly` attribute',
      );
    }

    const fix =
      flavor === 'js'
        ? 'Pass `{ secure: true, httpOnly: true, sameSite: "lax" }` as the third argument to `res.cookie()`.'
        : flavor === 'python'
          ? 'Pass `secure=True, httponly=True, samesite="Lax"` to `response.set_cookie(...)`.'
          : flavor === 'java'
            ? 'After constructing the cookie, call `cookie.setSecure(true)` and `cookie.setHttpOnly(true)` before adding it to the response.'
            : flavor === 'go'
              ? 'Set `Secure: true` and `HttpOnly: true` on the `http.Cookie` struct literal passed to `http.SetCookie`.'
              : 'Append `; Secure; HttpOnly` to the `Set-Cookie` header string.';

    ctx.addFinding({
      id: `${this.name}-${file}-${det.line}`,
      pass: this.name,
      category: this.category,
      rule_id: this.name,
      cwe: 'CWE-614',
      severity: 'medium',
      level: 'warning',
      message:
        `Cookie set without ${missing.join(' and ')} — vulnerable to ` +
        `cleartext transmission (CWE-614) and client-side JS access ` +
        `(CWE-1004).`,
      file,
      line: det.line,
      fix,
      evidence: {
        receiver: det.receiver,
        options_present: det.optionsPresent,
        missing_secure: det.missingSecure,
        missing_http_only: det.missingHttpOnly,
      },
    });
  }
}
