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
    // Java constructor: method_name === 'Cookie', receiver is null,
    // receiver_type === 'Cookie' (set by the Java plugin). Some plugins
    // also set call.is_constructor — accept any of the indicators.
    if (call.method_name !== 'Cookie') return null;
    const looksLikeCtor =
      call.is_constructor ||
      (!call.receiver && call.receiver_type === 'Cookie') ||
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

  private emit(
    ctx: PassContext,
    file: string,
    det: InsecureCookieResult['insecureCookies'][number],
    flavor: 'js' | 'python' | 'java',
  ): void {
    const missing: string[] = [];
    if (det.missingSecure)   missing.push(flavor === 'js' ? '`secure: true`' : flavor === 'python' ? '`secure=True`' : '`setSecure(true)`');
    if (det.missingHttpOnly) missing.push(flavor === 'js' ? '`httpOnly: true`' : flavor === 'python' ? '`httponly=True`' : '`setHttpOnly(true)`');

    const fix =
      flavor === 'js'
        ? 'Pass `{ secure: true, httpOnly: true, sameSite: "lax" }` as the third argument to `res.cookie()`.'
        : flavor === 'python'
          ? 'Pass `secure=True, httponly=True, samesite="Lax"` to `response.set_cookie(...)`.'
          : 'After constructing the cookie, call `cookie.setSecure(true)` and `cookie.setHttpOnly(true)` before adding it to the response.';

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
