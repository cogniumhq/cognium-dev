/**
 * Pass: insecure-cookie (CWE-614, category: security)
 *
 * JavaScript / TypeScript pattern pass that flags Express `res.cookie(name,
 * value, options)` calls where the options object is missing or does not
 * set both `secure: true` and `httpOnly: true`.
 *
 * Rationale: the absence of `Secure` / `HttpOnly` flags is a vulnerability
 * of *shape*, not of taint. `insecure_cookie` is already modeled as a
 * Java sink (`new Cookie(...)`) via the YAML config, but the equivalent
 * Express pattern uses a literal options object whose presence/absence
 * of flags must be inspected at the call site. The receiver type does
 * not propagate cleanly through middleware, so we do a syntactic check
 * on the literal source-text of arg 2.
 *
 * Detection:
 *   1. Filter language to javascript/typescript.
 *   2. Iterate `graph.ir.calls` for `method_name === 'cookie'` with a
 *      receiver that looks like an Express response (`res`, `response`,
 *      `reply`, `ctx.cookies` is intentionally excluded — Koa's API has
 *      different semantics).
 *   3. Read the raw expression text of arg 2 (the options object).
 *   4. Flag if:
 *        - arg 2 is absent, OR
 *        - arg 2 does not contain `secure: true` (regex), OR
 *        - arg 2 does not contain `httpOnly: true` (regex).
 *   5. Emit a single finding per call site listing the missing flags.
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

const COOKIE_RESPONSE_RECEIVERS = new Set([
  'res', 'response', 'reply',
]);

const SECURE_TRUE_RE  = /\bsecure\s*:\s*true\b/;
const HTTPONLY_TRUE_RE = /\bhttpOnly\s*:\s*true\b/i;

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
    const { graph, language } = ctx;

    if (language !== 'javascript' && language !== 'typescript') {
      return { insecureCookies: [] };
    }

    const file = graph.ir.meta.file;
    const insecureCookies: InsecureCookieResult['insecureCookies'] = [];

    for (const call of graph.ir.calls) {
      if (call.method_name !== 'cookie') continue;
      const receiver = call.receiver ?? '';
      if (!COOKIE_RESPONSE_RECEIVERS.has(receiver)) continue;

      // Must look like a setter call: at least (name, value) args.
      // `res.cookie('name')` (Express getter form) takes one arg — skip.
      if (call.arguments.length < 2) continue;

      const opts = call.arguments.find(a => a.position === 2);
      const optsExpr = (opts?.expression ?? '').trim();
      const optionsPresent = optsExpr.length > 0;

      const missingSecure = !SECURE_TRUE_RE.test(optsExpr);
      const missingHttpOnly = !HTTPONLY_TRUE_RE.test(optsExpr);
      if (!missingSecure && !missingHttpOnly) continue;

      const line = call.location.line;
      insecureCookies.push({
        line,
        receiver,
        missingSecure,
        missingHttpOnly,
        optionsPresent,
      });

      const missing: string[] = [];
      if (missingSecure)   missing.push('`secure: true`');
      if (missingHttpOnly) missing.push('`httpOnly: true`');

      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
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
        line,
        fix:
          'Pass `{ secure: true, httpOnly: true, sameSite: "lax" }` as the ' +
          'third argument to `res.cookie()`.',
        evidence: {
          receiver,
          options_present: optionsPresent,
          missing_secure: missingSecure,
          missing_http_only: missingHttpOnly,
        },
      });
    }

    return { insecureCookies };
  }
}
