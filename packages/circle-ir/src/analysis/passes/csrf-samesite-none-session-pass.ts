/**
 * Pass: csrf-samesite-none-session (CWE-352, category: security)
 *
 * Pattern pass for JavaScript / TypeScript (Express). One decidable shape:
 * a file mounts a cookie session whose cookie is explicitly sent on
 * cross-site requests, registers state-changing routes, and has no CSRF
 * defence in sight.
 *
 *   app.use(session({ secret, cookie: { sameSite: 'none', secure: true } }));
 *   app.post('/transfer', (req, res) => { ... });   // CSRF: reported at the session line
 *
 * Why only this shape: when `sameSite` is not set, current browsers default
 * the cookie to `Lax`, which already keeps it off cross-site POSTs; whether
 * that is enough, and whether a CSRF middleware is mounted in another
 * module, is not decidable from one file. `sameSite: 'none'` (or `false`)
 * turns that browser defence off on purpose, so the file itself has to
 * carry the defence.
 *
 * Matched: `<r>.use(session({...}))` / `cookieSession({...})` /
 * `expressSession({...})` / `cookieSession(...)` whose options set
 * `sameSite: 'none'` (any case) or `sameSite: false`, plus at least one
 * `<x>.{post,put,patch,delete}('<path>', ...)` route in the same file.
 *
 * Precision (abstain rather than guess):
 *   - Any mention of `csrf`, `csurf`, `xsrf` or `lusca` in the file (a
 *     token middleware, a double-submit helper, a header check).
 *   - Any `origin` / `referer` header check on the request
 *     (`req.headers.origin`, `req.get('origin')`, `req.header('referer')`).
 *   - `sameSite` set from a variable or expression, `'lax'` / `'strict'` /
 *     `true`, or not set at all.
 *   - Files without a state-changing route.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

const SESSION_FACTORIES: ReadonlySet<string> = new Set(['session', 'cookieSession', 'expressSession']);
const MUTATING_METHODS: ReadonlySet<string> = new Set(['post', 'put', 'patch', 'delete']);
const DEFENCE_MARKERS: readonly string[] = ['csrf', 'csurf', 'xsrf', 'lusca'];
const ORIGIN_CHECK_MARKERS: readonly string[] = [
  'headers.origin', "headers['origin']", 'headers["origin"]', "get('origin')", 'get("origin")',
  "header('origin')", 'header("origin")', 'headers.referer', "headers['referer']", 'headers["referer"]',
  "get('referer')", 'get("referer")', "header('referer')", 'header("referer")',
];

function isIdentChar(ch: string | undefined): boolean {
  return ch !== undefined && (ch === '_' || ch === '$' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'));
}

/**
 * The value the options text gives `sameSite`: `'none'` / `false` → 'none';
 * a literal `'lax'` / `'strict'` / `true` → 'set'; absent → null; anything
 * else (a variable, a ternary) → 'unknown'.
 */
export function sameSiteSetting(options: string): 'none' | 'set' | 'unknown' | null {
  let result: 'none' | 'set' | 'unknown' | null = null;
  let from = 0;
  for (;;) {
    const at = options.indexOf('sameSite', from);
    if (at < 0) return result;
    from = at + 'sameSite'.length;
    if (isIdentChar(options[at - 1]) || isIdentChar(options[from])) continue;
    let k = from;
    if (options[k] === "'" || options[k] === '"') k++; // quoted key
    while (options[k] === ' ') k++;
    if (options[k] !== ':') continue;
    k++;
    while (options[k] === ' ') k++;
    let value = '';
    while (k < options.length && options[k] !== ',' && options[k] !== '}' && options[k] !== '\n') value += options[k++];
    const v = value.trim();
    const unq = (v.startsWith("'") || v.startsWith('"')) && v.endsWith(v[0]) && v.length >= 2 ? v.slice(1, -1).toLowerCase() : null;
    let reading: 'none' | 'set' | 'unknown';
    if (unq === 'none' || v === 'false') reading = 'none';
    else if (unq === 'lax' || unq === 'strict' || v === 'true') reading = 'set';
    else reading = 'unknown';
    // The weakest reading wins only when every occurrence agrees.
    if (result === null) result = reading;
    else if (result !== reading) result = 'unknown';
  }
}

/** For `session({...})` passed to `.use(...)`, the options text; null otherwise. */
export function sessionOptions(useCall: CallInfo): { factory: string; options: string } | null {
  if (useCall.method_name !== 'use') return null;
  for (const a of useCall.arguments) {
    const e = (a.expression ?? '').trim();
    const paren = e.indexOf('(');
    if (paren <= 0 || !e.endsWith(')')) continue;
    const factory = e.slice(0, paren).trim();
    if (!SESSION_FACTORIES.has(factory)) continue;
    return { factory, options: e.slice(paren + 1, -1) };
  }
  return null;
}

function isStateChangingRoute(call: CallInfo): boolean {
  if (!MUTATING_METHODS.has(call.method_name)) return false;
  const receiver = (call.receiver ?? '').trim();
  if (!receiver || [...receiver].some(ch => !isIdentChar(ch))) return false;
  const path = (call.arguments.find(a => a.position === 0)?.expression ?? '').trim();
  return path.length >= 3 && (path[0] === "'" || path[0] === '"' || path[0] === '`') && path[1] === '/' && call.arguments.length >= 2;
}

export interface CsrfSameSiteNoneSessionResult {
  findings: Array<{ line: number; factory: string; routes: number }>;
}

export class CsrfSameSiteNoneSessionPass implements AnalysisPass<CsrfSameSiteNoneSessionResult> {
  readonly name = 'csrf-samesite-none-session';
  readonly category = 'security' as const;

  run(ctx: PassContext): CsrfSameSiteNoneSessionResult {
    const { graph, language, code } = ctx;
    const findings: CsrfSameSiteNoneSessionResult['findings'] = [];
    if (language !== 'javascript' && language !== 'typescript') return { findings };
    const lower = code.toLowerCase();
    if (DEFENCE_MARKERS.some(m => lower.includes(m))) return { findings };
    if (ORIGIN_CHECK_MARKERS.some(m => lower.includes(m))) return { findings };

    const routes = graph.ir.calls.filter(isStateChangingRoute);
    if (routes.length === 0) return { findings };
    const file = graph.ir.meta.file;

    for (const call of graph.ir.calls) {
      const s = sessionOptions(call);
      if (!s || sameSiteSetting(s.options) !== 'none') continue;
      const line = call.location.line;
      findings.push({ line, factory: s.factory, routes: routes.length });
      const first = routes[0];
      const route = `${first.method_name.toUpperCase()} ${(first.arguments.find(a => a.position === 0)?.expression ?? '').trim()}`;
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-352',
        severity: 'high',
        level: 'error',
        message:
          `The \`${s.factory}(...)\` cookie is sent on cross-site requests (\`sameSite: 'none'\`) and ` +
          `this file registers state-changing routes (${route}${routes.length > 1 ? ` and ${routes.length - 1} more` : ''}) ` +
          'with no CSRF token or origin check. Any site the user visits can submit them with the session.',
        file,
        line,
        fix:
          "Set the session cookie to `sameSite: 'lax'` (or `'strict'`) unless it must be sent cross-site; " +
          'if it must, add a CSRF token middleware (synchronizer or double-submit) to the state-changing routes.',
        evidence: { factory: s.factory, routes: routes.length, language },
      });
    }
    return { findings };
  }
}
