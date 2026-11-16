/**
 * Pass: missing-auth-middleware (CWE-862, category: security)
 *
 * Pattern pass for JavaScript / TypeScript (Express-style routers). One
 * decidable shape only: in a single file, routes of one resource on one
 * router are guarded by an authentication middleware, and a state-changing
 * route of that resource that addresses a record by a path parameter is not.
 *
 *   router.get('/notes/:id', requireAuth, getNote);
 *   router.delete('/notes/:id', deleteNote);          // reported
 *
 * Routes: `<r>.{get,post,put,patch,delete,all}('<path>', ...handlers)` where
 * `<r>` is a plain identifier (`app`, `router`, `notesRouter`) and the path a
 * string literal. A route is guarded when any of its handler arguments is an
 * auth middleware: an identifier, member or call whose last name is an
 * authentication name (`requireAuth`, `isAuthenticated`, `ensureLoggedIn`,
 * `passport.authenticate(...)`, `verifyToken`, `jwt(...)`, `protect`, …) or a
 * role / permission guard (`requireAdmin`, `isAdmin`, `authorize(...)`,
 * `hasRole(...)`, `denyAll()`). The resource is the first static path segment
 * after an optional `api` / `v<n>` prefix.
 *
 * Reported: a `post` / `put` / `patch` / `delete` route with a `:param`
 * segment and no middleware at all (just the path and the handler), when another route of the same router and resource
 * carries an authentication middleware (a role guard alone on the sibling is
 * not evidence: the unguarded route may rely on a parent-mounted login and
 * check ownership itself).
 *
 * Precision (abstain rather than guess):
 *   - Any `.use(...)` in the file with an auth middleware argument: the whole
 *     file is skipped (router-level guards and their order).
 *   - A handler (inline, or a function declared in the file) that reads
 *     `req.user` / `req.session` / `req.auth` / `res.locals.user`, calls
 *     `isAuthenticated(`, or answers 401 / 403 does its own check: skipped.
 *   - Routes without a `:param`, `get` routes, chained `router.route(...)`
 *     forms, computed paths and non-identifier receivers are not considered.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

const ROUTE_METHODS: ReadonlySet<string> = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const MUTATING_METHODS: ReadonlySet<string> = new Set(['post', 'put', 'patch', 'delete']);

/** Authentication middleware names, normalised (lower case, no `_` / `-`). */
const AUTHN_NAMES: ReadonlySet<string> = new Set([
  'auth', 'authenticate', 'authenticated', 'isauthenticated', 'ensureauthenticated', 'ensureauth',
  'ensureloggedin', 'isloggedin', 'loggedin', 'requireauth', 'requireauthentication', 'requirelogin',
  'requireslogin', 'mustbeloggedin', 'requireuser', 'requiresuser', 'authmiddleware', 'authrequired',
  'loginrequired', 'verifytoken', 'verifyjwt', 'checkjwt', 'jwt', 'expressjwt', 'jwtauth', 'checkauth',
  'protect', 'authguard', 'requiresession', 'withauth', 'needsauth', 'isauth', 'isuser',
]);

/** Role / permission guards: they imply a login check on the route that carries them. */
const AUTHZ_NAMES: ReadonlySet<string> = new Set([
  'authorize', 'authorized', 'isauthorized', 'isadmin', 'requireadmin', 'adminonly', 'ensureadmin',
  'hasrole', 'requirerole', 'checkrole', 'restrictto', 'permit', 'haspermission', 'requirepermission',
  'checkpermission', 'denyall', 'isowner', 'requireowner', 'checkowner',
]);

function isIdentChar(ch: string | undefined): boolean {
  return ch !== undefined && (ch === '_' || ch === '$' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'));
}

function isIdentifier(s: string): boolean {
  if (s.length === 0 || (s[0] >= '0' && s[0] <= '9')) return false;
  for (const ch of s) if (!isIdentChar(ch)) return false;
  return true;
}

/** The last name of an identifier, member or call expression (`a.b.c(x)` → `c`); null otherwise. */
export function middlewareName(expr: string): string | null {
  let e = expr.trim();
  const paren = e.indexOf('(');
  if (paren >= 0) {
    if (!e.endsWith(')')) return null;
    e = e.slice(0, paren).trim();
  }
  const segs = e.split('.');
  for (const s of segs) if (!isIdentifier(s.trim())) return null;
  return segs[segs.length - 1].trim();
}

function norm(name: string): string {
  let out = '';
  for (const ch of name) if (ch !== '_' && ch !== '-' && ch !== '$') out += ch.toLowerCase();
  return out;
}

export type GuardKind = 'authn' | 'authz' | null;

export function guardKind(expr: string): GuardKind {
  const name = middlewareName(expr);
  if (!name) return null;
  const n = norm(name);
  if (AUTHN_NAMES.has(n)) return 'authn';
  if (AUTHZ_NAMES.has(n)) return 'authz';
  return null;
}

function stringLiteral(expr: string | undefined): string | null {
  const e = (expr ?? '').trim();
  if (e.length < 2) return null;
  const q = e[0];
  if ((q !== "'" && q !== '"' && q !== '`') || e[e.length - 1] !== q) return null;
  const body = e.slice(1, -1);
  if (body.includes(q) || body.includes('\\') || (q === '`' && body.includes('${'))) return null;
  return body;
}

/** First static segment after an optional `api` / `v<n>` prefix; '' when there is none. */
export function resourceOf(path: string): string {
  for (const raw of path.split('/')) {
    const s = raw.trim().toLowerCase();
    if (s === '' || s.startsWith(':') || s === '*') continue;
    if (s === 'api') continue;
    if (s.length >= 2 && s[0] === 'v' && [...s.slice(1)].every(c => c >= '0' && c <= '9')) continue;
    return s;
  }
  return '';
}

function hasParamSegment(path: string): boolean {
  return path.split('/').some(s => s.startsWith(':') && s.length > 1);
}

/** Signals that a handler checks the caller itself. */
const SELF_CHECK_MARKERS: readonly string[] = [
  'req.user', 'req.session', 'req.auth', 'request.user', 'request.session', 'res.locals.user',
  'isAuthenticated(', 'status(401)', 'status(403)', 'sendStatus(401)', 'sendStatus(403)',
];

function checksCallerItself(text: string): boolean {
  return SELF_CHECK_MARKERS.some(m => text.includes(m));
}

/** The text of a function declared in the file under `name` (to its closing brace at column 0), or null. */
function sameFileFunctionText(lines: string[], name: string): string | null {
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trimStart();
    const isDecl =
      t.startsWith(`function ${name}(`) || t.startsWith(`async function ${name}(`) ||
      t.startsWith(`export function ${name}(`) || t.startsWith(`export async function ${name}(`) ||
      t.startsWith(`const ${name} =`) || t.startsWith(`export const ${name} =`);
    if (!isDecl) continue;
    const out: string[] = [];
    for (let j = i; j < lines.length && j < i + 200; j++) {
      out.push(lines[j]);
      if (j > i && lines[j].startsWith('}')) break;
      if (j === i && lines[j].trimEnd().endsWith(';') && !lines[j].includes('{')) break;
    }
    return out.join('\n');
  }
  return null;
}

interface Route {
  call: CallInfo;
  receiver: string;
  method: string;
  path: string;
  resource: string;
  guard: 'authn' | 'authz' | null;
  handler: string;
  /** Arguments between the path and the handler. */
  middlewareCount: number;
}

function routeOf(call: CallInfo): Route | null {
  if (!ROUTE_METHODS.has(call.method_name)) return null;
  const receiver = (call.receiver ?? '').trim();
  if (!isIdentifier(receiver)) return null;
  const args = [...call.arguments].sort((a, b) => a.position - b.position);
  if (args.length < 2) return null;
  const path = stringLiteral(args[0].expression);
  if (path === null || !path.startsWith('/')) return null;
  let guard: Route['guard'] = null;
  const exprs: string[] = [];
  for (const a of args.slice(1)) {
    const e = (a.expression ?? '').trim();
    // `[requireAuth, validate]` — a middleware array.
    if (e.startsWith('[') && e.endsWith(']')) exprs.push(...e.slice(1, -1).split(','));
    else exprs.push(e);
  }
  for (const e of exprs) {
    const k = guardKind(e);
    if (k === 'authn') { guard = 'authn'; break; }
    if (k === 'authz') guard = 'authz';
  }
  return {
    call, receiver, method: call.method_name, path, resource: resourceOf(path), guard,
    handler: (args[args.length - 1].expression ?? '').trim(),
    middlewareCount: args.length - 2,
  };
}

export interface MissingAuthMiddlewareResult {
  findings: Array<{ line: number; route: string; guardedBy: string }>;
}

export class MissingAuthMiddlewarePass implements AnalysisPass<MissingAuthMiddlewareResult> {
  readonly name = 'missing-auth-middleware';
  readonly category = 'security' as const;

  run(ctx: PassContext): MissingAuthMiddlewareResult {
    const { graph, language, code } = ctx;
    const findings: MissingAuthMiddlewareResult['findings'] = [];
    if (language !== 'javascript' && language !== 'typescript') return { findings };
    const calls = graph.ir.calls;

    // Router-level guards anywhere in the file: skip it.
    for (const c of calls) {
      if (c.method_name !== 'use') continue;
      if (c.arguments.some(a => guardKind(a.expression ?? '') !== null)) return { findings };
    }

    const routes = calls.map(routeOf).filter((r): r is Route => r !== null);
    if (routes.length < 2) return { findings };
    const lines = code.split('\n');
    const file = graph.ir.meta.file;
    const seen = new Set<number>();

    for (const r of routes) {
      // Only a route with no middleware at all: an unrecognised one may be its guard.
      if (r.guard !== null || r.middlewareCount > 0) continue;
      if (!MUTATING_METHODS.has(r.method) || !hasParamSegment(r.path) || r.resource === '') continue;
      const sibling = routes.find(s =>
        s !== r && s.receiver === r.receiver && s.resource === r.resource && s.guard === 'authn');
      if (!sibling) continue;
      const handlerText = isIdentifier(r.handler) ? sameFileFunctionText(lines, r.handler) ?? '' : r.handler;
      if (checksCallerItself(handlerText)) continue;
      const line = r.call.location.line;
      if (seen.has(line)) continue;
      seen.add(line);
      const route = `${r.method.toUpperCase()} ${r.path}`;
      const siblingRoute = `${sibling.method.toUpperCase()} ${sibling.path}`;
      findings.push({ line, route, guardedBy: siblingRoute });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-862',
        severity: 'high',
        level: 'error',
        message:
          `\`${r.receiver}.${r.method}('${r.path}')\` changes a record addressed by a path ` +
          `parameter with no authentication middleware, while \`${siblingRoute}\` on the same ` +
          'router requires one. Anyone can call this route.',
        file,
        line,
        fix:
          `Add the same authentication middleware as \`${siblingRoute}\` to this route ` +
          '(and check that the caller may change this record), or guard the whole router ' +
          'with `router.use(...)`.',
        evidence: { route, guardedSibling: siblingRoute, receiver: r.receiver, language },
      });
    }
    return { findings };
  }
}
