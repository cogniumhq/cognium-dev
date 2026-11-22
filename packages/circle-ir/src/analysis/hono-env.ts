/**
 * Hono bindings taint barrier.
 *
 * In a Hono handler `c.env` holds the deployment's bindings and configuration
 * (secrets, database handles, variables from the worker config). The request
 * does not write them. A handler that also reads the request taints its
 * context parameter `c`, and `const table = c.env.TABLE` then inherited that
 * taint through the use of `c`. A local whose whole initializer is a read of
 * `<id>.env` (optionally a member path below it), or a destructuring of it
 * without defaults, carries no request data.
 *
 * `<id>` must be the handler's context: the first parameter of a function
 * passed inline as a call argument (`app.get('/p', (c) => …)`,
 * `app.use(async (c, next) => …)`), or a first parameter typed `Context`.
 * Request data that happens to have an `env` field (`c.req.query().env`,
 * `c.req.param().env`) keeps its taint.
 *
 * Only files that import from `hono` are considered, and anything other than
 * a plain member read (a call, an index by a variable, an operator) keeps the
 * taint.
 */

import type { DFGDef, DFGUse } from '../types/index.js';

const HONO_IMPORT_RE = /\bfrom\s+['"]hono(?:\/[^'"]*)?['"]/;
/** `<id>.env` followed by plain member reads: `.NAME`, `?.NAME`, `['NAME']`. */
const ENV_READ = String.raw`(?<base>[A-Za-z_$][\w$]*)\s*\??\.\s*env(?:\s*(?:\??\.\s*[A-Za-z_$][\w$]*|(?:\?\.)?\[\s*(?:'[^']*'|"[^"]*")\s*\]))*`;
/** Drops a trailing `async` keyword. */
const stripAsync = (s: string) => (/(?:^|[^\w$])async$/.test(s) ? s.slice(0, -5).trimEnd() : s);

const ROUTE_CALL_RE = /(?:\.(?:get|post|put|delete|patch|options|head|all|on|use)|(?<![\w$])(?:createMiddleware|createHandlers))\s*\(/g;

/**
 * Text before a parameter list that opens as a direct argument of a route or
 * middleware call: `app.get('/p', `, `app.use(`, `app.post('/p', auth, async `.
 */
function opensInCall(text: string): boolean {
  const s = stripAsync(text);
  if (!/[(,]$/.test(s)) return false;
  let start = -1;
  for (const m of s.matchAll(ROUTE_CALL_RE)) start = m.index + m[0].length;
  if (start < 0) return false;
  let depth = 0;
  for (const ch of s.slice(start)) {
    if (ch === '(') depth++;
    else if (ch === ')' && --depth < 0) return false;
  }
  return depth === 0;
}

/**
 * The first parameter of a route handler or middleware: a function passed
 * inline as an argument of a route or middleware call (`(c) =>`,
 * `async (c, next) =>`, `c =>`, `function (c)`), or any function whose first
 * parameter is typed `Context`.
 */
function isContextParam(def: DFGDef, lines: readonly string[]): boolean {
  if (def.kind !== 'param' || def.column === undefined) return false;
  const text = lines[def.line - 1];
  if (text === undefined || text.slice(def.column, def.column + def.variable.length) !== def.variable) return false;
  const before = text.slice(0, def.column).trimEnd();
  const after = text.slice(def.column + def.variable.length).trimStart();
  if (!before.endsWith('(')) return after.startsWith('=>') && opensInCall(before);
  if (/^:\s*Context\b/.test(after)) return true;
  if (!/^(?:[,):]|=>)/.test(after)) return false;
  const head = before.slice(0, -1).trimEnd();
  const fn = /(?:^|[^\w$])function(?:\s+[\w$]+)?$/.exec(head);
  return opensInCall(fn ? head.slice(0, fn.index + (fn[0].startsWith('function') ? 0 : 1)).trimEnd() : head);
}

export function honoEnvDefIds(
  defs: readonly DFGDef[],
  uses: readonly DFGUse[],
  code: string,
  language: string,
): Set<number> {
  const out = new Set<number>();
  if (language !== 'javascript' && language !== 'typescript') return out;
  if (!HONO_IMPORT_RE.test(code)) return out;
  const lines = code.split('\n');
  const defById = new Map(defs.map(d => [d.id, d]));
  const contextParam = (id: number | null) => {
    const d = id === null ? undefined : defById.get(id);
    return d !== undefined && isContextParam(d, lines);
  };
  for (const def of defs) {
    if (def.kind !== 'local') continue;
    const text = lines[def.line - 1];
    if (text === undefined) continue;
    const esc = def.variable.replace(/\$/g, '\\$');
    const tail = String.raw`\s*=(?!=)\s*${ENV_READ}(?:\s+as\s+[\w$.<>\[\]]+)?\s*;?\s*(?:\/\/.*)?$`;
    const plain = new RegExp(String.raw`^\s*(?:(?:const|let|var)\s+)?${esc}\s*(?::[^=]+)?${tail}`);
    const destructure = new RegExp(String.raw`^\s*(?:const|let|var)\s*\{[^}=]*(?<![\w$])${esc}(?![\w$])[^}=]*\}\s*(?::[^=]+)?${tail}`);
    const base = (plain.exec(text) ?? destructure.exec(text))?.groups?.base;
    if (base === undefined) continue;
    const reaching = uses.filter(u => u.line === def.line && u.variable === base && u.def_id !== null);
    if (reaching.length > 0 && reaching.every(u => contextParam(u.def_id))) out.add(def.id);
  }
  return out;
}
