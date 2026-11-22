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
 * Only files that import from `hono` are considered, and anything other than
 * a plain member read (a call, an index by a variable, an operator) keeps the
 * taint.
 */

import type { DFGDef } from '../types/index.js';

const HONO_IMPORT_RE = /\bfrom\s+['"]hono(?:\/[^'"]*)?['"]/;
/** `<id>.env` followed by plain member reads: `.NAME`, `?.NAME`, `['NAME']`. */
const ENV_READ = String.raw`[A-Za-z_$][\w$]*\s*\??\.\s*env(?:\s*(?:\??\.\s*[A-Za-z_$][\w$]*|(?:\?\.)?\[\s*(?:'[^']*'|"[^"]*")\s*\]))*`;

export function honoEnvDefIds(defs: readonly DFGDef[], code: string, language: string): Set<number> {
  const out = new Set<number>();
  if (language !== 'javascript' && language !== 'typescript') return out;
  if (!HONO_IMPORT_RE.test(code)) return out;
  const lines = code.split('\n');
  for (const def of defs) {
    if (def.kind !== 'local') continue;
    const text = lines[def.line - 1];
    if (text === undefined) continue;
    const esc = def.variable.replace(/\$/g, '\\$');
    const tail = String.raw`\s*=(?!=)\s*${ENV_READ}(?:\s+as\s+[\w$.<>\[\]]+)?\s*;?\s*(?:\/\/.*)?$`;
    const plain = new RegExp(String.raw`^\s*(?:(?:const|let|var)\s+)?${esc}\s*(?::[^=]+)?${tail}`);
    const destructure = new RegExp(String.raw`^\s*(?:const|let|var)\s*\{[^}=]*(?<![\w$])${esc}(?![\w$])[^}=]*\}\s*(?::[^=]+)?${tail}`);
    if (plain.test(text) || destructure.test(text)) out.add(def.id);
  }
  return out;
}
