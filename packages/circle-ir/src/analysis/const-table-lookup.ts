/**
 * Constant-table lookup taint barrier (#667).
 *
 * `const handler = REGISTRY[req.query.mod]` selects one of the values the
 * program itself wrote into `REGISTRY`. The request picks the key; it does not
 * supply the value. When `REGISTRY` is a top-level `const` object or array
 * literal that the file never writes to, the lookup result carries no request
 * data, so it is neither a source nor a taint-carrying def.
 *
 * Proof comes from the file text alone, and anything short of it keeps the
 * taint: a table declared with `let`, a table whose literal mentions a request
 * object, a table the file assigns into, mutates or passes to `Object.assign`,
 * and a lookup that is only part of the initializer (`T[k] || k`).
 */

import type { DFGDef } from '../types/index.js';

const REQUEST_REF_RE = /\b(?:req|request|ctx|event|process|params|query|body|location|document|window)\b/;

function isJs(language: string): boolean {
  return language === 'javascript' || language === 'typescript';
}

/** Index just past the bracket closing the one at `open`, or -1. Skips string literals. */
function closeOf(text: string, open: number): number {
  const pairs: Record<string, string> = { '{': '}', '[': ']', '(': ')' };
  const stack: string[] = [];
  for (let i = open; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      for (; j < text.length && text[j] !== c; j++) if (text[j] === '\\') j++;
      i = j;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return -1;
      i = nl;
      continue;
    }
    if (pairs[c]) { stack.push(pairs[c]!); continue; }
    if (c === '}' || c === ']' || c === ')') {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i + 1;
    }
  }
  return -1;
}

/**
 * Names of top-level `const` tables — object or array literals, optionally
 * wrapped in `Object.freeze(...)` — whose literal text references no request
 * object and which the file never writes to.
 */
export function constLookupTables(code: string, language: string): Set<string> {
  const out = new Set<string>();
  if (!isJs(language)) return out;
  const declRe = /^const\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(Object\.freeze\(\s*)?([{[])/gm;
  for (const m of code.matchAll(declRe)) {
    const name = m[1]!;
    const open = m.index! + m[0].length - 1;
    const close = closeOf(code, open);
    if (close < 0) continue;
    if (REQUEST_REF_RE.test(code.slice(open, close))) continue;
    const esc = name.replace(/\$/g, '\\$');
    const write = new RegExp(
      `\\b${esc}\\s*(?:\\[[^\\]]*\\]|\\.[\\w$]+)\\s*(?:=(?!=)|\\+=|\\|\\|=|\\?\\?=)` +
      `|\\b${esc}\\s*\\.\\s*(?:push|unshift|splice|set|fill|copyWithin|reverse|sort)\\s*\\(` +
      `|Object\\.(?:assign|defineProperty|defineProperties|setPrototypeOf)\\s*\\(\\s*${esc}\\b` +
      `|\\bdelete\\s+${esc}\\b`,
    );
    if (write.test(code)) continue;
    if (!onlyReadByLookup(code, name, m.index! + m[0].indexOf(name, 5))) continue;
    out.add(name);
  }
  return out;
}

/** Writes or mutations through an element read: `[k] = v`, `[k].x = v`, `[k].push(v)`. */
const WRITE_THROUGH_RE = new RegExp(
  String.raw`^(?:\s*(?:\?\.\s*)?(?:\.\s*[\w$]+|\[[^\]]*\]))*\s*` +
  String.raw`(?:=(?!=)|[-+*/%&|^]=|\+\+|--|\?\?=|\|\|=|&&=|\.\s*(?:push|unshift|splice|set|add|delete|clear|fill|copyWithin|reverse|sort)\s*\()`,
);

/**
 * True when every use of `name` outside its declaration is a plain element
 * read `name[k]` / `name?.[k]` that is not written or mutated through
 * (`name[k] = v`, `name[k].x = v`, `name[k].push(v)`). Any other use — an
 * alias (`const t = name`), a nested write (`name.items.push(v)`), a helper
 * taking the table (`_.set(name, …)`) — may change the table's contents.
 */
function onlyReadByLookup(code: string, name: string, declAt: number): boolean {
  const esc = name.replace(/\$/g, '\\$');
  for (const m of code.matchAll(new RegExp(`(?<![\\w$.])${esc}(?![\\w$])`, 'g'))) {
    if (m.index === declAt) continue;
    const rest = code.slice(m.index! + name.length);
    const open = /^\s*(?:\?\.)?\s*\[/.exec(rest);
    if (!open) return false;
    const close = closeOf(rest, open[0].length - 1);
    if (close < 0) return false;
    if (WRITE_THROUGH_RE.test(rest.slice(close))) return false;
  }
  return true;
}

/**
 * True when `rhs` is exactly `TABLE[<key>]` (optionally `TABLE?.[<key>]`) for
 * a table in `tables`.
 */
export function isConstTableLookup(rhs: string, tables: ReadonlySet<string>): boolean {
  if (tables.size === 0) return false;
  const e = rhs.replace(/\s*\/\/.*$/, '').trim().replace(/;$/, '').trim();
  const m = /^([A-Za-z_$][\w$]*)\s*(?:\?\.)?\s*\[/.exec(e);
  if (!m || !tables.has(m[1]!)) return false;
  const close = closeOf(e, m[0].length - 1);
  return close === e.length;
}

/** DFG def ids of locals initialised by a whole constant-table lookup. */
export function constTableLookupDefIds(defs: readonly DFGDef[], code: string, language: string): Set<number> {
  const out = new Set<number>();
  const tables = constLookupTables(code, language);
  if (tables.size === 0) return out;
  const lines = code.split('\n');
  for (const def of defs) {
    if (def.kind !== 'local') continue;
    const text = lines[def.line - 1];
    if (text === undefined) continue;
    const esc = def.variable.replace(/\$/g, '\\$');
    const m = new RegExp(`^\\s*(?:(?:const|let|var)\\s+)?${esc}\\s*(?::[^=]+)?=(?!=)\\s*(.+)$`).exec(text);
    if (m && isConstTableLookup(m[1]!, tables)) out.add(def.id);
  }
  return out;
}
