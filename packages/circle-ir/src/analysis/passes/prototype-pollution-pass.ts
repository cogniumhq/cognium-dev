/**
 * Pass: prototype-pollution (CWE-1321, category: security)
 *
 * Pattern pass for JavaScript / TypeScript. Three shapes write an
 * attacker-chosen key into an object at depth, so a `__proto__` (or
 * `constructor` then `prototype`) key reaches `Object.prototype`:
 *
 *   1. recursive merge — a function iterates the keys of one object
 *      (`for (k in src)`, `for (k of Object.keys(src))`, `Object.entries`,
 *      `Object.keys(src).forEach(k => …)`), writes `target[k] = …`, and
 *      calls itself with `target[k]` among the arguments (a deep clone that
 *      recurses only on `src[k]` writes into fresh objects and is not one);
 *   2. set by path — a function walks an object along a key path
 *      (`cur = cur[k]`, or `cur[k] = cur[k] || {}`) inside a loop and
 *      writes `cur[…] = …`, where the keys come from `path.split('.')` (any
 *      non-empty separator) or from a collection named like a key path
 *      (`path`, `keys`, `segments`, `parts`, `props`);
 *   3. request keys — `obj[a][b] = …` where both `a` and `b` come from the
 *      HTTP request (`const { a, b } = req.body`, `const a = req.query.x`,
 *      or `req.body.x` written in the brackets).
 *
 * Precision (abstain rather than guess):
 *   - The function (shapes 1 and 2) or handler (shape 3) mentions
 *     `__proto__`, `constructor` or `prototype` in a string literal or as
 *     a name, or passes the key to a function whose name says it checks
 *     the key (`isSafeKey(k)`, `isPrototypeKey(k)`, `assertAllowed(k)`):
 *     that is the guard.
 *   - The written object was made with `Object.create(null)`.
 *   - A shallow copy (no recursion, no path walk) is not reported: writing
 *     `__proto__` one level deep changes only that object's own prototype.
 *   - Character iteration (`word.split('')`, `for (const ch of word)`) is not
 *     a key path: one character cannot spell `__proto__`.
 *   - Library calls (`_.merge`, `$.extend`, `Object.assign`) are left to the
 *     taint sinks that already model them.
 *
 * Detection runs on the source text with strings and comments masked, so
 * braces or keywords inside literals never count.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** A token, its offset, and for a bracket the index of its partner (-1 when unbalanced). */
type Tok = { t: string; pos: number; m: number };

interface Fn {
  name: string | null;
  /** Token index of the body's `{` and of its matching `}`. */
  open: number;
  close: number;
  params: string[];
}

export interface PrototypePollutionHit {
  line: number;
  shape: 'recursive-merge' | 'set-by-path' | 'request-keys';
  target: string;
  key: string;
  fn: string | null;
}

export interface PrototypePollutionResult {
  findings: PrototypePollutionHit[];
}

const KEYWORDS: ReadonlySet<string> = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'with', 'return', 'typeof', 'function', 'new', 'await',
  'yield', 'delete', 'void', 'in', 'of', 'do', 'else', 'try', 'finally', 'throw', 'case', 'super',
]);

const PATH_NAME_WORDS: readonly string[] = ['path', 'keys', 'segments', 'segs', 'parts', 'props', 'keypath', 'fields'];

const GUARD_NAME_WORDS: readonly string[] = [
  'safe', 'proto', 'pollut', 'forbid', 'unsafe', 'danger', 'block', 'allow', 'reserved', 'valid', 'deny', 'illegal',
];

const REQUEST_ROOTS: ReadonlySet<string> = new Set(['req', 'request']);
const REQUEST_BAGS: ReadonlySet<string> = new Set(['body', 'query', 'params']);

const MAX_CODE_LENGTH = 1_000_000;

function isIdentStart(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_' || ch === '$';
}

function isIdentChar(ch: string): boolean {
  return isIdentStart(ch) || (ch >= '0' && ch <= '9');
}

function isIdent(t: string | undefined): t is string {
  return !!t && isIdentStart(t[0]) && !KEYWORDS.has(t);
}

/**
 * Blank the content of comments and string / template literals (quotes kept,
 * newlines kept, so offsets and line numbers are unchanged). Regex literals
 * are not recognised; a stray quote inside one only blanks to the line end.
 */
export function maskLiterals(code: string): string {
  const out = code.split('');
  let i = 0;
  const n = code.length;
  while (i < n) {
    const ch = code[i];
    if (ch === '/' && code[i + 1] === '/') {
      while (i < n && code[i] !== '\n') out[i++] = ' ';
      continue;
    }
    if (ch === '/' && code[i + 1] === '*') {
      out[i] = ' '; out[i + 1] = ' '; i += 2;
      while (i < n && !(code[i] === '*' && code[i + 1] === '/')) { if (code[i] !== '\n') out[i] = ' '; i++; }
      if (i < n) { out[i] = ' '; out[i + 1] = ' '; i += 2; }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      i++;
      while (i < n && code[i] !== ch) {
        if (code[i] === '\n' && ch !== '`') break;
        if (code[i] === '\\') { out[i] = ' '; i++; if (i < n && code[i] !== '\n') out[i] = ' '; i++; continue; }
        if (code[i] !== '\n') out[i] = ' ';
        i++;
      }
      i++;
      continue;
    }
    i++;
  }
  return out.join('');
}

const PUNCT3: readonly string[] = ['===', '!==', '??=', '||=', '&&=', '...'];
const PUNCT2: readonly string[] = ['==', '!=', '=>', '||', '&&', '??', '<=', '>=', '+=', '-=', '?.', '++', '--'];

export function tokenize(masked: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  const n = masked.length;
  while (i < n) {
    const ch = masked[i];
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r') { i++; continue; }
    if (isIdentStart(ch)) {
      const s = i;
      while (i < n && isIdentChar(masked[i])) i++;
      toks.push({ t: masked.slice(s, i), pos: s, m: -1 });
      continue;
    }
    if (ch >= '0' && ch <= '9') {
      const s = i;
      while (i < n && (isIdentChar(masked[i]) || masked[i] === '.')) i++;
      toks.push({ t: masked.slice(s, i), pos: s, m: -1 });
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const s = i;
      i++;
      while (i < n && masked[i] !== ch && masked[i] !== '\n') i++;
      i++;
      toks.push({ t: '"', pos: s, m: -1 });
      continue;
    }
    const three = masked.slice(i, i + 3);
    if (PUNCT3.includes(three)) { toks.push({ t: three, pos: i, m: -1 }); i += 3; continue; }
    const two = masked.slice(i, i + 2);
    if (PUNCT2.includes(two)) { toks.push({ t: two, pos: i, m: -1 }); i += 2; continue; }
    toks.push({ t: ch, pos: i, m: -1 });
    i++;
  }
  // Pair brackets in one pass so every lookup below is O(1).
  const stack: number[] = [];
  for (let j = 0; j < toks.length; j++) {
    const t = toks[j].t;
    if (t === '(' || t === '[' || t === '{') stack.push(j);
    else if (t === ')' || t === ']' || t === '}') {
      const want = t === ')' ? '(' : t === ']' ? '[' : '{';
      // Drop unmatched openers of another kind (a regex literal's bracket, say).
      while (stack.length > 0 && toks[stack[stack.length - 1]].t !== want) stack.pop();
      const o = stack.pop();
      if (o !== undefined) { toks[o].m = j; toks[j].m = o; }
    }
  }
  return toks;
}

/** Index of the token closing the bracket opened at `i`, or -1. */
function matchClose(toks: Tok[], i: number): number {
  return toks[i]?.m ?? -1;
}

/** Index of the token opening the bracket closed at `i`, or -1. */
function matchOpen(toks: Tok[], i: number): number {
  return toks[i]?.m ?? -1;
}

function paramNames(toks: Tok[], open: number, close: number): string[] {
  const out: string[] = [];
  let depth = 0;
  let expectName = true;
  for (let j = open + 1; j < close; j++) {
    const t = toks[j].t;
    if (t === '(' || t === '[' || t === '{') depth++;
    else if (t === ')' || t === ']' || t === '}') depth--;
    else if (depth === 0 && t === ',') { expectName = true; continue; }
    if (depth === 0 && expectName && isIdent(t) && t !== 'this') { out.push(t); expectName = false; }
    else if (depth === 0 && t !== '...') expectName = false;
  }
  return out;
}

/** The name a function expression or arrow is bound to (`const f = …`, `f: …`), or null. */
function boundName(toks: Tok[], start: number): string | null {
  let k = start - 1;
  if (toks[k]?.t === 'async') k--;
  if (toks[k]?.t === '=' || toks[k]?.t === ':') return isIdent(toks[k - 1]?.t) ? toks[k - 1].t : null;
  return null;
}

export function findFunctions(toks: Tok[]): Fn[] {
  const fns: Fn[] = [];
  for (let i = 0; i < toks.length; i++) {
    if (toks[i].t !== '{') continue;
    const prev = toks[i - 1]?.t;
    let fn: Fn | null = null;
    if (prev === '=>') {
      const close = matchClose(toks, i);
      if (close < 0) continue;
      let start = i - 2;
      let params: string[] = [];
      if (toks[start]?.t === ')') {
        const po = matchOpen(toks, start);
        if (po < 0) continue;
        params = paramNames(toks, po, start);
        start = po;
      } else if (isIdent(toks[start]?.t)) {
        params = [toks[start].t];
      }
      fn = { name: boundName(toks, start), open: i, close, params };
    } else if (prev === ')') {
      const pc = i - 1;
      const po = matchOpen(toks, pc);
      if (po < 1) continue;
      const before = toks[po - 1].t;
      const close = matchClose(toks, i);
      if (close < 0) continue;
      const params = paramNames(toks, po, pc);
      if (before === 'function') {
        fn = { name: boundName(toks, po - 1), open: i, close, params };
      } else if (isIdent(before)) {
        const kw = toks[po - 2]?.t;
        if (kw === 'function') fn = { name: before, open: i, close, params };
        else if (kw !== '.' && kw !== 'new') fn = { name: before, open: i, close, params }; // method shorthand
      }
    }
    if (!fn && prev !== undefined && prev !== '=>' && prev !== ')') {
      // TypeScript return type: `function f(a: T): R {` / `m(a): Promise<R> {` / `): void {`.
      for (let j = i - 1; j > Math.max(0, i - 16); j--) {
        if (toks[j].t === ':' && toks[j - 1]?.t === ')') {
          const pc = j - 1;
          const po = matchOpen(toks, pc);
          if (po < 1) break;
          const before = toks[po - 1].t;
          const close = matchClose(toks, i);
          if (close < 0) break;
          const params = paramNames(toks, po, pc);
          if (before === 'function') fn = { name: boundName(toks, po - 1), open: i, close, params };
          else if (isIdent(before) && toks[po - 2]?.t !== '.') fn = { name: before, open: i, close, params };
          break;
        }
        if (toks[j].t === '{' || toks[j].t === '}' || toks[j].t === ';') break;
      }
    }
    if (fn) fns.push(fn);
  }
  return fns;
}

/** End index (exclusive) of a member chain `a.b.c` starting at `i`; returns the chain text too. */
function chainAt(toks: Tok[], i: number): { text: string; end: number } | null {
  if (!isIdent(toks[i]?.t) && toks[i]?.t !== 'this') return null;
  let text = toks[i].t;
  let j = i + 1;
  while ((toks[j]?.t === '.' || toks[j]?.t === '?.') && isIdent(toks[j + 1]?.t)) {
    text += '.' + toks[j + 1].t;
    j += 2;
  }
  return { text, end: j };
}

/** Is `toks[j]` the plain assignment operator (not `==`, `===`, `=>`)? */
function isAssign(t: string | undefined): boolean {
  return t === '=' || t === '||=' || t === '??=' || t === '&&=';
}

function lineOf(code: string, pos: number): number {
  let line = 1;
  for (let i = code.lastIndexOf('\n', pos - 1); i >= 0; i = code.lastIndexOf('\n', i - 1)) line++;
  return line;
}

/** True when the raw text of a range names a prototype key, or the key goes through a checking function. */
function hasGuard(raw: string, toks: Tok[], from: number, to: number, keys: ReadonlySet<string>): boolean {
  if (raw.includes('__proto__') || raw.includes('constructor') || raw.includes('prototype')) return true;
  for (let j = from; j < to; j++) {
    const t = toks[j].t;
    if (!isIdent(t) || toks[j + 1]?.t !== '(') continue;
    const lower = t.toLowerCase();
    // A set / list membership test on the key (`BLOCKED.has(k)`, `ALLOWED.includes(k)`) is a key check.
    const membership = toks[j - 1]?.t === '.' && (t === 'has' || t === 'includes' || t === 'indexOf');
    if (!membership && !GUARD_NAME_WORDS.some((w) => lower.includes(w))) continue;
    const close = matchClose(toks, j + 1);
    for (let k = j + 2; k < close; k++) if (keys.has(toks[k].t)) return true;
  }
  return false;
}

/** Names written as `X = Object.create(null)` in a range. */
function nullProtoNames(toks: Tok[], from: number, to: number): Set<string> {
  const out = new Set<string>();
  for (let j = from; j + 6 < to; j++) {
    if (toks[j + 1].t === '=' && isIdent(toks[j].t) && toks[j + 2].t === 'Object' && toks[j + 3].t === '.' &&
        toks[j + 4].t === 'create' && toks[j + 5].t === '(' && toks[j + 6].t === 'null') out.add(toks[j].t);
  }
  return out;
}

interface KeyLoop { key: string; source: string }

/** Loop variables bound to the keys of an object inside `[from, to)`. */
function keyLoops(toks: Tok[], from: number, to: number): KeyLoop[] {
  const out: KeyLoop[] = [];
  for (let j = from; j < to; j++) {
    const t = toks[j].t;
    if (t === 'for' && toks[j + 1]?.t === '(') {
      let k = j + 2;
      if (toks[k]?.t === 'const' || toks[k]?.t === 'let' || toks[k]?.t === 'var') k++;
      let key: string | null = null;
      if (isIdent(toks[k]?.t)) { key = toks[k].t; k++; }
      else if (toks[k]?.t === '[' && isIdent(toks[k + 1]?.t)) { key = toks[k + 1].t; const c = matchClose(toks, k); if (c < 0) continue; k = c + 1; }
      if (!key) continue;
      if (toks[k]?.t === 'in') {
        const c = chainAt(toks, k + 1);
        if (c && toks[c.end]?.t === ')') out.push({ key, source: c.text });
      } else if (toks[k]?.t === 'of' && toks[k + 1]?.t === 'Object' && toks[k + 2]?.t === '.' &&
                 ['keys', 'entries', 'getOwnPropertyNames'].includes(toks[k + 3]?.t ?? '') && toks[k + 4]?.t === '(') {
        const c = chainAt(toks, k + 5);
        if (c && toks[c.end]?.t === ')') out.push({ key, source: c.text });
      }
    } else if (t === 'Object' && toks[j + 1]?.t === '.' && (toks[j + 2]?.t === 'keys' || toks[j + 2]?.t === 'entries') &&
               toks[j + 3]?.t === '(') {
      const c = chainAt(toks, j + 4);
      if (!c || toks[c.end]?.t !== ')') continue;
      let k = c.end + 1;
      if (toks[k]?.t !== '.' || toks[k + 1]?.t !== 'forEach' || toks[k + 2]?.t !== '(') continue;
      k += 3;
      if (toks[k]?.t === 'function') k++;
      if (toks[k]?.t === '(') k++;
      if (toks[k]?.t === '[') k++;
      if (isIdent(toks[k]?.t)) out.push({ key: toks[k].t, source: c.text });
    }
  }
  return out;
}

/** Text of the member chain that ends just before token `k` (`a.b` for `a.b[k]`), or null. */
function chainBefore(toks: Tok[], k: number): string | null {
  let j = k - 1;
  if (!isIdent(toks[j]?.t) && toks[j]?.t !== 'this') return null;
  const parts = [toks[j].t];
  while ((toks[j - 1]?.t === '.' || toks[j - 1]?.t === '?.') && (isIdent(toks[j - 2]?.t) || toks[j - 2]?.t === 'this')) {
    parts.unshift(toks[j - 2].t);
    j -= 2;
  }
  return parts.join('.');
}

/**
 * Shape 1: recursive merge. The function writes `target[key] = …` and recurses with
 * `target[key]` as an argument: with `key === '__proto__'` that argument is
 * `Object.prototype`, and the recursive call writes into it. A deep clone that
 * recurses only on the source (`clone(src[key])`) writes into fresh objects and is
 * not reported.
 */
function recursiveMerge(toks: Tok[], fn: Fn): Array<{ pos: number; target: string; key: string }> {
  if (!fn.name) return [];
  const out: Array<{ pos: number; target: string; key: string }> = [];
  for (const loop of keyLoops(toks, fn.open, fn.close)) {
    // Targets the function recurses into: `fn(…, target[key], …)`.
    const recursedTargets = new Set<string>();
    for (let j = fn.open + 1; j < fn.close; j++) {
      if (toks[j].t !== fn.name || toks[j + 1]?.t !== '(') continue;
      const prev = toks[j - 1]?.t;
      if (prev === 'function' || (prev === '.' && toks[j - 2]?.t !== 'this')) continue;
      const close = matchClose(toks, j + 1);
      for (let k = j + 2; k + 2 < close; k++) {
        if (toks[k].t === '[' && toks[k + 1].t === loop.key && toks[k + 2].t === ']') {
          const t = chainBefore(toks, k);
          if (t && t !== loop.source) recursedTargets.add(t);
        }
      }
    }
    if (recursedTargets.size === 0) continue;
    for (let j = fn.open + 1; j < fn.close; j++) {
      if (toks[j - 1]?.t === '.') continue;
      const c = chainAt(toks, j);
      if (!c) continue;
      const k = c.end;
      if (recursedTargets.has(c.text) && toks[k]?.t === '[' && toks[k + 1]?.t === loop.key && toks[k + 2]?.t === ']' &&
          isAssign(toks[k + 3]?.t)) {
        out.push({ pos: toks[j].pos, target: c.text, key: loop.key });
        break;
      }
    }
  }
  return out;
}

function isPathName(name: string): boolean {
  const lower = name.toLowerCase();
  return PATH_NAME_WORDS.some((w) => lower === w || lower.endsWith(w));
}

/**
 * Shape 2: set by path. The function holds a key path (`parts = path.split('.')`,
 * or a loop over a collection named like one), walks a cursor along it inside a
 * loop (`cur = cur[k]`, `cur = cur[k] || (cur[k] = {})`, or a `reduce((o, k) => …)`
 * callback writing `o[k] = o[k] || {}`), and writes `cur[k] = …` with a key taken
 * from the path. A cache or map filled with `m[k] = m[k] || {}` and never walked is
 * not a path walk; a write whose key does not come from the path is not reported.
 */
function setByPath(toks: Tok[], raw: string, base: number, fn: Fn): Array<{ pos: number; target: string; key: string }> {
  let hasLoop = false;
  let pathEvidence = false;
  /** Names that hold the path or one of its keys. */
  const pathNames = new Set<string>();
  for (let j = fn.open + 1; j < fn.close; j++) {
    const t = toks[j].t;
    if (t === 'for' || t === 'while' || t === 'forEach' || t === 'reduce') hasLoop = true;
    if (t === 'split' && toks[j - 1]?.t === '.' && toks[j + 1]?.t === '(') {
      const arg = toks[j + 2];
      let real = false;
      if (arg && arg.t === '"') {
        const q = raw[arg.pos - base];
        real = raw[arg.pos - base + 1] !== q; // not `split('')`
      } else if (arg && arg.t === '/') {
        real = true;
      }
      if (real) {
        pathEvidence = true;
        // `const parts = path.split('.')` — find the name the split is bound to.
        let k = j - 2;
        while (k > fn.open && (isIdent(toks[k]?.t) || toks[k]?.t === '.' || toks[k]?.t === ')' || toks[k]?.t === '(')) {
          if (toks[k].t === ')') { const o = matchOpen(toks, k); if (o < 0) break; k = o - 1; continue; }
          k--;
        }
        if (toks[k]?.t === '=' && isIdent(toks[k - 1]?.t)) pathNames.add(toks[k - 1].t);
      }
    }
    if (t === 'for' && toks[j + 1]?.t === '(') {
      const close = matchClose(toks, j + 1);
      for (let k = j + 2; k < close; k++) {
        if (toks[k].t === 'of' || toks[k].t === 'in') {
          const c = chainAt(toks, k + 1);
          const last = c ? c.text.split('.').pop() ?? '' : '';
          if (c && (isPathName(last) || pathNames.has(last))) {
            pathEvidence = true;
            if (isIdent(toks[k - 1]?.t)) pathNames.add(toks[k - 1].t);
          }
        }
      }
    }
    if ((t === 'forEach' || t === 'reduce') && toks[j - 1]?.t === '.') {
      const coll = toks[j - 2]?.t;
      const isSplit = toks[j - 2]?.t === ')' && toks[matchOpen(toks, j - 2) - 1]?.t === 'split';
      if ((isIdent(coll) && (isPathName(coll) || pathNames.has(coll))) || isSplit) {
        pathEvidence = true;
        // Callback parameters: `forEach((k) =>`, `reduce((o, k) =>`.
        let k = j + 2;
        if (toks[k]?.t === 'function') k++;
        if (toks[k]?.t === '(') {
          const c = matchClose(toks, k);
          for (const n of paramNames(toks, k, c)) pathNames.add(n);
        } else if (isIdent(toks[k]?.t)) {
          pathNames.add(toks[k].t);
        }
      }
    }
  }
  if (!hasLoop || !pathEvidence) return [];
  // Names derived from a path name: `const p = parts[i]`, `const last = parts.pop()`.
  for (let j = fn.open + 1; j < fn.close; j++) {
    if ((toks[j].t === 'const' || toks[j].t === 'let' || toks[j].t === 'var') && isIdent(toks[j + 1]?.t) && toks[j + 2]?.t === '=' &&
        pathNames.has(toks[j + 3]?.t ?? '') && (toks[j + 4]?.t === '[' || toks[j + 4]?.t === '.')) {
      pathNames.add(toks[j + 1].t);
    }
  }

  // Cursors: reassigned along the path (`x = x[k]`, `x = x[k] || …`), or the
  // accumulator of a `reduce((x, k) => …)` callback.
  const cursors = new Set<string>();
  for (let j = fn.open + 1; j < fn.close; j++) {
    const x = toks[j].t;
    if (x === 'reduce' && toks[j - 1]?.t === '.' && toks[j + 1]?.t === '(' && toks[j + 2]?.t === '(' && isIdent(toks[j + 3]?.t)) {
      cursors.add(toks[j + 3].t);
    }
    if (!isIdent(x) || toks[j - 1]?.t === '.') continue;
    if (toks[j + 1]?.t === '=' && toks[j + 2]?.t === x && toks[j + 3]?.t === '[') cursors.add(x);
  }
  const out: Array<{ pos: number; target: string; key: string }> = [];
  for (const x of cursors) {
    // A computed write through the cursor whose key comes from the path: `x[k] = …`.
    for (let j = fn.open + 1; j < fn.close; j++) {
      if (toks[j].t !== x || toks[j - 1]?.t === '.' || toks[j + 1]?.t !== '[') continue;
      const c = matchClose(toks, j + 1);
      if (c < 0 || !isAssign(toks[c + 1]?.t)) continue;
      let key: string | null = null;
      for (let k = j + 2; k < c; k++) if (pathNames.has(toks[k].t)) { key = toks[k].t; break; }
      if (!key) continue;
      out.push({ pos: toks[j].pos, target: x, key });
      break;
    }
  }
  return out;
}

/** Names bound from the HTTP request inside `[from, to)`: `const { a } = req.body`, `const a = req.query.x`. */
function requestNames(toks: Tok[], from: number, to: number): Set<string> {
  const out = new Set<string>();
  const isBag = (k: number): boolean =>
    REQUEST_ROOTS.has(toks[k]?.t ?? '') && toks[k + 1]?.t === '.' && REQUEST_BAGS.has(toks[k + 2]?.t ?? '');
  for (let j = from; j < to; j++) {
    const t = toks[j].t;
    if (t !== 'const' && t !== 'let' && t !== 'var') continue;
    if (toks[j + 1]?.t === '{') {
      const close = matchClose(toks, j + 1);
      if (close < 0 || toks[close + 1]?.t !== '=' || !isBag(close + 2)) continue;
      let depth = 0;
      for (let k = j + 2; k < close; k++) {
        const s = toks[k].t;
        if (s === '{' || s === '[') depth++;
        else if (s === '}' || s === ']') depth--;
        else if (depth === 0 && isIdent(s) && toks[k + 1]?.t !== ':') out.add(s);
      }
    } else if (isIdent(toks[j + 1]?.t) && toks[j + 2]?.t === '=' && isBag(j + 3)) {
      out.add(toks[j + 1].t);
    }
  }
  return out;
}

/** Is the bracket content `[k]` request-controlled? */
function requestKey(toks: Tok[], open: number, close: number, names: ReadonlySet<string>): string | null {
  if (close === open + 2 && names.has(toks[open + 1].t)) return toks[open + 1].t;
  const k = open + 1;
  if (REQUEST_ROOTS.has(toks[k]?.t ?? '') && toks[k + 1]?.t === '.' && REQUEST_BAGS.has(toks[k + 2]?.t ?? '') &&
      toks[k + 3]?.t === '.' && isIdent(toks[k + 4]?.t) && close === k + 5) {
    return `${toks[k].t}.${toks[k + 2].t}.${toks[k + 4].t}`;
  }
  return null;
}

/** Shape 3: `obj[a][b] = …` with both keys from the request. */
function requestKeys(toks: Tok[], fn: Fn): Array<{ pos: number; target: string; key: string }> {
  const names = requestNames(toks, fn.open, fn.close);
  const out: Array<{ pos: number; target: string; key: string }> = [];
  for (let j = fn.open + 1; j < fn.close; j++) {
    if (toks[j - 1]?.t === '.') continue;
    const c = chainAt(toks, j);
    if (!c || toks[c.end]?.t !== '[') continue;
    const c1 = matchClose(toks, c.end);
    if (c1 < 0 || toks[c1 + 1]?.t !== '[') continue;
    const c2 = matchClose(toks, c1 + 1);
    if (c2 < 0 || !isAssign(toks[c2 + 1]?.t)) continue;
    const k1 = requestKey(toks, c.end, c1, names);
    const k2 = requestKey(toks, c1 + 1, c2, names);
    if (k1 && k2) out.push({ pos: toks[j].pos, target: c.text, key: `${k1}, ${k2}` });
  }
  return out;
}

export function detectPrototypePollution(code: string): PrototypePollutionHit[] {
  if (code.length > MAX_CODE_LENGTH) return [];
  const masked = maskLiterals(code);
  const toks = tokenize(masked);
  const fns = findFunctions(toks);
  const fileNullProto = nullProtoNames(toks, 0, toks.length);
  const hits: PrototypePollutionHit[] = [];
  const seen = new Set<number>();

  for (const fn of fns) {
    const base = toks[fn.open].pos;
    const raw = code.slice(base, toks[fn.close].pos + 1);
    const found: Array<{ pos: number; target: string; key: string; shape: PrototypePollutionHit['shape'] }> = [];
    for (const h of recursiveMerge(toks, fn)) found.push({ ...h, shape: 'recursive-merge' });
    for (const h of setByPath(toks, raw, base, fn)) found.push({ ...h, shape: 'set-by-path' });
    for (const h of requestKeys(toks, fn)) found.push({ ...h, shape: 'request-keys' });
    if (found.length === 0) continue;
    const keys = new Set<string>();
    for (const h of found) for (const k of h.key.split(', ')) keys.add(k);
    if (hasGuard(raw, toks, fn.open, fn.close, keys)) continue;
    const nullProto = nullProtoNames(toks, fn.open, fn.close);
    for (const h of found) {
      const root = h.target.split('.')[0];
      if (nullProto.has(root) || fileNullProto.has(root)) continue;
      const line = lineOf(code, h.pos);
      if (seen.has(line)) continue;
      seen.add(line);
      hits.push({ line, shape: h.shape, target: h.target, key: h.key, fn: fn.name });
    }
  }
  return hits.sort((a, b) => a.line - b.line);
}

const MESSAGES: Record<PrototypePollutionHit['shape'], (h: PrototypePollutionHit) => string> = {
  'recursive-merge': (h) =>
    `Recursive merge${h.fn ? ` \`${h.fn}\`` : ''} copies every key into \`${h.target}\` without rejecting ` +
    '`__proto__`, `constructor` or `prototype`: a source object with a `__proto__` key (for example from ' +
    '`JSON.parse`) writes into `Object.prototype`.',
  'set-by-path': (h) =>
    `Set-by-path${h.fn ? ` \`${h.fn}\`` : ''} walks \`${h.target}\` along a key path without rejecting ` +
    '`__proto__`, `constructor` or `prototype`: a path such as `__proto__.isAdmin` writes into `Object.prototype`.',
  'request-keys': (h) =>
    `\`${h.target}[…][…]\` is written with keys from the request (${h.key}): \`__proto__\` as the first key ` +
    'writes the second key into `Object.prototype`.',
};

export class PrototypePollutionPass implements AnalysisPass<PrototypePollutionResult> {
  readonly name = 'prototype-pollution';
  readonly category = 'security' as const;

  run(ctx: PassContext): PrototypePollutionResult {
    const { language } = ctx;
    if (language !== 'javascript' && language !== 'typescript') return { findings: [] };
    const file = ctx.graph.ir.meta.file;
    const findings = detectPrototypePollution(ctx.code);
    for (const h of findings) {
      ctx.addFinding({
        id: `${this.name}-${file}-${h.line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1321',
        severity: h.shape === 'request-keys' ? 'high' : 'medium',
        level: h.shape === 'request-keys' ? 'error' : 'warning',
        message: MESSAGES[h.shape](h),
        file,
        line: h.line,
        fix:
          'Skip the keys `__proto__`, `constructor` and `prototype` before writing, or write into an object made ' +
          'with `Object.create(null)` or a `Map`.',
        evidence: { shape: h.shape, target: h.target, key: h.key, ...(h.fn ? { function: h.fn } : {}) },
      });
    }
    return { findings };
  }
}
