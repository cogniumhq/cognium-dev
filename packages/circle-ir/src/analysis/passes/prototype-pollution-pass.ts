/**
 * Pass: prototype-pollution (CWE-1321, category: security)
 *
 * Pattern pass for JavaScript / TypeScript. Four shapes write an
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
 *      or `req.body.x` written in the brackets);
 *   4. browser keys — the same write with keys from browser input: the page
 *      URL (`location.search` / `.hash` / `.href` / `.pathname`,
 *      `document.URL`, the referrer) through `URLSearchParams` / `URL`
 *      getters, slicing, splitting, decoding and `JSON.parse`, or the `data`
 *      of a window `message` event.
 *
 * Shapes 3 and 4 also match a write through an alias of the first level
 * (`const bucket = obj[a] || (obj[a] = {}); bucket[b] = …`) and module
 * top-level code. A recursive merge (shape 1) that a same-file call hands
 * request or browser input, as the object it copies from, is reported at
 * `high` with that call's line.
 *
 * Precision (abstain rather than guess):
 *   - The function (shapes 1 and 2) or handler (shapes 3 and 4) mentions
 *     `__proto__`, `constructor` or `prototype` in a string literal or as
 *     a name, or passes the key to a function whose name says it checks
 *     the key (`isSafeKey(k)`, `isPrototypeKey(k)`, `assertAllowed(k)`), to
 *     `Object.hasOwn` or to a membership test: that is the guard.
 *   - A browser key that went through any call other than slicing, decoding
 *     or parsing (`cleanKey(k)`), or was looked up in another object
 *     (`TABLE[k]`), is not input; a WebSocket or worker `message` event is
 *     the app's own data.
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
  shape: 'recursive-merge' | 'set-by-path' | 'request-keys' | 'browser-keys';
  target: string;
  key: string;
  fn: string | null;
  /** Recursive merge only: the line of a same-file call that passes it request or browser input. */
  inputLine?: number;
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
  // `Object.hasOwn(target, k)`: only keys the object already owns are written.
  'hasown',
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
function recursiveMerge(toks: Tok[], fn: Fn): Array<{ pos: number; target: string; key: string; source: string }> {
  if (!fn.name) return [];
  const out: Array<{ pos: number; target: string; key: string; source: string }> = [];
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
        out.push({ pos: toks[j].pos, target: c.text, key: loop.key, source: loop.source });
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

/**
 * Browser input read as a member chain: the page URL (`location.search`,
 * `.hash`, `.href`, `.pathname`, with or without `window.` / `document.`),
 * `document.URL` / `documentURI` / `baseURI` and the referrer.
 */
const BROWSER_CHAIN =
  /^(?:(?:window|document|self|globalThis|top|parent)\.)?location\.(?:search|hash|href|pathname)(?:\.|$)|^(?:window\.)?document\.(?:URL|documentURI|baseURI|referrer)(?:\.|$)/;

/**
 * Calls whose result still carries the input they are given: string slicing
 * and decoding, `JSON.parse`, `URLSearchParams` / `URL` and their getters,
 * key and entry lists. Any other call (`sanitizeKey(k)`, `lookup(k)`, a
 * `replace` that may strip the underscores) ends the input, and so does a
 * method of an object that is not itself input (`cache.get(k)` reads what
 * the program stored).
 */
const CARRIER_CALLS: ReadonlySet<string> = new Set([
  'get', 'getAll', 'slice', 'substring', 'substr', 'split', 'trim', 'trimStart', 'trimEnd', 'toLowerCase',
  'toUpperCase', 'at', 'pop', 'shift', 'concat', 'decodeURIComponent', 'decodeURI',
  'parse', 'String', 'atob', 'URLSearchParams', 'URL', 'fromEntries', 'entries', 'values', 'keys', 'from',
]);

/** Receivers whose methods are plain functions of their arguments (`JSON.parse(x)`, `Object.keys(x)`). */
const NAMESPACE_RECEIVERS: ReadonlySet<string> = new Set(['JSON', 'Object', 'Array', 'String', 'window', 'globalThis', 'self']);

/** Names bound to browser input in one scope, and the parameters that hold a `message` event. */
interface BrowserScope {
  names: Set<string>;
  messageParams: Set<string>;
}

function isBrowserChain(text: string, scope: BrowserScope): boolean {
  if (BROWSER_CHAIN.test(text)) return true;
  const dot = text.indexOf('.');
  return dot > 0 && text.startsWith('data', dot + 1) && scope.messageParams.has(text.slice(0, dot)) &&
    (text.length === dot + 5 || text[dot + 5] === '.');
}

/**
 * Does `[from, to)` carry browser input? It must read browser input (a
 * browser chain or a bound name) and call nothing but carrier functions; a
 * lookup in another object (`TABLE[k]`) reads what the program wrote, so its
 * key does not count, and a function literal is not a value read.
 */
function carriesBrowserInput(toks: Tok[], from: number, to: number, scope: BrowserScope): boolean {
  let reads = false;
  for (let j = from; j < to; j++) {
    const t = toks[j].t;
    if (t === 'function' || t === '=>' || t === 'class') return false;
    if (t === '[') {
      const before = chainBefore(toks, j);
      const root = before?.split('.')[0] ?? '';
      if (!before || !(scope.names.has(root) || isBrowserChain(before, scope))) {
        const c = matchClose(toks, j);
        if (c > j) j = c;
      }
      continue;
    }
    if (!isIdent(t)) continue;
    const afterDot = toks[j - 1]?.t === '.' || toks[j - 1]?.t === '?.';
    if (toks[j + 1]?.t === '(') {
      if (!CARRIER_CALLS.has(t)) return false;
      // A method carries input only from an input receiver; a call result (`).split(`) was checked already.
      const receiver = afterDot ? chainBefore(toks, j - 1) : null;
      if (receiver && !NAMESPACE_RECEIVERS.has(receiver) && !scope.names.has(receiver.split('.')[0]) &&
          !isBrowserChain(receiver, scope)) return false;
    }
    if (afterDot) continue;
    if (scope.names.has(t)) { reads = true; continue; }
    const c = chainAt(toks, j);
    if (c && isBrowserChain(c.text, scope)) reads = true;
  }
  return reads;
}

/** End (exclusive) of the expression starting at `start`: `;`, `,` or an unmatched closer at depth 0, or a new statement line. */
function expressionEnd(toks: Tok[], start: number, limit: number, lines: number[]): number {
  let depth = 0;
  for (let j = start; j < limit; j++) {
    const t = toks[j].t;
    if (t === '(' || t === '[' || t === '{') depth++;
    else if (t === ')' || t === ']' || t === '}') { if (depth === 0) return j; depth--; }
    else if (depth === 0 && (t === ';' || t === ',')) return j;
    else if (depth === 0 && j > start && lines[j] !== lines[j - 1]) {
      const prev = toks[j - 1].t;
      const continues = t === '.' || t === '?.' || t === '?' || t === ':' || t === '||' || t === '&&' || t === '??' ||
        t === '+' || t === '(' || t === '[' || prev === '=' || prev === '(' || prev === ',' || prev === '+' ||
        prev === '||' || prev === '&&' || prev === '??' || prev === '?' || prev === ':' || prev === '=>';
      if (!continues) return j;
    }
  }
  return limit;
}

/** The names a declaration pattern at `[open, close]` (`{ a, b: c }` or `[a, b]`) binds. */
function patternNames(toks: Tok[], open: number, close: number): string[] {
  const out: string[] = [];
  let depth = 0;
  for (let k = open + 1; k < close; k++) {
    const s = toks[k].t;
    if (s === '{' || s === '[' || s === '(') depth++;
    else if (s === '}' || s === ']' || s === ')') depth--;
    else if (depth === 0 && isIdent(s) && toks[k + 1]?.t !== ':' && toks[k - 1]?.t !== '=' && toks[k - 1]?.t !== '.') out.push(s);
  }
  return out;
}

/**
 * Fill `scope.names` with the names bound to browser input in `[from, to)`
 * (`const p = new URLSearchParams(location.search)`, `const k = p.get('k')`,
 * `const { a, b } = JSON.parse(event.data)`, `[a, b] = location.hash.split('/')`).
 * A name bound again to anything else leaves the set. `skip` masks token
 * ranges that belong to another scope.
 */
function bindBrowserNames(toks: Tok[], from: number, to: number, lines: number[], scope: BrowserScope, skip?: (j: number) => boolean): void {
  for (let pass = 0; pass < 2; pass++) {
    for (let j = from; j < to; j++) {
      if (skip?.(j)) continue;
      const t = toks[j].t;
      let names: string[] = [];
      let rhs = -1;
      if (t === 'const' || t === 'let' || t === 'var') {
        const k = j + 1;
        if ((toks[k]?.t === '{' || toks[k]?.t === '[') && toks[matchClose(toks, k) + 1]?.t === '=') {
          const c = matchClose(toks, k);
          names = patternNames(toks, k, c);
          rhs = c + 2;
        } else if (isIdent(toks[k]?.t)) {
          let e = k + 1;
          if (toks[e]?.t === ':') { while (e < to && toks[e].t !== '=' && toks[e].t !== ';') e++; }
          if (toks[e]?.t === '=') { names = [toks[k].t]; rhs = e + 1; }
        }
      } else if (isIdent(t) && toks[j + 1]?.t === '=' && toks[j - 1]?.t !== '.' && toks[j - 1]?.t !== '?.') {
        names = [t];
        rhs = j + 2;
      }
      if (rhs < 0 || names.length === 0) continue;
      const end = expressionEnd(toks, rhs, to, lines);
      // The last binding in the scope decides: `k = normalizeKey(k)` ends the input.
      const carries = carriesBrowserInput(toks, rhs, end, scope);
      for (const n of names) {
        if (carries) scope.names.add(n);
        else if (scope.names.has(n)) scope.names = new Set([...scope.names].filter((x) => x !== n));
      }
    }
  }
}

const WINDOW_NAMES: ReadonlySet<string> = new Set(['window', 'self', 'globalThis', 'top', 'parent']);

/** Cheap pre-checks: a browser chain root in the code (strings masked), or a `message` event name. */
const BROWSER_INPUT_HINT = /\blocation\b|\bdocument\s*\.\s*(?:URL|documentURI|baseURI|referrer)\b/;
const MESSAGE_EVENT_HINT = /\bonmessage\b|['"`]message['"`]/;

/** First parameter of every function that handles a `message` event (`addEventListener('message', fn)`, `onmessage = fn`). */
function messageHandlerParams(toks: Tok[], code: string, fns: Fn[]): Map<Fn, string> {
  const out = new Map<Fn, string>();
  const firstFnAfter = (k: number, limit: number): Fn | undefined => {
    let best: Fn | undefined;
    for (const f of fns) if (f.open > k && f.open < limit && (!best || f.open < best.open)) best = f;
    return best;
  };
  for (let j = 0; j < toks.length; j++) {
    const t = toks[j].t;
    let fn: Fn | undefined;
    // Only the window's own `message` event: a WebSocket or worker port carries the app's own data.
    const onWindow = toks[j - 1]?.t !== '.' || WINDOW_NAMES.has(toks[j - 2]?.t ?? '');
    if (!onWindow) continue;
    if (t === 'addEventListener' && toks[j + 1]?.t === '(' && toks[j + 2]?.t === '"' && toks[j + 3]?.t === ',') {
      const lit = code.slice(toks[j + 2].pos + 1, toks[j + 2].pos + 8);
      if (lit !== 'message' || !/^['"`]/.test(code[toks[j + 2].pos + 8] ?? '')) continue;
      const close = matchClose(toks, j + 1);
      const arg = toks[j + 4];
      if (arg && isIdent(arg.t) && (toks[j + 5]?.t === ')' || toks[j + 5]?.t === ',')) fn = fns.find((f) => f.name === arg.t);
      else fn = firstFnAfter(j + 3, close < 0 ? toks.length : close);
    } else if (t === 'onmessage' && toks[j + 1]?.t === '=') {
      const end = toks.findIndex((x, k) => k > j + 1 && (x.t === ';' || x.t === '}'));
      fn = firstFnAfter(j + 1, end < 0 ? toks.length : end + 1);
    }
    if (fn && fn.params.length > 0) out.set(fn, fn.params[0]);
  }
  return out;
}

/**
 * Shapes 3 and 4: `obj[a][b] = …` with both keys from the request (shape 3)
 * or from browser input (shape 4), written directly or through an alias of
 * `obj[a]` (`const bucket = obj[a] || (obj[a] = {}); bucket[b] = …`).
 */
function nestedKeyWrites(
  toks: Tok[], fn: Fn, lines: number[], browser: BrowserScope, skip?: (j: number) => boolean,
): Array<{ pos: number; target: string; key: string; shape: 'request-keys' | 'browser-keys' }> {
  const request = requestNames(toks, Math.max(0, fn.open), fn.close);
  const keyAt = (open: number, close: number): { text: string; browser: boolean } | null => {
    const r = requestKey(toks, open, close, request);
    if (r) return { text: r, browser: false };
    if (close > open + 1 && carriesBrowserInput(toks, open + 1, close, browser)) {
      return { text: toks.slice(open + 1, close).map((x) => x.t).join('').replace(/"/g, '…'), browser: true };
    }
    return null;
  };
  const out: Array<{ pos: number; target: string; key: string; shape: 'request-keys' | 'browser-keys' }> = [];
  const push = (pos: number, target: string, k1: { text: string; browser: boolean }, k2: { text: string; browser: boolean }): void => {
    out.push({ pos, target, key: `${k1.text}, ${k2.text}`, shape: k1.browser || k2.browser ? 'browser-keys' : 'request-keys' });
  };
  /** `alias → (target, first key)` for `const alias = target[k1] …`. */
  const aliases = new Map<string, { target: string; key: { text: string; browser: boolean } }>();
  for (let j = fn.open + 1; j < fn.close; j++) {
    if (skip?.(j)) continue;
    if ((toks[j].t === 'const' || toks[j].t === 'let' || toks[j].t === 'var') && isIdent(toks[j + 1]?.t) && toks[j + 2]?.t === '=') {
      let k = j + 3;
      if (toks[k]?.t === '(') k++;
      const c = chainAt(toks, k);
      if (c && toks[c.end]?.t === '[') {
        const close = matchClose(toks, c.end);
        const after = toks[close + 1]?.t;
        const key = close > 0 ? keyAt(c.end, close) : null;
        if (key && after !== '.' && after !== '?.' && after !== '[' && after !== '(') aliases.set(toks[j + 1].t, { target: c.text, key });
      }
      continue;
    }
    if (toks[j - 1]?.t === '.') continue;
    const c = chainAt(toks, j);
    if (!c || toks[c.end]?.t !== '[') continue;
    const c1 = matchClose(toks, c.end);
    if (c1 < 0) continue;
    const alias = aliases.get(c.text);
    if (alias && isAssign(toks[c1 + 1]?.t)) {
      const k2 = keyAt(c.end, c1);
      if (k2) push(toks[j].pos, alias.target, alias.key, k2);
      continue;
    }
    if (toks[c1 + 1]?.t !== '[') continue;
    const c2 = matchClose(toks, c1 + 1);
    if (c2 < 0 || !isAssign(toks[c2 + 1]?.t)) continue;
    const k1 = keyAt(c.end, c1);
    const k2 = k1 ? keyAt(c1 + 1, c2) : null;
    if (k1 && k2) push(toks[j].pos, c.text, k1, k2);
  }
  return out;
}

/**
 * The first line of a same-file call to the merge function `name`, outside its
 * own body, that passes request or browser input as the object it copies from
 * (argument `sourceIndex`; any argument when that is not a parameter).
 */
function mergeInputLine(
  toks: Tok[], name: string, own: Fn, sourceIndex: number, scopeAt: (j: number) => BrowserScope, lines: number[],
): number | undefined {
  for (let j = 0; j < toks.length; j++) {
    if (toks[j].t !== name || toks[j + 1]?.t !== '(' || (j >= own.open && j <= own.close)) continue;
    const prev = toks[j - 1]?.t;
    if (prev === 'function' || (prev === '.' && toks[j - 2]?.t !== 'this')) continue;
    const close = matchClose(toks, j + 1);
    // A declaration (`merge(a, b) {`, `merge(a: T): T {`) is not a call.
    if (close < 0 || toks[close + 1]?.t === '{' || toks[close + 1]?.t === ':') continue;
    const scope = scopeAt(j);
    let argStart = j + 2;
    let argIndex = 0;
    let depth = 0;
    for (let k = j + 2; k <= close; k++) {
      const t = toks[k].t;
      if (t === '(' || t === '[' || t === '{') depth++;
      else if ((t === ')' || t === ']' || t === '}') && k < close) depth--;
      if (k === close || (depth === 0 && t === ',')) {
        const wanted = sourceIndex < 0 || argIndex === sourceIndex;
        argIndex++;
        if (!wanted) { argStart = k + 1; continue; }
        const isRequest = REQUEST_ROOTS.has(toks[argStart].t) && toks[argStart + 1]?.t === '.' &&
          REQUEST_BAGS.has(toks[argStart + 2]?.t ?? '');
        if (k > argStart && (isRequest || carriesBrowserInput(toks, argStart, k, scope))) {
          return lines[j];
        }
        argStart = k + 1;
      }
    }
  }
  return undefined;
}

export function detectPrototypePollution(code: string): PrototypePollutionHit[] {
  if (code.length > MAX_CODE_LENGTH) return [];
  const masked = maskLiterals(code);
  const toks = tokenize(masked);
  const fns = findFunctions(toks);
  const fileNullProto = nullProtoNames(toks, 0, toks.length);
  const hits: PrototypePollutionHit[] = [];
  const seen = new Set<number>();

  // 1-based line of every token.
  const lines: number[] = new Array<number>(toks.length);
  {
    let line = 1;
    let at = 0;
    for (let j = 0; j < toks.length; j++) {
      for (; at < toks[j].pos; at++) if (code.charCodeAt(at) === 10) line++;
      lines[j] = line;
    }
  }
  // Browser input: names bound at the top level are visible in every function;
  // a function adds its own bindings and the `message` event it handles. A
  // file that names no browser input skips all of it.
  const browserInput = BROWSER_INPUT_HINT.test(masked) || MESSAGE_EVENT_HINT.test(code);
  const inFunction = new Uint8Array(browserInput ? toks.length : 0);
  if (browserInput) for (const fn of fns) for (let j = fn.open; j <= fn.close; j++) inFunction[j] = 1;
  const topLevel: BrowserScope = { names: new Set(), messageParams: new Set() };
  const scopes = new Map<Fn, BrowserScope>();
  if (browserInput) {
    bindBrowserNames(toks, 0, toks.length, lines, topLevel, (j) => inFunction[j] === 1);
    const handlers = messageHandlerParams(toks, code, fns);
    for (const fn of fns) {
      const scope: BrowserScope = { names: new Set(topLevel.names), messageParams: new Set() };
      for (const [h, p] of handlers) if (h.open <= fn.open && fn.close <= h.close) scope.messageParams.add(p);
      bindBrowserNames(toks, fn.open + 1, fn.close, lines, scope);
      scopes.set(fn, scope);
    }
  } else {
    for (const fn of fns) scopes.set(fn, topLevel);
  }
  const scopeAt = (j: number): BrowserScope => {
    let best: Fn | undefined;
    for (const fn of fns) if (fn.open < j && j < fn.close && (!best || fn.open > best.open)) best = fn;
    return best ? scopes.get(best)! : topLevel;
  };

  // The top level is one more scope; a write inside a function belongs to that function.
  const top: Fn = { name: null, open: -1, close: toks.length, params: [] };
  for (const fn of browserInput ? [...fns, top] : fns) {
    const isTop = fn === top;
    const base = isTop ? 0 : toks[fn.open].pos;
    const raw = isTop ? code : code.slice(base, toks[fn.close].pos + 1);
    const found: Array<{ pos: number; target: string; key: string; shape: PrototypePollutionHit['shape']; source?: string }> = [];
    if (!isTop) {
      for (const h of recursiveMerge(toks, fn)) found.push({ ...h, shape: 'recursive-merge' });
      for (const h of setByPath(toks, raw, base, fn)) found.push({ ...h, shape: 'set-by-path' });
    }
    const browser = isTop ? topLevel : scopes.get(fn)!;
    for (const h of nestedKeyWrites(toks, fn, lines, browser, isTop ? (j) => inFunction[j] === 1 : undefined)) found.push(h);
    if (found.length === 0) continue;
    const keys = new Set<string>();
    for (const h of found) {
      for (const k of h.key.split(', ')) {
        // A browser key may be an expression (`state.section`); a check on any name in it counts.
        if (h.shape === 'browser-keys') { for (const part of k.split(/[^\w$]+/)) if (part) keys.add(part); }
        else keys.add(k);
      }
    }
    if (hasGuard(raw, toks, Math.max(0, fn.open), Math.min(toks.length, fn.close), keys)) continue;
    const nullProto = isTop ? fileNullProto : nullProtoNames(toks, fn.open, fn.close);
    for (const h of found) {
      const root = h.target.split('.')[0];
      if (nullProto.has(root) || fileNullProto.has(root)) continue;
      const line = lineOf(code, h.pos);
      if (seen.has(line)) continue;
      seen.add(line);
      const hit: PrototypePollutionHit = { line, shape: h.shape, target: h.target, key: h.key, fn: fn.name };
      if (h.shape === 'recursive-merge' && fn.name) {
        const inputLine = mergeInputLine(toks, fn.name, fn, fn.params.indexOf(h.source ?? ''), scopeAt, lines);
        if (inputLine !== undefined) hit.inputLine = inputLine;
      }
      hits.push(hit);
    }
  }
  return hits.sort((a, b) => a.line - b.line);
}

const MESSAGES: Record<PrototypePollutionHit['shape'], (h: PrototypePollutionHit) => string> = {
  'recursive-merge': (h) =>
    `Recursive merge${h.fn ? ` \`${h.fn}\`` : ''} copies every key into \`${h.target}\` without rejecting ` +
    '`__proto__`, `constructor` or `prototype`: a source object with a `__proto__` key (for example from ' +
    '`JSON.parse`) writes into `Object.prototype`.' +
    (h.inputLine !== undefined ? ` It is called with request or browser input on line ${h.inputLine}.` : ''),
  'set-by-path': (h) =>
    `Set-by-path${h.fn ? ` \`${h.fn}\`` : ''} walks \`${h.target}\` along a key path without rejecting ` +
    '`__proto__`, `constructor` or `prototype`: a path such as `__proto__.isAdmin` writes into `Object.prototype`.',
  'request-keys': (h) =>
    `\`${h.target}[…][…]\` is written with keys from the request (${h.key}): \`__proto__\` as the first key ` +
    'writes the second key into `Object.prototype`.',
  'browser-keys': (h) =>
    `\`${h.target}[…][…]\` is written with keys from browser input (${h.key}): \`__proto__\` as the first key ` +
    'writes the second key into `Object.prototype`.',
};

/** The keys come from the request or browser input, or the merge is called with it. */
function isUntrustedInput(h: PrototypePollutionHit): boolean {
  return h.shape === 'request-keys' || h.shape === 'browser-keys' || h.inputLine !== undefined;
}

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
        severity: isUntrustedInput(h) ? 'high' : 'medium',
        level: isUntrustedInput(h) ? 'error' : 'warning',
        message: MESSAGES[h.shape](h),
        file,
        line: h.line,
        fix:
          'Skip the keys `__proto__`, `constructor` and `prototype` before writing, or write into an object made ' +
          'with `Object.create(null)` or a `Map`.',
        evidence: {
          shape: h.shape, target: h.target, key: h.key,
          ...(h.fn ? { function: h.fn } : {}),
          ...(h.inputLine !== undefined ? { inputLine: h.inputLine } : {}),
        },
      });
    }
    return { findings };
  }
}
