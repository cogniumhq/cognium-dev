/**
 * Where a Rust literal-equality guard credit ends (cognium-dev#293): the first
 * rebind or possible mutation of the guarded name after the guard.
 *
 * Works on masked text (comments and string bodies blanked) over the whole
 * credit region, not line by line, so a rustfmt-wrapped pattern or parameter
 * list is seen in one piece. When in doubt it reports a rebind: ending the
 * credit early only keeps a finding, never hides one.
 *
 * Ends the credit:
 *   - the left side of any `=` / `op=` that names it (`x = ..`, `let (x, _) = ..`,
 *     `if let W { f: x } = ..`, `(x, n) = ..`, `W { x, .. } = ..`, `*x = ..`),
 *     a bare `let x;`,
 *   - a `for … in` head or a match-arm head (`… =>`) that names it,
 *   - a nested `fn` or closure whose parameter list names it (any pattern),
 *   - `&mut x`, `write!(x, ..)`, `mem::swap/replace/take(.. x ..)`,
 *   - a method call `x.m(..)`: when the binding is `mut` (or `&mut`) any method
 *     outside a short read-only list; otherwise a known `&mut self` method.
 *
 * Known limits (not guard bugs; the engine does not carry these flows even
 * without a guard): a derived value mutated later
 * (`let mut c = String::from(x); c.push_str(other)`) and a struct field of
 * another value reassigned.
 */

/** `name` used as a bare identifier: not a field (`.x`), not a path segment (`a::x`, `x::b`). */
function bareRe(name: string): RegExp {
  return new RegExp(String.raw`(?<![\w.]|::)${name}\b(?!\s*::)`);
}

/** Index of the `{` matching the `}` at `close` (walking back), or -1. */
function openOf(m: string, close: number, floor: number): number {
  let d = 0;
  for (let i = close; i >= floor; i--) {
    if (m[i] === '}') d++;
    else if (m[i] === '{' && --d === 0) return i;
  }
  return -1;
}

/**
 * Start of the pattern / assignee that ends just before `idx` (an `=` or `=>`):
 * walks back to the previous `;`, `,`, `=>` or unmatched opener at depth 0.
 * A `{ … }` preceded by a type name (`W { .. }`) is a struct pattern and is
 * stepped over; any other `}` is the end of the previous statement or arm.
 */
function headStart(m: string, idx: number, floor: number): number {
  let depth = 0;
  for (let i = idx - 1; i >= floor; i--) {
    const ch = m[i];
    if (ch === ')' || ch === ']') depth++;
    else if (ch === '(' || ch === '[' || ch === '{') {
      if (depth === 0) return i + 1;
      depth--;
    } else if (ch === '}') {
      if (depth > 0) { depth++; continue; }
      const open = openOf(m, i, floor);
      if (open > floor && /(?:[A-Z]\w*|::)\s*$/.test(m.slice(Math.max(floor, open - 80), open))) { i = open; continue; }
      return i + 1;
    } else if (depth === 0 && (ch === ';' || ch === ',')) return i + 1;
    else if (depth === 0 && ch === '>' && m[i - 1] === '=') return i + 1;
  }
  return floor;
}

/** Index just past the `)`/`|` that closes the list opened at `open`, or -1. */
function closeParen(m: string, open: number, to: number): number {
  let d = 0;
  for (let i = open; i < to; i++) {
    if (m[i] === '(' || m[i] === '[' || m[i] === '{') d++;
    else if ((m[i] === ')' || m[i] === ']' || m[i] === '}') && --d === 0) return i + 1;
  }
  return -1;
}

/** True when the `=` at `i` is an assignment (`=`, `+=`, `<<=`, …), not `==`, `!=`, `<=`, `>=`, `=>`, `..=`. */
function isAssign(m: string, i: number): boolean {
  const next = m[i + 1];
  const prev = m[i - 1];
  if (next === '=' || next === '>') return false;
  if (prev === '=' || prev === '!' || prev === '.') return false;
  if (prev === '<' || prev === '>') return m[i - 2] === prev; // `<<=` / `>>=`
  return true;
}

/** `&self` methods on str / String / &str that never change the value. */
const READ_ONLY = new Set([
  'as_str', 'as_bytes', 'as_ref', 'as_os_str', 'as_path', 'as_deref', 'borrow', 'deref', 'len', 'is_empty',
  'to_string', 'to_owned', 'clone', 'into', 'chars', 'char_indices', 'bytes', 'lines', 'trim', 'trim_start',
  'trim_end', 'trim_matches', 'trim_start_matches', 'trim_end_matches', 'starts_with', 'ends_with', 'contains',
  'find', 'rfind', 'split', 'splitn', 'rsplit', 'rsplitn', 'split_whitespace', 'split_once', 'rsplit_once',
  'strip_prefix', 'strip_suffix', 'eq', 'ne', 'cmp', 'partial_cmp', 'eq_ignore_ascii_case', 'to_lowercase',
  'to_uppercase', 'to_ascii_lowercase', 'to_ascii_uppercase', 'replace', 'replacen', 'repeat', 'parse',
  'capacity', 'get', 'iter', 'is_char_boundary', 'matches', 'to_str', 'to_string_lossy', 'is_ascii',
]);

/** `&mut self` methods, used when the binding is not known to be `mut`. */
const MUTATORS = new Set([
  'push', 'push_str', 'clear', 'insert_str', 'insert', 'extend', 'extend_from_slice', 'truncate', 'remove',
  'retain', 'drain', 'replace_range', 'make_ascii_lowercase', 'make_ascii_uppercase', 'clone_from',
  'write_fmt', 'write_str', 'write_char', 'add_assign', 'pop', 'split_off', 'as_mut_str', 'as_mut_vec',
  'as_mut', 'get_mut', 'iter_mut', 'append', 'resize', 'reserve',
]);

export interface RebindOptions {
  /** The guarded binding is `mut x` or `x: &mut T`, so any non-read-only method may mutate it. */
  mutBinding: boolean;
}

/**
 * Absolute index (first non-space char of the statement or head) of the
 * earliest rebind or possible mutation of `name` in `m[from, to)`, or -1.
 */
export function firstRebind(m: string, from: number, to: number, name: string, opts: RebindOptions): number {
  const region = m.slice(from, to);
  const bare = bareRe(name);
  let best = -1;
  const hit = (abs: number) => {
    while (abs < to && /\s/.test(m[abs])) abs++;
    if (best < 0 || abs < best) best = abs;
  };
  const scan = (re: RegExp, f: (mm: RegExpExecArray) => void) => {
    for (const mm of region.matchAll(re)) f(mm as RegExpExecArray);
  };

  // Left side of an assignment, a `let` pattern, a destructuring assignment.
  for (let i = from; i < to; i++) {
    if (m[i] !== '=' || !isAssign(m, i)) continue;
    const hs = headStart(m, i, from);
    if (bare.test(m.slice(hs, i))) hit(hs);
  }
  scan(new RegExp(String.raw`\blet\s+(?:mut\s+)?${name}\s*(?::[^;=]*)?;`, 'g'), (mm) => hit(from + mm.index));
  // Match-arm heads.
  scan(/=>/g, (mm) => {
    const at = from + mm.index;
    const hs = headStart(m, at, from);
    if (bare.test(m.slice(hs, at))) hit(hs);
  });
  // `for PATTERN in`.
  scan(/\bfor\b(?!\s*<)([\s\S]*?)\bin\b/g, (mm) => { if (bare.test(mm[1])) hit(from + mm.index); });
  // Nested fn parameter lists (any pattern, any number of lines).
  scan(/\bfn\s+\w+\s*/g, (mm) => {
    let i = from + mm.index + mm[0].length;
    if (m[i] === '<') {
      let d = 0;
      for (; i < to; i++) {
        if (m[i] === '<') d++;
        else if (m[i] === '>' && m[i - 1] !== '-' && --d === 0) { i++; break; }
      }
      while (i < to && /\s/.test(m[i])) i++;
    }
    if (m[i] !== '(') return;
    const end = closeParen(m, i, to);
    if (bare.test(m.slice(i, end < 0 ? to : end))) hit(from + mm.index);
  });
  // Closure parameter lists `|…|` (opening bar in expression position).
  scan(/(?:^|[(,=>{;]|\bmove)\s*\|/gm, (mm) => {
    const open = from + mm.index + mm[0].length - 1;
    const close = m.indexOf('|', open + 1);
    if (close < 0 || close >= to) return;
    const params = m.slice(open + 1, close);
    if (!params.includes(';') && bare.test(params)) hit(open);
  });
  // `&mut x`, `write!(x, ..)`, `mem::swap/replace/take(.. x ..)`.
  scan(new RegExp(String.raw`&\s*mut\s+${name}\b`, 'g'), (mm) => hit(from + mm.index));
  scan(new RegExp(String.raw`\b(?:write|writeln)\s*!\s*\(\s*${name}\b`, 'g'), (mm) => hit(from + mm.index));
  scan(new RegExp(String.raw`\bmem\s*::\s*(?:swap|replace|take)\s*\([^;]*?\b${name}\b`, 'g'), (mm) => hit(from + mm.index));
  // Method calls on the name, including a call on the next line (`x\n.write_str(..)`).
  scan(new RegExp(String.raw`(?<![\w.]|::)${name}\s*\.\s*(\w+)\s*(?:::\s*<[^>]*>\s*)?\(`, 'g'), (mm) => {
    const method = mm[1];
    if (opts.mutBinding ? !READ_ONLY.has(method) : MUTATORS.has(method)) hit(from + mm.index);
  });
  return best;
}
