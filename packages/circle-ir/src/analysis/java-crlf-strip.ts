/**
 * Which of CR / LF a Java `String.replace` / `replaceAll` call strips as a
 * match of its own (cognium-dev#562 / #605).
 *
 * Shared by the inline-chain credit (`taint-matcher.ts`) and the helper-body
 * credit (`language-sources-pass.ts`), so a pattern is judged the same way
 * wherever it appears.
 *
 * The literal is first decoded from Java source (`"\\r"` and `"\r"` both
 * become a CR atom for the regex engine, `"\\\\r"` becomes a literal
 * backslash followed by `r`), then the regex is read one atom at a time.
 */

/** Decode the escape sequences of the body of a Java string / char literal. */
export function decodeJavaLiteral(raw: string): string {
  return raw.replace(/\\(?:u+([0-9a-fA-F]{4})|([0-3][0-7]{0,2}|[4-7][0-7]?)|([btnfrs"'\\]))/g, (_m, hex, oct, simple) => {
    if (hex !== undefined) return String.fromCharCode(parseInt(hex, 16));
    if (oct !== undefined) return String.fromCharCode(parseInt(oct, 8));
    switch (simple) {
      case 'b': return '\b';
      case 't': return '\t';
      case 'n': return '\n';
      case 'f': return '\f';
      case 'r': return '\r';
      case 's': return ' ';
      default: return simple as string;
    }
  });
}

type Atom = 'cr' | 'lf' | 'other';

/** One regex atom at `i`: an escape (`\r`, `\n`, `\\`, `\t`…) or a single character. */
function readAtom(s: string, i: number): { atom: Atom; end: number } {
  const c = s[i]!;
  if (c === '\\' && i + 1 < s.length) {
    const n = s[i + 1]!;
    return { atom: n === 'r' ? 'cr' : n === 'n' ? 'lf' : 'other', end: i + 2 };
  }
  return { atom: c === '\r' ? 'cr' : c === '\n' ? 'lf' : 'other', end: i + 1 };
}

/** True when the quantifier text lets a single repetition match (min <= 1 <= max). */
function quantifierAllowsOne(q: string): boolean {
  if (q === '') return true;
  const m = /^(?:(\*)|(\+)|(\?)|\{(\d+)(?:(,)(\d*))?\})[+?]?$/.exec(q);
  if (!m) return false;
  if (m[1] || m[2] || m[3]) return true;
  const min = Number(m[4]);
  const max = m[5] ? (m[6] === '' ? Infinity : Number(m[6])) : min;
  return min <= 1 && max >= 1;
}

const NONE = { cr: false, lf: false };

/** Coverage of one alternative: a lone CR/LF atom or a non-negated class holding one, with a quantifier. */
function alternativeCoverage(alt: string): { cr: boolean; lf: boolean } {
  if (alt === '') return NONE;
  let cr = false;
  let lf = false;
  let i: number;
  if (alt[0] === '[') {
    if (alt[1] === '^') return NONE;
    i = 1;
    let closed = false;
    while (i < alt.length) {
      if (alt[i] === ']' && i > 1) { closed = true; i++; break; }
      if (alt[i] === '[' || (alt[i] === '&' && alt[i + 1] === '&')) return NONE;
      const { atom, end } = readAtom(alt, i);
      if (atom === 'cr') cr = true;
      else if (atom === 'lf') lf = true;
      i = end;
    }
    if (!closed) return NONE;
  } else {
    const { atom, end } = readAtom(alt, 0);
    if (atom === 'other') return NONE;
    cr = atom === 'cr';
    lf = atom === 'lf';
    i = end;
  }
  return quantifierAllowsOne(alt.slice(i)) ? { cr, lf } : NONE;
}

/** Split `s` at top-level `|` (outside classes, groups and escapes). */
function splitAlternatives(s: string): string[] {
  const alts: string[] = [];
  let depth = 0;
  let inClass = false;
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\') { cur += c + (s[i + 1] ?? ''); i++; continue; }
    if (inClass) { if (c === ']') inClass = false; cur += c; continue; }
    if (c === '[') { inClass = true; cur += c; continue; }
    if (c === '(') depth++;
    else if (c === ')') depth--;
    if (c === '|' && depth === 0) { alts.push(cur); cur = ''; continue; }
    cur += c;
  }
  alts.push(cur);
  return alts;
}

/** If `s` is one `(?:…)` / `(…)` group, optionally quantified, its body and quantifier. */
function unwrapGroup(s: string): { body: string; quantifier: string } | null {
  const open = /^\((?:\?:)?/.exec(s);
  if (!open) return null;
  let depth = 0;
  let inClass = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\') { i++; continue; }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; continue; }
    if (c === '(') depth++;
    else if (c === ')' && --depth === 0) {
      return { body: s.slice(open[0].length, i), quantifier: s.slice(i + 1) };
    }
  }
  return null;
}

/**
 * CR / LF coverage of a `replace` / `replaceAll` call from the raw source text
 * of its first literal argument (the text between the quotes).
 *
 * `replace` is a plain-text match: only a lone CR or LF removes one. `replaceAll`
 * is a regex: only a top-level alternation (optionally inside one `(?:…)` /
 * `(…)` group, which may carry a quantifier) whose alternatives are a lone
 * `\r` / `\n` atom or a non-negated class holding one, each quantified so that
 * a single repetition matches, removes a lone CR or LF. A longer sequence
 * (`\r\n`, `x\r\ny`) or a negated class does not.
 */
export function javaReplaceCrLfCoverage(
  method: 'replace' | 'replaceAll',
  rawFrom: string,
): { cr: boolean; lf: boolean } {
  const value = decodeJavaLiteral(rawFrom);
  if (method === 'replace') return { cr: value === '\r', lf: value === '\n' };
  let body = value;
  const group = unwrapGroup(value);
  if (group) {
    if (!quantifierAllowsOne(group.quantifier)) return NONE;
    body = group.body;
  }
  let cr = false;
  let lf = false;
  for (const alt of splitAlternatives(body)) {
    const c = alternativeCoverage(alt);
    if (c.cr) cr = true;
    if (c.lf) lf = true;
  }
  return { cr, lf };
}
