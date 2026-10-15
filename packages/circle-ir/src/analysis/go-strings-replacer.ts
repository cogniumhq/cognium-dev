/**
 * Go `strings.NewReplacer(old1, new1, old2, new2, …).Replace(x)` sanitizer
 * credit (cognium-dev#348, #293).
 *
 * The credit is argument-aware, like the Java replace credit:
 *   - `log_injection` when both "\r" and "\n" are replaced, each by a string
 *     that contains neither CR nor LF;
 *   - `xss` when both "<" and ">" are replaced by strings that contain
 *     neither.
 * A replacer that maps only some of those characters earns nothing.
 *
 * A replacer is recognised inline (`strings.NewReplacer(...).Replace(x)`)
 * and through a variable it is bound to (`var flat = strings.NewReplacer(...)`
 * at package scope or `flat := strings.NewReplacer(...)` in a function), on
 * every line that calls `<name>.Replace(`.
 */
import type { SinkType, TaintSanitizer } from '../types/index.js';

/** Decode one Go string literal (interpreted "…" or raw `…`); null when not a literal. */
function decodeGoLiteral(lit: string): string | null {
  if (lit.length >= 2 && lit.startsWith('`') && lit.endsWith('`')) return lit.slice(1, -1);
  if (lit.length < 2 || !lit.startsWith('"') || !lit.endsWith('"')) return null;
  return lit.slice(1, -1).replace(/\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|([abfnrtv\\"']))/g, (_m, hex, uni, c) => {
    if (hex !== undefined) return String.fromCharCode(parseInt(hex, 16));
    if (uni !== undefined) return String.fromCharCode(parseInt(uni, 16));
    const map: Record<string, string> = { a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' };
    return map[c as string] ?? (c as string);
  });
}

/** Split the argument list of a NewReplacer call into its literal operands; null if any is not a literal. */
function replacerPairs(args: string): Array<[string, string]> | null {
  const lits = args.match(/"(?:[^"\\]|\\.)*"|`[^`]*`/g) ?? [];
  // Every comma-separated operand must be a literal.
  const rest = args.replace(/"(?:[^"\\]|\\.)*"|`[^`]*`/g, '').replace(/[\s,]/g, '');
  if (rest !== '' || lits.length === 0 || lits.length % 2 !== 0) return null;
  const decoded = lits.map(decodeGoLiteral);
  if (decoded.some(d => d === null)) return null;
  const pairs: Array<[string, string]> = [];
  for (let i = 0; i < decoded.length; i += 2) pairs.push([decoded[i] as string, decoded[i + 1] as string]);
  return pairs;
}

/** Sink types a NewReplacer with these pairs neutralises. */
export function goReplacerCoverage(pairs: Array<[string, string]>): SinkType[] {
  const maps = (ch: string, banned: RegExp): boolean =>
    pairs.some(([o, n]) => o === ch && !banned.test(n));
  const out: SinkType[] = [];
  if (maps('\r', /[\r\n]/) && maps('\n', /[\r\n]/)) out.push('log_injection');
  if (maps('<', /[<>]/) && maps('>', /[<>]/)) out.push('xss');
  return out;
}

const NEW_REPLACER = /\bstrings\s*\.\s*NewReplacer\s*\(/g;

/** The balanced argument text of the call whose `(` is at `open`. */
function callArgs(text: string, open: number): { args: string; end: number } | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < text.length; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === '`') quote = c;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return { args: text.slice(open + 1, i), end: i };
  }
  return null;
}

export function findGoStringsReplacerSanitizers(code: string): TaintSanitizer[] {
  const out: TaintSanitizer[] = [];
  const lineStarts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') lineStarts.push(i + 1);
  const lineAt = (idx: number): number => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= idx) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
  // `method` names the call that does the replacing, so a sink-line credit
  // covers only that call's operand (#641).
  const emit = (line: number, sanitizes: SinkType[], method: string): void => {
    out.push({ type: 'go_strings_replacer', method, line, sanitizes });
  };

  const bound = new Map<string, SinkType[]>();
  NEW_REPLACER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = NEW_REPLACER.exec(code)) !== null) {
    const call = callArgs(code, m.index + m[0].length - 1);
    if (!call) continue;
    const pairs = replacerPairs(call.args);
    const covers = pairs ? goReplacerCoverage(pairs) : [];
    const after = code.slice(call.end + 1);
    if (/^\s*\.\s*Replace\s*\(/.test(after)) {
      if (covers.length > 0) emit(lineAt(m.index), covers, 'Replace()');
      continue;
    }
    // Bound to a name: `name = strings.NewReplacer(` / `name := ...`.
    const before = code.slice(code.lastIndexOf('\n', m.index) + 1, m.index);
    const b = /(?:^|[\s(])([A-Za-z_]\w*)\s*:?=\s*$/.exec(before);
    if (!b) continue;
    const name = b[1]!;
    // A name rebound to a replacer that covers less loses the credit.
    const prev = bound.get(name);
    bound.set(name, prev ? prev.filter(t => covers.includes(t)) : covers);
  }

  for (const [name, covers] of bound) {
    if (covers.length === 0) continue;
    const use = new RegExp(`(?<![\\w.])${name}\\s*\\.\\s*Replace\\s*\\(`, 'g');
    let u: RegExpExecArray | null;
    while ((u = use.exec(code)) !== null) emit(lineAt(u.index), covers, `${name}.Replace()`);
  }
  return out;
}
