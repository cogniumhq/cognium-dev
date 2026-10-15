/**
 * Rust literal-equality reject guard credit (cognium-dev#293, Rust cell).
 *
 *     if tool != "uptime" && tool != "whoami" { return Err("not allowed".into()); }
 *     Command::new(tool).output()          // `tool` is one of the two literals
 *
 * A guard whose block always rejects, written over string literals only,
 * proves the guarded variable is one of those literals for the rest of the
 * enclosing block. Recognised conditions (all compared values must be string
 * literals, the guarded value one plain local or parameter):
 *
 *   - `x != "a" && x != "b" …`          (also `"a" != x`)
 *   - `!(x == "a" || x == "b" …)`
 *   - `!matches!(x, "a" | "b" …)`
 *   - `!["a", "b"].contains(&x)`
 *
 * Not credited: an `||` of `!=` (or an `&&` of `==`), a comparison to a
 * non-literal, a guard on another variable, a guard that falls through or
 * rejects only inside an inner branch, a guard with an `else`, and any
 * `matches!` arm that is not a plain string literal.
 *
 * The credit is line-keyed. It starts after the guard block, ends with the
 * enclosing block (so never reaches another function), stops at the first
 * line that rebinds or mutates the variable (or at the start of a loop that
 * contains such a line), and skips a line that also reads another value
 * (`Command::new(x).arg(other)`), since the line credit would clean it too.
 */
import type { TaintSanitizer } from '../types/index.js';

const CREDITED_TYPES = [
  'command_injection', 'path_traversal', 'sql_injection', 'ssrf', 'open_redirect',
  'xss', 'code_injection', 'ldap_injection', 'xpath_injection', 'log_injection',
  'trust_boundary', 'external_taint_escape',
];

/** `code` with comments blanked and string / char literal bodies replaced by spaces (same length). */
function maskRust(code: string): string {
  const out = code.split('');
  const n = code.length;
  const blank = (from: number, to: number) => {
    for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < n) {
    const c = code[i];
    if (c === '/' && code[i + 1] === '/') {
      let j = i;
      while (j < n && code[j] !== '\n') j++;
      blank(i, j);
      i = j;
    } else if (c === '/' && code[i + 1] === '*') {
      let j = i + 2;
      let depth = 1;
      while (j < n && depth > 0) {
        if (code[j] === '/' && code[j + 1] === '*') { depth++; j += 2; }
        else if (code[j] === '*' && code[j + 1] === '/') { depth--; j += 2; }
        else j++;
      }
      blank(i, j);
      i = j;
    } else if (c === 'r' && /^r#*"/.test(code.slice(i, i + 12)) && !/[\w]/.test(code[i - 1] ?? ' ')) {
      const hashes = /^r(#*)"/.exec(code.slice(i, i + 12))![1].length;
      const close = '"' + '#'.repeat(hashes);
      const end = code.indexOf(close, i + 2 + hashes);
      const j = end === -1 ? n : end + close.length;
      blank(i + 2 + hashes, Math.max(i + 2 + hashes, j - close.length));
      i = j;
    } else if (c === '"') {
      let j = i + 1;
      while (j < n && code[j] !== '"') j += code[j] === '\\' ? 2 : 1;
      blank(i + 1, j);
      i = j + 1;
    } else if (c === "'") {
      // A char literal ('x', '\n', '\u{..}'), not a lifetime ('a).
      const m = /^'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'/.exec(code.slice(i, i + 14));
      if (m) { blank(i + 1, i + m[0].length - 1); i += m[0].length; } else i++;
    } else i++;
  }
  return out.join('');
}

/** Index of the `}` matching the `{` at `open` in `masked`, or -1. */
function matchBrace(masked: string, open: number): number {
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === '{') depth++;
    else if (masked[i] === '}' && --depth === 0) return i;
  }
  return -1;
}

const STR = String.raw`"(?:[^"\\]|\\.)*"`;
const VAR = String.raw`([A-Za-z_]\w*)(?:\s*\.\s*as_str\s*\(\s*\))?`;

/** The guarded variable when `cond` is a literal allow-list rejection condition, else null. */
function guardedVariable(cond: string): string | null {
  const c = cond.trim();
  let m: RegExpExecArray | null;

  // `!matches!(x, "a" | "b")`
  if ((m = new RegExp(String.raw`^!\s*matches!\s*\(\s*${VAR}\s*,\s*((?:\|\s*)?${STR}(?:\s*\|\s*${STR})*)\s*,?\s*\)$`).exec(c))) {
    return m[1];
  }
  // `!["a", "b"].contains(&x)`
  if ((m = new RegExp(String.raw`^!\s*\[\s*${STR}(?:\s*,\s*${STR})*\s*,?\s*\]\s*\.\s*contains\s*\(\s*&\s*${VAR}\s*\)$`).exec(c))) {
    return m[1];
  }
  // `!(x == "a" || x == "b")`
  if ((m = /^!\s*\(([\s\S]*)\)$/.exec(c))) {
    return chain(m[1], '||', '==');
  }
  // `x != "a" && x != "b"`
  return chain(c, '&&', '!=');
}

/** Terms joined by `joiner`, each `V op "lit"` or `"lit" op V` with one shared V. */
function chain(text: string, joiner: '||' | '&&', op: '==' | '!='): string | null {
  const other = joiner === '||' ? '&&' : '||';
  if (text.includes(other) || /[()]/.test(text.replace(/\.\s*as_str\s*\(\s*\)/g, '').replace(new RegExp(STR, 'g'), '""'))) {
    return null;
  }
  let name: string | null = null;
  const parts = text.split(joiner);
  for (const part of parts) {
    const t = part.trim();
    const m = new RegExp(String.raw`^(?:${VAR}\s*${op}\s*${STR}|${STR}\s*${op}\s*${VAR})$`).exec(t);
    if (!m) return null;
    const v = m[1] ?? m[2];
    if (name !== null && v !== name) return null;
    name = v;
  }
  return name;
}

const KEYWORDS = new Set([
  'let', 'mut', 'ref', 'as', 'if', 'else', 'return', 'true', 'false', 'self', 'move', 'in', 'for',
  'while', 'loop', 'match', 'fn', 'pub', 'use', 'mod', 'const', 'static', 'unsafe', 'where', 'dyn',
  'impl', 'break', 'continue', 'crate', 'super', 'async', 'await', 'box', 'type', 'struct', 'enum',
  'str', 'u8', 'u16', 'u32', 'u64', 'usize', 'i8', 'i16', 'i32', 'i64', 'isize', 'bool', 'char', 'f32', 'f64',
]);

/**
 * True when the (masked) `line` reads a value other than `name`: another
 * local, a lower-case free or module-qualified call (`std::env::args()`), or
 * an inline format argument (`{other}`). Method names, associated functions
 * of a type (`Command::new`), macros, type names and closure parameters are
 * not values.
 */
function readsOtherValue(original: string, masked: string, name: string): boolean {
  for (const m of original.matchAll(new RegExp(STR, 'g'))) {
    for (const f of m[0].matchAll(/(?<!\{)\{([A-Za-z_]\w*)(?:[:}])/g)) if (f[1] !== name) return true;
  }
  const closureParams = new Set<string>();
  for (const m of masked.matchAll(/\|\s*([\w\s,&:()]*?)\s*\|/g)) {
    for (const p of m[1].matchAll(/[A-Za-z_]\w*/g)) closureParams.add(p[0]);
  }
  const re = /[A-Za-z_]\w*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(masked)) !== null) {
    const id = m[0];
    const before = masked.slice(0, m.index);
    const after = masked.slice(m.index + id.length);
    if (id === name || KEYWORDS.has(id) || closureParams.has(id)) continue;
    if (/\.\s*$/.test(before)) continue;                       // method or field
    if (/^\s*!/.test(after) && !/^\s*!=/.test(after)) continue; // macro
    if (/[A-Z]/.test(id[0])) continue;                          // type, variant, constant
    if (/(?:\blet\s+(?:mut\s+)?)$/.test(before)) continue;      // the binding being introduced
    if (/::\s*$/.test(before)) continue;                        // path tail (`io::stdin` handled by its head)
    return true;                                                // other local, free call, module path
  }
  return false;
}

function mutates(masked: string, name: string): boolean {
  const n = name;
  return new RegExp(
    String.raw`\blet\s+(?:mut\s+)?${n}\b|(?<![\w.])${n}\s*(?:[-+*/%|&^]|<<|>>)?=(?![=>])|&\s*mut\s+${n}\b|\bfn\s+\w+\s*(?:<[^>]*>)?\([^)]*\b${n}\s*:|\|[^|]*\b${n}\b[^|]*\||\b${n}\s*\.\s*(?:push|push_str|clear|insert|extend|truncate|remove|retain|drain|replace_range|make_ascii_lowercase|make_ascii_uppercase)\s*\(`,
  ).test(masked);
}

export function findRustLiteralEqualityGuardSanitizers(code: string): TaintSanitizer[] {
  const masked = maskRust(code);
  const origLines = code.split('\n');
  const maskedLines = masked.split('\n');
  const lineStarts: number[] = [];
  for (let i = 0, off = 0; i < origLines.length; i++) { lineStarts.push(off); off += origLines[i].length + 1; }
  const lineOf = (idx: number): number => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1;
    }
    return lo; // 0-based
  };

  const out: TaintSanitizer[] = [];
  for (const ifm of masked.matchAll(/\bif\b/g)) {
    const at = ifm.index!;
    if (/\belse\s*$/.test(masked.slice(Math.max(0, at - 12), at))) continue;
    if (/\blet\b/.test(masked.slice(at + 2, at + 8))) continue; // `if let`
    // Condition: up to the `{` that opens the block, at bracket depth 0.
    let depth = 0;
    let open = -1;
    for (let i = at + 2; i < masked.length; i++) {
      const ch = masked[i];
      if (ch === '(' || ch === '[') depth++;
      else if (ch === ')' || ch === ']') depth--;
      else if (ch === '{' && depth === 0) { open = i; break; }
      else if (ch === ';' || ch === '}') break;
    }
    if (open < 0) continue;
    const name = guardedVariable(code.slice(at + 2, open));
    if (name === null) continue;
    const close = matchBrace(masked, open);
    if (close < 0) continue;
    if (/^\s*else\b/.test(masked.slice(close + 1, close + 12))) continue;

    // The block must reject at its own top level (not inside an inner branch).
    const body = masked.slice(open + 1, close).split('');
    for (let i = 0, d = 0; i < body.length; i++) {
      if (body[i] === '{') { d++; body[i] = ' '; }
      else if (body[i] === '}') { d--; body[i] = ' '; }
      else if (d > 0 && body[i] !== '\n') body[i] = ' ';
    }
    if (!/(?<![\w.])(?:return\b|panic\s*!|unreachable\s*!|bail\s*!|(?:std\s*::\s*)?process\s*::\s*exit\s*\()/.test(body.join(''))) continue;

    // Credit region: after the guard block to the end of the enclosing block.
    let end = masked.length;
    for (let i = close + 1, d = 0; i < masked.length; i++) {
      if (masked[i] === '{') d++;
      else if (masked[i] === '}' && --d < 0) { end = i; break; }
    }
    // Whole lines after the guard's closing line, up to the line before the
    // enclosing block's closing brace (or the end of the file).
    const firstLine = lineOf(close) + 1;
    const lastLine = end === masked.length ? origLines.length - 1 : lineOf(end) - 1;
    let stop = lastLine + 1;
    // A rebind or mutation ends the credit; inside a later loop it ends at the loop.
    for (let l = firstLine; l <= lastLine; l++) {
      if (!mutates(maskedLines[l], name)) continue;
      stop = l;
      for (const lp of masked.slice(close + 1, end).matchAll(/\b(?:for|while|loop)\b[^{;]*\{/g)) {
        const lpOpen = close + 1 + lp.index! + lp[0].length - 1;
        const lpClose = matchBrace(masked, lpOpen);
        const lpLine = lineOf(lpOpen);
        if (lpClose >= 0 && lineOf(lpClose) >= l && lpLine <= l) stop = Math.min(stop, lpLine);
      }
      break;
    }
    const mention = new RegExp(String.raw`(?<![\w.])${name}\b`);
    for (let l = firstLine; l < stop && l <= lastLine; l++) {
      if (!mention.test(maskedLines[l])) continue;
      if (readsOtherValue(origLines[l], maskedLines[l], name)) continue;
      out.push({
        type: 'rust_literal_equality_guard',
        method: 'guard',
        line: l + 1,
        sanitizes: CREDITED_TYPES as TaintSanitizer['sanitizes'],
      });
    }
  }
  return out;
}
