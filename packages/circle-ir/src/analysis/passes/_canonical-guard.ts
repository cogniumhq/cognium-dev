/**
 * #618 — separator check for the Java canonical-path `startsWith` guard.
 *
 *   f.getCanonicalPath().startsWith(base)
 *
 * is a containment check only when `base` ends in a path separator. Without
 * one, `/safe/dir-evil` passes a check against `/safe/dir` (the prefix
 * confusion behind ESAPI CVE-2022-23457).
 */

/**
 * A Java string / char literal that ends in a path separator.
 *
 * Forward slash is a single `/` before the closing quote. A trailing backslash
 * in the *value* is written as `\\` in Java source (an escape), so we match
 * `\\"` rather than a lone `\` before `"`. Anchored at both ends: the operand
 * must *be* the literal (wrapping parens are stripped first), so `label("/")`
 * or `helper(base, "/")` is not credited.
 */
const TRAILING_SEPARATOR_LITERAL = /^(?:"(?:[^"\\]|\\.)*(?:\/|\\\\)"|'\\?[/\\]')$/;

/** Statement keywords whose `(…) {` block is part of the enclosing method. */
const CONTROL_HEAD = /\b(?:if|for|while|switch|catch|synchronized|try)$/;

/** Text of the first argument of the call whose `(` is at `open`, or null if unbalanced. */
export function firstCallArgument(text: string, open: number): string | null {
  let depth = 0;
  let inStr: string | null = null;
  const start = open + 1;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (ch === '\\') i++;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") inStr = ch;
    else if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return text.slice(start, i).trim();
    } else if (ch === ',' && depth === 1) return text.slice(start, i).trim();
  }
  return null;
}

/**
 * Is the `startsWith` argument a separator-anchored base?
 *
 * - the last `+` operand names a separator (`File.separator`, `separatorChar`,
 *   `getSeparator()`) or ends in a `/` or `\` literal: anchored.
 * - a bare identifier is resolved through its nearest earlier definition in
 *   the current method (`precedingLines`); one that cannot be resolved (a
 *   parameter or field) is unknown and keeps the guard credited.
 * - anything else (`parent.getCanonicalPath()`, a literal with no trailing
 *   separator, a variable holding one, a separator ref mid-expression or
 *   inside a string): not anchored.
 * - an empty / unparseable argument keeps the credit; a `""` literal does not.
 */
export function isSeparatorAnchoredBase(arg: string, precedingLines: readonly string[], depth = 0): boolean {
  const a = stripWrappingParens(arg);
  if (a === '') return true;
  // A literal empty string is not a containment base.
  if (a === '""' || a === "''") return false;

  const last = stripWrappingParens(lastPlusOperand(a));
  if (isSeparatorName(last)) return true;
  if (TRAILING_SEPARATOR_LITERAL.test(last)) return true;

  if (/^[A-Za-z_]\w*$/.test(a) && depth < 3) {
    const def = findLocalDefinition(a, precedingLines);
    if (def === null) return true;
    return isSeparatorAnchoredBase(def, precedingLines, depth + 1);
  }
  return false;
}

/**
 * `expr` without parentheses that wrap the whole of it: `((a + b))` → `a + b`,
 * but `(a) + (b)` and `f(a)` are left alone.
 */
function stripWrappingParens(expr: string): string {
  let e = expr.trim();
  while (e.startsWith('(') && matchingClose(e, 0) === e.length - 1) e = e.slice(1, -1).trim();
  return e;
}

/** Index of the `)` matching the `(` at `open` (strings respected), or -1. */
function matchingClose(text: string, open: number): number {
  let depth = 0;
  let inStr: string | null = null;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (ch === '\\') i++;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") inStr = ch;
    else if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return i;
  }
  return -1;
}

/**
 * Last top-level `+` operand of `expr` (strings and nested parens respected).
 * Separator credit applies only to this operand, not to a mid-expression ref.
 */
function lastPlusOperand(expr: string): string {
  let depth = 0;
  let inStr: string | null = null;
  let lastPlus = -1;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (inStr) {
      if (ch === '\\') i++;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") inStr = ch;
    else if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (ch === '+' && depth === 0) lastPlus = i;
  }
  return lastPlus < 0 ? expr : expr.slice(lastPlus + 1);
}

/** True when `expr` *is* a separator name (not merely contains one). */
function isSeparatorName(expr: string): boolean {
  const t = stripWrappingParens(expr);
  return /^(?:[\w.]+\.)?(?:separator|separatorChar)$/.test(t)
    || /^(?:[\w.]+\.)?getSeparator\s*\(\s*\)$/.test(t);
}

/**
 * Java source with comments blanked (`code`) and, in `skel`, string / char
 * contents blanked too. Both keep the input's length and line breaks, so
 * offsets line up with each other and with the source.
 */
function blankJava(src: string): { code: string; skel: string } {
  const code = src.split('');
  const skel = src.split('');
  const blank = (i: number): void => {
    if (src[i] !== '\n') { code[i] = ' '; skel[i] = ' '; }
  };
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') blank(i++);
    } else if (ch === '/' && src[i + 1] === '*') {
      blank(i++); blank(i++);
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) blank(i++);
      if (i < src.length) { blank(i++); blank(i); }
    } else if (ch === '"' || ch === "'") {
      for (i++; i < src.length && src[i] !== ch && src[i] !== '\n'; i++) {
        if (src[i] === '\\' && i + 1 < src.length) skel[i++] = ' ';
        skel[i] = ' ';
      }
    }
  }
  return { code: code.join(''), skel: skel.join('') };
}

/** Index of the `(` matching the `)` at `close` in a string-blanked skeleton, or -1. */
function matchingOpen(skel: string, close: number): number {
  let depth = 0;
  for (let i = close; i >= 0; i--) {
    if (skel[i] === ')') depth++;
    else if (skel[i] === '(' && --depth === 0) return i;
  }
  return -1;
}

/**
 * Does the unmatched `{` at `brace` open a method / constructor / type body
 * (the end of local scope) rather than a block inside the method — a
 * control statement, `else` / `try` / `finally` / `do`, a lambda, an
 * anonymous class, an array initializer or a bare block?
 */
function opensScopeBoundary(skel: string, brace: number): boolean {
  const pre = skel.slice(0, brace).trimEnd();
  if (pre === '') return true;
  if (/(?:->|[;{}:=,(\[\]]|\b(?:else|try|finally|do))$/.test(pre)) return false;
  const p = pre.replace(/\bthrows\s+[\w.$<>,?\s[\]]+$/, '').trimEnd();
  if (!p.endsWith(')')) return true; // class / interface / enum header, initializer
  const open = matchingOpen(p, p.length - 1);
  if (open < 0) return true;
  const head = p.slice(0, open).trimEnd();
  if (CONTROL_HEAD.test(head)) return false;
  if (/\bnew\s+[\w.$]+\s*(?:<[^()]*>)?$/.test(head)) return false; // anonymous class
  return true; // method or constructor body
}

/**
 * Nearest earlier definition of `name` in the current method, walking back
 * from the end of `lines`. Comments are ignored; the walk stops at the
 * method's opening brace (found by brace depth, so a wrapped signature or a
 * nested block / anonymous class in between does not end it early or late).
 *
 * Only the depth-0 part of each line is searched, so an assignment inside a
 * nested `{…}` (anonymous class, lambda body, local class) is not this
 * method's definition, and matching runs on the string-blanked skeleton so an
 * assignment written inside a string / char literal is skipped. The RHS is
 * then read from the source text, so a real literal RHS keeps its value.
 */
function findLocalDefinition(name: string, lines: readonly string[]): string | null {
  const re = new RegExp(`(?:^|[\\s;{(])(?:[A-Za-z_][\\w.<>\\[\\]]*\\s+)?${name}\\s*=(?!=)\\s*([^;]*)`, 'd');
  const { code, skel } = blankJava(lines.join('\n'));
  const codeLines = code.split('\n');
  let end = code.length;
  let depth = 0;
  for (let i = codeLines.length - 1; i >= 0; i--) {
    const start = end - codeLines[i].length;
    let boundary = -1;
    // `skel` for this line with everything inside a nested `{…}` blanked.
    const top = skel.slice(start, end).split('');
    for (let k = end - 1; k >= start; k--) {
      if (skel[k] === '}') { depth++; top[k - start] = ' '; }
      else if (skel[k] === '{') {
        if (depth > 0) { depth--; top[k - start] = ' '; }
        else if (opensScopeBoundary(skel, k)) { boundary = k; break; }
      } else if (depth > 0) top[k - start] = ' ';
    }
    const from = boundary < 0 ? start : boundary + 1;
    const m = re.exec(top.join('').slice(from - start));
    if (m?.indices?.[1]) {
      const [rs, rEnd] = m.indices[1];
      let rhs = code.slice(from + rs, from + rEnd);
      // A definition split over lines: gather up to the terminating `;`.
      for (let j = i; !codeLines[j].includes(';') && j + 1 < codeLines.length && j < i + 4; j++) {
        rhs += ' ' + codeLines[j + 1].split(';')[0];
      }
      return rhs.trim();
    }
    if (boundary >= 0) break;
    end = start - 1;
  }
  return null;
}
