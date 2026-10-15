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
 * - the last `+` operand is a qualified separator (`File.separator`,
 *   `File.separatorChar`, `….getSeparator()`) or ends in a `/` or `\`
 *   literal: anchored.
 * - a bare identifier (the whole base, or its last `+` operand) is resolved
 *   first, through its nearest earlier definition in the current method
 *   (`precedingLines`), so a local merely *named* `separator` is judged by its
 *   value. One that cannot be resolved (a parameter or field) is unknown: as
 *   the whole base it keeps the guard credited; as a trailing operand only a
 *   `separator` / `separatorChar` name (a static import or field) does.
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
  if (isQualifiedSeparator(last)) return true;
  if (TRAILING_SEPARATOR_LITERAL.test(last)) return true;

  if (/^[A-Za-z_]\w*$/.test(last) && depth < 3) {
    const def = findLocalDefinition(last, precedingLines);
    if (def !== null) return isSeparatorAnchoredBase(def, precedingLines, depth + 1);
    if (last === a) return true; // unresolved base (parameter / field): keep credit
    return /^(?:separator|separatorChar)$/.test(last); // static import / field
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

/**
 * True when `expr` *is* a qualified separator reference (not merely contains
 * one). A bare `separator` / `separatorChar` may be a local holding anything,
 * so it is resolved by the caller instead.
 */
function isQualifiedSeparator(expr: string): boolean {
  const t = stripWrappingParens(expr);
  return /^[\w.]+\.(?:separator|separatorChar)$/.test(t)
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
 * Does the `{` at `brace` open a nested scope — a lambda body, an anonymous
 * class body or a local class / interface / enum / record body — rather than
 * a block that is part of the enclosing method (`if` / `for` / `while` /
 * `switch` / `try` / `catch` / `finally` / `else` / `do`, a switch-rule
 * block, a bare block, an array initializer)?
 */
function opensNestedScope(skel: string, brace: number): boolean {
  // A bounded look-back keeps this linear per brace on large files.
  const pre = skel.slice(Math.max(0, brace - 2048), brace).trimEnd();
  if (pre.endsWith('->')) return !/(?:\bcase\b[^;{}]*|\bdefault\s*)->$/.test(pre); // lambda, not a switch rule
  if (/\b(?:class|interface|enum)\s+[\w$][^;{}=()]*$/.test(pre)) return true; // local type
  const p = pre.replace(/\b(?:implements)\s+[^;{}=()]+$/, '').trimEnd();
  if (!p.endsWith(')')) return false;
  const open = matchingOpen(p, p.length - 1);
  if (open < 0) return false;
  const head = p.slice(0, open).trimEnd();
  if (/\bnew\s+[\w.$]+\s*(?:<[^()]*>)?$/.test(head)) return true; // anonymous class
  return /\brecord\s+[\w$]+\s*(?:<[^()]*>)?$/.test(head); // local record
}

/**
 * Nearest earlier definition of `name` in the current method, walking back
 * from the end of `lines`. Comments are ignored; the walk stops at the
 * method's opening brace (the innermost still-open `{` that opens a method /
 * constructor / type body, so a wrapped signature or a block in between does
 * not end it early or late).
 *
 * Blocks that are part of the method (`if` / `for` / `try` / … bodies) are
 * searched like any other method code, so the nearest assignment wins
 * wherever it sits. A closed nested scope (lambda body, anonymous class,
 * local class) is skipped: an assignment there is not this method's
 * definition. Matching runs on the string-blanked skeleton so an assignment
 * written inside a string / char literal is skipped; the RHS is then read
 * from the source text, so a real literal RHS keeps its value.
 *
 * `name += rhs` appends `rhs` to the previous value, so it is returned as a
 * concatenation whose last operand is `rhs`'s.
 */
function findLocalDefinition(name: string, lines: readonly string[]): string | null {
  const re = new RegExp(`(?:^|[\\s;{}(])(?:[A-Za-z_][\\w.<>\\[\\]]*\\s+)?${name}\\s*(\\+?)=(?!=)\\s*([^;]*)`, 'dg');
  const { code, skel } = blankJava(lines.join('\n'));

  // Pair the braces. The still-open ones enclose the guard; the innermost of
  // those that opens a method / type body bounds the search.
  const openStack: number[] = [];
  const closed: Array<[number, number]> = [];
  for (let k = 0; k < skel.length; k++) {
    if (skel[k] === '{') openStack.push(k);
    else if (skel[k] === '}' && openStack.length > 0) closed.push([openStack.pop() as number, k]);
  }
  let boundary = -1;
  for (let s = openStack.length - 1; s >= 0; s--) {
    if (opensScopeBoundary(skel, openStack[s])) { boundary = openStack[s]; break; }
  }
  // Blank every closed nested scope inside the method; method blocks stay.
  const masked = skel.split('');
  let maskedTo = -1;
  closed.sort((x, y) => x[0] - y[0]);
  for (const [o, c] of closed) {
    if (o <= boundary || c <= maskedTo) continue; // outside the method, or already blanked
    if (!opensNestedScope(skel, o)) continue;
    for (let q = o; q <= c; q++) if (masked[q] !== '\n') masked[q] = ' ';
    maskedTo = c;
  }
  const top = masked.join('');

  const codeLines = code.split('\n');
  let end = code.length;
  for (let i = codeLines.length - 1; i >= 0 && end > boundary; i--) {
    const start = end - codeLines[i].length;
    const from = Math.max(start, boundary + 1);
    const seg = top.slice(from, end);
    let m: RegExpExecArray | null;
    let last: RegExpExecArray | null = null;
    re.lastIndex = 0;
    while ((m = re.exec(seg)) !== null) last = m;
    if (last?.indices?.[2]) {
      const [rs, rEnd] = last.indices[2];
      let rhs = code.slice(from + rs, from + rEnd);
      // A definition split over lines: gather up to the terminating `;`.
      for (let j = i; !codeLines[j].includes(';') && j + 1 < codeLines.length && j < i + 4; j++) {
        rhs += ' ' + codeLines[j + 1].split(';')[0];
      }
      rhs = rhs.trim();
      return last[1] === '+' ? `"" + ${rhs}` : rhs;
    }
    end = start - 1;
  }
  return null;
}
