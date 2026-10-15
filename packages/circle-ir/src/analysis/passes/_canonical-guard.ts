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
 * `\\"` rather than a lone `\` before `"`.
 */
const TRAILING_SEPARATOR_LITERAL = /(?:"(?:[^"\\]|\\.)*(?:\/|\\\\)"|'\\?[/\\]')\s*\)*\s*$/;

/** A method / constructor header — used to bound local-definition lookup. */
const JAVA_METHOD_HEADER =
  /^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract|default)\s+)*(?:<\s*[\w?,\s]+\s*>\s*)?(?:[\w.\[\]]+\s+)+\w+\s*\([^;]*\)\s*(?:throws\s+[^{;]+)?\s*\{?\s*$/;

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
  const a = arg.trim();
  if (a === '') return true;
  // A literal empty string is not a containment base.
  if (a === '""' || a === "''") return false;

  const last = lastPlusOperand(a).trim();
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
  const t = expr.trim().replace(/^\(+/, '').replace(/\)+\s*$/, '').trim();
  return /^(?:[\w.]+\.)?(?:separator|separatorChar)$/.test(t)
    || /^(?:[\w.]+\.)?getSeparator\s*\(\s*\)$/.test(t);
}

function findLocalDefinition(name: string, lines: readonly string[]): string | null {
  const re = new RegExp(`(?:^|[\\s;{(])(?:[A-Za-z_][\\w.<>\\[\\]]*\\s+)?${name}\\s*=(?!=)\\s*([^;]*)`);
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = re.exec(lines[i]);
    if (m) {
      let rhs = m[1];
      // A definition split over lines: gather up to the terminating `;`.
      for (let j = i; !lines[j].includes(';') && j + 1 < lines.length && j < i + 4; j++) {
        rhs += ' ' + lines[j + 1].split(';')[0];
      }
      return rhs.trim();
    }
    // Stop at the current method's header so an earlier method's assignment
    // cannot resolve a parameter of this one.
    if (JAVA_METHOD_HEADER.test(lines[i])) break;
  }
  return null;
}
