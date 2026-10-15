/**
 * #618 — separator check for the Java canonical-path `startsWith` guard.
 *
 *   f.getCanonicalPath().startsWith(base)
 *
 * is a containment check only when `base` ends in a path separator. Without
 * one, `/safe/dir-evil` passes a check against `/safe/dir` (the prefix
 * confusion behind ESAPI CVE-2022-23457).
 */

const SEPARATOR_REF = /\b(?:separator|separatorChar|getSeparator)\b/;
const TRAILING_SEPARATOR_LITERAL = /(?:"(?:[^"\\]|\\.)*[/\\]"|'\\?[/\\]')\s*\)*\s*$/;

/** Text of the first argument of the call whose `(` is at `open`, or null if unbalanced. */
export function firstCallArgument(text: string, open: number): string | null {
  let depth = 0;
  let inStr: string | null = null;
  let start = open + 1;
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
 * - names a separator (`File.separator`, `separatorChar`, `getSeparator()`) or
 *   ends in a `/` or `\` literal: anchored.
 * - a bare identifier is resolved through its nearest earlier definition in
 *   `precedingLines` (a local variable); one that cannot be resolved (a
 *   parameter or field) is unknown and keeps the guard credited.
 * - anything else (`parent.getCanonicalPath()`, a literal with no trailing
 *   separator, a variable holding one): not anchored.
 */
export function isSeparatorAnchoredBase(arg: string, precedingLines: readonly string[], depth = 0): boolean {
  const a = arg.trim();
  if (a === '') return true;
  if (SEPARATOR_REF.test(a)) return true;
  if (TRAILING_SEPARATOR_LITERAL.test(a)) return true;
  if (/^[A-Za-z_]\w*$/.test(a) && depth < 3) {
    const def = findLocalDefinition(a, precedingLines);
    if (def === null) return true;
    return isSeparatorAnchoredBase(def, precedingLines, depth + 1);
  }
  return false;
}

function findLocalDefinition(name: string, lines: readonly string[]): string | null {
  const re = new RegExp(`(?:^|[\\s;{(])(?:[A-Za-z_][\\w.<>\\[\\]]*\\s+)?${name}\\s*=(?!=)\\s*([^;]*)`);
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = re.exec(lines[i]);
    if (!m) continue;
    let rhs = m[1];
    // A definition split over lines: gather up to the terminating `;`.
    for (let j = i; !lines[j].includes(';') && j + 1 < lines.length && j < i + 4; j++) {
      rhs += ' ' + lines[j + 1].split(';')[0];
    }
    return rhs.trim();
  }
  return null;
}
