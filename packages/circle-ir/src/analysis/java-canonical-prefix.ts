/**
 * Is the base of a Java `<file>.getCanonicalPath().startsWith(<base>)` check a
 * bare canonical path, with no trailing separator? (cognium-dev#618)
 *
 * A string-prefix check against a base that does not end in a separator is the
 * classic prefix-confusion bypass: `/safe/dir-evil` starts with `/safe/dir`.
 * That is the ESAPI CVE-2022-23457 shape:
 *
 *     if (!dir.getCanonicalPath().startsWith(parent.getCanonicalPath())) throw ...
 *
 * This answers `true` only when it can prove the base is a bare canonical /
 * absolute path call (`x.getCanonicalPath()`, `x.getCanonicalFile().getPath()`,
 * `x.getAbsolutePath()`, …), either inline or through a local variable whose
 * nearest preceding assignment in the same method is such a call — or a
 * concatenation / compound assignment that still involves such a call and does
 * not *end with* a separator. Anything it cannot resolve (a parameter, a field,
 * a literal without a trailing separator it already accepted) answers `false`,
 * so existing guard credit is kept. A trailing separator (`+ File.separator`,
 * `+ "/"`, `+ '/'`, or a literal that ends with `/` or `\`) answers `false`:
 *
 *     String base = root.getCanonicalPath() + File.separator;
 *     if (!f.getCanonicalPath().startsWith(base)) throw ...   // still a guard
 *
 * A separator that is not at the end (`File.separator + path`, `path + "X"`,
 * `path + "/foo"`) does not keep the credit: `/srv/data/foo-evil` still starts
 * with `/srv/data/foo`.
 */

const BARE_CANONICAL_RE =
  /^[A-Za-z_][\w.]*(?:\s*\(\s*\))?(?:\s*\.\s*getCanonicalFile\s*\(\s*\)|\s*\.\s*getAbsoluteFile\s*\(\s*\))?\s*\.\s*(?:getCanonicalPath|getAbsolutePath|getPath|toString)\s*\(\s*\)$/;
const CANONICAL_CALL_RE = /\b(?:getCanonicalPath|getCanonicalFile|getAbsolutePath|getAbsoluteFile)\s*\(/;
const METHOD_HEADER_RE =
  /^\s*(?!(?:if|for|while|switch|catch|synchronized|try|else|do)\b)[^=;]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$/;

/** True when `expr` ends with a path-separator fragment. */
function endsWithSeparator(expr: string): boolean {
  const t = expr.trim();
  // Whole-expression string literal ending in / or \
  if (/^"(?:[^"\\]|\\.)*[\/\\]"$/.test(t)) return true;
  if (/^'(?:[^'\\]|\\.)*[\/\\]'$/.test(t)) return true;
  // Concatenation ending in + File.separator / File.separatorChar
  if (/\+\s*File\s*\.\s*(?:separator|separatorChar)\s*$/.test(t)) return true;
  // Concatenation ending in + "/" or + '/' or + "\\" or + '\\'
  if (/\+\s*"(?:\/|\\\\)"\s*$/.test(t)) return true;
  if (/\+\s*'(?:\/|\\\\)'\s*$/.test(t)) return true;
  return false;
}

/** Text of the call argument opening at `open` (index of `(`), or null when unbalanced. */
export function javaCallArgument(text: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < text.length; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return text.slice(open + 1, i).trim();
  }
  return null;
}

/** RHS of the nearest assignment to `name` above line `from`, within the enclosing method. */
function resolveLocal(lines: string[], from: number, name: string): string | null {
  const assignRe = new RegExp(`(?:^|[^\\w.])${name}\\s*([-+*/%&|^]|<<|>>>?)?=(?!=)\\s*([^;]+);`);
  for (let l = from - 1; l >= 0; l--) {
    const m = assignRe.exec(lines[l]!);
    if (m) {
      if (m[1] === undefined) return m[2]!.trim();
      // `base += File.separator` / `base += "X"`: fold into `prev + rhs` so
      // trailing-separator checks still see the full expression. Other
      // compounds stay unresolved and the guard keeps its credit.
      if (m[1] === '+') {
        const prev = resolveLocal(lines, l, name);
        if (prev === null) return null;
        return `${prev} + ${m[2]!.trim()}`;
      }
      return null;
    }
    if (METHOD_HEADER_RE.test(lines[l]!)) return null;
  }
  return null;
}

/**
 * True when `arg` — the argument of a canonical-path `startsWith` call on line
 * `lineIdx` (0-based) — provably evaluates to a canonical path with no
 * trailing separator.
 */
export function javaCanonicalBaseLacksSeparator(lines: string[], lineIdx: number, arg: string): boolean {
  let expr = arg.trim();
  for (let hop = 0; hop < 3; hop++) {
    if (endsWithSeparator(expr)) return false;
    if (BARE_CANONICAL_RE.test(expr)) return CANONICAL_CALL_RE.test(expr);
    // Concat / compound that still mentions a canonical call and does not end
    // with a separator (e.g. `File.separator + path`, `path + "X"`, `path + "/foo"`).
    if (CANONICAL_CALL_RE.test(expr)) return true;
    if (!/^[A-Za-z_]\w*$/.test(expr)) return false;
    const rhs = resolveLocal(lines, lineIdx, expr);
    if (rhs === null) return false;
    expr = rhs;
  }
  return false;
}

/**
 * True when every canonical-path `startsWith(<base>)` in `text` (a method body)
 * whose base mentions a canonical path call lacks a separator, and there is at
 * least one such call. Used by the method-level guard check.
 */
export function javaCanonicalStartsWithAllBare(text: string): boolean {
  const lines = text.split('\n');
  const re = /\.\s*startsWith\s*\(/g;
  let seen = 0;
  for (let l = 0; l < lines.length; l++) {
    const rest = lines.slice(l).join('\n');
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(lines[l]!)) !== null) {
      const open = m.index + m[0].length - 1;
      const arg = javaCallArgument(rest, open);
      if (arg === null || !/getCanonicalPath/.test(arg)) continue;
      seen++;
      if (!javaCanonicalBaseLacksSeparator(lines, l, arg)) return false;
    }
  }
  return seen > 0;
}
