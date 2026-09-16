/**
 * Provable-literal expression test (cognium-dev#358).
 *
 * Shared by the two paths that can emit a DOM-assignment `xss` sink:
 * `findJavaScriptDOMSinks` (line-regex scan) and the synthetic `innerHTML` /
 * `outerHTML` CallInfo the JS extractor produces for `el.innerHTML = <rhs>`,
 * which matches the configured method sink. Both were emitting a sink for a
 * fully static assignment, which then paired with whatever source the file
 * carried — a finding on a line no untrusted value can reach.
 *
 * The bar is PROOF from the expression text alone. Anything that is not
 * demonstrably literal keeps the sink: an identifier, a call, a `${…}`
 * interpolation, or an expression that continues beyond what we can see.
 * Being wrong in the permissive direction costs a false positive; being wrong
 * in the other direction drops a real XSS.
 */

/**
 * True when `expr` is built exclusively from string literals and
 * concatenation. Template literals count only when they contain no `${`.
 *
 * Returns false for an expression that appears to continue (a trailing `+`,
 * or an unterminated quote), because a multi-line right-hand side cannot be
 * judged from one line.
 */
export function isProvablyLiteralExpression(expr: string): boolean {
  let e = (expr ?? '').trim();
  if (e.length === 0) return false;

  // Strip a trailing line comment and statement terminator.
  e = e.replace(/\/\/.*$/, '').replace(/;\s*$/, '').trim();
  if (e.length === 0) return false;

  // An interpolation is a runtime value.
  if (e.includes('${')) return false;

  // A trailing operator means the expression continues on the next line.
  if (/[+]\s*$/.test(e)) return false;

  // Remove complete string and (non-interpolating) template literals.
  const stripped = e.replace(
    /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\$]|\\.)*`/g,
    '',
  );

  // A leftover quote means an unterminated literal — do not claim proof.
  if (/["'`]/.test(stripped)) return false;

  // Only concatenation punctuation may remain.
  return /^[\s+()]*$/.test(stripped);
}

/**
 * DOM assignment targets whose right-hand side is the whole attack surface,
 * so a provably literal RHS means no sink. `insertAdjacentHTML` and
 * `document.write` are call shapes with their own argument guards and are not
 * listed here.
 */
export const DOM_ASSIGNMENT_SINK_METHODS: ReadonlySet<string> = new Set([
  'innerHTML',
  'outerHTML',
  'cssText',
  'src',
  'href',
  'textContent',
]);
