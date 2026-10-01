/**
 * JSON Canonicalization Scheme (RFC 8785).
 *
 * One byte sequence per JSON value, so a signature over a payload survives
 * being re-encoded by anything that handles it on the way. The licence token
 * signs the canonical form rather than the bytes it happened to arrive in.
 *
 * Implemented here rather than taken as a dependency: it is forty lines, and
 * this package keeps its dependency list short on purpose.
 *
 * Two pieces come free from the platform and are worth stating so nobody
 * "fixes" them later:
 *
 *   - `JSON.stringify` on a string already produces JCS-conformant escaping.
 *     It escapes only `"`, `\` and the C0 controls, uses the short forms
 *     (`\b \t \n \f \r`) where RFC 8785 requires them, `\uXXXX` for the rest,
 *     leaves every other code point as literal UTF-8, and escapes lone
 *     surrogates — all exactly as the RFC specifies.
 *   - `Array.prototype.sort()` with no comparator orders strings by UTF-16
 *     code unit, which is the ordering RFC 8785 §3.2.3 mandates for keys.
 */

/** Thrown for input JSON cannot represent canonically. */
export class JcsError extends Error {}

export function canonicalise(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      // RFC 8785 §3.2.2.3 defers number serialization to ECMAScript's
      // Number-to-String, which is what JSON.stringify applies. Non-finite
      // values have no JSON form at all.
      if (!Number.isFinite(value)) throw new JcsError(`cannot canonicalise ${String(value)}`);
      return JSON.stringify(value);

    case 'string':
      return JSON.stringify(value);

    case 'object':
      break;

    default:
      throw new JcsError(`cannot canonicalise a ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalise(v)).join(',')}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    // `undefined` is absent rather than null, matching JSON.stringify.
    .filter(([, v]) => v !== undefined);
  // Sort on the key as written: the default comparator is UTF-16 code unit
  // order, which is what the RFC asks for.
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalise(v)}`).join(',')}}`;
}

/** The canonical form as the bytes a signature covers. */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalise(value), 'utf8');
}
