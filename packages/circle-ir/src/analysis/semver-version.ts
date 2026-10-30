/**
 * Semantic Versioning 2.0.0 precedence (https://semver.org/#spec-item-11),
 * the order npm and OSV's `SEMVER` ranges use.
 *
 * - `major.minor.patch` compare numerically; a missing part counts as 0.
 * - A version with a pre-release (`1.0.0-rc.1`) sorts before the same version
 *   without one.
 * - Pre-release identifiers compare left to right: numeric ones by value,
 *   alphanumeric ones in ASCII order, numeric before alphanumeric, and a
 *   shorter list before a longer one that starts with it.
 * - Build metadata (`+…`) is ignored, as the specification says.
 * - A leading `v` or `=` is tolerated (`v1.2.3`), as npm does.
 *
 * Pure and synchronous; no dependencies.
 */

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

const SEMVER =
  /^[v=]?\s*(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** Parse a SemVer string, or `null` when it is not one (a range, a tag, a URL). */
export function parseSemver(version: string): ParsedSemver | null {
  const m = SEMVER.exec(version.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: m[2] === undefined ? 0 : Number(m[2]),
    patch: m[3] === undefined ? 0 : Number(m[3]),
    prerelease: m[4] === undefined ? [] : m[4].split('.'),
  };
}

const NUMERIC = /^\d+$/;

function compareIdentifiers(a: string, b: string): number {
  const an = NUMERIC.test(a);
  const bn = NUMERIC.test(b);
  if (an && bn) {
    const d = Number(a) - Number(b);
    return d < 0 ? -1 : d > 0 ? 1 : 0;
  }
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compare two SemVer versions: negative, zero or positive. A string that is
 * not SemVer sorts before every SemVer version, and two such strings compare
 * as plain text, so the order stays total and deterministic.
 */
export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) {
    if (pa) return 1;
    if (pb) return -1;
    return a < b ? -1 : a > b ? 1 : 0;
  }
  for (const k of ['major', 'minor', 'patch'] as const) {
    if (pa[k] !== pb[k]) return pa[k] < pb[k] ? -1 : 1;
  }
  const ra = pa.prerelease;
  const rb = pb.prerelease;
  if (ra.length === 0 || rb.length === 0) {
    if (ra.length === rb.length) return 0;
    return ra.length === 0 ? 1 : -1;
  }
  for (let i = 0; i < Math.min(ra.length, rb.length); i++) {
    const c = compareIdentifiers(ra[i], rb[i]);
    if (c !== 0) return c;
  }
  return ra.length === rb.length ? 0 : ra.length < rb.length ? -1 : 1;
}
