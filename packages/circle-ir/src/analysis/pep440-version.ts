/**
 * Python version order (PEP 440, https://peps.python.org/pep-0440/), the
 * order OSV's PyPI `ECOSYSTEM` ranges use, and PyPI's package-name
 * normalisation (PEP 503).
 *
 * Normalisation follows PEP 440's rules: case-insensitive; `alpha`/`beta`/
 * `c`/`pre`/`preview` → `a`/`b`/`rc`; `post`/`rev`/`r` and the implicit `-N`
 * post-release; optional separators and implicit `0` numbers; a leading `v`.
 *
 * Order: epoch, then release (trailing zeros ignored), then a dev-only
 * release (`1.0.dev1`) before its pre-releases, pre-releases (`a` < `b` <
 * `rc`) before the release, post-releases after it, dev before the release
 * they precede, and a local version (`+…`) after the same public version.
 *
 * Pure and synchronous; no dependencies.
 */

export interface ParsedPep440 {
  epoch: number;
  release: number[];
  pre: [phase: 'a' | 'b' | 'rc', n: number] | null;
  post: number | null;
  dev: number | null;
  local: Array<number | string>;
}

const PEP440 = new RegExp(
  '^\\s*v?' +
    '(?:(\\d+)!)?' + // epoch
    '(\\d+(?:\\.\\d+)*)' + // release
    '(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\\d+)?)?' + // pre
    '(?:-(\\d+)|[-_.]?(post|rev|r)[-_.]?(\\d+)?)?' + // post
    '(?:[-_.]?(dev)[-_.]?(\\d+)?)?' + // dev
    '(?:\\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?' + // local
    '\\s*$',
  'i',
);

const PRE: Record<string, 'a' | 'b' | 'rc'> = { a: 'a', alpha: 'a', b: 'b', beta: 'b', c: 'rc', rc: 'rc', pre: 'rc', preview: 'rc' };

/** Parse a PEP 440 version, or `null` when it is not one (a specifier, a URL, a name). */
export function parsePep440(version: string): ParsedPep440 | null {
  const m = PEP440.exec(version);
  if (!m) return null;
  const release = m[2].split('.').map(Number);
  while (release.length > 1 && release[release.length - 1] === 0) release.pop();
  const pre = m[3] ? ([PRE[m[3].toLowerCase()], m[4] === undefined ? 0 : Number(m[4])] as ParsedPep440['pre']) : null;
  let post: number | null = null;
  if (m[5] !== undefined) post = Number(m[5]);
  else if (m[6] !== undefined) post = m[7] === undefined ? 0 : Number(m[7]);
  const dev = m[8] !== undefined ? (m[9] === undefined ? 0 : Number(m[9])) : null;
  const local = m[10] ? m[10].toLowerCase().split(/[-_.]/).map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [];
  return { epoch: m[1] === undefined ? 0 : Number(m[1]), release, pre, post, dev, local };
}

const PHASE = { a: 0, b: 1, rc: 2 } as const;

const num = (a: number, b: number): number => (a < b ? -1 : a > b ? 1 : 0);

/** PEP 440's sort key for the pre-release slot: dev-only < pre-releases < none. */
function preKey(v: ParsedPep440): [number, number] {
  if (v.pre === null && v.post === null && v.dev !== null) return [-1, 0];
  if (v.pre === null) return [3, 0];
  return [PHASE[v.pre[0]], v.pre[1]];
}

function compareLocal(a: Array<number | string>, b: Array<number | string>): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (typeof x === 'number' && typeof y === 'number') {
      if (x !== y) return num(x, y);
    } else if (typeof x === 'number') {
      return 1; // numeric segments sort after alphanumeric ones
    } else if (typeof y === 'number') {
      return -1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return num(a.length, b.length);
}

/**
 * Compare two PEP 440 versions: negative, zero or positive. A string that is
 * not a valid version sorts before every valid one, and two such strings
 * compare as plain text, so the order stays total and deterministic.
 */
export function comparePep440(a: string, b: string): number {
  const pa = parsePep440(a);
  const pb = parsePep440(b);
  if (!pa || !pb) {
    if (pa) return 1;
    if (pb) return -1;
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (pa.epoch !== pb.epoch) return num(pa.epoch, pb.epoch);
  for (let i = 0; i < Math.max(pa.release.length, pb.release.length); i++) {
    const c = num(pa.release[i] ?? 0, pb.release[i] ?? 0);
    if (c !== 0) return c;
  }
  const [ka, na] = preKey(pa);
  const [kb, nb] = preKey(pb);
  if (ka !== kb) return num(ka, kb);
  if (na !== nb) return num(na, nb);
  const c = num(pa.post ?? -1, pb.post ?? -1);
  if (c !== 0) return c;
  const d = num(pa.dev ?? Number.POSITIVE_INFINITY, pb.dev ?? Number.POSITIVE_INFINITY);
  if (d !== 0) return d;
  if (pa.local.length === 0 || pb.local.length === 0) return num(pa.local.length, pb.local.length);
  return compareLocal(pa.local, pb.local);
}

/** PEP 503 name normalisation: lower case, runs of `-`, `_`, `.` become `-`. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}
