/**
 * Maven coordinates → Java packages, for `dependencyCalls` (E02).
 *
 * - **From the jar**: the package directories of the resolved artifact's
 *   `.class` entries, read from the zip's central directory only (no entry
 *   is inflated). Multi-release classes (`META-INF/versions/<n>/…`) count
 *   under their own package; other `META-INF/` entries, `module-info` and
 *   classes in the default package do not.
 * - **From the table**: a small fallback for the demo dependencies, used
 *   only when no jar is given.
 *
 * Pure: the caller reads the jar's bytes (the library reads no files).
 */

export type MavenPackageSource = 'jar' | 'table';

export interface MavenPackages {
  /** `groupId:artifactId`, as given without a version. */
  artifact: string;
  /** Sorted, distinct package names. */
  packages: string[];
  source: MavenPackageSource;
}

/** The artifact has no jar and no fallback row, or its jar holds no classes. */
export class UnknownArtifact extends Error {
  constructor(readonly artifact: string, reason: string) {
    super(`${artifact}: ${reason}`);
    this.name = 'UnknownArtifact';
  }
}

/**
 * Package prefixes for the demo dependencies, `groupId:artifactId` → the
 * packages the artifact defines (a package covers its subpackages).
 */
export const MAVEN_PACKAGE_FALLBACK: Readonly<Record<string, readonly string[]>> = {
  'org.apache.logging.log4j:log4j-core': ['org.apache.logging.log4j.core'],
  'com.fasterxml.jackson.core:jackson-databind': ['com.fasterxml.jackson.databind'],
  'com.fasterxml.jackson.core:jackson-core': ['com.fasterxml.jackson.core'],
  'org.yaml:snakeyaml': ['org.yaml.snakeyaml'],
  'org.apache.commons:commons-text': ['org.apache.commons.text'],
  'org.codehaus.plexus:plexus-utils': ['org.codehaus.plexus.util'],
  'com.thoughtworks.xstream:xstream': ['com.thoughtworks.xstream'],
  'commons-collections:commons-collections': ['org.apache.commons.collections'],
  'org.apache.commons:commons-collections4': ['org.apache.commons.collections4'],
};

/** `groupId:artifactId[:…]` → `groupId:artifactId`; throws on anything else. */
export function mavenArtifact(coordinate: string): string {
  const parts = coordinate.trim().split(':');
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    throw new UnknownArtifact(coordinate, 'expected groupId:artifactId');
  }
  return `${parts[0]}:${parts[1]}`;
}

/** The packages for `coordinate`: from `jar` when given, else the fallback table. */
export function mavenPackages(coordinate: string, options: { jar?: Uint8Array } = {}): MavenPackages {
  const artifact = mavenArtifact(coordinate);
  if (options.jar) {
    const packages = jarPackages(options.jar);
    if (packages.length === 0) throw new UnknownArtifact(artifact, 'the jar holds no classes in a named package');
    return { artifact, packages, source: 'jar' };
  }
  const row = MAVEN_PACKAGE_FALLBACK[artifact];
  if (!row) throw new UnknownArtifact(artifact, 'no jar given and no fallback row');
  return { artifact, packages: [...row].sort(), source: 'table' };
}

// ─── Zip central directory ───────────────────────────────────────────────────

const EOCD = 0x06054b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;
const CENTRAL = 0x02014b50;

/** The package names of a jar's `.class` entries, sorted and distinct. */
export function jarPackages(jar: Uint8Array): string[] {
  const out = new Set<string>();
  for (const name of zipEntryNames(jar)) {
    const pkg = classPackage(name);
    if (pkg) out.add(pkg);
  }
  return [...out].sort();
}

function classPackage(entry: string): string | null {
  let name = entry;
  const mr = /^META-INF\/versions\/\d+\//.exec(name);
  if (mr) name = name.slice(mr[0].length);
  else if (name.startsWith('META-INF/')) return null;
  if (!name.endsWith('.class')) return null;
  const slash = name.lastIndexOf('/');
  if (slash <= 0) return null;
  if (name.slice(slash + 1) === 'module-info.class') return null;
  return name.slice(0, slash).replace(/\//g, '.');
}

/** Entry names from the zip's central directory; throws when it is not a zip. */
export function zipEntryNames(zip: Uint8Array): string[] {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  const eocd = findEocd(view);
  if (eocd < 0) throw new Error('not a zip: no end of central directory record');
  let count = view.getUint16(eocd + 10, true);
  let offset = view.getUint32(eocd + 16, true);
  if (count === 0xffff || offset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || view.getUint32(loc, true) !== ZIP64_LOCATOR) throw new Error('zip64 locator missing');
    const z64 = Number(view.getBigUint64(loc + 8, true));
    if (z64 + 56 > zip.byteLength || view.getUint32(z64, true) !== ZIP64_EOCD) throw new Error('zip64 record missing');
    count = Number(view.getBigUint64(z64 + 32, true));
    offset = Number(view.getBigUint64(z64 + 48, true));
  }
  const decoder = new TextDecoder();
  const names: string[] = [];
  let p = offset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > zip.byteLength || view.getUint32(p, true) !== CENTRAL) throw new Error('corrupt central directory');
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    if (p + 46 + nameLen > zip.byteLength) throw new Error('corrupt central directory');
    names.push(decoder.decode(zip.subarray(p + 46, p + 46 + nameLen)));
    p += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

function findEocd(view: DataView): number {
  const min = Math.max(0, view.byteLength - 22 - 0xffff);
  for (let p = view.byteLength - 22; p >= min; p--) {
    if (view.getUint32(p, true) === EOCD) return p;
  }
  return -1;
}
