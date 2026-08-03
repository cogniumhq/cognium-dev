/**
 * Software Bill of Materials (SBOM) generation.
 *
 * cognium-dev — deterministic SBOM emission (Pillar I). The engine never
 * reads the filesystem (browser-safety); the caller passes raw manifest text
 * via the same {@link DependencyContext} surface the deserialization gate
 * uses (#258/#261). This module turns those manifests into a normalized
 * dependency list and emits two industry formats:
 *
 *   - **CycloneDX 1.5** (`toCycloneDx`) — the OWASP BOM format.
 *   - **SPDX 2.3** (`toSpdx`) — the Linux Foundation format.
 *
 * Both outputs are deterministic: no timestamps, UUIDs, or randomness are
 * introduced here. Volatile document metadata (generation time, serial
 * number, namespace) is *injected* by the caller via {@link SbomMetadata},
 * so a given input always produces byte-identical output unless the caller
 * chooses otherwise — which keeps SBOMs diffable in CI and tests stable.
 *
 * Parsing is regex/`JSON.parse`-scoped, never a full TOML/XML tree: the only
 * runtime dependencies circle-ir permits are `web-tree-sitter` and `yaml`,
 * and a manifest dependency list needs nothing heavier.
 */

import type { DependencyContext } from '../analyzer.js';

/** Package ecosystem, aligned with Package-URL (purl) `pkg:<type>` names. */
export type Ecosystem = 'npm' | 'pypi' | 'maven' | 'cargo' | 'golang';

/** How a dependency is used, mapped from the manifest's declaration site. */
export type DependencyScope = 'required' | 'optional' | 'dev';

/** One normalized dependency, ecosystem-agnostic. */
export interface Dependency {
  /** Package name. For Maven this is `groupId:artifactId`. */
  name: string;
  /** Declared version spec verbatim (e.g. `^3.1.0`, `>=1.2`), or `'unknown'`. */
  version: string;
  ecosystem: Ecosystem;
  scope: DependencyScope;
  /** Package URL (https://github.com/package-url/purl-spec). */
  purl: string;
}

/**
 * Caller-injected document metadata. Everything here is optional; supplying
 * it makes the output richer but non-deterministic (e.g. a real timestamp).
 * Leaving it out yields a minimal, fully-deterministic document.
 */
export interface SbomMetadata {
  /** Name of the project the SBOM describes. */
  name?: string;
  /** Version of the project the SBOM describes. */
  version?: string;
  /** ISO-8601 generation time. Injected — never read from a clock here. */
  timestamp?: string;
  /** CycloneDX `serialNumber` (expected form `urn:uuid:...`). */
  serialNumber?: string;
  /** SPDX `documentNamespace`. Defaults to a cognium.dev URI. */
  namespace?: string;
  /** Generating tool name recorded in the document. Defaults to `circle-ir`. */
  tool?: string;
}

// ---------------------------------------------------------------------------
// purl helpers
// ---------------------------------------------------------------------------

/**
 * Reduce a declared version spec to a clean, exact-ish version for the purl,
 * or `undefined` when the spec is a range/reference we should not pin. A purl
 * without a version is valid, so omitting is preferable to guessing.
 */
function purlVersion(spec: string): string | undefined {
  // Strip range operators/whitespace but NOT a leading `v` — Go module
  // versions (`v1.2.3`) keep it as part of the canonical version.
  const stripped = spec.trim().replace(/^[\s^~=<>]+/, '');
  // Accept a single concrete version token (optional Go `v` prefix); reject
  // residual ranges (`1.0 <2.0`), commas, or unresolved `${...}` / `*`.
  if (/^v?[0-9][\w.\-+]*$/.test(stripped)) return stripped;
  return undefined;
}

/** Percent-encode a purl name segment, preserving the `@scope/name` shape. */
function encodePurlName(name: string): string {
  return name
    .split('/')
    .map((seg) => encodeURIComponent(seg))
    .join('/');
}

function makePurl(ecosystem: Ecosystem, name: string, version: string): string {
  const v = purlVersion(version);
  // Maven names are `groupId:artifactId`; the purl expresses that as the
  // `namespace/name` path (`pkg:maven/groupId/artifactId`).
  const path = ecosystem === 'maven' ? name.replace(':', '/') : name;
  const base = `pkg:${ecosystem}/${encodePurlName(path)}`;
  return v ? `${base}@${encodeURIComponent(v)}` : base;
}

function dep(ecosystem: Ecosystem, name: string, version: string, scope: DependencyScope): Dependency {
  const v = version.trim() || 'unknown';
  return { name, version: v, ecosystem, scope, purl: makePurl(ecosystem, name, v) };
}

// ---------------------------------------------------------------------------
// per-ecosystem manifest parsers
// ---------------------------------------------------------------------------

/**
 * Parse an npm `package.json`. `dependencies` → required,
 * `optionalDependencies` / `peerDependencies` → optional,
 * `devDependencies` → dev. Malformed JSON yields an empty list rather than
 * throwing — a bad manifest should not abort a scan.
 */
export function parseNpmDependencies(packageJson: string): Dependency[] {
  if (!packageJson) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(packageJson);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object') return [];
  const obj = parsed as Record<string, unknown>;
  const out: Dependency[] = [];
  const sections: Array<[string, DependencyScope]> = [
    ['dependencies', 'required'],
    ['optionalDependencies', 'optional'],
    ['peerDependencies', 'optional'],
    ['devDependencies', 'dev'],
  ];
  for (const [key, scope] of sections) {
    const block = obj[key];
    if (!block || typeof block !== 'object') continue;
    for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
      out.push(dep('npm', name, typeof spec === 'string' ? spec : 'unknown', scope));
    }
  }
  return out;
}

/**
 * Parse a pip `requirements.txt`. Handles `name==1.2`, `name>=1.2`, `name~=1`,
 * bare `name`, extras (`name[x]`), and environment markers (`; marker`).
 * Skips comments, blank lines, and option lines (`-r`, `-e`, `--hash`, URLs).
 */
export function parsePypiDependencies(requirementsTxt: string): Dependency[] {
  if (!requirementsTxt) return [];
  const out: Dependency[] = [];
  for (const raw of requirementsTxt.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('-') || /^[a-z]+:\/\//i.test(line)) continue; // options / URLs
    line = line.split('#')[0].trim(); // strip trailing comment
    line = line.split(';')[0].trim(); // strip environment marker
    if (!line) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/);
    if (!m) continue;
    const name = m[1];
    const rest = m[2].trim();
    // Take the first comparator clause's version (drop `,` compound ranges).
    const verMatch = rest.match(/^(?:==|>=|<=|~=|!=|>|<|===)?\s*([^,\s]+)/);
    const version = verMatch && verMatch[1] ? verMatch[1] : 'unknown';
    out.push(dep('pypi', name, version, 'required'));
  }
  return out;
}

/**
 * Parse a Maven `pom.xml` `<dependency>` blocks. Name is `groupId:artifactId`.
 * `<scope>test|provided</scope>` → dev, `<optional>true</optional>` → optional.
 * A `${...}` version is recorded as `unknown` (unresolved property reference).
 */
export function parseMavenDependencies(pomXml: string): Dependency[] {
  if (!pomXml) return [];
  const out: Dependency[] = [];
  const depRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = depRe.exec(pomXml)) !== null) {
    const block = m[1];
    const gid = block.match(/<groupId>\s*([^<\s]+)\s*<\/groupId>/)?.[1];
    const aid = block.match(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/)?.[1];
    if (!gid || !aid) continue;
    let version = block.match(/<version>\s*([^<\s]+)\s*<\/version>/)?.[1] ?? 'unknown';
    if (version.startsWith('${')) version = 'unknown';
    const mvnScope = block.match(/<scope>\s*([^<\s]+)\s*<\/scope>/)?.[1];
    const optional = /<optional>\s*true\s*<\/optional>/.test(block);
    const scope: DependencyScope =
      mvnScope === 'test' || mvnScope === 'provided' ? 'dev' : optional ? 'optional' : 'required';
    out.push(dep('maven', `${gid}:${aid}`, version, scope));
  }
  return out;
}

/**
 * Parse a Cargo `Cargo.toml`. `[dependencies]` → required,
 * `[dev-dependencies]` → dev, `[build-dependencies]` → optional. Handles both
 * `name = "1.2"` and `name = { version = "1.2", ... }` forms.
 */
export function parseCargoDependencies(cargoToml: string): Dependency[] {
  if (!cargoToml) return [];
  const out: Dependency[] = [];
  let scope: DependencyScope | null = null;
  for (const raw of cargoToml.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const section = line.match(/^\[([^\]]+)\]$/);
    if (section) {
      const s = section[1];
      if (s === 'dependencies') scope = 'required';
      else if (s === 'dev-dependencies') scope = 'dev';
      else if (s === 'build-dependencies') scope = 'optional';
      else scope = null; // some other table — stop collecting until next dep table
      continue;
    }
    if (!scope) continue;
    const kv = line.match(/^([A-Za-z0-9._-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const name = kv[1];
    const value = kv[2].trim();
    let version = 'unknown';
    if (value.startsWith('"') || value.startsWith("'")) {
      version = value.replace(/^["']|["'].*$/g, '');
    } else {
      const inline = value.match(/version\s*=\s*["']([^"']+)["']/);
      if (inline) version = inline[1];
    }
    out.push(dep('cargo', name, version, scope));
  }
  return out;
}

/**
 * Parse a Go `go.mod`. Collects `require` directives in both the grouped
 * `require ( ... )` block and single-line `require path v1.2.3` forms.
 * A `// indirect` marker maps to the `optional` scope. The module path is
 * the purl name (`pkg:golang/github.com/foo/bar@v1.2.3`).
 */
export function parseGoDependencies(goMod: string): Dependency[] {
  if (!goMod) return [];
  const out: Dependency[] = [];
  let inBlock = false;
  for (const raw of goMod.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('//')) continue;
    if (!inBlock && /^require\s*\($/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    let spec: string;
    if (inBlock) spec = line;
    else if (/^require\s+/.test(line)) spec = line.replace(/^require\s+/, '');
    else continue;
    const indirect = /\/\/\s*indirect/.test(spec);
    spec = spec.replace(/\/\/.*$/, '').trim();
    const m = spec.match(/^(\S+)\s+(\S+)$/);
    if (!m) continue;
    out.push(dep('golang', m[1], m[2], indirect ? 'optional' : 'required'));
  }
  return out;
}

// ---------------------------------------------------------------------------
// aggregation
// ---------------------------------------------------------------------------

/**
 * Parse every manifest present in a {@link DependencyContext} into one
 * de-duplicated dependency list. De-dup key is `ecosystem|name|version|scope`,
 * so the same package declared once stays once but a genuine dev/required
 * split is preserved.
 */
export function collectDependencies(ctx: DependencyContext | undefined): Dependency[] {
  if (!ctx) return [];
  const all: Dependency[] = [];
  if (ctx.js?.packageJson) all.push(...parseNpmDependencies(ctx.js.packageJson));
  if (ctx.python?.requirementsTxt) all.push(...parsePypiDependencies(ctx.python.requirementsTxt));
  if (ctx.java?.pomXml) all.push(...parseMavenDependencies(ctx.java.pomXml));
  if (ctx.rust?.cargoToml) all.push(...parseCargoDependencies(ctx.rust.cargoToml));

  const seen = new Set<string>();
  const deduped: Dependency[] = [];
  for (const d of all) {
    const key = `${d.ecosystem}|${d.name}|${d.version}|${d.scope}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(d);
  }
  return deduped;
}

// ---------------------------------------------------------------------------
// emitters
// ---------------------------------------------------------------------------

/** Emit a CycloneDX 1.5 BOM document object (serialize with `JSON.stringify`). */
export function toCycloneDx(deps: Dependency[], meta: SbomMetadata = {}): Record<string, unknown> {
  const bom: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
  };
  if (meta.serialNumber) bom.serialNumber = meta.serialNumber;

  const metadata: Record<string, unknown> = {};
  if (meta.timestamp) metadata.timestamp = meta.timestamp;
  metadata.tools = [{ vendor: 'Cognium', name: meta.tool ?? 'circle-ir' }];
  if (meta.name) {
    metadata.component = {
      type: 'application',
      name: meta.name,
      ...(meta.version ? { version: meta.version } : {}),
    };
  }
  bom.metadata = metadata;

  bom.components = deps.map((d) => ({
    type: 'library',
    name: d.name,
    version: d.version,
    purl: d.purl,
    scope: d.scope === 'dev' ? 'excluded' : d.scope === 'optional' ? 'optional' : 'required',
    'bom-ref': d.purl,
  }));
  return bom;
}

/** SPDX identifiers allow only `[a-zA-Z0-9.-]`; sanitize everything else. */
function spdxId(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9.-]/g, '-');
}

/** Emit an SPDX 2.3 document object (serialize with `JSON.stringify`). */
export function toSpdx(deps: Dependency[], meta: SbomMetadata = {}): Record<string, unknown> {
  const docName = meta.name ?? 'document';
  const packages = deps.map((d, i) => ({
    SPDXID: `SPDXRef-Package-${spdxId(d.ecosystem)}-${spdxId(d.name)}-${i}`,
    name: d.name,
    versionInfo: d.version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    externalRefs: [
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: d.purl,
      },
    ],
  }));

  const relationships = packages.map((p) => ({
    spdxElementId: 'SPDXRef-DOCUMENT',
    relatedSpdxElement: p.SPDXID,
    relationshipType: 'DESCRIBES',
  }));

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: docName,
    documentNamespace: meta.namespace ?? `https://cognium.dev/spdxdocs/${spdxId(docName)}`,
    creationInfo: {
      created: meta.timestamp ?? '1970-01-01T00:00:00Z',
      creators: [`Tool: ${meta.tool ?? 'circle-ir'}`],
    },
    packages,
    relationships,
  };
}
