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
  /**
   * Declared license as an SPDX license expression or name, when the source
   * records it (e.g. `package-lock.json` carries a per-package `license`).
   * Most manifests do not list dependency licenses, so this is usually absent.
   */
  license?: string;
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
  /** SPDX license expression/name for the described project (its own license). */
  license?: string;
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
 * Parse a single PEP 508 requirement string (`name[extras] (>=|==|~=…)ver ; marker`)
 * into `{ name, version }`, or `null` when no name can be read. Shared by the
 * `requirements.txt` and `pyproject.toml` parsers.
 */
function parsePep508(spec: string): { name: string; version: string } | null {
  let s = spec.trim();
  s = s.split(';')[0].trim(); // strip environment marker
  if (!s) return null;
  const m = s.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/);
  if (!m) return null;
  const rest = m[2].trim();
  // First comparator clause's version (drop `,` compound ranges and `(` groups).
  const verMatch = rest.replace(/^\(/, '').match(/^(?:==|>=|<=|~=|!=|>|<|===)?\s*([^,\s)]+)/);
  const version = verMatch && verMatch[1] ? verMatch[1] : 'unknown';
  return { name: m[1], version };
}

/**
 * Parse an npm `package-lock.json` (or `npm-shrinkwrap.json`). Unlike
 * `package.json`, a lockfile pins the *exact resolved* version of every direct
 * and transitive dependency — a far more complete SBOM. Supports:
 *
 *   - **lockfileVersion 2/3** — the `packages` map keyed by install path
 *     (`node_modules/foo`, `node_modules/a/node_modules/b`); the name is the
 *     segment after the final `node_modules/`. The root entry (`""`) is skipped.
 *   - **lockfileVersion 1** — the nested `dependencies` tree.
 *
 * `dev` / `optional` flags map to the scope.
 */
export function parseNpmLockDependencies(packageLock: string): Dependency[] {
  if (!packageLock) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(packageLock);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object') return [];
  const root = parsed as Record<string, unknown>;
  const out: Dependency[] = [];

  const scopeOf = (info: Record<string, unknown>): DependencyScope =>
    info.dev === true ? 'dev' : info.optional === true ? 'optional' : 'required';

  const packages = root.packages;
  if (packages && typeof packages === 'object') {
    for (const [path, raw] of Object.entries(packages as Record<string, unknown>)) {
      if (!path || !raw || typeof raw !== 'object') continue; // skip root ""
      const info = raw as Record<string, unknown>;
      const marker = 'node_modules/';
      const idx = path.lastIndexOf(marker);
      const name = idx >= 0 ? path.slice(idx + marker.length) : (typeof info.name === 'string' ? info.name : path);
      if (!name) continue;
      const version = typeof info.version === 'string' ? info.version : 'unknown';
      const entry = dep('npm', name, version, scopeOf(info));
      if (typeof info.license === 'string' && info.license) entry.license = info.license;
      out.push(entry);
    }
  } else if (root.dependencies && typeof root.dependencies === 'object') {
    const walk = (deps: Record<string, unknown>): void => {
      for (const [name, raw] of Object.entries(deps)) {
        if (!raw || typeof raw !== 'object') continue;
        const info = raw as Record<string, unknown>;
        const version = typeof info.version === 'string' ? info.version : 'unknown';
        out.push(dep('npm', name, version, scopeOf(info)));
        if (info.dependencies && typeof info.dependencies === 'object') {
          walk(info.dependencies as Record<string, unknown>);
        }
      }
    };
    walk(root.dependencies as Record<string, unknown>);
  }

  // A package can resolve at multiple install paths; keep one per name+version+scope.
  const seen = new Set<string>();
  return out.filter((d) => {
    const key = `${d.name}|${d.version}|${d.scope}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Parse a TOML `[[package]]` array (the shared shape of `Cargo.lock` and
 * `poetry.lock`): a sequence of blocks each carrying `name = "..."` and
 * `version = "..."`. Every entry is the resolved dependency set, so all map to
 * the `required` scope — a lockfile does not reliably separate dev packages
 * (Cargo.lock has no such notion; poetry's group data varies by version).
 */
function parseTomlPackageArray(content: string, ecosystem: Ecosystem): Dependency[] {
  const out: Dependency[] = [];
  let name: string | null = null;
  let version: string | null = null;
  let inPackage = false;
  const flush = (): void => {
    if (inPackage && name && version) out.push(dep(ecosystem, name, version, 'required'));
    name = null;
    version = null;
  };
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[[package]]') {
      flush();
      inPackage = true;
      continue;
    }
    if (line.startsWith('[')) {
      // any other table header ends the current package block
      flush();
      inPackage = false;
      continue;
    }
    if (!inPackage) continue;
    const nm = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nm) name = nm[1];
    const vm = line.match(/^version\s*=\s*"([^"]+)"/);
    if (vm) version = vm[1];
  }
  flush();
  return out;
}

/** Parse a Cargo `Cargo.lock` — exact resolved versions of the full crate graph. */
export function parseCargoLockDependencies(cargoLock: string): Dependency[] {
  return cargoLock ? parseTomlPackageArray(cargoLock, 'cargo') : [];
}

/** Parse a Poetry `poetry.lock` — exact resolved versions of the full dependency graph. */
export function parsePoetryLockDependencies(poetryLock: string): Dependency[] {
  return poetryLock ? parseTomlPackageArray(poetryLock, 'pypi') : [];
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
    if (!line) continue;
    const parsed = parsePep508(line);
    if (parsed) out.push(dep('pypi', parsed.name, parsed.version, 'required'));
  }
  return out;
}

/**
 * Parse a `pyproject.toml`. Covers the two dominant layouts:
 *
 *   - **PEP 621** — `[project]` `dependencies = ["flask>=2.0", …]` (required)
 *     and `[project.optional-dependencies]` group arrays (optional).
 *   - **Poetry** — `[tool.poetry.dependencies]` (required, skipping the
 *     `python` version pin) and any `dev`/`group.*` dependency table (dev).
 *
 * TOML is scanned with regex, not a full parser (minimal-deps guardrail).
 */
export function parsePyprojectDependencies(pyprojectToml: string): Dependency[] {
  if (!pyprojectToml) return [];
  const out: Dependency[] = [];

  // Line-scan tracking the current TOML table so `dependencies = [...]` under
  // `[project]` (required) and arrays under `[project.optional-dependencies]`
  // (optional) are distinguished, and Poetry tables are read as key/value.
  const lines = pyprojectToml.split(/\r?\n/);
  let table = '';
  let poetryScope: DependencyScope | null = null;
  let inArray = false;
  let arrayScope: DependencyScope = 'required';

  const pushReq = (raw: string, scope: DependencyScope): void => {
    const cleaned = raw.trim().replace(/^["']|["'],?$/g, '').replace(/,$/, '').trim();
    if (!cleaned) return;
    const parsed = parsePep508(cleaned);
    if (parsed && parsed.name.toLowerCase() !== 'python') out.push(dep('pypi', parsed.name, parsed.version, scope));
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    if (inArray) {
      if (line.startsWith(']')) { inArray = false; continue; }
      pushReq(line, arrayScope);
      continue;
    }

    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      table = header[1];
      if (table === 'tool.poetry.dependencies') poetryScope = 'required';
      else if (/^tool\.poetry\.(dev-dependencies|group\..+\.dependencies)$/.test(table)) poetryScope = 'dev';
      else poetryScope = null;
      continue;
    }

    // PEP 621 array openers.
    const arrayOpen = line.match(/^(dependencies|[A-Za-z0-9._-]+)\s*=\s*\[(.*)$/);
    if (arrayOpen && (arrayOpen[1] === 'dependencies' || table === 'project.optional-dependencies')) {
      arrayScope = arrayOpen[1] === 'dependencies' ? 'required' : 'optional';
      const inline = arrayOpen[2];
      if (inline.includes(']')) {
        // single-line array
        for (const item of inline.slice(0, inline.indexOf(']')).split(',')) pushReq(item, arrayScope);
      } else {
        inArray = true;
        if (inline.trim()) pushReq(inline, arrayScope);
      }
      continue;
    }

    // Poetry table entries: `name = "^1.0"` or `name = { version = "1.0" }`.
    if (poetryScope) {
      const kv = line.match(/^([A-Za-z0-9._-]+)\s*=\s*(.+)$/);
      if (!kv || kv[1].toLowerCase() === 'python') continue;
      let version = 'unknown';
      const strv = kv[2].match(/^["']([^"']+)["']/);
      if (strv) version = strv[1];
      else {
        const inlinev = kv[2].match(/version\s*=\s*["']([^"']+)["']/);
        if (inlinev) version = inlinev[1];
      }
      out.push(dep('pypi', kv[1], version, poetryScope));
    }
  }
  return out;
}

/**
 * Parse a Gradle build script (`build.gradle` Groovy or `build.gradle.kts`
 * Kotlin DSL) dependency block. Recognises the common configurations
 * (`implementation` / `api` / `compileOnly` / `runtimeOnly` /
 * `annotationProcessor` / `kapt` / `classpath` and their `test*` variants) in
 * both `impl 'g:a:v'` and `impl("g:a:v")` forms. Coordinates are Maven, so the
 * ecosystem is `maven` and the name is `groupId:artifactId`. `test*`
 * configurations map to the `dev` scope. `platform(...)` BOM imports are
 * skipped (they declare no concrete artifact).
 */
export function parseGradleDependencies(buildGradle: string): Dependency[] {
  if (!buildGradle) return [];
  const out: Dependency[] = [];
  const re =
    /\b(implementation|api|compileOnly|compileOnlyApi|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|annotationProcessor|kapt|classpath)\s*[(\s]\s*['"]([\w.-]+:[\w.-]+(?::[\w.\-+]+)?)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(buildGradle)) !== null) {
    const config = m[1];
    const coord = m[2].split(':');
    if (coord.length < 2) continue;
    const name = `${coord[0]}:${coord[1]}`;
    const version = coord[2] ?? 'unknown';
    const scope: DependencyScope = config.startsWith('test') ? 'dev' : 'required';
    out.push(dep('maven', name, version, scope));
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
  if (ctx.python?.pyprojectToml) all.push(...parsePyprojectDependencies(ctx.python.pyprojectToml));
  if (ctx.java?.pomXml) all.push(...parseMavenDependencies(ctx.java.pomXml));
  if (ctx.java?.buildGradle) all.push(...parseGradleDependencies(ctx.java.buildGradle));
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
      ...(meta.license ? { licenses: [{ license: { name: meta.license } }] } : {}),
    };
  }
  bom.metadata = metadata;

  bom.components = deps.map((d) => ({
    type: 'library',
    name: d.name,
    version: d.version,
    purl: d.purl,
    scope: d.scope === 'dev' ? 'excluded' : d.scope === 'optional' ? 'optional' : 'required',
    ...(d.license ? { licenses: [{ license: { name: d.license } }] } : {}),
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
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: d.license ?? 'NOASSERTION',
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
