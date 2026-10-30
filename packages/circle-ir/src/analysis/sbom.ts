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

import { parse as parseYaml } from 'yaml';
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
  /**
   * Whether the project declares this dependency itself. Set only by inputs
   * that carry the graph (`mvn dependency:tree`); absent when unknown.
   */
  direct?: boolean;
  /**
   * The path from a direct dependency down to this one's parent, as
   * `groupId:artifactId` names: `[]` for a direct dependency. Set only by
   * inputs that carry the graph (`mvn dependency:tree`); absent when unknown.
   */
  via?: string[];
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

// ---------------------------------------------------------------------------
// pnpm / yarn lockfiles (cognium-dev: E02 npm resolved sets, DT4)
// ---------------------------------------------------------------------------

/** A lockfile-resolved package node: identity, the edges it pins, and its flags. */
interface LockNode {
  name: string;
  version: string;
  deps: string[];
  flagDev?: boolean;
  flagOptional?: boolean;
}

/** One project root's declared dependencies, as lock-node keys. */
interface LockRoots {
  required: string[];
  optional: string[];
  dev: string[];
}

/**
 * Scope every node by reachability from the project roots: reached from a
 * production root → `required`; else from an optional root → `optional`;
 * else from a dev root → `dev`. A node no root reaches keeps the lockfile's
 * own flag (pnpm v5/v6 `dev` / `optional`), else `required`.
 * `direct` is set when any root names the node; `undefined` when `hasRoots`
 * is false (the input did not carry the project's declarations).
 */
function scopeLockNodes(nodes: Map<string, LockNode>, roots: LockRoots, hasRoots: boolean): Dependency[] {
  const reach = (starts: string[]): Set<string> => {
    const seen = new Set<string>();
    const stack = starts.filter((k) => nodes.has(k));
    while (stack.length > 0) {
      const k = stack.pop() as string;
      if (seen.has(k)) continue;
      seen.add(k);
      for (const next of nodes.get(k)?.deps ?? []) if (nodes.has(next) && !seen.has(next)) stack.push(next);
    }
    return seen;
  };
  const prod = reach(roots.required);
  const opt = reach(roots.optional);
  const dev = reach(roots.dev);
  const direct = new Set([...roots.required, ...roots.optional, ...roots.dev]);

  const out: Dependency[] = [];
  const seen = new Set<string>();
  for (const [key, n] of [...nodes.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    let scope: DependencyScope;
    if (prod.has(key)) scope = 'required';
    else if (opt.has(key)) scope = 'optional';
    else if (dev.has(key)) scope = 'dev';
    else scope = n.flagDev ? 'dev' : n.flagOptional ? 'optional' : 'required';
    const id = `${n.name}|${n.version}|${scope}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const d = dep('npm', n.name, n.version, scope);
    if (hasRoots) d.direct = direct.has(key);
    out.push(d);
  }
  return out;
}

/** Split `name@version` (name may be `@scope/name`). */
function splitAt(spec: string): { name: string; rest: string } | null {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: spec.slice(0, at), rest: spec.slice(at + 1) };
}

/** Drop pnpm's peer suffix: `1.2.3(react@18.2.0)` → `1.2.3`; v5 `1.2.3_react@18` → `1.2.3`. */
function stripPnpmPeers(v: string): string {
  const paren = v.indexOf('(');
  let out = paren >= 0 ? v.slice(0, paren) : v;
  const us = out.indexOf('_');
  if (us > 0) out = out.slice(0, us);
  return out;
}

/** Local or workspace references are the project's own code, not npm packages. */
const PNPM_LOCAL = /^(link:|file:|workspace:|portal:)/;

/**
 * Turn a pnpm package key into `{ name, version }`:
 *   - v9: `name@1.2.3` / `name@1.2.3(peer@x)`
 *   - v6: `/name@1.2.3(peer@x)`
 *   - v5: `/name/1.2.3_peer@x` / `/@scope/name/1.2.3`
 */
function parsePnpmKey(rawKey: string): { name: string; version: string } | null {
  let key = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;
  // v5 slash form first: its peer suffix (`_react@18`) contains an `@`.
  const v5 = key.match(/^(@[^/@]+\/[^/@]+|[^/@]+)\/(\d[^/]*)$/);
  if (v5) return { name: v5[1], version: stripPnpmPeers(v5[2]) };
  const paren = key.indexOf('(');
  if (paren >= 0) key = key.slice(0, paren);
  const at = splitAt(key);
  if (at && /^\d/.test(at.rest)) return { name: at.name, version: stripPnpmPeers(at.rest) };
  return null;
}

/**
 * Resolve a dependency reference inside a pnpm lockfile to a node key
 * (`name@version`). A reference is a version (`1.2.3`, `1.2.3(peer)`), a
 * path key (`/other@1.0.0`, v5 `/other/1.0.0`) or an alias (`other@1.0.0`).
 * Returns `null` for local/workspace links.
 */
function pnpmRef(depName: string, ref: unknown): string | null {
  if (typeof ref !== 'string') return null;
  if (PNPM_LOCAL.test(ref)) return null;
  if (/^\d/.test(ref)) return `${depName}@${stripPnpmPeers(ref)}`;
  const parsed = parsePnpmKey(ref);
  return parsed ? `${parsed.name}@${parsed.version}` : null;
}

/** The version of an importer entry: v6/v9 `{ specifier, version }`, v5 a plain string. */
function importerVersion(entry: unknown): unknown {
  if (entry && typeof entry === 'object' && 'version' in (entry as Record<string, unknown>)) {
    return (entry as Record<string, unknown>).version;
  }
  return entry;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/**
 * Parse a `pnpm-lock.yaml` (lockfile formats 5.x, 6.0 and 9.0) into exact
 * resolved npm dependencies, direct and transitive.
 *
 * - **Roots:** every importer (`importers['.']`, `importers['packages/x']`, …),
 *   or, in single-project v5/v6 files, the top-level `dependencies` /
 *   `devDependencies` / `optionalDependencies`. Workspace and local links
 *   (`link:`, `file:`, `workspace:`) are the project's own packages and are
 *   not listed.
 * - **Scope:** by reachability from the roots (prod → `required`, optional
 *   roots → `optional`, dev-only → `dev`); a package no root reaches keeps
 *   pnpm v5/v6's own `dev` / `optional` flag.
 * - **direct:** `true` for a package an importer declares, else `false`.
 *
 * Peer-dependency variants of one version (`a@1.0.0(react@17)`,
 * `a@1.0.0(react@18)`) collapse into one entry. Malformed YAML yields `[]`.
 */
export function parsePnpmLockDependencies(pnpmLock: string): Dependency[] {
  if (!pnpmLock) return [];
  let root: Record<string, unknown> | undefined;
  try {
    root = asRecord(parseYaml(pnpmLock, { uniqueKeys: false }));
  } catch {
    return [];
  }
  if (!root) return [];

  const nodes = new Map<string, LockNode>();
  const addNode = (rawKey: string, info: Record<string, unknown> | undefined): void => {
    const id = parsePnpmKey(rawKey);
    if (!id) return;
    const key = `${id.name}@${id.version}`;
    const node = nodes.get(key) ?? { name: id.name, version: id.version, deps: [] };
    if (info) {
      for (const section of ['dependencies', 'optionalDependencies']) {
        for (const [n, ref] of Object.entries(asRecord(info[section]) ?? {})) {
          const k = pnpmRef(n, ref);
          if (k && !node.deps.includes(k)) node.deps.push(k);
        }
      }
      if (info.dev === true) node.flagDev = true;
      if (info.optional === true) node.flagOptional = true;
    }
    nodes.set(key, node);
  };
  for (const [k, v] of Object.entries(asRecord(root.packages) ?? {})) addNode(k, asRecord(v));
  // v9 keeps the graph in `snapshots`, identities in `packages`.
  for (const [k, v] of Object.entries(asRecord(root.snapshots) ?? {})) addNode(k, asRecord(v));

  const roots: LockRoots = { required: [], optional: [], dev: [] };
  const importers = asRecord(root.importers);
  const projects: Record<string, unknown>[] = importers
    ? Object.values(importers).map(asRecord).filter((x): x is Record<string, unknown> => Boolean(x))
    : [root];
  for (const project of projects) {
    for (const [section, bucket] of [
      ['dependencies', roots.required],
      ['optionalDependencies', roots.optional],
      ['devDependencies', roots.dev],
    ] as const) {
      for (const [n, entry] of Object.entries(asRecord(project[section]) ?? {})) {
        const k = pnpmRef(n, importerVersion(entry));
        if (k) bucket.push(k);
      }
    }
  }
  return scopeLockNodes(nodes, roots, true);
}

/**
 * The project directories a `pnpm-lock.yaml` covers, relative to the
 * lockfile (`.` for the root). A workspace lockfile resolves every listed
 * package, so it supersedes each of their `package.json` files (DT4).
 * Single-project lockfiles return `['.']`; malformed YAML returns `[]`.
 */
export function pnpmLockImporters(pnpmLock: string): string[] {
  if (!pnpmLock) return [];
  let root: Record<string, unknown> | undefined;
  try {
    root = asRecord(parseYaml(pnpmLock, { uniqueKeys: false }));
  } catch {
    return [];
  }
  if (!root) return [];
  const importers = asRecord(root.importers);
  return importers ? Object.keys(importers).sort() : ['.'];
}

/** Unquote a yarn v1 token: `"@babel/core@^7.0.0"` → `@babel/core@^7.0.0`. */
function yarnUnquote(s: string): string {
  const t = s.trim();
  return t.length >= 2 && t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
}

/**
 * Parse a Yarn classic (v1) `yarn.lock` into exact resolved npm
 * dependencies. Yarn v1 records no dev or direct marker, so:
 *
 * - with only the lockfile, every package is `required` and `direct` is
 *   absent (unknown);
 * - with the project's `package.json` as the second argument, scope and
 *   `direct` come from reachability, as for pnpm.
 *
 * Yarn Berry (v2+, a YAML file with `__metadata`) is not handled and yields
 * `[]`. Malformed entries are skipped.
 */
export function parseYarnLockDependencies(yarnLock: string, packageJson?: string): Dependency[] {
  if (!yarnLock) return [];
  if (/^__metadata:/m.test(yarnLock)) return [];

  const nodes = new Map<string, LockNode>();
  const specToKey = new Map<string, string>();
  const pendingDeps: Array<[string, string[]]> = [];

  let specs: string[] = [];
  let version: string | undefined;
  let deps: string[] = [];
  let inDeps = false;
  const flush = (): void => {
    if (specs.length > 0 && version) {
      const first = splitAt(specs[0]);
      if (first) {
        const key = `${first.name}@${version}`;
        if (!nodes.has(key)) nodes.set(key, { name: first.name, version, deps: [] });
        for (const s of specs) specToKey.set(s, key);
        pendingDeps.push([key, deps]);
      }
    }
    specs = [];
    version = undefined;
    deps = [];
    inDeps = false;
  };

  for (const rawLine of yarnLock.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trimStart().startsWith('#')) continue;
    const indent = rawLine.length - rawLine.trimStart().length;
    const line = rawLine.trim();
    if (indent === 0) {
      flush();
      if (!line.endsWith(':')) continue;
      specs = line.slice(0, -1).split(',').map(yarnUnquote).filter(Boolean);
      continue;
    }
    if (indent <= 2) {
      inDeps = false;
      const m = line.match(/^(\S+)\s+(.+)$/);
      if (line === 'dependencies:' || line === 'optionalDependencies:') {
        inDeps = true;
      } else if (m && yarnUnquote(m[1]) === 'version') {
        version = yarnUnquote(m[2]);
      }
      continue;
    }
    if (inDeps) {
      const m = line.match(/^(\S+)\s+(.+)$/);
      if (m) deps.push(`${yarnUnquote(m[1])}@${yarnUnquote(m[2])}`);
    }
  }
  flush();

  for (const [key, ds] of pendingDeps) {
    const node = nodes.get(key);
    if (!node) continue;
    for (const s of ds) {
      const k = specToKey.get(s);
      if (k && !node.deps.includes(k)) node.deps.push(k);
    }
  }

  const roots: LockRoots = { required: [], optional: [], dev: [] };
  let hasRoots = false;
  if (packageJson) {
    try {
      const pkg = asRecord(JSON.parse(packageJson));
      if (pkg) {
        hasRoots = true;
        for (const [section, bucket] of [
          ['dependencies', roots.required],
          ['peerDependencies', roots.required],
          ['optionalDependencies', roots.optional],
          ['devDependencies', roots.dev],
        ] as const) {
          for (const [n, range] of Object.entries(asRecord(pkg[section]) ?? {})) {
            if (typeof range !== 'string') continue;
            const k = specToKey.get(`${n}@${range}`);
            if (k) bucket.push(k);
          }
        }
      }
    } catch {
      hasRoots = false;
    }
  }
  return scopeLockNodes(nodes, roots, hasRoots);
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
 * Parse a Gradle dependency lockfile — the resolved, exact versions of every
 * direct and transitive dependency, per configuration. Two layouts:
 *
 *   - **`gradle.lockfile`** (Gradle 6.4+, one file per project):
 *     `group:artifact:version=conf1,conf2,…`; the `empty=…` line lists
 *     configurations that resolved nothing and is skipped.
 *   - **`gradle/dependency-locks/<configuration>.lockfile`** (older, one file
 *     per configuration): bare `group:artifact:version` lines. The
 *     configuration is the file name, which the caller may pass as
 *     `configuration`; without it the entries count as `required`.
 *
 * A dependency is `dev` only when every configuration that resolved it is a
 * test configuration (`test…`, or `…Test…` such as `integrationTestRuntimeClasspath`);
 * any other configuration makes it `required`. Comment lines (`#`) are skipped.
 */
export function parseGradleLockfile(lockfile: string, configuration?: string): Dependency[] {
  if (!lockfile) return [];
  const out: Dependency[] = [];
  const seen = new Set<string>();
  for (const raw of lockfile.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    const coordPart = eq >= 0 ? line.slice(0, eq).trim() : line;
    if (coordPart === 'empty') continue;
    const coord = coordPart.split(':');
    if (coord.length !== 3 || coord.some((c) => !c)) continue;
    const configs =
      eq >= 0
        ? line.slice(eq + 1).split(',').map((c) => c.trim()).filter(Boolean)
        : configuration
          ? [configuration]
          : [];
    const scope: DependencyScope =
      configs.length > 0 && configs.every(isGradleTestConfiguration) ? 'dev' : 'required';
    const name = `${coord[0]}:${coord[1]}`;
    const key = `${name}|${coord[2]}|${scope}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(dep('maven', name, coord[2], scope));
  }
  return out;
}

function isGradleTestConfiguration(config: string): boolean {
  return /^test[A-Z]?/.test(config) || /Test[A-Z]/.test(config);
}

/** Maven scopes as printed by `dependency:list` / `dependency:tree`. */
const MAVEN_SCOPES = 'compile|provided|runtime|test|system|import';

/**
 * Coordinate as Maven prints it in resolved output:
 * `groupId:artifactId:type[:classifier]:version:scope`.
 */
const MAVEN_RESOLVED_COORD = new RegExp(
  `^([\\w.-]+):([\\w.-]+):([\\w.-]+)(?::([\\w.-]+))?:([^:\\s()]+):(${MAVEN_SCOPES})\\b(.*)$`,
);

/**
 * Parse the text output of `mvn dependency:list` or `mvn dependency:tree`
 * (console or `-DoutputFile`): the dependency set Maven actually resolved,
 * direct and transitive, after mediation. A `pom.xml` alone cannot give this —
 * versions come from parents, BOMs and nearest-wins mediation — so the caller
 * runs Maven (in a build sandbox) and hands the text here; the engine never
 * runs a build.
 *
 * Accepts `[INFO]` prefixes, tree drawing (`+-`, `|`, `\-`), the module
 * suffix newer plugins print (`-- module x`), and the root project line of a
 * tree (skipped: it has no scope). Verbose-tree entries that Maven did **not**
 * resolve (`omitted for conflict with …`) are skipped; `omitted for duplicate`
 * entries collapse into the one kept. `test` / `provided` → `dev`, a trailing
 * `(optional)` → `optional`, everything else → `required`. From a tree, each
 * entry also carries `direct` and `via` (its path from a direct dependency).
 */
export function parseMavenResolvedDependencies(output: string): Dependency[] {
  if (!output) return [];
  const out: Dependency[] = [];
  const seen = new Set<string>();
  const lines = output.split(/\r?\n/).map((raw) => raw.replace(/^\s*\[(?:INFO|WARNING|DEBUG)\]\s?/, ''));
  // A tree carries the graph: depth from indentation (3 columns per level),
  // the path from the stack of ancestors. A list does not.
  const isTree = lines.some((l) => /^[\s|]*[+\\]- /.test(l));
  const ancestors: string[] = [];
  for (const raw of lines) {
    const depth = isTree ? Math.round(raw.search(/[A-Za-z0-9(]/) / 3) : -1;
    if (/omitted for conflict/.test(raw)) continue;
    // Strip tree drawing and the verbose-tree parenthesis around an entry.
    const line = raw.replace(/^[\s|+\\`-]*/, '').replace(/^\(/, '').trim();
    const m = MAVEN_RESOLVED_COORD.exec(line);
    if (!m) {
      // A root (project) line of a tree starts a new graph.
      if (isTree && depth === 0 && /^[\w.-]+:[\w.-]+:/.test(line)) ancestors.length = 0;
      continue;
    }
    const [, gid, aid, , , version, mvnScope, rest] = m;
    const name = `${gid}:${aid}`;
    let via: string[] | undefined;
    if (isTree && depth >= 1) {
      ancestors.length = depth - 1;
      via = ancestors.slice();
      ancestors.push(name);
    }
    const optional = /\(optional\)/.test(rest);
    const scope: DependencyScope =
      mvnScope === 'test' || mvnScope === 'provided' ? 'dev' : optional ? 'optional' : 'required';
    const key = `${name}|${version}|${scope}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const d = dep('maven', name, version, scope);
    if (via) {
      d.direct = via.length === 0;
      d.via = via;
    }
    out.push(d);
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
  // npm resolved sets (exact + transitive) supersede `package.json` (DT4):
  // pnpm > package-lock > yarn when more than one is supplied.
  if (ctx.js?.pnpmLock) all.push(...parsePnpmLockDependencies(ctx.js.pnpmLock));
  else if (ctx.js?.packageLock) all.push(...parseNpmLockDependencies(ctx.js.packageLock));
  else if (ctx.js?.yarnLock) all.push(...parseYarnLockDependencies(ctx.js.yarnLock, ctx.js.packageJson));
  else if (ctx.js?.packageJson) all.push(...parseNpmDependencies(ctx.js.packageJson));
  if (ctx.python?.requirementsTxt) all.push(...parsePypiDependencies(ctx.python.requirementsTxt));
  if (ctx.python?.pyprojectToml) all.push(...parsePyprojectDependencies(ctx.python.pyprojectToml));
  // Resolved Java dependency sets (exact + transitive) supersede the declared
  // manifest they came from, as a lockfile does for npm, Cargo and Poetry.
  if (ctx.java?.mavenResolved) all.push(...parseMavenResolvedDependencies(ctx.java.mavenResolved));
  else if (ctx.java?.pomXml) all.push(...parseMavenDependencies(ctx.java.pomXml));
  if (ctx.java?.gradleLockfile) all.push(...parseGradleLockfile(ctx.java.gradleLockfile));
  else if (ctx.java?.buildGradle) all.push(...parseGradleDependencies(ctx.java.buildGradle));
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
// licences (offline; the library never reads files or the network)
// ---------------------------------------------------------------------------

/**
 * Offline licence map: keys are `name@version` (exact) or `name` (any
 * version); values are SPDX expressions or names. `name@version` wins.
 */
export type LicenseMap = Record<string, string>;

/**
 * The licence a package's own `package.json` declares, as one expression:
 * `license` (string, or the legacy `{ type }` object), else the legacy
 * `licenses: [{ type }]` array joined with ` OR `. `undefined` when the text
 * does not parse or declares none.
 */
export function licenseFromPackageJson(packageJson: string): string | undefined {
  let pkg: unknown;
  try { pkg = JSON.parse(packageJson); } catch { return undefined; }
  if (!pkg || typeof pkg !== 'object') return undefined;
  const rec = pkg as Record<string, unknown>;
  const one = (v: unknown): string | undefined => {
    if (typeof v === 'string' && v.trim()) return v.trim();
    if (v && typeof v === 'object') {
      const t = (v as Record<string, unknown>).type;
      if (typeof t === 'string' && t.trim()) return t.trim();
    }
    return undefined;
  };
  const direct = one(rec.license);
  if (direct) return direct;
  if (Array.isArray(rec.licenses)) {
    const all = rec.licenses.map(one).filter((x): x is string => !!x);
    if (all.length === 1) return all[0];
    if (all.length > 1) return `(${all.join(' OR ')})`;
  }
  return undefined;
}

/**
 * Fill in `license` from an offline map for dependencies that have none.
 * Returns new objects; an existing `license` is never overwritten.
 */
export function applyLicenses(deps: Dependency[], map: LicenseMap): Dependency[] {
  return deps.map((d) => {
    if (d.license) return d;
    const lic = map[`${d.name}@${d.version}`] ?? map[d.name];
    return lic ? { ...d, license: lic } : d;
  });
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
