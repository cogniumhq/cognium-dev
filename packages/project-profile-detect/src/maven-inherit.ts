/**
 * Maven parent-pom inheritance pass.
 *
 * After `discoverBuildModules` collects all build files, this pass walks the
 * `<parent><relativePath>` chain for every Maven module and merges
 * inheritable signals (distributionManagement URLs + build plugins) from
 * ancestors into the child's `signals`.
 *
 * Scope of inheritance (intentionally narrow — Maven's full inheritance
 * model is much richer):
 *  - `signals.distributionUrls` (set union)
 *  - `signals.plugins`          (set union)
 *
 * NOT inherited:
 *  - `groupId`/`artifactId`/`version`/`packaging` — module identity
 *  - `hasJpmsModuleInfo`/`hasSpiServices`/`hasMainMethod` — filesystem-local
 *
 * Safety:
 *  - Chain depth capped at `MAX_DEPTH`, enforced as a true horizon: the walk
 *    reads a snapshot of each ancestor's OWN signals taken before any merging,
 *    so a module can never inherit values that another module merged in first
 *    (cognium-dev #290). Without the snapshot the effective horizon was
 *    unbounded and the result depended on filesystem discovery order.
 *  - Cycle detection via visited-path Set.
 *  - Scan-root boundary enforced — never follow `<relativePath>` that
 *    resolves outside `scanRoot` (Pillar I sandboxing).
 *  - Empty `<relativePath/>` is a Maven "do not walk the workspace" signal;
 *    chain walk stops.
 *  - Parents that exist on disk but weren't discovered by the walker
 *    (e.g. excluded by SKIP_DIRS) are simply absent from the lookup map
 *    and the walk stops there.
 */

import { dirname, isAbsolute, normalize, relative, resolve } from 'path';
import type { BuildModule } from './types.js';

/** Maximum parent-chain depth. Real-world Maven repos rarely exceed 4. */
const MAX_DEPTH = 6;

/** Maven default when a child pom omits `<relativePath>`. */
const DEFAULT_RELATIVE_PATH = '../pom.xml';

/**
 * Merge inherited distributionUrls + plugins from each Maven module's
 * parent chain into the module's own `signals`. Operates in place.
 *
 * Non-Maven modules and Maven modules without a `parentRef` are
 * untouched.
 */
export function mergeMavenInheritance(modules: BuildModule[], scanRoot: string): void {
  const normalizedScanRoot = normalize(scanRoot);

  // Index Maven modules by their absolute buildFile path for chain lookup.
  const byBuildFile = new Map<string, BuildModule>();
  for (const m of modules) {
    if (m.buildSystem === 'maven') {
      byBuildFile.set(normalize(m.buildFile), m);
    }
  }

  // cognium-dev #290 — snapshot each module's OWN signals before any merging.
  // `walkParents` used to read the live `parent.signals` arrays, which this
  // same loop mutates. A module processed early absorbed its ancestors' values
  // and wrote them into its own signals; a module processed later then walked
  // into it and inherited those too. That made `MAX_DEPTH` no bound at all and
  // made the output depend on directory-iteration order, so the same project
  // could yield different `distributionUrls` on different machines.
  const ownSignals = new Map<string, { urls: readonly string[]; plugins: readonly string[] }>();
  for (const [buildFile, m] of byBuildFile) {
    ownSignals.set(buildFile, {
      urls: [...m.signals.distributionUrls],
      plugins: [...m.signals.plugins],
    });
  }

  for (const child of modules) {
    if (child.buildSystem !== 'maven') continue;
    if (!child.parentRef) continue;

    const inheritedUrls = new Set<string>();
    const inheritedPlugins = new Set<string>();

    walkParents(
      child,
      byBuildFile,
      ownSignals,
      normalizedScanRoot,
      inheritedUrls,
      inheritedPlugins,
    );

    if (inheritedUrls.size === 0 && inheritedPlugins.size === 0) continue;

    // Merge into child (set union — preserves order of existing entries).
    const existingUrls = new Set(child.signals.distributionUrls);
    for (const u of inheritedUrls) {
      if (!existingUrls.has(u)) child.signals.distributionUrls.push(u);
    }
    const existingPlugins = new Set(child.signals.plugins);
    for (const p of inheritedPlugins) {
      if (!existingPlugins.has(p)) child.signals.plugins.push(p);
    }
  }
}

function walkParents(
  start: BuildModule,
  byBuildFile: Map<string, BuildModule>,
  ownSignals: Map<string, { urls: readonly string[]; plugins: readonly string[] }>,
  scanRoot: string,
  outUrls: Set<string>,
  outPlugins: Set<string>,
): void {
  const visited = new Set<string>([normalize(start.buildFile)]);
  let current: BuildModule = start;

  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    const ref = current.parentRef;
    if (!ref) return;
    if (ref.emptyRelativePath) return;

    const childDir = dirname(current.buildFile);
    const rel = ref.relativePath ?? DEFAULT_RELATIVE_PATH;
    const candidateAbs = normalize(
      isAbsolute(rel) ? rel : resolve(childDir, rel),
    );

    // A <relativePath> may point at a directory (Maven convention: the
    // directory implicitly contains pom.xml) or at a pom.xml file.
    const parentBuildFile = candidateAbs.endsWith('pom.xml')
      ? candidateAbs
      : normalize(resolve(candidateAbs, 'pom.xml'));

    // Scan-root boundary. `relative` returns a path starting with `..` when
    // `parentBuildFile` is outside `scanRoot`.
    const relToRoot = relative(scanRoot, parentBuildFile);
    if (relToRoot.startsWith('..') || isAbsolute(relToRoot)) return;

    if (visited.has(parentBuildFile)) return; // cycle
    visited.add(parentBuildFile);

    const parent = byBuildFile.get(parentBuildFile);
    if (!parent) return; // parent not discovered by walker → stop

    // Read the ancestor's OWN pre-merge signals, never the live arrays (#290).
    const parentOwn = ownSignals.get(parentBuildFile);
    if (parentOwn) {
      for (const u of parentOwn.urls) outUrls.add(u);
      for (const p of parentOwn.plugins) outPlugins.add(p);
    }

    current = parent;
  }
}
