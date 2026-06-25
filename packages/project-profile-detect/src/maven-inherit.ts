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
 *  - Chain depth capped at `MAX_DEPTH` to bound pathological cases.
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

  for (const child of modules) {
    if (child.buildSystem !== 'maven') continue;
    if (!child.parentRef) continue;

    const inheritedUrls = new Set<string>();
    const inheritedPlugins = new Set<string>();

    walkParents(child, byBuildFile, normalizedScanRoot, inheritedUrls, inheritedPlugins);

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

    for (const u of parent.signals.distributionUrls) outUrls.add(u);
    for (const p of parent.signals.plugins) outPlugins.add(p);

    current = parent;
  }
}
