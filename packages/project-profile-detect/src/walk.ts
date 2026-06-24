/**
 * Filesystem walker for project-profile detection.
 *
 * Discovers all build-file boundaries (`pom.xml`, `build.gradle`,
 * `build.gradle.kts`) under a scan root, and for each one collects the
 * directory-level signals the parsers need (presence of `module-info.java`,
 * `META-INF/services/`, source files containing `main(String[])`).
 *
 * Pillar I: Node-only module. Caller-side detector — circle-ir itself
 * never reads the filesystem.
 */

import { readdir, readFile, stat } from 'fs/promises';
import { join, relative } from 'path';
import type { BuildModule, ModuleSignals } from './types.js';
import { parseMavenPom } from './maven-parse.js';
import { parseGradleBuild } from './gradle-parse.js';

const BUILD_FILES = ['pom.xml', 'build.gradle', 'build.gradle.kts'] as const;

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg',
  'target', 'build', 'out', 'dist',
  '.gradle', '.idea', '.vscode',
  'bin', 'obj',
]);

/**
 * Walk `scanRoot` and return one `BuildModule` per detected build file.
 * Modules are emitted in pre-order so that a parent module appears before
 * any nested submodule (the resolver uses this ordering to give the
 * deepest module ownership of a given source file).
 */
export async function discoverBuildModules(scanRoot: string): Promise<BuildModule[]> {
  const modules: BuildModule[] = [];
  await walk(scanRoot, modules);
  return modules;
}

async function walk(dir: string, out: BuildModule[]): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }

  // Identify a build file in this directory, if any.
  const buildFile = entries.find(e => (BUILD_FILES as readonly string[]).includes(e));
  if (buildFile) {
    const buildFilePath = join(dir, buildFile);
    const buildSystem: BuildModule['buildSystem'] =
      buildFile === 'pom.xml' ? 'maven'
        : buildFile === 'build.gradle.kts' ? 'gradle-kts'
        : 'gradle';

    const signals = await collectDirectorySignals(dir);
    let mod: BuildModule;
    try {
      const raw = await readFile(buildFilePath, 'utf-8');
      mod = buildSystem === 'maven'
        ? parseMavenPom(raw, dir, buildFilePath, signals)
        : parseGradleBuild(raw, dir, buildFilePath, buildSystem, signals);
    } catch {
      mod = { root: dir, buildSystem, buildFile: buildFilePath, signals };
    }
    out.push(mod);
  }

  // Recurse into children.
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry) || entry.startsWith('.')) continue;
    const full = join(dir, entry);
    let s;
    try {
      s = await stat(full);
    } catch {
      continue;
    }
    if (s.isDirectory()) {
      await walk(full, out);
    }
  }
}

/**
 * Collect directory-level signals: JPMS module-info presence, SPI
 * services directory presence, and whether any Java source under the
 * module's `src/main/java` declares a `main(String[])`.
 *
 * Scoped to the module's own `src/main/java` (and its `src/main/resources`)
 * so signals from a deeper submodule don't bleed in.
 */
async function collectDirectorySignals(moduleRoot: string): Promise<ModuleSignals> {
  const signals: ModuleSignals = {
    plugins: [],
    distributionUrls: [],
    hasJpmsModuleInfo: false,
    hasSpiServices: false,
    hasMainMethod: false,
  };

  const javaRoot = join(moduleRoot, 'src', 'main', 'java');
  const resourcesRoot = join(moduleRoot, 'src', 'main', 'resources');

  // module-info.java may live at the root of src/main/java.
  try {
    await stat(join(javaRoot, 'module-info.java'));
    signals.hasJpmsModuleInfo = true;
  } catch { /* missing → leave false */ }

  // META-INF/services/ under resources.
  try {
    const s = await stat(join(resourcesRoot, 'META-INF', 'services'));
    if (s.isDirectory()) signals.hasSpiServices = true;
  } catch { /* missing → leave false */ }

  // Scan src/main/java for any `main(String[])`. Capped to keep startup snappy.
  try {
    signals.hasMainMethod = await scanForMainMethod(javaRoot, 200);
  } catch { /* missing or unreadable → leave false */ }

  return signals;
}

const MAIN_METHOD_RE = /\bpublic\s+static\s+void\s+main\s*\(\s*(?:final\s+)?String\s*(?:\[\s*\]|\.{3})/;

async function scanForMainMethod(root: string, maxFiles: number): Promise<boolean> {
  let visited = 0;
  const stack: string[] = [root];
  while (stack.length > 0 && visited < maxFiles) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = join(dir, e);
      let s;
      try {
        s = await stat(full);
      } catch {
        continue;
      }
      if (s.isDirectory()) {
        stack.push(full);
      } else if (s.isFile() && e.endsWith('.java')) {
        visited++;
        try {
          const text = await readFile(full, 'utf-8');
          if (MAIN_METHOD_RE.test(text)) return true;
        } catch { /* unreadable → skip */ }
        if (visited >= maxFiles) break;
      }
    }
  }
  return false;
}

/**
 * Enumerate every regular file under `scanRoot` that the analyzer will
 * touch. Used to build the `profileByFile` map even for files outside any
 * detected module (they fall back to `'unknown'`).
 */
export async function enumerateScanFiles(scanRoot: string): Promise<string[]> {
  const out: string[] = [];
  await enumerate(scanRoot, out);
  return out;
}

async function enumerate(dir: string, out: string[]): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e) || e.startsWith('.')) continue;
    const full = join(dir, e);
    let s;
    try {
      s = await stat(full);
    } catch {
      continue;
    }
    if (s.isDirectory()) {
      await enumerate(full, out);
    } else if (s.isFile()) {
      out.push(full);
    }
  }
}

/**
 * Find the most specific (deepest) module that owns `file`. Returns
 * `undefined` if no module's root is a prefix of the file path.
 */
export function ownerOf(file: string, modules: BuildModule[]): BuildModule | undefined {
  let best: BuildModule | undefined;
  let bestLen = -1;
  for (const m of modules) {
    if (file === m.root || file.startsWith(m.root + '/')) {
      if (m.root.length > bestLen) {
        best = m;
        bestLen = m.root.length;
      }
    }
  }
  return best;
}

/** Re-export of `relative` for callers that want a stable import surface. */
export { relative };
