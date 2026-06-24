/**
 * Project-profile detector entry point.
 *
 * `detectProjectProfiles(scanRoot, options)` walks the scan tree, parses
 * every build file (Maven + Gradle), resolves each module to a
 * `ProjectProfile`, then maps every enumerated source file to its owning
 * module's profile (optionally overridden by glob entries from
 * `cognium.config.json`).
 *
 * Output is consumed by the caller and passed to circle-ir's
 * `analyzeOptions.projectProfile` as a `Map<file, ProjectProfile>`.
 *
 * Pillar I: Node-only module. Detection lives entirely on the caller
 * side; circle-ir itself never reads the filesystem.
 *
 * See `circle-ir/docs/ARCHITECTURE.md` ADR-008.
 */

import { relative } from 'path';
import type {
  DetectionResult, ProjectProfile, ProfileOverrides, ResolvedModule,
} from './types.js';
import {
  discoverBuildModules, enumerateScanFiles, ownerOf,
} from './walk.js';
import { resolveShape } from './shape-resolve.js';
import { resolveEnv } from './env-resolve.js';
import { compileOverrides, applyOverrides } from './overrides.js';

export type { DetectionResult, ProjectProfile, ProfileOverrides, ResolvedModule };

export interface DetectOptions {
  /**
   * Forced shape (from `--profile=<shape>/<env>` CLI flag or
   * `cognium.config.json` top-level `profile`). When set, every file
   * resolves to `<shape>/<env-from-path>` regardless of build-file
   * signals. Glob overrides still take precedence.
   */
  forcedProfile?: ProjectProfile;
  /** Glob → profile overrides from `cognium.config.json`. */
  overrides?: ProfileOverrides;
}

export async function detectProjectProfiles(
  scanRoot: string,
  options: DetectOptions = {},
): Promise<DetectionResult> {
  const modules = await discoverBuildModules(scanRoot);
  const files   = await enumerateScanFiles(scanRoot);
  const compiledOverrides = compileOverrides(options.overrides);

  // Resolve each module's shape once.
  const resolvedByRoot = new Map<string, ResolvedModule>();
  const resolvedModules: ResolvedModule[] = [];
  for (const m of modules) {
    const sr = resolveShape(m);
    // Per-module profile uses the module *root* for env resolution, so a
    // module whose root lives under `examples/` is itself a `sample`.
    const moduleEnv = resolveEnv(m.root);
    const profile: ProjectProfile = sr.shape === 'unknown'
      ? 'unknown'
      : `${sr.shape}/${moduleEnv}`;
    const r: ResolvedModule = { module: m, profile, reasons: sr.reasons };
    resolvedByRoot.set(m.root, r);
    resolvedModules.push(r);
  }

  const profileByFile = new Map<string, ProjectProfile>();
  const unknownFiles: string[] = [];

  for (const file of files) {
    // 1. Glob overrides win over everything.
    const rel = relative(scanRoot, file);
    const ov = applyOverrides(rel, compiledOverrides);
    if (ov) {
      profileByFile.set(file, ov.profile);
      continue;
    }

    // 2. Forced profile via `--profile=` flag: per-file env still resolved
    //    from path.
    if (options.forcedProfile && options.forcedProfile !== 'unknown') {
      const [shape] = options.forcedProfile.split('/');
      const env = resolveEnv(file);
      profileByFile.set(file, `${shape}/${env}` as ProjectProfile);
      continue;
    }

    // 3. Owner-module-driven detection.
    const owner = ownerOf(file, modules);
    if (!owner) {
      profileByFile.set(file, 'unknown');
      unknownFiles.push(file);
      continue;
    }
    const ownerResolution = resolvedByRoot.get(owner.root);
    if (!ownerResolution || ownerResolution.profile === 'unknown') {
      profileByFile.set(file, 'unknown');
      unknownFiles.push(file);
      continue;
    }
    // Per-file env axis (path-based) overrides the module's env when the
    // file lives under `test/`, `samples/`, etc.
    const [shape] = ownerResolution.profile.split('/');
    const env = resolveEnv(file);
    profileByFile.set(file, `${shape}/${env}` as ProjectProfile);
  }

  return { profileByFile, modules: resolvedModules, unknownFiles };
}
