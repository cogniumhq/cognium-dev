/**
 * Project-profile detection types (cognium-dev CLI side).
 *
 * Mirrors `ProjectProfile` from circle-ir but adds detector-internal types
 * needed to walk the filesystem and reason about per-module shape/env.
 *
 * See `packages/circle-ir/docs/ARCHITECTURE.md` ADR-008 for the design
 * contract. Pillar I: no LLM-themed identifiers.
 */

import type { ProjectProfile, ProjectShape, ProjectEnv } from 'circle-ir';

export type { ProjectProfile, ProjectShape, ProjectEnv };

/**
 * One detected build-file boundary in the scan tree. Each `BuildModule`
 * corresponds to a `pom.xml`, `build.gradle`, or `build.gradle.kts` and
 * owns every source file under its directory that isn't claimed by a
 * deeper module.
 */
export interface BuildModule {
  /** Absolute path to the module root directory (the build-file's dir). */
  root: string;
  /** Build system that produced this module. */
  buildSystem: 'maven' | 'gradle' | 'gradle-kts';
  /** Absolute path to the build file. */
  buildFile: string;
  /** Module's parsed coordinates, when available. */
  groupId?: string;
  artifactId?: string;
  version?: string;
  /** Raw plugin / dependency / packaging signals collected by parsers. */
  signals: ModuleSignals;
}

/**
 * Signals collected from a single build file. The detector composes these
 * with directory-shape heuristics to resolve a final `ProjectProfile`.
 */
export interface ModuleSignals {
  /**
   * Build-file plugins that strongly indicate shape:
   *  - `'spring-boot'`     → application/server
   *  - `'java-library'`    → library
   *  - `'application'`     → cli/application (Gradle `application` plugin)
   *  - `'war'` / `'ear'`   → server
   *  - `'maven-publish'`   → publication intent (any shape)
   *  - `'maven-plugin'`    → plugin
   * Free-form lowercase identifiers; unknown plugins are ignored.
   */
  plugins: string[];

  /** Maven `<packaging>` element value, when present. */
  packaging?: string;

  /**
   * Distribution-management URL(s). Used to classify publication target as
   * public (Maven Central / Sonatype / Gradle Plugins Portal) vs internal
   * (corporate Nexus / Artifactory). See `publication-detect.ts`.
   */
  distributionUrls: string[];

  /** Whether the build file's directory contains a `module-info.java`. */
  hasJpmsModuleInfo: boolean;

  /** Whether the build file's directory contains a `META-INF/services/` resource dir. */
  hasSpiServices: boolean;

  /** Whether at least one source file declares `public static void main(...)`. */
  hasMainMethod: boolean;
}

/**
 * Result of resolving a single module to a `ProjectProfile` plus the
 * evidence the detector used. Useful for the `--profile-explain` CLI flag.
 */
export interface ResolvedModule {
  module: BuildModule;
  profile: ProjectProfile;
  /** Short human-readable reason chain, e.g. `['spring-boot plugin', 'env=production']`. */
  reasons: string[];
}

/**
 * Final detector output. Maps each scanned source file to its resolved
 * `ProjectProfile`. Files not under any detected module map to `'unknown'`.
 */
export interface DetectionResult {
  /** Per-file profile mapping (absolute paths). */
  profileByFile: Map<string, ProjectProfile>;
  /** Per-module resolution details (for explain output). */
  modules: ResolvedModule[];
  /** Files that fell back to `'unknown'` (no enclosing module). */
  unknownFiles: string[];
}

/**
 * Glob-keyed override map sourced from `cognium.config.json`
 * `profileOverrides`. Keys are glob patterns; values are `ProjectProfile`
 * strings (or `'unknown'` to explicitly mask a directory).
 */
export type ProfileOverrides = Record<string, ProjectProfile>;
