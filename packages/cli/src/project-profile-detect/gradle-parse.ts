/**
 * Minimal Gradle (Groovy + Kotlin DSL) build-file parser for
 * project-profile detection.
 *
 * Extracts: `group`, `version`, applied plugins, and publishing repository
 * URLs from `publishing { repositories { … } }`. Regex-based — no Gradle
 * tooling dependency.
 */

import type { BuildModule, ModuleSignals } from './types.js';

/**
 * Map Gradle plugin id (`'org.springframework.boot'`, `'java-library'`,
 * `'application'`, `'war'`, `'java-gradle-plugin'`, `'maven-publish'`) to
 * the generic plugin tag used by the resolver. Unknown plugin ids are
 * ignored.
 */
const GRADLE_PLUGIN_MAP: Record<string, string> = {
  'org.springframework.boot':            'spring-boot',
  'io.spring.dependency-management':     'spring-boot',
  'java-library':                        'java-library',
  'application':                         'application',
  'war':                                 'war',
  'ear':                                 'ear',
  'maven-publish':                       'maven-publish',
  'java-gradle-plugin':                  'gradle-plugin',
  'com.gradle.plugin-publish':           'gradle-plugin',
};

// Matches both `id 'org.springframework.boot'` and `id("org.springframework.boot")`.
const PLUGIN_ID_RE = /\bid\s*[(\s]\s*['"]([^'"]+)['"]/g;
// Matches `apply plugin: 'java-library'` (legacy form).
const APPLY_PLUGIN_RE = /\bapply\s+plugin\s*:\s*['"]([^'"]+)['"]/g;
// `group = 'com.example'` or `group("com.example")`.
const GROUP_RE   = /\bgroup\s*[=(]\s*['"]([^'"]+)['"]/;
// `version = '1.2.3'` (very common, applies to both DSLs).
const VERSION_RE = /\bversion\s*[=(]\s*['"]([^'"]+)['"]/;
// `url = uri('https://nexus.example.com/repo')` or `url 'https://…'` inside
// a publishing.repositories block. We don't try to scope: we match all and
// later filter via the public-registry list.
const URL_RE = /\burl\s*[=(]?\s*(?:uri\s*\(\s*)?['"]([^'"]+)['"]/g;

function parsePlugins(text: string): Set<string> {
  const ids = new Set<string>();
  let m: RegExpExecArray | null;
  PLUGIN_ID_RE.lastIndex = 0;
  while ((m = PLUGIN_ID_RE.exec(text)) !== null) ids.add(m[1]);
  APPLY_PLUGIN_RE.lastIndex = 0;
  while ((m = APPLY_PLUGIN_RE.exec(text)) !== null) ids.add(m[1]);

  const out = new Set<string>();
  for (const id of ids) {
    const tag = GRADLE_PLUGIN_MAP[id];
    if (tag) out.add(tag);
  }
  return out;
}

function parseUrls(text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) out.push(m[1]);
  return out;
}

export function parseGradleBuild(
  text: string,
  moduleRoot: string,
  buildFile: string,
  buildSystem: 'gradle' | 'gradle-kts',
  directorySignals: ModuleSignals,
): BuildModule {
  // Strip block comments to keep regex from matching inside commented code.
  const cleaned = text.replace(/\/\*[\s\S]*?\*\//g, '');

  const pluginsSet = parsePlugins(cleaned);
  const urls       = parseUrls(cleaned);
  const groupId    = GROUP_RE.exec(cleaned)?.[1];
  const version    = VERSION_RE.exec(cleaned)?.[1];
  // Gradle modules don't have a single artifactId in the same sense; use
  // the directory name as a best-effort fallback for explain output.
  const artifactId = moduleRoot.split(/[\\/]/).filter(Boolean).pop();

  const signals: ModuleSignals = {
    ...directorySignals,
    plugins: [...directorySignals.plugins, ...pluginsSet],
    distributionUrls: [...directorySignals.distributionUrls, ...urls],
  };

  return {
    root: moduleRoot,
    buildSystem,
    buildFile,
    groupId,
    artifactId,
    version,
    signals,
  };
}
