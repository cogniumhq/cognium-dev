# Changelog

All notable changes to `@cognium/project-profile-detect` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-06-24

### Added — Maven parent-pom inheritance (#192)
- **`mergeMavenInheritance`** — new second-pass that walks the `<parent><relativePath>` chain for each Maven module and merges inherited `<distributionManagement>` URLs and `<build><plugins>` entries into the child's signals.
- **`MavenParentRef`** type on `BuildModule.parentRef` exposing the parsed `<parent>` block (`groupId`, `artifactId`, `version`, `relativePath`, `emptyRelativePath`).
- Chain walk is bounded: depth cap 6, cycle detection, scan-root boundary enforced (never reads filesystem above `scanRoot` — Pillar I sandbox preserved).
- Empty `<relativePath/>` (Maven's "do not walk workspace" signal) stops the chain.

### Added — Modern publish-plugin recognition (#192)
- `parseMavenPom` now recognises two publish-plugins whose mere presence
  implies public-registry publication, even when no
  `<distributionManagement>` block is declared:
  - `central-publishing-maven-plugin` → synthesises `https://central.sonatype.com/`
  - `nexus-staging-maven-plugin` → synthesises `https://oss.sonatype.org/`
- Both URLs hit `PUBLIC_REGISTRY_HOSTS`, so `isPubliclyPublished` fires and
  the inheritance pass propagates the synthetic URL through the parent chain
  to children that declare neither plugin nor block directly (the langchain4j
  shape: parent carries the publish plugin, children inherit via
  `<parent><relativePath>`).

### Added — Implicit Maven library shape (#192)
- `resolveShape` gains a new branch (5b): a module that is publicly published (per `PUBLIC_REGISTRY_HOSTS` allowlist) but carries no application/server/plugin signals now resolves to `library`. Covers Maven libraries (e.g. langchain4j) that don't declare an explicit `java-library` plugin (Gradle-only), JPMS `module-info.java`, or `META-INF/services` SPI directory.
- Reason chain includes `"public-registry distribution"` and `"no application/server/plugin signals → implicit library"` for `--profile-explain` traceability.

### Why both together
Either fix alone is a no-op against parent-pom-driven Maven repos: inheritance without implicit-library still hits `libSignals.length === 0`, and implicit-library without inheritance still sees `distributionUrls: []` on the child.

### Notes
- No `circle-ir` change. ADR-008 contract unchanged.
- Pillar I-safe: no LLM identifiers introduced.

## [1.0.0] — 2026-06-24

### Added
- Initial release. Extracted from `cognium-dev` CLI 3.106.0 (#169) as a standalone workspace package so that downstream consumers (notably `cognium-ai`) can share the same detection logic without copy-paste drift.
- `detectProjectProfiles(scanRoot, opts)` — walks Maven (`pom.xml`) + Gradle (`build.gradle`, `build.gradle.kts`) build files under `scanRoot`, parses module metadata, and produces a per-file `Map<absolutePath, ProjectProfile>`.
- Re-exports `ProjectProfile`, `ProjectShape`, `ProjectEnv` from `circle-ir` (peer dependency).
- Three-tier resolution: glob overrides > forced profile > owner-module-driven detection > unknown.
- Hybrid Approach C library gate: `java-library` plugin only resolves to `library` when paired with a public-registry distribution URL (`PUBLIC_REGISTRY_HOSTS` allowlist).
- Path-based environment axis evaluated per file (production / dev / sample / benchmark / test).

### Notes
- Pillar I-safe: no LLM identifiers anywhere in source or tests.
- Node-only (uses `fs/promises`, `path`). Not browser-compatible by design — caller-side filesystem walk.
