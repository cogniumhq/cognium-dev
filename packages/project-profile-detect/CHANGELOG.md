# Changelog

All notable changes to `@cognium/project-profile-detect` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
