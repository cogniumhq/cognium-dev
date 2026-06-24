# @cognium/project-profile-detect

Detect a Java project's **shape** (`library` / `application` / `cli` / `server` / `plugin`) and **environment** (`production` / `dev` / `sample` / `benchmark` / `test`) from its Maven/Gradle build files. Designed as a caller-side companion to [`circle-ir`](https://www.npmjs.com/package/circle-ir): the detector walks the filesystem and produces a per-file `ProjectProfile` map that circle-ir's `analyzeOptions.projectProfile` consumes.

## Install

```bash
npm install @cognium/project-profile-detect circle-ir
```

`circle-ir` is a **peer dependency** — `ProjectProfile`, `ProjectShape`, and `ProjectEnv` types are owned by circle-ir and re-exported from this package.

## Usage

```ts
import { detectProjectProfiles } from '@cognium/project-profile-detect';
import { analyzeProject } from 'circle-ir';

const detection = await detectProjectProfiles(scanRoot, {
  // Optional: force a single profile for every file in the scan.
  forcedProfile: 'library/production',
  // Optional: glob → profile overrides (from cognium.config.json or similar).
  overrides: {
    'samples/**': 'sample/dev',
    'integration-tests/**': 'application/test',
  },
});

const result = await analyzeProject(files, {
  projectProfile: detection.profileByFile,   // Map<absolutePath, ProjectProfile>
});
```

`DetectionResult` shape:

```ts
interface DetectionResult {
  /** Per-file profile mapping (absolute paths). */
  profileByFile: Map<string, ProjectProfile>;
  /** Per-module resolution details (for explain output). */
  modules: ResolvedModule[];
  /** Files that fell back to 'unknown' (no enclosing module). */
  unknownFiles: string[];
}
```

## Shape resolution

Precedence ladder (highest first):

1. `spring-boot` plugin → `server`
2. `war` / `ear` packaging → `server`
3. `maven-plugin` / `java-gradle-plugin` → `plugin`
4. Gradle `application` plugin → `application`
5. Source file declares `public static void main(String[])` → `application`
6. `java-library` plugin / `module-info.java` / `META-INF/services/` — **hybrid-gated**: only resolves to `library` if the module's distribution URL is on the public-registry allowlist; otherwise falls back to `application` (internal helper library).
7. Otherwise → `unknown`

### Public-registry allowlist

Only these hosts flip the `java-library` signal to `library` (corporate Nexus / Artifactory does NOT count):

- `repo.maven.apache.org`
- `repo1.maven.org`
- `oss.sonatype.org`
- `s01.oss.sonatype.org`
- `central.sonatype.com`
- `central.sonatype.org`
- `plugins.gradle.org`
- `jcenter.bintray.com`

## Environment resolution

Path-based, evaluated **per file**:

| Path contains | Environment |
|---|---|
| `/test/` or `/tests/` | `test` |
| `/samples/`, `/examples/`, `/demo/` | `sample` |
| `/benchmarks/`, `/benchmark/`, `/perf/` | `benchmark` |
| `/src/main/` | `production` |
| anything else | `dev` |

## Why caller-side?

`circle-ir` runs in both Node and browser environments and never reads the filesystem (Pillar I — browser/Node compatibility). Project-profile detection is the caller's responsibility; this package is the reference Node implementation.

See [`circle-ir/docs/ARCHITECTURE.md`](https://github.com/cogniumhq/cognium-dev/blob/main/packages/circle-ir/docs/ARCHITECTURE.md) ADR-008 for the full decision tree and severity-transform contract.

## License

MIT
