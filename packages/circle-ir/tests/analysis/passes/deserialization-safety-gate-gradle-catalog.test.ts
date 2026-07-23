/**
 * Tests for cognium-dev #261 (Gradle catalog slice) — extends the
 * Fastjson gate to read `gradle/libs.versions.toml` version-catalog
 * references (`libs.<alias>` accessors in build.gradle).
 *
 * Direct integration tests via `analyze()`. The catalog resolver is
 * the third fallback in the Gate A chain, after pomXml and the direct
 * buildGradle form.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countDeserSinks = (r: any) =>
  (r.taint?.sinks ?? []).filter((s: any) => s.type === 'deserialization').length;

// ---------------------------------------------------------------------------
// Fastjson-using Java code (fixed across the tests)
// ---------------------------------------------------------------------------

const FASTJSON_CODE = [
  'import com.alibaba.fastjson.JSON;',
  'import com.alibaba.fastjson.JSONObject;',
  '',
  'public class Ctrl {',
  '  public Object m(String payload) { return JSON.parseObject(payload); }',
  '}',
].join('\n');

// ---------------------------------------------------------------------------
// Catalog fixtures
// ---------------------------------------------------------------------------

// Standard shape: [versions] + [libraries] with version.ref, noneautotype.
const CATALOG_MODULE_VERSION_REF = `
[versions]
fastjson = "1.2.83_noneautotype"
tokio = "1.36.0"

[libraries]
fastjson = { module = "com.alibaba:fastjson", version.ref = "fastjson" }
junit = { module = "junit:junit", version.ref = "junit" }
`;

// Group + name split form (equivalent to module).
const CATALOG_GROUP_NAME_VERSION_REF = `
[versions]
fastjson = "1.2.83_noneautotype"

[libraries]
fastjson = { group = "com.alibaba", name = "fastjson", version.ref = "fastjson" }
`;

// Inline version on the library entry (no [versions] indirection).
const CATALOG_INLINE_VERSION = `
[libraries]
fastjson = { module = "com.alibaba:fastjson", version = "1.2.83_noneautotype" }
`;

// Regular (non-noneautotype) fastjson.
const CATALOG_REGULAR = `
[versions]
fastjson = "1.2.83"

[libraries]
fastjson = { module = "com.alibaba:fastjson", version.ref = "fastjson" }
`;

// Fastjson defined but NOT referenced from build.gradle — should not
// suppress.
const CATALOG_UNREFERENCED = `
[versions]
fastjson = "1.2.83_noneautotype"

[libraries]
fastjson = { module = "com.alibaba:fastjson", version.ref = "fastjson" }
`;

// Custom alias name that doesn't equal 'fastjson'.
const CATALOG_ALIAS_MISMATCH = `
[versions]
sentinel-fastjson = "1.2.83_noneautotype"

[libraries]
sentinel-fastjson = { module = "com.alibaba:fastjson", version.ref = "sentinel-fastjson" }
`;

const GRADLE_USES_FASTJSON = `
dependencies {
  implementation libs.fastjson
  implementation libs.junit
}
`;

const GRADLE_USES_SENTINEL_ALIAS = `
dependencies {
  implementation(libs.sentinel-fastjson)
}
`;

const GRADLE_USES_JUNIT_ONLY = `
dependencies {
  implementation libs.junit
}
`;

describe('#261 Gradle catalog slice — libs.versions.toml resolution', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — module + version.ref → noneautotype drops the sink', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: GRADLE_USES_FASTJSON,
          libsVersionsToml: CATALOG_MODULE_VERSION_REF,
        },
      },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — group + name split form also resolves', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: GRADLE_USES_FASTJSON,
          libsVersionsToml: CATALOG_GROUP_NAME_VERSION_REF,
        },
      },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — inline version on library entry (no [versions] indirection)', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: GRADLE_USES_FASTJSON,
          libsVersionsToml: CATALOG_INLINE_VERSION,
        },
      },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — custom alias (sentinel-fastjson) also resolves when the build.gradle references it', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: GRADLE_USES_SENTINEL_ALIAS,
          libsVersionsToml: CATALOG_ALIAS_MISMATCH,
        },
      },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — regular (non-noneautotype) fastjson catalog: sink still fires', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: GRADLE_USES_FASTJSON,
          libsVersionsToml: CATALOG_REGULAR,
        },
      },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — catalog defines fastjson but build.gradle does NOT reference it: no suppression', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: GRADLE_USES_JUNIT_ONLY,
          libsVersionsToml: CATALOG_UNREFERENCED,
        },
      },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — catalog supplied without buildGradle: gate no-ops and sink still fires', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: { libsVersionsToml: CATALOG_MODULE_VERSION_REF },
      },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Direct-form buildGradle takes precedence over catalog (both supplied, direct-form regular → sink fires despite catalog noneautotype)', async () => {
    const gradleDirectRegular = `
dependencies {
  implementation 'com.alibaba:fastjson:1.2.83'
  implementation libs.fastjson
}
`;
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: {
          buildGradle: gradleDirectRegular,
          libsVersionsToml: CATALOG_MODULE_VERSION_REF,
        },
      },
    });
    // The direct-form regex matches first and returns
    // { version: '1.2.83', noneAutotype: false }, so the fastjson
    // resolver chain does NOT fall through to the catalog resolver.
    // Sink still fires.
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});
