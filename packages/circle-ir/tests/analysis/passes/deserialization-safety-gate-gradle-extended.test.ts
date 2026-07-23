/**
 * Tests for cognium-dev #261 (Gradle extended forms) — covers the
 * shapes beyond the direct-literal / property-interpolation MVP:
 *
 *   - `constraints { }` block with direct declaration (already
 *     handled by the direct-form regex; pinning test)
 *   - `constraints { }` block with `version { strictly 'X' }` sub-
 *     block (new in this ship)
 *   - `subprojects { }` / `allprojects { }` conditional declarations
 *     (already handled by direct-form; pinning tests)
 *   - `enforcedPlatform(...)` when the argument IS `com.alibaba:fastjson`
 *     itself (already handled; pinning test)
 *
 * NOT included — deliberately deferred as out-of-scope:
 *
 *   - `platform('com.alibaba:fastjson-bom:X')` where the BOM is a
 *     separate artifact from `fastjson` itself. Gradle BOMs
 *     recommend versions for OTHER artifacts; the BOM's own version
 *     does not automatically tell us the fastjson version. Returning
 *     null on this shape is CORRECT.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countDeserSinks = (r: any) =>
  (r.taint?.sinks ?? []).filter((s: any) => s.type === 'deserialization').length;

const FASTJSON_CODE = [
  'import com.alibaba.fastjson.JSON;',
  '',
  'public class C {',
  '  public Object m(String payload) { return JSON.parseObject(payload); }',
  '}',
].join('\n');

describe('#261 Gradle extended forms', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — constraints{} with `version { strictly \'X\' }` sub-block (NEW in this ship)', async () => {
    const gradle = `
dependencies {
  constraints {
    implementation('com.alibaba:fastjson') {
      version {
        strictly '1.2.83_noneautotype'
      }
    }
  }
  implementation 'com.alibaba:fastjson'
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — constraints{} with `version { require \'X\' }` sub-block', async () => {
    const gradle = `
dependencies {
  constraints {
    implementation('com.alibaba:fastjson') {
      version { require '1.2.83_noneautotype' }
    }
  }
  implementation 'com.alibaba:fastjson'
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — constraints{} with direct declaration (already handled by direct-form regex)', async () => {
    const gradle = `
dependencies {
  constraints {
    implementation 'com.alibaba:fastjson:1.2.83_noneautotype'
  }
  implementation 'com.alibaba:fastjson'
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — subprojects{} direct declaration', async () => {
    const gradle = `
subprojects {
  dependencies {
    implementation 'com.alibaba:fastjson:1.2.83_noneautotype'
  }
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — allprojects{} direct declaration', async () => {
    const gradle = `
allprojects {
  dependencies {
    implementation 'com.alibaba:fastjson:1.2.83_noneautotype'
  }
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — enforcedPlatform() where arg IS com.alibaba:fastjson (not a separate BOM)', async () => {
    const gradle = `
dependencies {
  implementation enforcedPlatform('com.alibaba:fastjson:1.2.83_noneautotype')
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock (deliberate no-op) — platform(fastjson-bom) does NOT suppress; BOM version ≠ fastjson version', async () => {
    // Gradle BOMs recommend versions for OTHER artifacts; the BOM's
    // own version string does not tell us the fastjson version.
    // The gate correctly returns null and the sink fires.
    const gradle = `
dependencies {
  implementation platform('com.alibaba:fastjson-bom:1.2.83_noneautotype')
  implementation 'com.alibaba:fastjson'
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — constraints{} strictly with regular (non-noneautotype) version: sink still fires', async () => {
    const gradle = `
dependencies {
  constraints {
    implementation('com.alibaba:fastjson') {
      version {
        strictly '1.2.83'
      }
    }
  }
}
`;
    const r = await analyze(FASTJSON_CODE, 'C.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});
