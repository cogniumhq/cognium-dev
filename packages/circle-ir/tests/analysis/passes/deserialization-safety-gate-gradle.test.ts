/**
 * Tests for cognium-dev #261 (Gradle-first slice) — extends the
 * DeserializationSafetyGatePass Gate A (Fastjson `*_noneautotype`)
 * to also read Gradle build scripts, not just Maven `pom.xml`.
 *
 * Direct integration tests via `analyze()` — same shape as the
 * pomXml-side tests in `deserialization-safety-gate.test.ts`, but
 * exercising the `dependencyContext.java.buildGradle` path.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countDeserSinks = (r: any) =>
  (r.taint?.sinks ?? []).filter((s: any) => s.type === 'deserialization').length;

// ---------------------------------------------------------------------------
// Sample Gradle scripts
// ---------------------------------------------------------------------------

const GRADLE_GROOVY_DIRECT_NONEAUTOTYPE = `
plugins { id 'java' }
repositories { mavenCentral() }
dependencies {
  implementation 'com.alibaba:fastjson:1.2.83_noneautotype'
  testImplementation 'junit:junit:4.13.2'
}
`;

const GRADLE_KOTLIN_PAREN_NONEAUTOTYPE = `
plugins { id("java") }
repositories { mavenCentral() }
dependencies {
    implementation("com.alibaba:fastjson:1.2.83_noneautotype")
    testImplementation("junit:junit:4.13.2")
}
`;

const GRADLE_GROOVY_INTERPOLATED_NONEAUTOTYPE = `
plugins { id 'java' }
ext {
  fastjsonVersion = '1.2.83_noneautotype'
}
repositories { mavenCentral() }
dependencies {
  implementation "com.alibaba:fastjson:\${fastjsonVersion}"
}
`;

const GRADLE_KOTLIN_INTERPOLATED_NONEAUTOTYPE = `
plugins { id("java") }
val fastjsonVersion = "1.2.83_noneautotype"
repositories { mavenCentral() }
dependencies {
    implementation("com.alibaba:fastjson:\$fastjsonVersion")
}
`;

const GRADLE_GROOVY_REGULAR_FASTJSON = `
dependencies {
  implementation 'com.alibaba:fastjson:1.2.83'
}
`;

// A file that uses Fastjson — the code stays fixed across the tests.
const FASTJSON_CODE = [
  'import com.alibaba.fastjson.JSON;',
  'import com.alibaba.fastjson.JSONObject;',
  'import org.springframework.web.bind.annotation.PostMapping;',
  'import org.springframework.web.bind.annotation.RequestBody;',
  '',
  'public class Ctrl {',
  '  @PostMapping("/m")',
  '  public Object m(@RequestBody String payload) {',
  '    JSONObject body = JSON.parseObject(payload);',
  '    return body;',
  '  }',
  '}',
].join('\n');

describe('#261 Gradle-first slice — Gate A (Fastjson noneautotype) from build.gradle', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — Groovy DSL direct literal noneautotype drops the sink', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: { java: { buildGradle: GRADLE_GROOVY_DIRECT_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — Kotlin DSL paren-wrapped noneautotype drops the sink', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: { java: { buildGradle: GRADLE_KOTLIN_PAREN_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — Groovy `ext {}` interpolation resolves to noneautotype and drops the sink', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: { java: { buildGradle: GRADLE_GROOVY_INTERPOLATED_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — Kotlin `val` interpolation resolves to noneautotype and drops the sink', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: { java: { buildGradle: GRADLE_KOTLIN_INTERPOLATED_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — regular Fastjson (non-noneautotype) in Gradle still fires', async () => {
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: { java: { buildGradle: GRADLE_GROOVY_REGULAR_FASTJSON } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — Gradle noneautotype BUT file re-enables autotype: sink still fires', async () => {
    const code = [
      'import com.alibaba.fastjson.JSON;',
      'import com.alibaba.fastjson.parser.ParserConfig;',
      '',
      'public class ReEnable {',
      '  static { ParserConfig.getGlobalInstance().setAutoTypeSupport(true); }',
      '  public Object m(String payload) {',
      '    return JSON.parseObject(payload);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'ReEnable.java', 'java', {
      dependencyContext: { java: { buildGradle: GRADLE_GROOVY_DIRECT_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — Gradle has an unrelated dep (no fastjson): gate no-ops and sink still fires', async () => {
    const gradle = `
dependencies {
  implementation 'com.google.guava:guava:32.1.3-jre'
}
`;
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: { java: { buildGradle: gradle } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Both pom + gradle supplied: pom takes precedence (pom regular → sink fires despite gradle noneautotype)', async () => {
    const pomRegular = `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>x</groupId><artifactId>y</artifactId><version>1</version>
  <properties>
    <fastjson.version>1.2.83</fastjson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.alibaba</groupId><artifactId>fastjson</artifactId>
      <version>\${fastjson.version}</version>
    </dependency>
  </dependencies>
</project>
`;
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: { pomXml: pomRegular, buildGradle: GRADLE_GROOVY_DIRECT_NONEAUTOTYPE },
      },
    });
    // Pom returns { version: '1.2.83', noneAutotype: false }, so the
    // gate does NOT drop the sink even though gradle would.
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Both supplied, gradle noneautotype falls back when pom does NOT resolve fastjson', async () => {
    const pomNoFastjson = `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>x</groupId><artifactId>y</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId><artifactId>guava</artifactId>
      <version>32.1.3-jre</version>
    </dependency>
  </dependencies>
</project>
`;
    const r = await analyze(FASTJSON_CODE, 'Ctrl.java', 'java', {
      dependencyContext: {
        java: { pomXml: pomNoFastjson, buildGradle: GRADLE_GROOVY_DIRECT_NONEAUTOTYPE },
      },
    });
    // Pom returns null (no fastjson block), so gradle is consulted and
    // returns { version: '1.2.83_noneautotype', noneAutotype: true } →
    // sink is dropped.
    expect(countDeserSinks(r)).toBe(0);
  });
});
