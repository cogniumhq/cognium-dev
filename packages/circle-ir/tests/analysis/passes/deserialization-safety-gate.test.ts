/**
 * Tests for cognium-dev #258 — DeserializationSafetyGatePass.
 *
 * Three sub-gates, exercised via `AnalyzerOptions.dependencyContext`
 * (Gate A) and via file-local scanning (Gates B + C):
 *
 *   Gate A — Fastjson `*_noneautotype` build (from pom.xml)
 *   Gate B — Jackson polymorphism not enabled in-file
 *   Gate C — SnakeYAML `SafeConstructor` in-file
 *
 * Each gate has both FP-suppression and recall-lock coverage. Recall
 * locks confirm that the gate stays defensive on missing / partial
 * signals (a resolver miss must fall through to the current
 * over-firing behaviour, never to a false negative).
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countDeserSinks = (r: any) =>
  (r.taint?.sinks ?? []).filter((s: any) => s.type === 'deserialization').length;

// ---------------------------------------------------------------------------
// Sample manifests
// ---------------------------------------------------------------------------

const POM_FASTJSON_NONEAUTOTYPE = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>sentinel-dashboard</artifactId>
  <version>1.0.0</version>
  <properties>
    <fastjson.version>1.2.83_noneautotype</fastjson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.alibaba</groupId>
      <artifactId>fastjson</artifactId>
      <version>\${fastjson.version}</version>
    </dependency>
  </dependencies>
</project>
`;

const POM_FASTJSON_REGULAR = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>example</artifactId>
  <version>1.0.0</version>
  <properties>
    <fastjson.version>1.2.83</fastjson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.alibaba</groupId>
      <artifactId>fastjson</artifactId>
      <version>\${fastjson.version}</version>
    </dependency>
  </dependencies>
</project>
`;

// ---------------------------------------------------------------------------
// Gate A — Fastjson `*_noneautotype`
// ---------------------------------------------------------------------------

describe('#258 Gate A — Fastjson noneautotype (manifest-based)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — Sentinel-shape parseObject with 1.2.83_noneautotype pom drops the deser sink', async () => {
    // Verbatim from the ticket: Sentinel ClusterConfigController.java:76
    const code = [
      'import com.alibaba.fastjson.JSON;',
      'import com.alibaba.fastjson.JSONObject;',
      'import org.springframework.web.bind.annotation.PostMapping;',
      'import org.springframework.web.bind.annotation.RequestBody;',
      '',
      'public class ClusterConfigController {',
      '  @PostMapping("/config/modify_single")',
      '  public Object apiModifyClusterConfig(@RequestBody String payload) {',
      '    JSONObject body = JSON.parseObject(payload);',
      '    return body;',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'ClusterConfigController.java', 'java', {
      dependencyContext: { java: { pomXml: POM_FASTJSON_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — same code with a regular (non-noneautotype) Fastjson still fires', async () => {
    const code = [
      'import com.alibaba.fastjson.JSON;',
      'import com.alibaba.fastjson.JSONObject;',
      '',
      'public class C {',
      '  public Object m(String payload) {',
      '    return JSON.parseObject(payload);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java', {
      dependencyContext: { java: { pomXml: POM_FASTJSON_REGULAR } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — noneautotype pom BUT file re-enables autotype: sink still fires', async () => {
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
      dependencyContext: { java: { pomXml: POM_FASTJSON_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — no pomXml supplied: gate no-ops and sink still fires', async () => {
    const code = [
      'import com.alibaba.fastjson.JSON;',
      '',
      'public class C {',
      '  public Object m(String payload) {',
      '    return JSON.parseObject(payload);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java'); // no dependencyContext
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Gate B — Jackson polymorphism not enabled
// ---------------------------------------------------------------------------

describe('#258 Gate B — Jackson polymorphism not enabled (in-file)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — ObjectMapper.readValue in a file with no enableDefaultTyping or @JsonTypeInfo drops the deser sink', async () => {
    const code = [
      'import com.fasterxml.jackson.databind.ObjectMapper;',
      '',
      'public class Safe {',
      '  private static final ObjectMapper MAPPER = new ObjectMapper();',
      '  public User parse(String payload) throws Exception {',
      '    return MAPPER.readValue(payload, User.class);',
      '  }',
      '  static class User { public String name; }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Safe.java', 'java');
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — enableDefaultTyping in file: sink still fires', async () => {
    // Use `Class.forName(userType)` so the pre-existing
    // safe_if_class_literal_at gate (#22 / #256) does not pre-suppress
    // the sink; that gate's recall lock is that `Class.forName` calls
    // return null from the type resolver → gate defaults dangerous.
    const code = [
      'import com.fasterxml.jackson.databind.ObjectMapper;',
      '',
      'public class Dangerous {',
      '  private static final ObjectMapper MAPPER;',
      '  static {',
      '    MAPPER = new ObjectMapper();',
      '    MAPPER.enableDefaultTyping();',
      '  }',
      '  public Object parse(String payload, String userType) throws Exception {',
      '    return MAPPER.readValue(payload, Class.forName(userType));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Dangerous.java', 'java');
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — @JsonTypeInfo in file: sink still fires', async () => {
    // Same reasoning as above — dynamic class arg keeps
    // safe_if_class_literal_at from pre-suppressing the sink.
    const code = [
      'import com.fasterxml.jackson.annotation.JsonTypeInfo;',
      'import com.fasterxml.jackson.databind.ObjectMapper;',
      '',
      '@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)',
      'abstract class Base {}',
      '',
      'public class D {',
      '  private final ObjectMapper mapper = new ObjectMapper();',
      '  public Object parse(String payload, String userType) throws Exception {',
      '    return mapper.readValue(payload, Class.forName(userType));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'D.java', 'java');
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Gate C — SnakeYAML SafeConstructor
// ---------------------------------------------------------------------------

describe('#258 Gate C — SnakeYAML SafeConstructor (in-file)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — new Yaml(new SafeConstructor()).load(input) drops the deser sink', async () => {
    const code = [
      'import org.yaml.snakeyaml.Yaml;',
      'import org.yaml.snakeyaml.constructor.SafeConstructor;',
      '',
      'public class Safe {',
      '  public Object parse(String input) {',
      '    Yaml yaml = new Yaml(new SafeConstructor());',
      '    return yaml.load(input);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Safe.java', 'java');
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — new Yaml() (default constructor) load still fires', async () => {
    const code = [
      'import org.yaml.snakeyaml.Yaml;',
      '',
      'public class Dangerous {',
      '  public Object parse(String input) {',
      '    Yaml yaml = new Yaml();',
      '    return yaml.load(input);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Dangerous.java', 'java');
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Cross-gate isolation
// ---------------------------------------------------------------------------

describe('#258 — cross-gate isolation', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('Fastjson pom does NOT suppress a Jackson sink in the same file', async () => {
    // The pom is Fastjson-noneautotype, but the code uses Jackson with
    // enableDefaultTyping (unsafe). Gate A should not fire on the
    // Jackson sink; Gate B should not fire because polymorphism IS
    // enabled. Dynamic class arg keeps safe_if_class_literal_at
    // (#22 / #256) from pre-suppressing before our gate sees it.
    const code = [
      'import com.fasterxml.jackson.databind.ObjectMapper;',
      '',
      'public class Mixed {',
      '  private final ObjectMapper mapper;',
      '  public Mixed() {',
      '    mapper = new ObjectMapper();',
      '    mapper.enableDefaultTyping();',
      '  }',
      '  public Object parse(String p, String t) throws Exception {',
      '    return mapper.readValue(p, Class.forName(t));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Mixed.java', 'java', {
      dependencyContext: { java: { pomXml: POM_FASTJSON_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Non-Java file is untouched even with dependencyContext.java present', async () => {
    // Python file with a deserialization sink; dependencyContext.java
    // is provided but should have no effect on Python analysis.
    const code = [
      'import pickle',
      'from flask import request',
      '',
      'def handler():',
      '    return pickle.loads(request.data)',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python', {
      dependencyContext: { java: { pomXml: POM_FASTJSON_NONEAUTOTYPE } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});
