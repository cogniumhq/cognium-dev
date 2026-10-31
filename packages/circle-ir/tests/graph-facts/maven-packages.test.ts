/**
 * Maven coordinates → Java packages (E02): from the resolved jar's package
 * directories, else a fallback table; and `dependencyCalls({ artifact })`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import {
  MAVEN_PACKAGE_FALLBACK,
  UnknownArtifact,
  dependencyCalls,
  jarPackages,
  mavenArtifact,
  mavenPackages,
  zipEntryNames,
} from '../../src/graph-facts/index.js';
import * as publicApi from '../../src/index.js';

/** A zip with empty stored entries: enough central directory to read names. */
function zip(names: string[], { zip64 = false, comment = '' } = {}): Uint8Array {
  const enc = new TextEncoder();
  const chunks: number[] = [];
  const u16 = (n: number) => chunks.push(n & 0xff, (n >>> 8) & 0xff);
  const u32 = (n: number) => { u16(n & 0xffff); u16((n >>> 16) & 0xffff); };
  const u64 = (n: number) => { u32(n); u32(0); };
  const offsets: number[] = [];
  for (const name of names) {
    offsets.push(chunks.length);
    const b = enc.encode(name);
    u32(0x04034b50); u16(20); u16(0); u16(0); u16(0); u16(0); u32(0); u32(0); u32(0); u16(b.length); u16(0);
    chunks.push(...b);
  }
  const cd = chunks.length;
  names.forEach((name, i) => {
    const b = enc.encode(name);
    u32(0x02014b50); u16(20); u16(20); u16(0); u16(0); u16(0); u16(0); u32(0); u32(0); u32(0);
    u16(b.length); u16(0); u16(0); u16(0); u16(0); u32(0); u32(offsets[i]);
    chunks.push(...b);
  });
  const cdSize = chunks.length - cd;
  if (zip64) {
    const rec = chunks.length;
    u32(0x06064b50); u64(44); u16(45); u16(45); u32(0); u32(0); u64(names.length); u64(names.length); u64(cdSize); u64(cd);
    u32(0x07064b50); u32(0); u64(rec); u32(1);
  }
  const c = enc.encode(comment);
  u32(0x06054b50); u16(0); u16(0);
  u16(zip64 ? 0xffff : names.length); u16(zip64 ? 0xffff : names.length);
  u32(zip64 ? 0xffffffff : cdSize); u32(zip64 ? 0xffffffff : cd); u16(c.length);
  chunks.push(...c);
  return Uint8Array.from(chunks);
}

const JACKSON_JAR = [
  'META-INF/MANIFEST.MF',
  'META-INF/versions/9/module-info.class',
  'META-INF/versions/11/com/fasterxml/jackson/databind/util/Java11Util.class',
  'META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.xml',
  'com/',
  'com/fasterxml/jackson/databind/ObjectMapper.class',
  'com/fasterxml/jackson/databind/ObjectMapper$1.class',
  'com/fasterxml/jackson/databind/node/ObjectNode.class',
  'com/fasterxml/jackson/databind/package-info.class',
  'Stray.class',
];

describe('jarPackages', () => {
  it('reads the package directories of the .class entries', () => {
    expect(jarPackages(zip(JACKSON_JAR))).toEqual([
      'com.fasterxml.jackson.databind',
      'com.fasterxml.jackson.databind.node',
      'com.fasterxml.jackson.databind.util',
    ]);
  });

  it('reads a zip64 central directory and skips a trailing comment', () => {
    const names = ['org/yaml/snakeyaml/Yaml.class'];
    expect(jarPackages(zip(names, { zip64: true }))).toEqual(['org.yaml.snakeyaml']);
    expect(zipEntryNames(zip(names, { comment: 'built by hand' }))).toEqual(names);
  });

  it('refuses bytes that are not a zip', () => {
    expect(() => jarPackages(new TextEncoder().encode('not a jar at all, just text'))).toThrow(/not a zip/);
  });
});

describe('mavenPackages', () => {
  it('prefers the jar, and ignores a version in the coordinate', () => {
    const r = mavenPackages('com.fasterxml.jackson.core:jackson-databind:2.15.2', { jar: zip(JACKSON_JAR) });
    expect(r.source).toBe('jar');
    expect(r.artifact).toBe('com.fasterxml.jackson.core:jackson-databind');
    expect(r.packages).toContain('com.fasterxml.jackson.databind.node');
  });

  it('falls back to the table for the demo dependencies', () => {
    expect(mavenPackages('org.apache.logging.log4j:log4j-core')).toEqual({
      artifact: 'org.apache.logging.log4j:log4j-core',
      packages: ['org.apache.logging.log4j.core'],
      source: 'table',
    });
    for (const [artifact, packages] of Object.entries(MAVEN_PACKAGE_FALLBACK)) {
      expect(artifact.split(':')).toHaveLength(2);
      expect(packages.length).toBeGreaterThan(0);
    }
  });

  it('throws UnknownArtifact rather than return no packages', () => {
    expect(() => mavenPackages('org.example:nothing')).toThrow(UnknownArtifact);
    expect(() => mavenPackages('org.example:empty', { jar: zip(['META-INF/MANIFEST.MF']) })).toThrow(UnknownArtifact);
    expect(() => mavenArtifact('jackson-databind')).toThrow(UnknownArtifact);
  });
});

describe('dependencyCalls with a Maven artifact', () => {
  let g: JavaGraph;
  beforeAll(async () => {
    g = await buildJavaGraph([
      {
        path: 'src/main/java/app/Codec.java',
        code: `package app;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;
public class Codec {
  private final ObjectMapper mapper = new ObjectMapper();
  public String write(Object o) throws Exception { return mapper.writeValueAsString(o); }
  public Object yaml(String s) { return new Yaml().load(s); }
}`,
      },
      {
        path: 'src/test/java/app/CodecTest.java',
        code: `package app;
import org.junit.jupiter.api.Test;
public class CodecTest {
  @Test
  void writes() throws Exception { new Codec().write("x"); }
}`,
      },
    ]);
  }, 60_000);

  it('takes groupId:artifactId alone, through the fallback table', () => {
    const r = dependencyCalls(g, { artifact: 'org.yaml:snakeyaml' });
    expect(r.artifact).toBe('org.yaml:snakeyaml');
    expect(r.packageSource).toBe('table');
    expect(r.calls.map(c => `${c.receiver}.${c.methodName}`)).toContain('org.yaml.snakeyaml.Yaml.load');
    expect(r.covered).toBe(false);
  });

  it('takes the packages from the resolved jar when given', () => {
    const r = dependencyCalls(g, { artifact: 'com.fasterxml.jackson.core:jackson-databind', jar: zip(JACKSON_JAR) });
    expect(r.packageSource).toBe('jar');
    const write = r.calls.find(c => c.methodName === 'writeValueAsString');
    expect(write?.receiver).toBe('com.fasterxml.jackson.databind.ObjectMapper');
    expect(write?.tests.map(t => t.class)).toEqual(['strong']);
    expect(r.calls.every(c => c.receiver.startsWith('com.fasterxml.jackson.databind.'))).toBe(true);
  });

  it('still takes packages directly', () => {
    expect(dependencyCalls(g, { packages: ['org.yaml.snakeyaml'] }).packageSource).toBe('given');
  });

  it('is exported from the package root', () => {
    expect(publicApi.mavenPackages).toBe(mavenPackages);
    expect(publicApi.jarPackages).toBe(jarPackages);
    expect(publicApi.UnknownArtifact).toBe(UnknownArtifact);
  });
});
