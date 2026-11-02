import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { UnknownArtifact } from 'circle-ir';
import {
  capabilities, mavenJarPath, runDependencyCalls,
  type DependencyCallRow, type DependencyCallsSite,
} from '../src/index.js';

/* capability `dependency-calls` (E02): calls into one Maven artifact, covered or not. */

let tmp: string;
let subject: string;
let repo: string;

const write = (root: string, files: Record<string, string | Uint8Array>): string => {
  for (const [p, body] of Object.entries(files)) {
    const full = join(root, p);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  }
  return root;
};

/** A zip of empty stored entries: enough central directory to list names. */
function jar(names: string[]): Uint8Array {
  const enc = new TextEncoder();
  const b: number[] = [];
  const u16 = (n: number) => b.push(n & 0xff, (n >>> 8) & 0xff);
  const u32 = (n: number) => { u16(n & 0xffff); u16((n >>> 16) & 0xffff); };
  const at: number[] = [];
  for (const n of names) {
    at.push(b.length);
    const e = enc.encode(n);
    u32(0x04034b50); u16(20); u16(0); u16(0); u16(0); u16(0); u32(0); u32(0); u32(0); u16(e.length); u16(0); b.push(...e);
  }
  const cd = b.length;
  names.forEach((n, i) => {
    const e = enc.encode(n);
    u32(0x02014b50); u16(20); u16(20); u16(0); u16(0); u16(0); u16(0); u32(0); u32(0); u32(0);
    u16(e.length); u16(0); u16(0); u16(0); u16(0); u32(0); u32(at[i]); b.push(...e);
  });
  const size = b.length - cd;
  u32(0x06054b50); u16(0); u16(0); u16(names.length); u16(names.length); u32(size); u32(cd); u16(0);
  return Uint8Array.from(b);
}

const CODEC = `package app;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.*;
public class Codec {
  private final ObjectMapper mapper = new ObjectMapper();
  public String write(Object o) throws Exception { return mapper.writeValueAsString(o); }
  public Object yaml(String s) { return new Yaml().load(s); }
  public Object loose(String s) { return new Loader().load(s); }
}`;
const TEST = `package app;
import org.junit.jupiter.api.Test;
public class CodecTest {
  @Test
  void writes() throws Exception { new Codec().write("x"); }
}`;

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'code-facts-depcalls-'));
  subject = write(join(tmp, 'subject'), {
    'src/main/java/app/Codec.java': CODEC,
    'src/test/java/app/CodecTest.java': TEST,
  });
  repo = join(tmp, 'm2');
  write(repo, {
    'com/fasterxml/jackson/core/jackson-databind/2.15.2/jackson-databind-2.15.2.jar': jar([
      'META-INF/MANIFEST.MF',
      'com/fasterxml/jackson/databind/ObjectMapper.class',
      'com/fasterxml/jackson/databind/node/ObjectNode.class',
    ]),
  });
});

afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const site = (r: { anchors: Array<{ anchor: string; observation: unknown }> }): DependencyCallsSite =>
  r.anchors.find(a => a.anchor === 'site')!.observation as DependencyCallsSite;
const rows = (r: { anchors: Array<{ anchor: string; observation: unknown }> }): DependencyCallRow[] =>
  r.anchors.filter(a => a.anchor !== 'site').map(a => a.observation as DependencyCallRow);

describe('runDependencyCalls', () => {
  it('is a listed capability', () => {
    expect(capabilities()).toContain('dependency-calls');
  });

  it('reads the packages from the jar in the Maven repository and marks each call covered or uncovered', async () => {
    const r = await runDependencyCalls(subject, {}, {
      artifact: 'com.fasterxml.jackson.core:jackson-databind:2.15.2', language: 'java', mavenRepo: repo,
    });
    expect(r.capability).toBe('dependency-calls');
    const s = site(r);
    expect(s.packageSource).toBe('jar');
    expect(s.jarDigest).toMatch(/^sha256:/);
    expect(s.packages).toEqual(['com.fasterxml.jackson.databind', 'com.fasterxml.jackson.databind.node']);
    const write = rows(r).find(x => x.call.methodName === 'writeValueAsString');
    expect(write?.state).toBe('covered');
    expect(write?.call.tests[0]).toMatchObject({ file: 'src/test/java/app/CodecTest.java', class: 'strong' });
    expect(s.counts.calls).toBe(rows(r).length);
    expect(s.counts.covered + s.counts.uncovered).toBe(s.counts.calls);
  });

  it('falls back to the table without a version or jar, and lists uncovered and unattributed sites', async () => {
    const r = await runDependencyCalls(subject, {}, { artifact: 'org.yaml:snakeyaml', language: 'java', mavenRepo: repo });
    const s = site(r);
    expect(s.packageSource).toBe('table');
    expect(s.jarDigest).toBeUndefined();
    expect(rows(r).map(x => `${x.state} ${x.call.receiver}.${x.call.methodName}`)).toContain('uncovered org.yaml.snakeyaml.Yaml.load');
    expect(s.covered).toBe(false);
    expect(s.counts.unattributed).toBe(s.unattributed.length);
    expect(s.unattributed.map(u => `${u.site.file}:${u.site.line}`)).toContain('src/main/java/app/Codec.java:9');
  });

  it('gives byte-identical output for the same tree and jar', async () => {
    const p = { artifact: 'com.fasterxml.jackson.core:jackson-databind:2.15.2', language: 'java' as const, mavenRepo: repo };
    expect(JSON.stringify(await runDependencyCalls(subject, {}, p))).toBe(JSON.stringify(await runDependencyCalls(subject, {}, p)));
  });

  it('takes the jar from views, and refuses an artifact nothing resolves', async () => {
    const r = await runDependencyCalls(subject, { jar: jar(['org/yaml/snakeyaml/Yaml.class']) }, { artifact: 'org.yaml:snakeyaml', language: 'java' });
    expect(site(r).packageSource).toBe('jar');
    await expect(runDependencyCalls(subject, {}, { artifact: 'org.example:nothing', language: 'java', mavenRepo: repo })).rejects.toBeInstanceOf(UnknownArtifact);
  });

  it('builds the Maven repository path only for a versioned coordinate', () => {
    expect(mavenJarPath('org.yaml:snakeyaml:2.2', '/r')).toBe('/r/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar');
    expect(mavenJarPath('org.yaml:snakeyaml', '/r')).toBeNull();
  });
});
