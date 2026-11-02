/**
 * `depcalls`: option validation, then the real engine on a small Java tree
 * (calls into one Maven artifact; packages from the table or a jar on disk).
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { mavenJarPath, parseDepCallsOptions } from '../src/graph-facts';
import { UsageError } from '../src/utils/options';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

function write(root: string, rel: string, body: string | Uint8Array): void {
  const abs = join(root, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, body);
}

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
  u32(0x06054b50); u16(0); u16(0); u16(names.length); u16(names.length); u32(b.length - cd); u32(cd); u16(0);
  return Uint8Array.from(b);
}

let dir: string;
let java: string;
let repo: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'cli-depcalls-'));
  java = join(dir, 'java');
  write(java, 'src/main/java/app/Codec.java', `package app;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;
public class Codec {
  private final ObjectMapper mapper = new ObjectMapper();
  public String write(Object o) throws Exception { return mapper.writeValueAsString(o); }
  public Object yaml(String s) { return new Yaml().load(s); }
}`);
  write(java, 'src/test/java/app/CodecTest.java', `package app;
import org.junit.jupiter.api.Test;
public class CodecTest {
  @Test
  void writes() throws Exception { new Codec().write("x"); }
}`);
  repo = join(dir, 'm2');
  write(repo, 'com/fasterxml/jackson/core/jackson-databind/2.15.2/jackson-databind-2.15.2.jar',
    jar(['com/fasterxml/jackson/databind/ObjectMapper.class']));
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('parseDepCallsOptions', () => {
  test('requires a groupId:artifactId', () => {
    expect(() => parseDepCallsOptions({})).toThrow(UsageError);
    expect(() => parseDepCallsOptions({ artifact: 'snakeyaml' })).toThrow(UsageError);
    expect(parseDepCallsOptions({ artifact: 'org.yaml:snakeyaml', f: 'json' })).toMatchObject({ artifact: 'org.yaml:snakeyaml', format: 'json' });
  });

  test('takes java only', () => {
    expect(() => parseDepCallsOptions({ artifact: 'org.yaml:snakeyaml', language: 'ts' })).toThrow(/java only/);
  });

  test('builds the Maven repository path for a versioned coordinate only', () => {
    expect(mavenJarPath('org.yaml:snakeyaml:2.2', '/r')).toBe('/r/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar');
    expect(mavenJarPath('org.yaml:snakeyaml', '/r')).toBeNull();
  });
});

describe('depcalls', () => {
  test('reads the jar from the Maven repository and lists covered calls', async () => {
    const r = await runCli(['depcalls', '--artifact', 'com.fasterxml.jackson.core:jackson-databind:2.15.2', '--maven-repo', repo, java, '-f', 'json']);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.scheme).toBe('dependency-calls@0.1');
    expect(out.packageSource).toBe('jar');
    const write = out.calls.find((c: { methodName: string }) => c.methodName === 'writeValueAsString');
    expect(write.tests[0]).toMatchObject({ file: 'src/test/java/app/CodecTest.java', class: 'strong' });
  }, 60_000);

  test('falls back to the table and says what is uncovered', async () => {
    const r = await runCli(['depcalls', '--artifact', 'org.yaml:snakeyaml', '--maven-repo', repo, java]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('packages from table');
    expect(r.stdout).toMatch(/uncovered src\/main\/java\/app\/Codec\.java:7\s+org\.yaml\.snakeyaml\.Yaml\.load/);
  }, 60_000);

  test('refuses an artifact nothing resolves, with exit 1', async () => {
    const r = await runCli(['depcalls', '--artifact', 'org.example:nothing', '--maven-repo', repo, java]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('org.example:nothing');
  }, 60_000);
});
