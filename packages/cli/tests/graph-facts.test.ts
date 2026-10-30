/**
 * `deadcode`, `reach` and `entries`: option validation, then the real engine on
 * small fixtures (TypeScript, Python, Go, and a git base for `reach`).
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  parseDeadCodeOptions,
  parseEntriesOptions,
  parseGraphLanguage,
  parseReachOptions,
  parseRootKinds,
  parseVerdicts,
} from '../src/graph-facts';
import { UsageError } from '../src/utils/options';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

function write(root: string, rel: string, text: string): void {
  const abs = join(root, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

let dir: string;
let ts: string;
let py: string;
let go: string;
let mixed: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'graph-facts-'));
  ts = join(dir, 'ts');
  write(ts, 'package.json', JSON.stringify({ name: 'fx', version: '1.0.0', main: 'src/index.js' }));
  write(ts, 'src/index.ts', "import { used } from './lib';\nexport function api(): number { return used(); }\n");
  write(ts, 'src/lib.ts', 'export function used(): number { return 1; }\nfunction neverCalled(): number { return 2; }\n');
  write(ts, 'node_modules/dep/index.js', 'export function ignored() {}\n');

  py = join(dir, 'py');
  write(py, 'pyproject.toml', '[project]\nname = "x"\n\n[project.scripts]\nx = "app.main:run"\n');
  write(py, 'app/main.py', 'def run():\n    return helper()\n\ndef helper():\n    return 1\n\ndef orphan():\n    return 2\n');

  go = join(dir, 'go');
  write(go, 'go.mod', 'module example.com/x\n\ngo 1.22\n');
  write(go, 'main.go', 'package main\n\nfunc main() { used() }\n\nfunc used() {}\n\nfunc orphan() {}\n');

  mixed = join(dir, 'mixed');
  write(mixed, 'a.py', 'x = 1\n');
  write(mixed, 'b.ts', 'export const b = 1;\n');
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('files that did not parse (cognium-dev#1004)', () => {
  let broken: string;
  beforeAll(() => {
    broken = join(dir, 'broken');
    write(broken, 'package.json', JSON.stringify({ name: 'fx', version: '1.0.0', main: 'src/index.js' }));
    write(broken, 'src/index.ts', "import { used } from './lib';\nexport function api(): number { return used(); }\n");
    write(broken, 'src/lib.ts', 'export function used(): number { return 1; }\n');
    write(broken, 'src/bad.ts', 'export function ok() {}\n\nfunction broken( {\n');
  });

  test('deadcode JSON names each partial file and its first error', async () => {
    const out = JSON.parse((await runCli(['deadcode', broken, '-f', 'json'])).stdout);
    expect(out.partial).toEqual(['src/bad.ts']);
    expect(out.partialFiles).toHaveLength(1);
    const p = out.partialFiles[0];
    expect(p.file).toBe('src/bad.ts');
    expect(p.line).toBe(3);
    expect(typeof p.column).toBe('number');
    expect(p.nodeKind === 'ERROR' || p.nodeKind.startsWith('MISSING ')).toBe(true);
    expect(typeof p.parent).toBe('string');
  });

  test('deadcode text lists the file with line and node kind', async () => {
    const r = await runCli(['deadcode', broken]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('1 file(s) did not parse fully');
    expect(r.stdout).toMatch(/src\/bad\.ts:3:\d+ {2}(ERROR|MISSING \S+) in \w+/);
  });

  test('deadcode SARIF has a note-level partial-parse result at the error', async () => {
    const sarif = JSON.parse((await runCli(['deadcode', broken, '-f', 'sarif'])).stdout);
    const run = sarif.runs[0];
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toContain('graph-facts/partial-parse');
    const notes = run.results.filter((r: { ruleId: string }) => r.ruleId === 'graph-facts/partial-parse');
    expect(notes).toHaveLength(1);
    expect(notes[0].level).toBe('note');
    expect(notes[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/bad.ts');
    expect(notes[0].locations[0].physicalLocation.region.startLine).toBe(3);
    expect(run.properties.partialFiles).toHaveLength(1);
  });

  test('reach JSON and SARIF carry the partial files', async () => {
    const head = join(dir, 'broken-head');
    write(head, 'package.json', JSON.stringify({ name: 'fx', version: '1.0.0', main: 'src/index.js' }));
    write(head, 'src/index.ts', 'export function api(): number { return 1; }\n');
    write(head, 'src/bad.ts', 'export function ok() {}\n\nfunction broken( {\n');
    const json = JSON.parse((await runCli(['reach', '--base', broken, head, '-f', 'json'])).stdout);
    expect(json.locations).toBeUndefined();
    expect(json.partialFiles.map((p: { file: string }) => p.file)).toEqual(['src/bad.ts']);
    expect(json.partialFiles[0].line).toBe(3);
    const r = await runCli(['reach', '--base', broken, head, '-f', 'sarif']);
    expect(r.code).toBe(0);
    const run = JSON.parse(r.stdout).runs[0];
    const byRule = (id: string) => run.results.filter((x: { ruleId: string }) => x.ruleId === id);
    expect(byRule('graph-facts/partial-parse')).toHaveLength(1);
    expect(byRule('graph-facts/partial-parse')[0].level).toBe('note');
    // `used` was reached from the base export and is gone at the head.
    const reached = byRule('removal-reach/reached');
    expect(reached.map((x: { message: { text: string } }) => x.message.text).join(' ')).toContain('src/lib:used');
    expect(reached.every((x: { level: string }) => x.level === 'warning')).toBe(true);
  });

  test('clean trees report no partial files', async () => {
    const out = JSON.parse((await runCli(['deadcode', ts, '-f', 'json'])).stdout);
    expect(out.partialFiles).toEqual([]);
  });
});

describe('option parsing', () => {
  test('languages and aliases', () => {
    expect(parseGraphLanguage('ts')).toBe('typescript');
    expect(parseGraphLanguage('JavaScript')).toBe('typescript');
    expect(parseGraphLanguage('py')).toBe('python');
    expect(parseGraphLanguage('go')).toBe('go');
    expect(parseGraphLanguage(undefined)).toBeUndefined();
    expect(() => parseGraphLanguage('rust')).toThrow(UsageError);
    expect(() => parseGraphLanguage(true)).toThrow(UsageError);
  });

  test('root kinds and verdicts are checked against the engine enums', () => {
    expect(parseRootKinds('main, route,main')).toEqual(['main', 'route']);
    expect(() => parseRootKinds('main,nope')).toThrow(/root-kinds value 'nope'/);
    expect(() => parseRootKinds(true)).toThrow(UsageError);
    expect(parseVerdicts('dead')).toEqual(['dead']);
    expect(() => parseVerdicts('gone')).toThrow(UsageError);
    expect(() => parseVerdicts(',')).toThrow(UsageError);
  });

  test('defaults and formats', () => {
    expect(parseDeadCodeOptions({})).toMatchObject({ format: 'text', verdicts: ['dead', 'may-be-live'] });
    expect(parseDeadCodeOptions({ f: 'sarif' }).format).toBe('sarif');
    expect(() => parseEntriesOptions({ format: 'sarif' })).toThrow(UsageError);
    expect(() => parseReachOptions({})).toThrow(/--base/);
    expect(() => parseReachOptions({ base: true })).toThrow(/--base/);
    expect(parseReachOptions({ base: 'main', format: 'json' })).toMatchObject({ base: 'main', format: 'json' });
    expect(() => parseDeadCodeOptions({ output: true })).toThrow(/--output/);
  });
});

describe('refused before scanning', () => {
  test('bad options exit 1 with nothing on stdout', async () => {
    for (const args of [
      ['deadcode', ts, '--verdicts', 'bogus'],
      ['deadcode', ts, '--root-kinds', 'nope'],
      ['deadcode', ts, '-f', 'xml'],
      ['entries', ts, '--language', 'cobol'],
      ['reach', ts],
      ['deadcode', join(dir, 'missing')],
    ]) {
      const r = await runCli(args);
      expect(r.code).toBe(1);
      expect(r.stdout).toBe('');
      expect(r.stderr).toContain('Error:');
    }
  });

  test('a mixed tree must name its language', async () => {
    const r = await runCli(['entries', mixed]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('pass --language');
    const ok = await runCli(['entries', mixed, '--language', 'python', '-f', 'json']);
    expect(ok.code).toBe(0);
    expect(JSON.parse(ok.stdout).language).toBe('python');
  });
});

describe('deadcode', () => {
  test('JSON is the dead-code@0.1 payload; summary counts every fact', async () => {
    const r = await runCli(['deadcode', ts, '-f', 'json']);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.scheme).toBe('dead-code@0.1');
    expect(out.ids).toBe('ids@0.1');
    expect(out.language).toBe('typescript');
    expect(out.engine.package).toBe('circle-ir');
    expect(typeof out.entryIndexDigest).toBe('string');
    expect(out.rootKinds).not.toContain('test');
    expect(out.locations).toBeUndefined();
    const names = out.facts.map((f: { qualified_name: string }) => f.qualified_name);
    expect(names).toContain('src/lib:neverCalled');
    expect(names).not.toContain('src/lib:used');
    expect(out.summary.live).toBeGreaterThan(0);
    expect(out.facts.every((f: { file: string }) => !f.file.includes('node_modules'))).toBe(true);
  });

  test('--verdicts live lists live facts only', async () => {
    const out = JSON.parse((await runCli(['deadcode', ts, '-f', 'json', '--verdicts', 'live'])).stdout);
    expect(out.facts.length).toBeGreaterThan(0);
    expect(out.facts.every((f: { verdict: string }) => f.verdict === 'live')).toBe(true);
  });

  test('SARIF 2.1.0 with a location per result', async () => {
    const r = await runCli(['deadcode', ts, '-f', 'sarif']);
    expect(r.code).toBe(0);
    const sarif = JSON.parse(r.stdout);
    expect(sarif.version).toBe('2.1.0');
    const results = sarif.runs[0].results;
    const dead = results.find((x: { message: { text: string } }) => x.message.text.includes('neverCalled'));
    expect(dead.ruleId).toBe('dead-code/dead');
    expect(dead.level).toBe('warning');
    const loc = dead.locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/lib.ts');
    expect(loc.region.startLine).toBe(2);
    const ruleIds = sarif.runs[0].tool.driver.rules.map((x: { id: string }) => x.id);
    for (const res of results) expect(ruleIds).toContain(res.ruleId);
  });

  test('text names file:line of the dead declaration; -o writes a file', async () => {
    const r = await runCli(['deadcode', ts]);
    expect(r.stdout).toContain('src/lib.ts:2');
    const file = join(dir, 'out.json');
    const w = await runCli(['deadcode', ts, '-f', 'json', '-o', file]);
    expect(w.code).toBe(0);
    expect(w.stdout).toBe('');
    expect(JSON.parse(readFileSync(file, 'utf-8')).scheme).toBe('dead-code@0.1');
  });

  test('Python: console script is a root', async () => {
    const out = JSON.parse((await runCli(['deadcode', py, '-f', 'json', '--verdicts', 'dead,live'])).stdout);
    const by = new Map(out.facts.map((f: { qualified_name: string; verdict: string }) => [f.qualified_name, f.verdict]));
    expect(by.get('app.main:orphan')).toBe('dead');
    expect(by.get('app.main:helper')).toBe('live');
  });

  test('Go: main is a root', async () => {
    const out = JSON.parse((await runCli(['deadcode', go, '-f', 'json', '--verdicts', 'dead'])).stdout);
    expect(out.language).toBe('go');
    const names = out.facts.map((f: { qualified_name: string }) => f.qualified_name);
    expect(names.some((n: string) => n.endsWith('orphan'))).toBe(true);
    expect(names.some((n: string) => n.endsWith('used'))).toBe(false);
  });

  test('large output drains fully through a pipe', async () => {
    const big = join(dir, 'big');
    const fns = Array.from({ length: 1500 }, (_, i) => `function unused${i}(): number { return ${i}; }`).join('\n');
    write(big, 'package.json', JSON.stringify({ name: 'big', main: 'src/index.js' }));
    write(big, 'src/index.ts', `export const x = 1;\n${fns}\n`);
    const r = await runCli(['deadcode', big, '-f', 'json']);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).facts.length).toBeGreaterThanOrEqual(1500);
  }, 60_000);
});

describe('entries', () => {
  test('the package export is an entry', async () => {
    const out = JSON.parse((await runCli(['entries', ts, '-f', 'json'])).stdout);
    expect(out.entries.some((e: { kind: string; file: string }) => e.kind === 'export' && e.file === 'src/index.ts')).toBe(true);
    expect(out.summary.export).toBeGreaterThan(0);
    expect(typeof out.entryIndexDigest).toBe('string');
  });
});

describe('reach', () => {
  test('directory base: a removed declaration is listed', async () => {
    const head = join(dir, 'head');
    write(head, 'package.json', JSON.stringify({ name: 'fx', version: '1.0.0', main: 'src/index.js' }));
    write(head, 'src/index.ts', "import { used } from './lib';\nexport function api(): number { return used(); }\n");
    write(head, 'src/lib.ts', 'export function used(): number { return 1; }\n');
    const out = JSON.parse((await runCli(['reach', '--base', ts, head, '-f', 'json'])).stdout);
    expect(out.scheme).toBe('removal-reach@0.1');
    expect(out.removed.map((d: { qualified_name?: string }) => d.qualified_name)).toEqual(['src/lib:neverCalled']);
  });

  test('git ref base is exported, not checked out', async () => {
    const repo = join(dir, 'repo');
    write(repo, 'package.json', JSON.stringify({ name: 'fx', main: 'src/index.js' }));
    write(repo, 'src/index.ts', 'export function api(): number { return helper(); }\nfunction helper(): number { return 1; }\n');
    const git = (...a: string[]) => execFileSync('git', ['-C', repo, '-c', 'user.email=t@t', '-c', 'user.name=t', ...a]);
    git('init', '-q');
    git('add', '-A');
    git('commit', '-qm', 'base');
    write(repo, 'src/index.ts', 'export function api(): number { return 1; }\n');
    const r = await runCli(['reach', '--base', 'HEAD', repo, '-f', 'json']);
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.baseRef).toBe('HEAD');
    const removed = out.removed.find((d: { qualified_name?: string }) => d.qualified_name === 'src/index:helper');
    expect(removed).toBeDefined();
    expect(removed.strong).toBeTruthy(); // the base export still reached it
    // The working tree keeps its edit.
    expect(readFileSync(join(repo, 'src/index.ts'), 'utf-8')).toBe('export function api(): number { return 1; }\n');

    const bad = await runCli(['reach', '--base', 'no-such-ref', repo]);
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain('neither a directory nor a commit');
  });
});
