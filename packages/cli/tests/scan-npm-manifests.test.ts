/**
 * The CLI hands the nearest package.json / package-lock.json to circle-ir
 * (`dependencyContext.js`), so the js-yaml deserialization gate sees the
 * installed version: `yaml.load(req.body)` is no finding under js-yaml 4 and
 * stays one under js-yaml 3.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { nearestNpmManifests } from '../src/cli';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');
let work: string;

function project(name: string, jsYaml: string): string {
  const root = join(work, name);
  mkdirSync(join(root, 'src'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name, dependencies: { 'js-yaml': `^${jsYaml}`, express: '^4.0.0' } }));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/js-yaml': { version: jsYaml } } }));
  writeFileSync(join(root, 'src', 'app.ts'), `import yaml from 'js-yaml';
import express from 'express';
const app = express();
app.post('/cfg', (req, res) => {
  res.json(yaml.load(req.body));
});
`);
  return root;
}

async function deserFindings(root: string): Promise<number> {
  const proc = Bun.spawn(['bun', 'run', CLI, 'scan', join(root, 'src'), '-f', 'json', '-q'], { cwd: root, stdout: 'pipe', stderr: 'pipe' });
  const out = await new Response(proc.stdout).text();
  await proc.exited;
  const j = JSON.parse(out);
  return j.results.flatMap((r: any) => r.vulnerabilities ?? []).filter((v: any) => v.cwe === 'CWE-502').length;
}

beforeAll(() => { work = mkdtempSync(join(tmpdir(), 'npm-manifests-')); });
afterAll(() => rmSync(work, { recursive: true, force: true }));

describe('nearest npm manifests', () => {
  test('finds package.json above the target and the workspace lockfile above that', () => {
    const root = join(work, 'ws');
    mkdirSync(join(root, 'packages', 'a', 'src'), { recursive: true });
    mkdirSync(join(root, '.git'));
    writeFileSync(join(root, 'package-lock.json'), '{"lockfileVersion":3}');
    writeFileSync(join(root, 'packages', 'a', 'package.json'), '{"name":"a"}');
    const m = nearestNpmManifests(join(root, 'packages', 'a', 'src'))!;
    expect(m.js.packageJson).toBe('{"name":"a"}');
    expect(m.js.packageLock).toBe('{"lockfileVersion":3}');
  });

  test('stops at .git: nothing found means no context', () => {
    const root = join(work, 'bare');
    mkdirSync(join(root, '.git'), { recursive: true });
    expect(nearestNpmManifests(root)).toBeUndefined();
  });
});

describe('scan with the js-yaml gate', () => {
  test('js-yaml 4 in the lockfile: yaml.load(req.body) is no CWE-502 finding', async () => {
    expect(await deserFindings(project('v4', '4.1.0'))).toBe(0);
  }, 60_000);

  test('js-yaml 3 in the lockfile: still a CWE-502 finding', async () => {
    expect(await deserFindings(project('v3', '3.14.1'))).toBeGreaterThan(0);
  }, 60_000);
});
