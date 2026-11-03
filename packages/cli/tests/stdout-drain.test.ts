/**
 * Large payloads reach a slow pipe in full, and a reader that stops early
 * ends the CLI quietly (#1001 under Bun: a write callback can fire before the
 * pipe has taken the data).
 */
import { test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const CLI = `'${process.execPath}' run ${join(import.meta.dir, '..', 'src', 'cli.ts')}`;
// Created at load: the test table below builds its arguments from it.
const dir = mkdtempSync(join(tmpdir(), 'drain-'));

async function sh(cmd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['sh', '-c', cmd], { cwd: dir, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

beforeAll(() => {
  // sbom: ~3,000 npm dependencies, well over the 64 KiB pipe buffer.
  const deps: Record<string, string> = {};
  for (let i = 0; i < 3000; i++) deps[`package-number-${i}`] = `1.0.${i}`;
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'drain', version: '1.0.0', dependencies: deps }));
  // scan: one file with many findings.
  mkdirSync(join(dir, 'src'));
  const body = Array.from({ length: 400 }, (_, i) =>
    `export function run${i}(req: any) { return eval(req.query.code${i}); }`).join('\n');
  writeFileSync(join(dir, 'src', 'app.ts'), body + '\n');
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

for (const [name, args] of [
  ['sbom', `sbom ${dir} --deterministic`],
  ['scan -f json', `scan ${dir}/src -f json -q`],
  ['metrics -f json', `metrics ${dir}/src -f json`],
] as const) {
  test(`${name}: a slow reader gets the whole payload`, async () => {
    const file = join(dir, `${name.split(' ')[0]}.out`);
    const direct = await sh(`${CLI} ${args} > ${file}`);
    const full = readFileSync(file, 'utf-8');
    if (full.length === 0) throw new Error(`no output: ${direct.stderr}`);
    expect(full.length).toBeGreaterThan(65536);
    JSON.parse(full);
    const slow = await sh(`${CLI} ${args} 2>/dev/null | (sleep 1; wc -c)`);
    expect(Number(slow.stdout.trim())).toBe(Buffer.byteLength(full));
  }, 120_000);
}

for (const [name, args] of [
  ['sbom', `sbom ${dir} --deterministic`],
  ['deadcode', `deadcode ${dir}/src -f json --verdicts live,may-be-live,dead`],
] as const) {
  test(`${name}: a reader that stops early ends the CLI quietly`, async () => {
    const err = join(dir, `${name}.err`);
    await sh(`${CLI} ${args} 2>${err} | head -c 10 >/dev/null`);
    expect(readFileSync(err, 'utf-8')).not.toContain('EPIPE');
  }, 60_000);
}
