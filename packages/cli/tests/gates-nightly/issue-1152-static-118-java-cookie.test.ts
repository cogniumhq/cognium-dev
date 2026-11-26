/**
 * cognium-dev#1152 — static #118 java cookie fixture: no `trust_boundary` (built CLI).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURE = 'java-vuln-demo/src/main/java/com/demo/fpcorpus/InsecureCookieTp.java';
const FIXTURE_SRC = join(import.meta.dir, 'fixtures', FIXTURE);
// Header findings the static gate drops before comparing types.
const NOISE = new Set([
  'missing-csp-frame-ancestors',
  'missing-x-frame-options',
  'missing-hsts-header',
  'missing-x-content-type-options',
  'missing-referrer-policy',
]);
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run npm run build:all from repo root`);
  }
  stage = mkdtempSync(join(tmpdir(), 'static-1152-'));
  const dest = join(stage, FIXTURE);
  mkdirSync(join(dest, '..'), { recursive: true });
  cpSync(FIXTURE_SRC, dest);
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(): Promise<Array<{ type: string; line: number }>> {
  const file = join(stage, FIXTURE);
  const out = join(stage, 'report.json');
  const proc = Bun.spawn([process.execPath, CLI_DIST, 'scan', file, '-f', 'json', '-o', out, '-q'], {
    cwd: stage,
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env, NO_COLOR: '1' },
  });
  const code = await proc.exited;
  if (code !== 0 && code !== 1) {
    throw new Error(`scan exited ${code}: ${await new Response(proc.stderr).text()}`);
  }
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  rmSync(out, { force: true });
  return parsed.results.flatMap((r: { vulnerabilities?: Array<{ type: string; line: number; category: string }> }) =>
    (r.vulnerabilities ?? [])
      .filter((v) => v.category === 'security' && !NOISE.has(v.type))
      .map((v) => ({ type: v.type, line: v.line })),
  );
}

const cookieLine =
  readFileSync(FIXTURE_SRC, 'utf8')
    .split('\n')
    .findIndex((l) => l.includes('new Cookie(')) + 1;

describe('#1152 static #118 java insecure cookie (built CLI)', () => {
  test('insecure-cookie fires and trust_boundary does not', async () => {
    expect(cookieLine).toBeGreaterThan(0);
    const v = await scan();
    expect(v.filter((x) => x.type === 'insecure-cookie' && x.line === cookieLine).length).toBeGreaterThan(0);
    expect(v.filter((x) => x.type === 'trust_boundary')).toEqual([]);
  }, 60_000);

  test('type set matches the gate baseline or the correct value', async () => {
    const types = [...new Set((await scan()).map((x) => x.type))].sort().join(',');
    expect(['crlf,insecure-cookie', 'insecure-cookie']).toContain(types);
  }, 60_000);
});
