/**
 * cognium-dev#1148 — variant stored XSS v12_stored (built CLI, gates-nightly fixture).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURE = join(import.meta.dir, 'fixtures/javascript-vuln-demo/variants/xss/v12_stored.js');
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run npm run build:all from repo root`);
  }
  stage = mkdtempSync(join(tmpdir(), 'variant-1148-'));
  const dest = join(stage, 'javascript-vuln-demo', 'variants', 'xss');
  mkdirSync(dest, { recursive: true });
  cpSync(FIXTURE, join(dest, 'v12_stored.js'));
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(): Promise<Array<{ type: string; line: number; file?: string }>> {
  const file = join(stage, 'javascript-vuln-demo', 'variants', 'xss', 'v12_stored.js');
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
  return parsed.results.flatMap(
    (r: {
      file?: string;
      vulnerabilities?: Array<{ type: string; line: number; category: string }>;
    }) =>
      (r.vulnerabilities ?? [])
        .filter((v) => v.category === 'security')
        .map((v) => ({ type: v.type, line: v.line, file: r.file })),
  );
}

const sinkLine =
  readFileSync(FIXTURE, 'utf8')
    .split('\n')
    .findIndex((l) => l.includes('res.send')) + 1;

describe('#1148 variant stored xss v12_stored (built CLI)', () => {
  test('xss at res.send line', async () => {
    expect(sinkLine).toBeGreaterThan(0);
    const v = await scan();
    expect(v.filter((x) => x.type === 'xss' && x.line === sinkLine).length).toBeGreaterThan(0);
  }, 60_000);
});