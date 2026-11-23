/**
 * cognium-dev#1150 — interop IL-57 rust JSON param → yaml deser (built CLI).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURES = join(import.meta.dir, 'fixtures/rust-vuln-demo/interop');
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run npm run build:all from repo root`);
  }
  stage = mkdtempSync(join(tmpdir(), 'interop-1150-'));
  cpSync(join(FIXTURES, 'interop_env_json_to_deser.rs'), join(stage, 'interop_env_json_to_deser.rs'));
  cpSync(join(FIXTURES, 'safe_interop_env_json_to_deser.rs'), join(stage, 'safe_interop_env_json_to_deser.rs'));
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(file: string): Promise<Array<{ type: string; line: number }>> {
  const out = join(stage, 'report.json');
  const proc = Bun.spawn([process.execPath, CLI_DIST, 'scan', file, '-f', 'json', '-o', out, '-q'], {
    cwd: stage,
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env, NO_COLOR: '1' },
  });
  const code = await proc.exited;
  if (code !== 0 && code !== 1) throw new Error(`scan exited ${code}: ${await new Response(proc.stderr).text()}`);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  rmSync(out, { force: true });
  return parsed.results.flatMap((r: { vulnerabilities?: Array<{ type: string; line: number; category: string }> }) =>
    (r.vulnerabilities ?? []).filter((v) => v.category === 'security').map((v) => ({ type: v.type, line: v.line })),
  );
}

const sinkLine =
  readFileSync(join(FIXTURES, 'interop_env_json_to_deser.rs'), 'utf8')
    .split('\n')
    .findIndex((l) => l.includes('serde_yaml::from_str')) + 1;

describe('#1150 interop IL-57 rust JSON→yaml deser (built CLI)', () => {
  test('deserialization at serde_yaml::from_str line', async () => {
    expect(sinkLine).toBeGreaterThan(0);
    const file = join(stage, 'interop_env_json_to_deser.rs');
    const v = await scan(file);
    expect(v.filter((x) => x.type === 'deserialization' && x.line === sinkLine).length).toBeGreaterThan(0);
  }, 60_000);

  test('safe mirror has no deserialization finding', async () => {
    const file = join(stage, 'safe_interop_env_json_to_deser.rs');
    const v = await scan(file);
    expect(v.filter((x) => x.type === 'deserialization').length).toBe(0);
  }, 60_000);
});
