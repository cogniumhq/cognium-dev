/**
 * cognium-dev#1149 — interop IL-22 js JSON → sql_injection (built CLI).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURE = join(
  import.meta.dir,
  'fixtures/interop-vuln-demo/service/interop_json_deserialize_sink.js',
);
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run npm run build:all from repo root`);
  }
  stage = mkdtempSync(join(tmpdir(), 'interop-1149-'));
  cpSync(FIXTURE, join(stage, 'interop_json_deserialize_sink.js'));
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(): Promise<Array<{ type: string; line: number }>> {
  const file = join(stage, 'interop_json_deserialize_sink.js');
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
    (r: { vulnerabilities?: Array<{ type: string; line: number; category: string }> }) =>
      (r.vulnerabilities ?? [])
        .filter((v) => v.category === 'security')
        .map((v) => ({ type: v.type, line: v.line })),
  );
}

const sinkLine =
  readFileSync(FIXTURE, 'utf8')
    .split('\n')
    .findIndex((l) => l.includes("pool.query")) + 1;

describe('#1149 interop IL-22 js JSON→sql (built CLI)', () => {
  test('sql_injection at pool.query line', async () => {
    expect(sinkLine).toBeGreaterThan(0);
    const v = await scan();
    expect(v.filter((x) => x.type === 'sql_injection' && x.line === sinkLine).length).toBeGreaterThan(0);
  }, 60_000);
});
