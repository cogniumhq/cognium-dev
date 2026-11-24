/**
 * cognium-dev#1378 — variant-regression `log_injection` / `slf4j_concat` / java (built CLI).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURE =
  'java-vuln-demo/src/main/java/com/demo/variants/log_injection/V50Slf4jConcat.java';
const FIXTURE_SRC = join(import.meta.dir, 'fixtures', FIXTURE);
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run npm run build:all from repo root`);
  }
  stage = mkdtempSync(join(tmpdir(), 'variant-1378-'));
  const dest = join(stage, FIXTURE);
  mkdirSync(join(dest, '..'), { recursive: true });
  cpSync(FIXTURE_SRC, dest);
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(): Promise<Array<{ type: string; line: number; file?: string }>> {
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
  readFileSync(FIXTURE_SRC, 'utf8')
    .split('\n')
    .findIndex((l) => l.includes('log.info')) + 1;

describe('#1378 slf4j_concat log_injection (built CLI)', () => {
  test('log_injection at SLF4J concat sink line', async () => {
    expect(sinkLine).toBeGreaterThan(0);
    const v = await scan();
    expect(v.filter((x) => x.type === 'log_injection' && x.line === sinkLine).length).toBeGreaterThan(0);
  }, 60_000);
});