/**
 * cognium-dev#1244 — flow-combo c05 xxe js (built CLI, gates-nightly fixture).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURE = join(import.meta.dir, 'fixtures/javascript-vuln-demo/oop_xxe_c05.js');
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run bun run build from packages/cli`);
  }
  stage = mkdtempSync(join(tmpdir(), 'flow-combo-c05-1244-'));
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(file: string): Promise<Array<{ type: string; line: number }>> {
  const out = join(stage, 'report.json');
  const proc = Bun.spawn([process.execPath, CLI_DIST, 'scan', file, '-f', 'json', '-o', out, '-q'], {
    cwd: stage,
    env: { ...process.env, NO_COLOR: '1' },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const code = await proc.exited;
  if (code !== 0 && code !== 1) {
    throw new Error(`scan exited ${code}: ${await new Response(proc.stderr).text()}`);
  }
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  rmSync(out, { force: true });
  return parsed.results.flatMap((r: { vulnerabilities?: Array<{ type: string; line: number; category: string }> }) =>
    (r.vulnerabilities ?? []).filter((v) => v.category === 'security').map((v) => ({ type: v.type, line: v.line })),
  );
}

describe('#1244 flow-combo c05 xxe js (built CLI)', () => {
  test('xxe at libxml.parseXml sinks for OOP-carried taint', async () => {
    const sinkLines = readFileSync(FIXTURE, 'utf8')
      .split('\n')
      .map((l, i) => (l.includes('libxml.parseXml') ? i + 1 : 0))
      .filter((n) => n > 0);
    expect(sinkLines.length).toBeGreaterThanOrEqual(2);
    const v = await scan(FIXTURE);
    for (const sinkLine of sinkLines) {
      expect(v.filter((x) => x.type === 'xxe' && x.line === sinkLine).length).toBeGreaterThan(0);
    }
  }, 60_000);
});