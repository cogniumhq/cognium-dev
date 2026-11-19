/**
 * cognium-dev#1244 — flow-combo c04 xpath java (built CLI, gates-nightly fixture).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { join, resolve } from 'path';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const CLI_DIST = join(resolve(import.meta.dir, '../..'), 'dist/cli.js');
const FIXTURE = join(import.meta.dir, 'fixtures/java-vuln-demo/src/main/java/com/demo/AsyncTaintXpath.java');
let stage = '';

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run bun run build from packages/cli`);
  }
  stage = mkdtempSync(join(tmpdir(), 'flow-combo-c04-1244-java-xpath-'));
  const dest = join(stage, 'com', 'demo');
  mkdirSync(dest, { recursive: true });
  cpSync(FIXTURE, join(dest, 'AsyncTaintXpath.java'));
});

afterAll(() => {
  if (stage) rmSync(stage, { recursive: true, force: true });
});

async function scan(): Promise<Array<{ type: string; line: number }>> {
  const file = join(stage, 'com', 'demo', 'AsyncTaintXpath.java');
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

describe('#1244 flow-combo c04 xpath java (built CLI)', () => {
  test('xpath_injection at XPath.evaluate after CompletableFuture async taint', async () => {
    const sinkLine =
      readFileSync(FIXTURE, 'utf8')
        .split('\n')
        .findIndex((l) => l.includes('newXPath().evaluate')) + 1;
    expect(sinkLine).toBeGreaterThan(0);
    const v = await scan();
    expect(v.filter((x) => x.type === 'xpath_injection' && x.line === sinkLine).length).toBeGreaterThan(0);
  }, 60_000);
});