/**
 * cognium-dev#1199 — CLI acceptance for Commandline-style field-carried argv.
 */
import { describe, test, expect, beforeAll } from 'bun:test';
import { join, resolve } from 'path';
import { existsSync, readFileSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';

const CLI_PKG = resolve(import.meta.dir, '../..');
const CLI_DIST = join(CLI_PKG, 'dist/cli.js');
const POSITIVE_DIR = join(import.meta.dir, 'fixtures/issue-1199-positive');
const NEGATIVE_DIR = join(import.meta.dir, 'fixtures/issue-1199-negative');
const SCAN_PROFILE = join(import.meta.dir, 'cognium.issue-1199.config.json');

beforeAll(() => {
  if (!existsSync(CLI_DIST)) {
    throw new Error(`Built CLI missing at ${CLI_DIST}; run npm run build:all from repo root`);
  }
});

type VulnRow = { type: string; file: string; line: number };

async function scanPaths(...paths: string[]): Promise<VulnRow[]> {
  const outFile = join(tmpdir(), `issue-1199-${Date.now()}.json`);
  const proc = Bun.spawn(
    ['node', CLI_DIST, 'scan', ...paths, '-f', 'json', '-o', outFile, '-q', '--profile', SCAN_PROFILE],
    { stdout: 'pipe', stderr: 'pipe', env: { ...process.env, NO_COLOR: '1' } },
  );
  const exitCode = await proc.exited;
  const stderr = await new Response(proc.stderr).text();
  if (exitCode !== 0 && exitCode !== 1) {
    throw new Error(`scan failed exit ${exitCode}: ${stderr}`);
  }
  const parsed = JSON.parse(readFileSync(outFile, 'utf8'));
  unlinkSync(outFile);
  return parsed.results.flatMap((r: { vulnerabilities?: Array<{ type: string; line: number }>; file?: string }) =>
    (r.vulnerabilities ?? []).map(v => ({
      type: v.type,
      file: r.file ?? '',
      line: v.line,
    })),
  );
}

async function taskLineSinkLine(dir: string): Promise<number> {
  const text = await Bun.file(join(dir, 'TaskLine.java')).text();
  return text.split('\n').findIndex(l => l.includes('SINK_LINE')) + 1;
}

describe('#1199 commandline field argv (CLI)', () => {
  test('positive: command_injection at TaskLine SINK_LINE', async () => {
    const vulns = await scanPaths(POSITIVE_DIR);
    const sinkLine = await taskLineSinkLine(POSITIVE_DIR);
    const hits = vulns.filter(
      v => v.type === 'command_injection' && v.file.includes('TaskLine.java') && v.line === sinkLine,
    );
    expect(hits.length).toBeGreaterThan(0);
  }, 60_000);

  test('negative: no command_injection at TaskLine SINK_LINE for git log argv', async () => {
    const vulns = await scanPaths(NEGATIVE_DIR);
    const sinkLine = await taskLineSinkLine(NEGATIVE_DIR);
    const hits = vulns.filter(
      v => v.type === 'command_injection' && v.file.includes('TaskLine.java') && v.line === sinkLine,
    );
    expect(hits.length).toBe(0);
  }, 60_000);
});
