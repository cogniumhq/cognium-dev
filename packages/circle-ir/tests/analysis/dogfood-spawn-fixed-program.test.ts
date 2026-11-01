/**
 * Dogfood 2026-10-31 (cognium-ai benchmark runners): `spawnSync(process.execPath,
 * ['--import', 'tsx', SELF, '--scan-one', dir])` was a critical command_injection.
 * With a fixed program, no shell and no `-e`, the argument array is argv only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const cmd = async (code: string) =>
  (await analyze(code, 'r.ts', 'typescript')).taint.sinks.filter(s => s.type === 'command_injection');

const wrap = (call: string) => `import { spawnSync } from 'child_process';\nexport function run(dir: string) {\n  ${call}\n}`;

describe('spawn family with a fixed program and an argument array', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('process.execPath with an args array is not command injection', async () => {
    expect(await cmd(wrap(`return spawnSync(process.execPath, ['--import', 'tsx', 'self.ts', '--scan-one', dir], { encoding: 'utf8' });`))).toHaveLength(0);
  });

  it('keeps shell: true, a shell program, node -e, and a variable program', async () => {
    expect((await cmd(wrap(`return spawnSync(process.execPath, [dir], { shell: true });`))).length).toBeGreaterThan(0);
    expect((await cmd(wrap(`return spawnSync('sh', ['-c', dir]);`))).length).toBeGreaterThan(0);
    expect((await cmd(wrap(`return spawnSync(process.execPath, ['-e', dir]);`))).length).toBeGreaterThan(0);
    expect((await cmd(wrap(`return spawnSync(dir, []);`))).length).toBeGreaterThan(0);
  });
});
