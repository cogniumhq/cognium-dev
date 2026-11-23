/**
 * S3: `--file-timeout-ms` is checked between circle-ir phases, so one step
 * that never yields could hold a scan for hours. The watchdog stops such a run
 * from a worker thread once a file has been in flight past the bound, and
 * names the file. These tests block the main thread on purpose in a child
 * process.
 */
import { test, expect, describe } from 'bun:test';
import { join } from 'path';
import { startFileWatchdog, watchdogBoundMs } from '../src/file-watchdog';

const WATCHDOG = join(import.meta.dir, '..', 'src', 'file-watchdog.ts');

async function runChild(script: string): Promise<{ code: number | null; signal: string | null; stderr: string; ms: number }> {
  const t = Date.now();
  const proc = Bun.spawn(['bun', '-e', script], { stdout: 'pipe', stderr: 'pipe' });
  const stderr = await new Response(proc.stderr).text();
  const code = await proc.exited;
  return { code, signal: proc.signalCode ?? null, stderr, ms: Date.now() - t };
}

const blockFor = (ms: number) => `const t = Date.now(); while (Date.now() - t < ${ms}) {}`;

describe('file watchdog', () => {
  test('the bound is twice the limit, and at least the limit plus a second', () => {
    expect(watchdogBoundMs(5000)).toBe(10_000);
    expect(watchdogBoundMs(300)).toBe(1300);
  });

  test('is off without a limit', () => {
    expect(startFileWatchdog(0)).toBeNull();
  });

  test('stops a run blocked on a file past the bound and names the file', async () => {
    const r = await runChild(`
      const { startFileWatchdog } = await import(${JSON.stringify(WATCHDOG)});
      const w = startFileWatchdog(300);
      await new Promise(r => setTimeout(r, 200));
      w.onFileStart('src/slow.go');
      ${blockFor(15000)}
      console.log('not stopped');
    `);
    expect(r.code === 143 || r.signal === 'SIGTERM').toBe(true);
    expect(r.stderr).toContain('src/slow.go');
    expect(r.stderr).toContain('--file-timeout-ms 300');
    expect(r.ms).toBeLessThan(8000);
  }, 20_000);

  test('does not stop a run blocked with no file in flight', async () => {
    const r = await runChild(`
      const { startFileWatchdog } = await import(${JSON.stringify(WATCHDOG)});
      const w = startFileWatchdog(300);
      w.onFileStart('a.go'); w.onFileEnd('a.go');
      await new Promise(r => setTimeout(r, 200));
      ${blockFor(2500)}
      w.stop();
    `);
    expect(r.code).toBe(0);
    expect(r.stderr).toBe('');
  }, 20_000);
});
