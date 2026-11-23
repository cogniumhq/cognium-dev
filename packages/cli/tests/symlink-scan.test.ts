/**
 * S4 (8 Nov security Request; scale-run ER-1): the file walk followed
 * symlinked directories, out of the scan root too, and one broken or looping
 * link anywhere aborted the scan (exit 2, no SARIF). A link to a directory
 * inside the tree was scanned twice. Now a symlink is never followed: a target
 * inside the root is walked at its real path (counted once), a target outside
 * it is left out, and a broken or looping link is reported, not fatal.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, existsSync, readFileSync, realpathSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative } from 'path';
import { collectFiles, type SkippedPath } from '../src/cli';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');
let work: string;

async function runCli(args: string[], cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { cwd, stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

/** A tree `root/` with `src/a.js` and `lib/b.js`, plus `outside/c.js` next to it. */
function tree(name: string): string {
  const base = join(work, name);
  mkdirSync(join(base, 'root', 'src'), { recursive: true });
  mkdirSync(join(base, 'root', 'lib'), { recursive: true });
  mkdirSync(join(base, 'outside'), { recursive: true });
  writeFileSync(join(base, 'root', 'src', 'a.js'), 'module.exports = 1;\n');
  writeFileSync(join(base, 'root', 'lib', 'b.js'), 'module.exports = 2;\n');
  writeFileSync(join(base, 'outside', 'c.js'), 'module.exports = 3;\n');
  return join(base, 'root');
}

async function walk(root: string): Promise<{ files: string[]; skipped: SkippedPath[] }> {
  const skipped: SkippedPath[] = [];
  const files = await collectFiles(root, { basePath: root, skipped });
  return { files: files.map(f => relative(root, f)).sort(), skipped: skipped.map(s => ({ ...s, path: relative(root, s.path) })) };
}

beforeAll(() => { work = realpathSync(mkdtempSync(join(tmpdir(), 's4-symlink-'))); });
afterAll(() => rmSync(work, { recursive: true, force: true }));

describe('collectFiles and symlinks', () => {
  test('a link that leaves the scan root is not followed', async () => {
    const root = tree('leaves');
    symlinkSync('../outside', join(root, 'out-dir'));
    symlinkSync('../outside/c.js', join(root, 'out-file.js'));
    const r = await walk(root);
    expect(r.files).toEqual(['lib/b.js', 'src/a.js']);
    expect(r.skipped).toEqual([
      { path: 'out-dir', reason: 'symlink leaves the scan root' },
      { path: 'out-file.js', reason: 'symlink leaves the scan root' },
    ]);
  });

  test('a broken link is skipped and reported', async () => {
    const root = tree('broken');
    symlinkSync(join(work, 'does-not-exist'), join(root, 'dangling'));
    const r = await walk(root);
    expect(r.files).toEqual(['lib/b.js', 'src/a.js']);
    expect(r.skipped).toEqual([{ path: 'dangling', reason: 'broken symlink' }]);
  });

  test('a looping link is skipped and reported; a link to the root itself is not followed', async () => {
    const root = tree('loop');
    symlinkSync('cyc2', join(root, 'cyc1'));
    symlinkSync('cyc1', join(root, 'cyc2'));
    symlinkSync('.', join(root, 'self'));
    const r = await walk(root);
    expect(r.files).toEqual(['lib/b.js', 'src/a.js']);
    expect(r.skipped).toEqual([
      { path: 'cyc1', reason: 'symlink loop' },
      { path: 'cyc2', reason: 'symlink loop' },
      { path: 'self', reason: 'symlink inside the scan root' },
    ]);
  });

  test('a linked directory inside the tree is counted once, at its real path', async () => {
    const root = tree('inside');
    symlinkSync('lib', join(root, 'a-lib-link'));
    symlinkSync('src/a.js', join(root, 'a-file-link.js'));
    const r = await walk(root);
    expect(r.files).toEqual(['lib/b.js', 'src/a.js']);
    expect(r.skipped.map(s => s.reason)).toEqual(['symlink inside the scan root', 'symlink inside the scan root']);
  });
});

describe('scan with bad symlinks', () => {
  test('exits normally, writes SARIF with a notification per link, and JSON lists them', async () => {
    const root = tree('cli');
    symlinkSync(join(work, 'does-not-exist'), join(root, 'dangling'));
    symlinkSync('cyc2', join(root, 'cyc1'));
    symlinkSync('cyc1', join(root, 'cyc2'));
    symlinkSync('../outside', join(root, 'out-dir'));
    symlinkSync('lib', join(root, 'lib-link'));
    const sarifPath = join(work, 'cli.sarif');
    const r = await runCli(['scan', root, '-f', 'sarif', '-o', sarifPath], work);
    expect(r.code).not.toBe(2);
    expect(existsSync(sarifPath)).toBe(true);
    const run = JSON.parse(readFileSync(sarifPath, 'utf8')).runs[0];
    expect(run.invocations[0].executionSuccessful).toBe(true);
    const notes = run.invocations[0].toolExecutionNotifications.map((n: { level: string; message: { text: string } }) => `${n.level} ${n.message.text}`);
    expect(notes).toEqual([
      'warning Not scanned: cyc1 (symlink loop).',
      'warning Not scanned: cyc2 (symlink loop).',
      'warning Not scanned: dangling (broken symlink).',
      'note Not scanned: lib-link (symlink inside the scan root).',
      'warning Not scanned: out-dir (symlink leaves the scan root).',
    ]);
    expect(r.stderr).toContain('Not scanned: dangling (broken symlink)');

    const j = await runCli(['scan', root, '-f', 'json'], work);
    const report = JSON.parse(j.stdout);
    expect(report.summary.filesScanned).toBe(2);
    expect(report.skipped_paths.map((p: { path: string }) => p.path)).toEqual(['cyc1', 'cyc2', 'dangling', 'lib-link', 'out-dir']);
  }, 60_000);
});
