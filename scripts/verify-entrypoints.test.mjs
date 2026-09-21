/**
 * Tests for the pack dry-run entrypoint checker.
 *
 * Run with `node --test scripts/` — the built-in runner, so this adds no
 * dependency to a repo that keeps them deliberately few.
 *
 * The script is exercised as a subprocess rather than imported, because its
 * contract *is* the process contract: which exit code CI sees, and whether the
 * `::warning::` annotation reaches stdout. An imported-function test would
 * verify neither, and both have already been wrong once — the first version
 * fell through to "all entrypoints present" after emitting a warning.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'verify-entrypoints.mjs');

/** Build a throwaway package dir; `files` are created relative to it. */
function pkg(manifest, files = []) {
  const dir = mkdtempSync(join(tmpdir(), 'entrypoints-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2));
  for (const rel of files) {
    mkdirSync(join(dir, dirname(rel)), { recursive: true });
    writeFileSync(join(dir, rel), '// built\n');
  }
  return dir;
}

/** Run the checker, returning { code, stdout, stderr } without throwing. */
function run(dir, ...args) {
  try {
    const stdout = execFileSync('node', [SCRIPT, dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout, stderr: '' };
  } catch (e) {
    return { code: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

const cleanup = [];
test.after(() => { for (const d of cleanup) rmSync(d, { recursive: true, force: true }); });
const fixture = (...a) => { const d = pkg(...a); cleanup.push(d); return d; };

test('passes when every declared entrypoint exists', () => {
  const dir = fixture(
    { name: 'ok-pkg', main: 'dist/index.js', types: 'dist/index.d.ts', bin: { tool: 'dist/cli.js' } },
    ['dist/index.js', 'dist/index.d.ts', 'dist/cli.js'],
  );
  const r = run(dir);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /all declared entrypoints present/);
});

test('fails when main is missing', () => {
  const dir = fixture({ name: 'no-main', main: 'dist/index.js' }, []);
  const r = run(dir);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /main -> dist\/index\.js/);
});

test('fails when a bin target is missing', () => {
  const dir = fixture({ name: 'no-bin', bin: { tool: 'dist/cli.js' } }, []);
  const r = run(dir);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /bin\.tool -> dist\/cli\.js/);
});

test('accepts `typings` as an alias for `types`', () => {
  const missing = fixture({ name: 'typings-missing', typings: 'dist/index.d.ts' }, []);
  assert.equal(run(missing).code, 1);

  const present = fixture({ name: 'typings-ok', typings: 'dist/index.d.ts' }, ['dist/index.d.ts']);
  assert.equal(run(present).code, 0);
});

test('a package declaring nothing passes vacuously', () => {
  assert.equal(run(fixture({ name: 'bare' }, [])).code, 0);
});

test('walks nested exports conditions', () => {
  const dir = fixture(
    {
      name: 'exports-pkg',
      exports: {
        '.': { types: './dist/index.d.ts', import: './dist/index.js' },
        './sub': { import: './dist/sub.js' },
      },
    },
    ['dist/index.d.ts', 'dist/index.js'], // dist/sub.js deliberately absent
  );
  const r = run(dir);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /sub\.js/);
  // The two present paths must not be reported.
  assert.doesNotMatch(r.stderr, /dist\/index\.js/);
});

test('a null exports subpath is skipped rather than treated as a path', () => {
  const dir = fixture(
    { name: 'null-export', exports: { '.': './dist/index.js', './blocked': null } },
    ['dist/index.js'],
  );
  assert.equal(run(dir).code, 0);
});

test('--warn-only reports an annotation and exits 0', () => {
  const dir = fixture({ name: 'warn-pkg', main: 'dist/index.js' }, []);
  const r = run(dir, '--warn-only');
  assert.equal(r.code, 0, 'warn-only must not fail the job');
  assert.match(r.stdout, /^::warning title=warn-pkg entrypoints missing::/m);
  assert.match(r.stdout, /main -> dist\/index\.js/);
});

// Regression: the first version emitted the warning and then fell through to
// the success line, so a run reported both "missing" and "all present".
test('--warn-only does not also claim success', () => {
  const dir = fixture({ name: 'warn-pkg2', main: 'dist/index.js' }, []);
  const r = run(dir, '--warn-only');
  assert.doesNotMatch(r.stdout, /all declared entrypoints present/);
});

test('--warn-only stays silent when nothing is missing', () => {
  const dir = fixture({ name: 'clean-pkg', main: 'dist/index.js' }, ['dist/index.js']);
  const r = run(dir, '--warn-only');
  assert.equal(r.code, 0);
  assert.doesNotMatch(r.stdout, /::warning/);
  assert.match(r.stdout, /all declared entrypoints present/);
});

test('argument order does not matter', () => {
  const dir = fixture({ name: 'order-pkg', main: 'dist/index.js' }, []);
  const r = run(dir, '--warn-only');
  const swapped = (() => {
    try {
      const stdout = execFileSync('node', [SCRIPT, '--warn-only', dir], { encoding: 'utf8' });
      return { code: 0, stdout };
    } catch (e) {
      return { code: e.status ?? 1, stdout: e.stdout ?? '' };
    }
  })();
  assert.equal(swapped.code, r.code);
  assert.match(swapped.stdout, /::warning/);
});

test('exits 2 with usage when no package dir is given', () => {
  const r = (() => {
    try {
      execFileSync('node', [SCRIPT], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return { code: 0, stderr: '' };
    } catch (e) {
      return { code: e.status ?? 1, stderr: e.stderr ?? '' };
    }
  })();
  assert.equal(r.code, 2);
  assert.match(r.stderr, /usage/);
});
