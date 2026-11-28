/**
 * Tests for the changelog PR coverage check.
 *
 * Run with `node --test scripts/`. The parsing helpers are imported; the exit
 * code is checked on a throwaway git repo, because that is what a release
 * step reads.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prNumber, changelogSection, missingPrs } from './changelog-prs.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'changelog-prs.mjs');

test('prNumber reads the trailing (#N) a squash merge adds', () => {
  assert.equal(prNumber('fix(graph): resolve mjs imports (#1457) (#1460)'), 1460);
  assert.equal(prNumber('fix(cli)!: exit 2 on usage errors (#1354)'), 1354);
  assert.equal(prNumber('agent: fix #1349 Class.forName duplicate (#1384)'), 1384);
  assert.equal(prNumber('release: 4.24.0'), null);
  assert.equal(prNumber('refs (#1305 E2) only'), null);
});

test('changelogSection returns one version, up to the next version heading', () => {
  const text = [
    '# Changelog', '', '## [Unreleased]', '', '## [4.24.0] - 2026-11-26', '', '- a (#2)', '',
    '## [4.23.0] - 2026-11-19', '', '- b (#1)', '',
  ].join('\n');
  assert.equal(changelogSection(text, '4.24.0').trim(), '- a (#2)');
  assert.equal(changelogSection(text, '4.23.0').trim(), '- b (#1)');
  assert.equal(changelogSection(text, '9.9.9'), null);
});

test('missingPrs matches whole numbers only', () => {
  assert.deepEqual(missingPrs('- x (#1341), y (#13)', [1341, 134, 13]), [134]);
  assert.deepEqual(missingPrs('- cognium-dev#1311', [1311]), []);
});

function repo(commits, changelog) {
  const dir = mkdtempSync(join(tmpdir(), 'changelog-prs-'));
  const git = (...a) => execFileSync('git', ['-C', dir, ...a], { stdio: 'pipe' });
  git('init', '-q');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'base');
  git('tag', 'v1');
  for (const m of commits) git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', m);
  writeFileSync(join(dir, 'CHANGELOG.md'), changelog);
  return dir;
}

function run(dir, ...args) {
  try {
    return { code: 0, out: execFileSync('node', [SCRIPT, ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stdout ?? '') + (e.stderr ?? '') };
  }
}

test('exits 0 when every merged PR since the tag is listed', () => {
  const dir = repo(['a (#10)', 'b (#11)'], '## [2.0.0]\n\n- a (#10)\n- b (#11)\n\n## [1.0.0]\n');
  const r = run(dir, 'v1', '2.0.0', 'CHANGELOG.md');
  assert.equal(r.code, 0, r.out);
});

test('exits 1 and names each PR a changelog misses', () => {
  const dir = repo(['a (#10)', 'b (#11)', 'c (#12)'], '## [2.0.0]\n\n- a (#10)\n\n## [1.0.0]\n\n- b (#11)\n');
  const r = run(dir, 'v1', '2.0.0', 'CHANGELOG.md');
  assert.equal(r.code, 1);
  assert.match(r.out, /CHANGELOG\.md: \[2\.0\.0\] does not list 2 of 3 PRs/);
  assert.match(r.out, /#11\b/);
  assert.match(r.out, /#12\b/);
  assert.doesNotMatch(r.out, /#10\b/);
});

test('exits 2 on a missing version section or bad usage', () => {
  const dir = repo(['a (#10)'], '## [1.0.0]\n');
  assert.equal(run(dir, 'v1', '2.0.0', 'CHANGELOG.md').code, 2);
  assert.equal(run(dir, 'v1').code, 2);
});
