// bench-candidate writes the candidate results file from saved bench-diff
// output and checks it was measured on this code. All output here is
// hand-made; nothing comes from a real scan or benchmark.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'bench-candidate.mjs');
const TAG = 'engine-v4.21.0-rc.1';
const SHA = 'a'.repeat(40);
const SHA2 = 'b'.repeat(40);

const output = (tp, outside = 0) => [
  'before: worktree main@0000000',
  'after:  worktree main@1111111',
  `summary: files_changed=1 removed=${tp + outside} added=0 reattributed=0 tp_loss=${tp} off_category=0 removed_outside_allow=${outside}`,
  `GATE: ${tp === 0 && outside === 0 ? 'PASS' : 'FAIL'}`,
].join('\n');

function run(args, { cwd, input } = {}) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { cwd, input, encoding: 'utf8' });
  return { code: r.status, out: r.stdout + r.stderr };
}

const tmp = () => mkdtempSync(join(tmpdir(), 'bench-candidate-'));

/** write with sensible defaults; `o` overrides any option. */
function write(dir, text, o = {}) {
  const opts = { tag: TAG, measured: SHA, reference: 'circle-ir-v4.20.0', suite: 'bench-diff/owasp', date: '2026-11-14', out: join(dir, 'results.json'), ...o };
  const args = ['write'];
  for (const [k, v] of Object.entries(opts)) if (v !== undefined) args.push(`--${k}`, v);
  args.push('-');
  return run(args, { input: text });
}
const read = dir => JSON.parse(readFileSync(join(dir, 'results.json'), 'utf8'));

test('write: tp_loss 0 gives the file shape and exit 0', () => {
  const d = tmp();
  const r = write(d, output(0));
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(read(d), {
    tag: TAG,
    sha: SHA,
    version: `${SHA.slice(0, 12)} vs circle-ir-v4.20.0`,
    date: '2026-11-14',
    method: 'bench-diff diff via scripts/bench-gate.mjs vs circle-ir-v4.20.0',
    results: [{ suite: 'bench-diff/owasp', metric: 'tp_loss', value: 0 }],
  });
  const raw = readFileSync(join(d, 'results.json'), 'utf8');
  assert.ok(raw.endsWith('}\n'));
  assert.match(raw, /^\{\n {2}"tag"/);
});

test('write: tp_loss 2 is recorded as 2 with exit 0', () => {
  const d = tmp();
  const r = write(d, output(2, 1));
  assert.equal(r.code, 0, r.out);
  assert.equal(read(d).results[0].value, 2);
});

test('write: no summary line exits 3 and leaves the file untouched', () => {
  const d = tmp();
  writeFileSync(join(d, 'results.json'), 'before\n');
  const r = write(d, 'GATE: PASS\n');
  assert.equal(r.code, 3);
  assert.match(r.out, /^bench-candidate: cannot judge: /m);
  assert.equal(readFileSync(join(d, 'results.json'), 'utf8'), 'before\n');
});

for (const [what, o] of [
  ['a bad tag', { tag: 'engine-v4.21.0' }],
  ['a tag with rc.0', { tag: 'engine-v4.21.0-rc.0' }],
  ['a short sha', { measured: 'abc1234' }],
  ['an upper-case sha', { measured: 'A'.repeat(40) }],
  ['a bad suite', { suite: '../owasp suite' }],
  ['a reference that is not a plain tag', { reference: 'refs/tags/x' }],
  ['a bad date', { date: '2026-13-01' }],
  ['no tag', { tag: undefined }],
]) {
  test(`write: ${what} exits 2 and writes nothing`, () => {
    const d = tmp();
    const r = write(d, output(0), o);
    assert.equal(r.code, 2, r.out);
    assert.equal(existsSync(join(d, 'results.json')), false);
  });
}

test('write: the same tag and sha keeps the other suite', () => {
  const d = tmp();
  assert.equal(write(d, output(0)).code, 0);
  assert.equal(write(d, output(1), { suite: 'bench-diff/juliet-java' }).code, 0);
  assert.deepEqual(read(d).results, [
    { suite: 'bench-diff/owasp', metric: 'tp_loss', value: 0 },
    { suite: 'bench-diff/juliet-java', metric: 'tp_loss', value: 1 },
  ]);
});

test('write: the same suite twice keeps one entry, the newer', () => {
  const d = tmp();
  assert.equal(write(d, output(3)).code, 0);
  assert.equal(write(d, output(0)).code, 0);
  assert.deepEqual(read(d).results, [{ suite: 'bench-diff/owasp', metric: 'tp_loss', value: 0 }]);
});

test('write: another tag starts a fresh file with only the new suite', () => {
  const d = tmp();
  assert.equal(write(d, output(0), { suite: 'bench-diff/juliet-java' }).code, 0);
  assert.equal(write(d, output(0), { tag: 'engine-v4.21.0-rc.2' }).code, 0);
  const f = read(d);
  assert.equal(f.tag, 'engine-v4.21.0-rc.2');
  assert.deepEqual(f.results, [{ suite: 'bench-diff/owasp', metric: 'tp_loss', value: 0 }]);
});

test('write: another sha starts a fresh file with only the new suite', () => {
  const d = tmp();
  assert.equal(write(d, output(0), { suite: 'bench-diff/juliet-java' }).code, 0);
  assert.equal(write(d, output(0), { measured: SHA2 }).code, 0);
  const f = read(d);
  assert.equal(f.sha, SHA2);
  assert.deepEqual(f.results.map(r => r.suite), ['bench-diff/owasp']);
});

// --- check, in a throwaway git repository ---

function git(cwd, ...args) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
}
function repo() {
  const d = tmp();
  git(d, 'init', '-q', '-b', 'main');
  git(d, 'config', 'user.email', 'test@example.com');
  git(d, 'config', 'user.name', 'test');
  git(d, 'config', 'commit.gpgsign', 'false');
  writeFileSync(join(d, 'code.txt'), 'one\n');
  git(d, 'add', '.');
  git(d, 'commit', '-q', '-m', 'measured');
  return { d, measured: git(d, 'rev-parse', 'HEAD') };
}
function commitResults(d, sha) {
  mkdirSync(join(d, '.release'), { recursive: true });
  writeFileSync(join(d, '.release', 'candidate-results.json'),
    `${JSON.stringify({ tag: TAG, sha, results: [{ suite: 'bench-diff/owasp', metric: 'tp_loss', value: 0 }] }, null, 2)}\n`);
  git(d, 'add', '.');
  git(d, 'commit', '-q', '-m', 'results');
}
const check = (d, ...args) => run(['check', ...args], { cwd: d });

test('check: only the results file added since the measured commit passes', () => {
  const { d, measured } = repo();
  commitResults(d, measured);
  const r = check(d);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, new RegExp(`measured at ${measured} \\(${TAG}\\); nothing but the results file changed since`));
});

test('check: a further commit touching another file fails and names it', () => {
  const { d, measured } = repo();
  commitResults(d, measured);
  writeFileSync(join(d, 'code.txt'), 'two\n');
  git(d, 'commit', '-q', '-am', 'later');
  const r = check(d);
  assert.equal(r.code, 1);
  assert.match(r.out, /changed since: code\.txt; re-measure/);
});

test('check: a sha that is not an ancestor of HEAD fails', () => {
  const { d } = repo();
  git(d, 'checkout', '-q', '-b', 'side');
  writeFileSync(join(d, 'side.txt'), 'x\n');
  git(d, 'add', '.');
  git(d, 'commit', '-q', '-m', 'side');
  const side = git(d, 'rev-parse', 'HEAD');
  git(d, 'checkout', '-q', 'main');
  commitResults(d, side);
  const r = check(d);
  assert.equal(r.code, 1);
  assert.match(r.out, /not an ancestor of HEAD/);
});

test('check: an unknown sha fails', () => {
  const { d } = repo();
  commitResults(d, 'c'.repeat(40));
  assert.equal(check(d).code, 1);
});

test('check: no results file exits 3', () => {
  const { d } = repo();
  const r = check(d);
  assert.equal(r.code, 3);
  assert.match(r.out, /^bench-candidate: no candidate results file$/m);
});

test('check: a file with no sha fails', () => {
  const { d } = repo();
  mkdirSync(join(d, '.release'));
  writeFileSync(join(d, '.release', 'candidate-results.json'), `{"tag":"${TAG}"}\n`);
  const r = check(d);
  assert.equal(r.code, 1);
  assert.match(r.out, /no 40-hex sha/);
});

test('check: a file that is not JSON fails', () => {
  const { d } = repo();
  mkdirSync(join(d, '.release'));
  writeFileSync(join(d, '.release', 'candidate-results.json'), 'not json\n');
  assert.equal(check(d).code, 1);
});

test('check: --file names another results file', () => {
  const { d, measured } = repo();
  writeFileSync(join(d, 'other.json'), `${JSON.stringify({ tag: TAG, sha: measured })}\n`);
  git(d, 'add', '.');
  git(d, 'commit', '-q', '-m', 'other');
  assert.equal(check(d, '--file', 'other.json').code, 0);
  assert.equal(check(d).code, 3);
});
