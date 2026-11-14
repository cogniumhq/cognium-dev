// The release flow as this repository sets it up: rc-tag.yml, release-readiness.yml,
// the ci.yml triggers they rely on, .release-readiness.json and the files under
// .release/, and the review's benchmark gate on those files. Synthetic data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, mkdirSync, copyFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { review, VERSION } from './release-readiness.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = p => readFileSync(join(ROOT, p), 'utf8');
const RC_TAG = read('.github/workflows/rc-tag.yml');
const READINESS = read('.github/workflows/release-readiness.yml');
const CI = read('.github/workflows/ci.yml');
const CONFIG = JSON.parse(read('.release-readiness.json'));
const RECORD = JSON.parse(read('.release/figures-of-record.json'));

/** The top-level env value of `name`, unquoted, comment dropped. */
function topEnv(yml, name) {
  const block = yml.split('\n\n').find(b => b.startsWith('env:'));
  assert.ok(block, 'a top-level env block');
  const m = new RegExp(`^  ${name}: *("([^"]*)"|[^ #\\n]+)`, 'm').exec(block);
  assert.ok(m, `env ${name}`);
  return m[2] ?? m[1];
}

/** Each job's text, by name: the lines under `jobs:` at two-space indent. */
function jobs(yml) {
  const lines = yml.slice(yml.indexOf('\njobs:\n') + 7).split('\n');
  const out = {};
  let name = null;
  for (const l of lines) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(l);
    if (m) { name = m[1]; out[name] = ''; continue; }
    if (name) out[name] += `${l}\n`;
  }
  return out;
}

/** The permissions block of a job, as { key: value }. */
function permissions(job) {
  const m = /^ {4}permissions:\n((?: {6}.*\n)+)/m.exec(job);
  if (!m) return null;
  const out = {};
  for (const l of m[1].split('\n')) {
    const p = /^ {6}([a-z-]+): *([a-z]+)/.exec(l);
    if (p) out[p[1]] = p[2];
  }
  return out;
}

/** The text of every run: | block. */
function runScripts(yml) {
  const out = [];
  const lines = yml.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^( *)(?:- )?run: \|/.exec(lines[i]);
    if (!m) continue;
    const indent = lines[i].indexOf('run:');
    const body = [];
    for (i++; i < lines.length && (lines[i].trim() === '' || lines[i].search(/\S/) > indent); i++) body.push(lines[i]);
    i--;
    out.push(body.join('\n'));
  }
  return out;
}

function commonRules(name, yml) {
  test(`${name}: every action is pinned by a 40-hex sha with a version comment`, () => {
    const uses = [...yml.matchAll(/^\s*(?:- )?uses: (.*)$/gm)].map(m => m[1]);
    assert.ok(uses.length > 0);
    for (const u of uses) assert.match(u, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40} # v\d/, u);
  });
  test(`${name}: every checkout keeps no credentials`, () => {
    const checkouts = yml.split(/\n(?= *- )/).filter(s => /uses: actions\/checkout@/.test(s));
    assert.ok(checkouts.length > 0);
    for (const c of checkouts) assert.match(c, /persist-credentials: false/);
  });
  test(`${name}: no expression inside a run: script`, () => {
    for (const s of runScripts(yml)) assert.doesNotMatch(s, /\$\{\{/);
  });
  test(`${name}: base branch is main`, () => {
    assert.equal(topEnv(yml, 'BASE'), 'main');
  });
}

// --- rc-tag.yml ---

test('rc-tag: engine candidates, ci.yml, tag-only', () => {
  assert.equal(topEnv(RC_TAG, 'RC_TRACKS'), 'engine');
  assert.equal(topEnv(RC_TAG, 'CI_WORKFLOW'), 'ci.yml');
  assert.equal(topEnv(RC_TAG, 'RC_OUTPUTS'), '');
});

test('rc-tag: every job on ubuntu-latest, in the node container', () => {
  const j = jobs(RC_TAG);
  assert.deepEqual(Object.keys(j), ['gate', 'build', 'tag']);
  for (const [name, text] of Object.entries(j)) {
    assert.match(text, /^ {4}runs-on: ubuntu-latest$/m, name);
    assert.match(text, /^ {6}image: node:22-bookworm$/m, name);
  }
  assert.equal([...RC_TAG.matchAll(/runs-on:/g)].length, 3);
});

test('rc-tag: top-level permissions are empty; only the tag job can write', () => {
  assert.match(RC_TAG, /^permissions: \{\}/m);
  const j = jobs(RC_TAG);
  assert.deepEqual(permissions(j.gate), { contents: 'read', actions: 'read' });
  assert.deepEqual(permissions(j.build), { contents: 'read' });
  assert.deepEqual(permissions(j.tag), { contents: 'write' });
  assert.doesNotMatch(j.tag, /actions\/checkout|scripts\//);
});

test('rc-tag: triggers only on rc/** pushes', () => {
  assert.match(RC_TAG, /^on:\n {2}push:\n {4}branches: \["rc\/\*\*"\]\n\n/m);
});

commonRules('rc-tag', RC_TAG);

// --- release-readiness.yml ---

test('release-readiness: follows rc-tag, checks ci.yml', () => {
  assert.match(READINESS, /^ {2}workflow_run:\n {4}workflows: \[rc-tag\]$/m);
  assert.equal(topEnv(READINESS, 'CI_WORKFLOW'), 'ci.yml');
});

test('release-readiness: both jobs on ubuntu-latest, in the node container', () => {
  const j = jobs(READINESS);
  assert.deepEqual(Object.keys(j), ['review', 'notes']);
  for (const [name, text] of Object.entries(j)) {
    assert.match(text, /^ {4}runs-on: ubuntu-latest$/m, name);
    assert.match(text, /^ {6}image: node:22-bookworm$/m, name);
  }
});

test('release-readiness: review reads only; notes writes and runs no repository code', () => {
  const j = jobs(READINESS);
  assert.deepEqual(permissions(j.review), { contents: 'read', actions: 'read' });
  assert.deepEqual(permissions(j.notes), { contents: 'write' });
  assert.doesNotMatch(j.notes, /actions\/checkout|scripts\//);
});

commonRules('release-readiness', READINESS);

// --- ci.yml ---

test('ci.yml runs on main and release/** pushes', () => {
  const m = /^ {2}push:\n {4}branches: \[(.*)\]$/m.exec(CI);
  assert.ok(m);
  const branches = m[1].split(',').map(s => s.trim().replace(/^"|"$/g, ''));
  assert.ok(branches.includes('main'));
  assert.ok(branches.includes('release/**'));
});

test('ci.yml: a push never cancels another commit\'s run', () => {
  assert.match(CI, /group: ci-\$\{\{ github\.workflow \}\}-\$\{\{ github\.event_name == 'push' && github\.sha \|\| github\.ref \}\}/);
  assert.match(CI, /cancel-in-progress: \$\{\{ github\.event_name != 'push' \}\}/);
});

// --- config and records ---

test('.release-readiness.json: shape', () => {
  assert.deepEqual(CONFIG, {
    required: ['ci'],
    ci: [
      { id: 'ci-green', run: 'bash scripts/ci-green.sh' },
      { id: 'bench-candidate', run: 'node scripts/bench-candidate.mjs check' },
    ],
    benchmark: { record: '.release/figures-of-record.json', candidate: '.release/candidate-results.json', run: null },
    hooks: { security: null, 'sbom-licence': null, customer: [] },
    waivers: '.release/waivers.json',
    agents: ['cogbot-eng'],
    timeoutSeconds: 600,
  });
});

test('.release-readiness.json: the files it names exist; no waiver', () => {
  for (const p of [CONFIG.benchmark.record, CONFIG.waivers, 'scripts/ci-green.sh', 'scripts/bench-candidate.mjs', 'scripts/gate-from-base.sh']) {
    assert.ok(existsSync(join(ROOT, p)), p);
  }
  assert.deepEqual(JSON.parse(read(CONFIG.waivers)), { waivers: [] });
});

test('figures of record: OWASP tp_loss of record; Juliet rows have no record yet', () => {
  const [owasp, java, csharp] = RECORD.records;
  assert.equal(RECORD.records.length, 3);
  assert.equal(owasp.suite, 'bench-diff/owasp');
  assert.equal(owasp.metric, 'tp_loss');
  assert.equal(owasp.kind, 'count');
  assert.equal(owasp.value, 0);
  assert.equal(owasp.direction, 'lower');
  assert.equal(owasp.tolerance, 0);
  for (const k of ['version', 'date', 'method']) assert.ok(String(owasp[k] ?? '').trim(), k);
  assert.deepEqual([java.suite, java.status], ['bench-diff/juliet-java', 'no record yet']);
  assert.deepEqual([csharp.suite, csharp.status], ['bench-diff/juliet-csharp', 'no record yet']);
});

test('the vendored reviewer is 0.4.4', () => {
  assert.equal(VERSION, '0.4.4');
});

// --- the review's benchmark gate on these files ---

const TAG = 'engine-v4.21.0-rc.1';
const SHA = '1'.repeat(40);

/** Review the benchmark group only (no command runs) in a copy of the gate files. */
function benchmarkReview(candidate) {
  const d = mkdtempSync(join(tmpdir(), 'release-flow-'));
  mkdirSync(join(d, '.release'));
  for (const p of ['.release-readiness.json', CONFIG.benchmark.record, CONFIG.waivers]) copyFileSync(join(ROOT, p), join(d, p));
  if (candidate) writeFileSync(join(d, CONFIG.benchmark.candidate), JSON.stringify(candidate));
  const v = review(CONFIG, { root: d, tag: TAG, sha: SHA, only: ['benchmark'], today: '2026-11-14' });
  return { v, by: id => v.checks.find(c => c.id === id) };
}
const results = (value, o = {}) => ({ tag: TAG, sha: SHA, version: '111111111111 vs circle-ir-v4.20.0', date: '2026-11-14',
  method: 'bench-diff diff via scripts/bench-gate.mjs vs circle-ir-v4.20.0',
  results: [{ suite: 'bench-diff/owasp', metric: 'tp_loss', value }], ...o });

test('gate: no candidate file fails the OWASP row as not measured: NO-GO', () => {
  const { v, by } = benchmarkReview(null);
  assert.equal(by('benchmark:bench-diff/owasp:tp_loss').status, 'fail');
  assert.equal(by('benchmark:bench-diff/owasp:tp_loss').summary, 'not measured on the candidate');
  assert.equal(v.verdict, 'NO-GO');
});

test('gate: tp_loss 0 for this tag passes; Juliet rows abstain', () => {
  const { v, by } = benchmarkReview(results(0));
  assert.equal(by('benchmark:results').status, 'pass');
  assert.equal(by('benchmark:bench-diff/owasp:tp_loss').status, 'pass');
  assert.equal(by('benchmark:bench-diff/juliet-java:tp_loss').status, 'abstain');
  assert.equal(by('benchmark:bench-diff/juliet-csharp:tp_loss').status, 'abstain');
  assert.equal(v.verdict, 'GO');
});

test('gate: tp_loss 1 fails beyond tolerance 0', () => {
  const { v, by } = benchmarkReview(results(1));
  assert.equal(by('benchmark:bench-diff/owasp:tp_loss').status, 'fail');
  assert.match(by('benchmark:bench-diff/owasp:tp_loss').summary, /beyond tolerance 0/);
  assert.equal(v.verdict, 'NO-GO');
});

test('gate: a results file for another tag and sha fails benchmark:results', () => {
  const { v, by } = benchmarkReview(results(0, { tag: 'engine-v4.20.9-rc.3', sha: '2'.repeat(40) }));
  assert.equal(by('benchmark:results').status, 'fail');
  assert.equal(by('benchmark:bench-diff/owasp:tp_loss').status, 'fail');
  assert.equal(v.verdict, 'NO-GO');
});

test('gate: the suite listed twice fails', () => {
  const twice = results(0);
  twice.results.push({ suite: 'bench-diff/owasp', metric: 'tp_loss', value: 0 });
  const { v, by } = benchmarkReview(twice);
  assert.equal(by('benchmark:bench-diff/owasp:tp_loss').status, 'fail');
  assert.match(by('benchmark:bench-diff/owasp:tp_loss').summary, /measured 2 times/);
  assert.equal(v.verdict, 'NO-GO');
});
