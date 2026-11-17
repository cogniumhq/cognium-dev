// bench-fp-gate judges bench-diff `diff` output on findings added to
// expected=false cases. All output here is hand-made; nothing comes from a real scan.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { judge } from './bench-fp-gate.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'bench-fp-gate.mjs');

const summary = added =>
  `summary: files_changed=1 removed=0 added=${added} reattributed=0 tp_loss=0 off_category=0 removed_outside_allow=0`;
const added = (file, sig, exp) => `ADDED\t${file}\t${sig}\texpected=${exp}`;
const output = (rows, addedCount = rows.length) => [
  'before: pretree main@0000000',
  'after:  working-tree HEAD@1111111',
  ...rows,
  '',
  summary(addedCount),
  'detection-level: lost=0 (gated)  source_after_sink: 0 -> 0',
  'GATE: PASS',
].join('\n');

/** Run the script with the current node; returns { code, out }. */
function run(args, input, env = {}) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], {
    input, encoding: 'utf8', env: { ...process.env, FP_GAIN_MAX: '', ...env },
  });
  return { code: r.status, out: r.stdout };
}
const parse = (text, env) => run(['parse', '-'], text, env);

test('1: no added rows gives exit 0 and fp_gain 0', () => {
  const r = parse(output([]));
  assert.equal(r.code, 0);
  assert.match(r.out, /^bench-fp-gate: fp_gain=0 max=0 added_on_real=0 added_unscored=0$/m);
});

test('2: an addition on an expected=false case fails at the default max 0', () => {
  const r = parse(output([added('BenchmarkTest00001.java', 'xss@12->30', 'false/xss')]));
  assert.equal(r.code, 1);
  assert.match(r.out, /^bench-fp-gate: fp_gain=1 max=0 /m);
  assert.match(r.out, /^bench-fp-gate: offending BenchmarkTest00001\.java xss@12->30$/m);
});

test('3: additions on expected=true and expected=? are evidence and do not gate', () => {
  const r = parse(output([
    added('BenchmarkTest00002.java', 'sql_injection@5->9', 'true/sqli'),
    added('helpers/Util.java', 'xss@1->2', '?'),
  ]));
  assert.equal(r.code, 0);
  assert.match(r.out, /^bench-fp-gate: fp_gain=0 max=0 added_on_real=1 added_unscored=1$/m);
  assert.doesNotMatch(r.out, /offending/);
});

test('4: FP_GAIN_MAX raises the limit', () => {
  const rows = [
    added('BenchmarkTest00003.java', 'xss@1->2', 'false/xss'),
    added('BenchmarkTest00004.java', 'xss@1->2', 'false/xss'),
  ];
  assert.equal(parse(output(rows), { FP_GAIN_MAX: '2' }).code, 0);
  assert.equal(parse(output(rows), { FP_GAIN_MAX: '1' }).code, 1);
});

test('5: a non-numeric FP_GAIN_MAX cannot be judged', () => {
  for (const v of ['-1', 'abc', '1.5']) {
    const r = parse(output([]), { FP_GAIN_MAX: v });
    assert.equal(r.code, 3, v);
    assert.match(r.out, /^bench-fp-gate: cannot judge: FP_GAIN_MAX /m, v);
  }
});

test('6: only the first 20 offending rows are listed', () => {
  const rows = Array.from({ length: 25 }, (_, i) => added(`BenchmarkTest${i}.java`, 'xss@1->2', 'false/xss'));
  const r = parse(output(rows));
  assert.equal(r.code, 1);
  assert.match(r.out, /fp_gain=25 /);
  assert.equal(r.out.split('\n').filter(l => l.startsWith('bench-fp-gate: offending ')).length, 20);
});

test('7: no or two summary lines cannot be judged', () => {
  assert.equal(parse('before: x\nGATE: PASS\n').code, 3);
  assert.equal(parse(`${summary(0)}\n${output([])}`).code, 3);
});

test('8: a summary without a numeric added cannot be judged', () => {
  for (const s of ['summary: files_changed=1 tp_loss=0', 'summary: added=x tp_loss=0']) {
    assert.equal(parse(`${s}\n`).code, 3, s);
  }
});

test('9: more ADDED rows than the summary counts cannot be judged', () => {
  const r = parse(output([added('BenchmarkTest00005.java', 'xss@1->2', 'false/xss')], 0));
  assert.equal(r.code, 3);
  assert.match(r.out, /cannot judge: 1 ADDED rows but summary added=0/);
});

test('10: a malformed ADDED row cannot be judged', () => {
  for (const row of ['ADDED\tBenchmarkTest00006.java\txss@1->2', 'ADDED\ta\tb\tnot-expected']) {
    assert.equal(parse(output([row], 1)).code, 3, row);
  }
});

test('11: other row kinds are ignored', () => {
  const r = parse(output([
    'REATTRIBUTED\tBenchmarkTest00007.java\txss@1->2 -> xss@3->2\texpected=false/xss',
    'REMOVED-UNCLASSIFIED\tBenchmarkTest00008.java\txss@1->2\texpected=false/xss',
  ], 1));
  assert.equal(r.code, 0);
  assert.match(r.out, /fp_gain=0 /);
});

test('12: an offending row is reduced to a safe character set', () => {
  const r = parse(output([added('a b`$(x).java', 'xss@1->2', 'false/xss')]));
  assert.equal(r.code, 1);
  assert.match(r.out, /^bench-fp-gate: offending a\?b\?\?\?x\?\.java xss@1->2$/m);
});

test('13: parse of a missing file and usage errors exit 3', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bench-fp-gate-'));
  for (const args of [[], ['nope'], ['parse'], ['parse', join(dir, 'absent.txt')]]) {
    const r = run(args);
    assert.equal(r.code, 3, args.join(' '));
    assert.match(r.out, /^bench-fp-gate: cannot judge: /m);
  }
});

test('judge: the exported function', () => {
  const j = judge(output([added('BenchmarkTest00009.java', 'xss@1->2', 'false/xss')]), '1');
  assert.equal(j.code, 0);
  assert.equal(j.fpGain, 1);
  assert.deepEqual(j.offending, ['BenchmarkTest00009.java xss@1->2']);
  assert.equal(judge(output([])).code, 0);
  assert.equal(judge('').code, 3);
});
