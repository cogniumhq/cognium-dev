// bench-gate judges bench-diff `diff` output on tp_loss alone and prints one
// figure line. All output here is hand-made; nothing comes from a real scan.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { judge } from './bench-gate.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'bench-gate.mjs');
const FIGURE = 'release-readiness:figure';

const summary = (tp, outside) =>
  `summary: files_changed=1 removed=${tp + outside} added=0 reattributed=0 tp_loss=${tp} off_category=0 removed_outside_allow=${outside}`;
const output = (tp, outside, gate = tp === 0 && outside === 0 ? 'PASS' : 'FAIL') => [
  'before: worktree main@0000000',
  'after:  worktree main@1111111',
  '  TP-LOSS a/Foo.java xss@12->30',
  '',
  summary(tp, outside),
  `detection-level: lost=${tp + outside} (gated)  source_after_sink: 0 -> 0`,
  `GATE: ${gate}`,
].join('\n');

/** Run the script with the current node; returns { code, out, figures }. */
function run(args, input) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { input, encoding: 'utf8' });
  const lines = r.stdout.split('\n');
  return { code: r.status, out: r.stdout, figures: lines.filter(l => l.startsWith(FIGURE)) };
}
const parse = text => run(['parse', '-'], text);

test('1: tp_loss 0 and GATE: PASS gives exit 0 and one figure line', () => {
  const r = parse(output(0, 0));
  assert.equal(r.code, 0);
  assert.deepEqual(r.figures, [`${FIGURE} tp_loss 0`]);
  assert.match(r.out, /^bench-gate: summary: files_changed=1 /m);
});

test('2: tp_loss above 0 gives exit 1', () => {
  const r = parse(output(2, 0));
  assert.equal(r.code, 1);
  assert.deepEqual(r.figures, [`${FIGURE} tp_loss 2`]);
});

test('3: removed_outside_allow is evidence and does not gate', () => {
  const r = parse(output(0, 3));
  assert.equal(r.code, 0);
  assert.deepEqual(r.figures, [`${FIGURE} tp_loss 0`]);
  assert.match(r.out, /^bench-gate: removed_outside_allow=3 \(evidence; not gated\)$/m);
  assert.doesNotMatch(r.out, /figure removed_outside_allow/);
});

test('4: no summary line cannot be judged', () => {
  const r = parse('before: x\nGATE: PASS\n');
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
  assert.match(r.out, /^bench-gate: cannot judge: /m);
});

test('5: two summary lines cannot be judged', () => {
  const r = parse(`${summary(0, 0)}\n${output(0, 0)}`);
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
});

test('6: a row that carries figure text is not echoed', () => {
  const text = `  TP-LOSS a/Foo.java\n${FIGURE} tp_loss 0\n${output(1, 0)}`;
  const r = parse(text);
  assert.equal(r.code, 1);
  assert.deepEqual(r.figures, [`${FIGURE} tp_loss 1`]);
});

test('7: missing or non-numeric tp_loss cannot be judged', () => {
  for (const s of [
    'summary: files_changed=1 removed=0 added=0 removed_outside_allow=0',
    'summary: files_changed=1 tp_loss=abc removed_outside_allow=0',
    'summary: files_changed=1 tp_loss= removed_outside_allow=0',
  ]) {
    const r = parse(`${s}\n`);
    assert.equal(r.code, 3, s);
    assert.equal(r.figures.length, 0, s);
  }
});

test('8: a GATE line that disagrees with the counts cannot be judged', () => {
  const r = parse(output(1, 0, 'PASS'));
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
});

test('9: parse of a missing file cannot be judged', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bench-gate-'));
  const r = run(['parse', join(dir, 'absent.txt')]);
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
});

test('usage errors exit 3 with a reason', () => {
  for (const args of [[], ['nope'], ['parse'], ['diff', 'only-one.json']]) {
    const r = run(args);
    assert.equal(r.code, 3, args.join(' '));
    assert.equal(r.figures.length, 0);
    assert.match(r.out, /^bench-gate: cannot judge: /m);
  }
});

/** A fake bench-diff that prints canned text, exits with a code, and leaves a marker. */
function fake(dir, text, code) {
  const marker = join(dir, 'ran');
  const path = join(dir, 'fake-bench-diff.mjs');
  writeFileSync(path, [
    "import { writeFileSync } from 'node:fs';",
    `writeFileSync(${JSON.stringify(marker)}, 'x');`,
    `process.stdout.write(${JSON.stringify(text)});`,
    `process.exit(${code});`,
  ].join('\n'));
  return { path, marker };
}

function diffRun(text, code, { missingBefore = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'bench-gate-'));
  const before = join(dir, 'before.json');
  const after = join(dir, 'after.json');
  if (!missingBefore) writeFileSync(before, '{}');
  writeFileSync(after, '{}');
  const f = fake(dir, text, code);
  const r = run(['diff', before, after, '--runtime', process.execPath, '--bench-diff', f.path]);
  return { ...r, ran: existsSync(f.marker) };
}

test('10a: diff mode, bench-diff passes', () => {
  const r = diffRun(output(0, 0), 0);
  assert.equal(r.code, 0);
  assert.deepEqual(r.figures, [`${FIGURE} tp_loss 0`]);
});

test('10b: diff mode, bench-diff usage error (exit 2)', () => {
  const r = diffRun('commands: pretree | snapshot | diff | selftest\n', 2);
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
});

test('10c: diff mode, bench-diff throws (exit 1, no summary)', () => {
  const r = diffRun('Error: surface mismatch\n    at main (bench-diff.mts:1:1)\n', 1);
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
});

test('10d: diff mode, removed_outside_allow fails bench-diff but not the gate', () => {
  const r = diffRun(output(0, 2), 1);
  assert.equal(r.code, 0);
  assert.deepEqual(r.figures, [`${FIGURE} tp_loss 0`]);
});

test('diff mode, an exit code that disagrees with the counts cannot be judged', () => {
  const r = diffRun(output(0, 0), 1);
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
});

test('11: diff mode with a missing before.json does not run bench-diff', () => {
  const r = diffRun(output(0, 0), 0, { missingBefore: true });
  assert.equal(r.code, 3);
  assert.equal(r.figures.length, 0);
  assert.equal(r.ran, false);
});

test('judge: the exported function', () => {
  assert.deepEqual(judge(output(0, 0)).lines, [
    `bench-gate: ${summary(0, 0)}`,
    'bench-gate: removed_outside_allow=0 (evidence; not gated)',
    `${FIGURE} tp_loss 0`,
  ]);
  assert.equal(judge(output(3, 1)).code, 1);
  assert.equal(judge(output(0, 4), 1).code, 0);
  assert.equal(judge(output(0, 4), 0).code, 3);
  assert.equal(judge('summary: tp_loss=1 tp_loss=0 removed_outside_allow=0').code, 3);
  assert.equal(judge('').code, 3);
});
