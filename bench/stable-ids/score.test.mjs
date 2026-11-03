// Unit tests for the join and the scoring (node --test).
import test from 'node:test';
import assert from 'node:assert/strict';
import { addCounts, formatRatio, joinDecl, metrics, ratio, scorePair, totals } from './score.mjs';

const d = (id, body, name, start, end, parent = 'm', kind = 'function') => ({ id, body_id: `${id}.${body}`, name, kind, start_line: start, end_line: end, parent });
const rec = (o) => ({ file: 'a.ts', kind: 'function', chain: '', signature: '()', line: 1, start: 1, end: 1, label: null, change: null, reason: null, judgement: null, after: null, ...o });
const map = (o) => new Map(Object.entries(o));

test('joinDecl: the file, then name and line, then start line', () => {
  const decls = [d('m', 'x', 'mod', 1, 20, null, 'module'), d('k', 'x', 'K', 2, 10, 'm', 'type'), d('km', 'x', 'm', 3, 5, 'k', 'method'), d('f', 'x', 'm', 12, 14)];
  assert.equal(joinDecl(decls, { isFile: true }).id, 'm');
  assert.equal(joinDecl(decls, { name: 'm', line: 4, start: 3, kind: 'method' }).id, 'km');
  assert.equal(joinDecl(decls, { name: 'm', line: 12, start: 12, kind: 'function' }).id, 'f');
  // the innermost of two candidates with the name
  assert.equal(joinDecl([d('o', 'x', 'n', 1, 9), d('i', 'x', 'n', 2, 3)], { name: 'n', line: 2, start: 2 }).id, 'i');
  // the provider names it differently: fall back to the start line
  assert.equal(joinDecl(decls, { name: 'other', line: 9, start: 12, kind: 'function' }).id, 'f');
  assert.equal(joinDecl(decls, { name: 'zzz', line: 30, start: 30 }), null);
  assert.equal(joinDecl(undefined, { isFile: true }), null);
});

test('scorePair: true and false stable, misses, judgements, unjoined', () => {
  const records = [
    rec({ name: 'keep', line: 1, label: 'stable', after: { file: 'a.ts', line: 3, start: 3, end: 3 } }),
    rec({ name: 'edit', line: 2, start: 2, label: 'changed', change: 'body', after: { file: 'a.ts', line: 4, start: 4, end: 4 } }),
    rec({ name: 'sig', line: 5, start: 5, label: 'changed', change: 'identity', reason: 'signature' }),
    rec({ name: 'lost', line: 6, start: 6, label: 'stable', after: { file: 'a.ts', line: 7, start: 7, end: 7 } }),
    rec({ name: 'odd', line: 8, start: 8, judgement: 'header' }),
    rec({ name: 'nowhere', line: 40, start: 40, label: 'stable', after: { file: 'a.ts', line: 41, start: 41, end: 41 } }),
  ];
  const before = map({ 'a.ts': [d('keep', 'k', 'keep', 1, 1), d('edit', 'e1', 'edit', 2, 2), d('sig', 's', 'sig', 5, 5), d('lost', 'l', 'lost', 6, 6), d('odd', 'o', 'odd', 8, 8)] });
  // `sig` keeps its id and body although its identity changed: a false stable.
  // `lost` gets a new id although it is stable: a miss.
  const after = map({ 'a.ts': [d('keep', 'k', 'keep', 3, 3), d('edit', 'e2', 'edit', 4, 4), d('sig', 's', 'sig', 5, 5), d('lost2', 'l', 'lost', 7, 7), d('odd', 'o2', 'odd', 8, 8)] });
  const { counts, misses } = scorePair(records, { before, after });
  assert.equal(counts.scored, 5);
  assert.deepEqual([counts.tp, counts.fp, counts.fn, counts.unjoined], [1, 1, 2, 1]);
  assert.deepEqual(counts.judgement, { header: 1 });
  assert.deepEqual(counts.confusion.stable, { stable: 1, body: 0, identity: 1, none: 1 });
  assert.deepEqual(counts.confusion.body, { stable: 0, body: 1, identity: 0, none: 0 });
  assert.deepEqual(counts.confusion.identity, { stable: 1, body: 0, identity: 0, none: 0 });
  assert.deepEqual(misses.map(m => `${m.name}:${m.label}->${m.pred}`).sort(), ['lost:stable->identity', 'nowhere:stable->none', 'sig:identity->stable']);
  const m = metrics(counts);
  assert.deepEqual([m.precision.num, m.precision.den, m.recall.num, m.recall.den], [1, 2, 1, 3]);
  assert.deepEqual([m.body_keeps_decl.num, m.body_keeps_decl.den], [1, 1]);
  assert.deepEqual([m.identity_new_decl.num, m.identity_new_decl.den], [0, 1]);
});

test('scorePair: a stable claim matched to the wrong declaration', () => {
  // Two identical bodies; the provider keys them so that `a` before finds `b` after.
  const records = [rec({ name: 'a', line: 1, label: 'stable', after: { file: 'a.ts', line: 1, start: 1, end: 1 } })];
  const before = map({ 'a.ts': [d('X', 'same', 'a', 1, 1)] });
  const after = map({ 'a.ts': [d('Y', 'same', 'a', 1, 1), d('X', 'same', 'b', 2, 2)] });
  const { counts, misses } = scorePair(records, { before, after });
  assert.deepEqual([counts.tp, counts.fp, counts.fn, counts.wrong_partner], [0, 1, 1, 1]);
  assert.equal(misses[0].pred, 'stable (wrong partner)');
});

test('scorePair: node ids under a stable body', () => {
  const records = [
    rec({ name: 'a', line: 1, label: 'stable', after: { file: 'a.ts', line: 1, start: 1, end: 1 } }),
    rec({ name: 'b', line: 2, start: 2, label: 'stable', after: { file: 'a.ts', line: 2, start: 2, end: 2 } }),
  ];
  const before = map({ 'a.ts': [d('A', 'x', 'a', 1, 1), d('B', 'y', 'b', 2, 2)] });
  const after = map({ 'a.ts': [d('A', 'x', 'a', 1, 1), d('B', 'y', 'b', 2, 2)] });
  const nodes = {
    before: map({ 'a.ts': new Map([['A.x', ['A.x/c0', 'A.x/b0']], ['B.y', ['B.y/b0']]]) }),
    after: map({ 'a.ts': new Map([['A.x', ['A.x/b0', 'A.x/c0']], ['B.y', ['B.y/b1']]]) }),
  };
  const { counts, misses } = scorePair(records, { before, after, nodes });
  assert.deepEqual(counts.nodes, { checked: 2, kept: 1 });
  assert.equal(misses[0].note, 'node ids changed');
});

test('totals, ratios and formatting', () => {
  const a = totals();
  const records = [rec({ name: 'k', label: 'stable', after: { file: 'a.ts', line: 1, start: 1, end: 1 } })];
  const engine = { before: map({ 'a.ts': [d('K', 'b', 'k', 1, 1)] }), after: map({ 'a.ts': [d('K', 'b', 'k', 1, 1)] }) };
  addCounts(a, scorePair(records, engine).counts);
  addCounts(a, scorePair(records, engine).counts);
  assert.equal(a.tp, 2);
  assert.equal(formatRatio(metrics(a).precision), '100.0% (2/2)');
  assert.equal(formatRatio(ratio(0, 0)), 'n/a (0/0)');
});
