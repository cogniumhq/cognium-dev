/**
 * cognium-dev#1079 — graph-fact JSON reports are written in pieces. `jsonChunks` must give
 * exactly `JSON.stringify(v, null, 2)`, and no piece may be the whole report: a single
 * string of a large `depcalls` report passed V8's string limit ("Invalid string length").
 */
import { test, expect, describe } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { jsonChunks, writeJson } from '../src/utils/json-stream';

const same = (v: unknown) => expect([...jsonChunks(v)].join('')).toBe(JSON.stringify(v, null, 2));

describe('jsonChunks equals JSON.stringify(v, null, 2)', () => {
  test('scalars, empty and nested collections', () => {
    for (const v of [null, 0, -1.5, 'x', true, [], {}, [[]], [{}], { a: [] }, { a: {} }, [1, [2, [3, [4, [5]]]]],
      { a: { b: { c: { d: { e: 1 } } } } }, { 'k"ey': 'v\n"', 'ü': ['é', null] }]) same(v);
  });

  test('undefined, functions and symbols are skipped in objects and null in arrays', () => {
    same({ a: undefined, b: () => 1, c: Symbol('s'), d: 1 });
    same([undefined, () => 1, Symbol('s'), 2]);
    same({ only: undefined });
    expect([...jsonChunks(undefined)].join('')).toBe('');
  });

  test('toJSON is applied once, at every depth', () => {
    const d = new Date(0);
    same({ when: d, list: [d, { at: d }], deep: { a: { b: { c: d } } } });
    same({ x: { toJSON: () => ({ y: [1, 2] }) } });
  });

  test('a report-shaped value: big arrays of objects', () => {
    const calls = Array.from({ length: 5000 }, (_, i) => ({ from: `id${i}`, site: { file: `F${i % 7}.java`, line: i, col: 3 }, methodName: 'm', receiver: 'org.x.Y', tests: i % 3 ? [] : [`t${i}`] }));
    const report = { root: '/r', language: 'java', engine: { package: 'circle-ir', version: '4.19.0' }, packages: ['org.x'], calls, uncovered: 3, covered: false, partial: [] };
    same(report);
    // no piece is the whole report: the largest piece is one element of `calls`
    const pieces = [...jsonChunks(report)];
    const total = pieces.reduce((n, p) => n + p.length, 0);
    expect(Math.max(...pieces.map(p => p.length))).toBeLessThan(total / 100);
  });
});

test('writeJson writes JSON.stringify(v, null, 2) + newline to a file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'json-stream-'));
  try {
    const v = { a: Array.from({ length: 20000 }, (_, i) => ({ i, s: 'x'.repeat(i % 50) })), b: { c: [1, 2, 3] } };
    const f = join(dir, 'out.json');
    writeJson(v, f);
    expect(readFileSync(f, 'utf8')).toBe(JSON.stringify(v, null, 2) + '\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
