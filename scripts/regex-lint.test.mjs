import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compare, summarize } from './regex-lint.mjs';

test('summarize counts regexp reports per file and picks out certain exponential ones', () => {
  const results = [
    { filePath: '/r/packages/a/src/x.ts', messages: [
      { ruleId: 'regexp/no-super-linear-backtracking', line: 1, column: 2, message: 'This might cause exponential backtracking.' },
      { ruleId: 'regexp/no-super-linear-move', line: 3, column: 4, message: 'polynomial' },
      { ruleId: 'other', line: 5, column: 1, message: 'ignored' },
    ] },
    { filePath: '/r/packages/a/src/y.ts', messages: [
      { ruleId: 'regexp/no-super-linear-backtracking', line: 7, column: 1, message: 'This is going to cause exponential backtracking resulting in exponential worst-case runtime behavior.' },
    ] },
  ];
  const s = summarize(results, '/r');
  assert.deepEqual(s.counts, { 'packages/a/src/x.ts': 2, 'packages/a/src/y.ts': 1 });
  assert.equal(s.exponential.length, 1);
  assert.match(s.exponential[0], /^packages\/a\/src\/y\.ts:7:1 /);
});

test('compare reports files over and under their baseline; a new file counts from zero', () => {
  const { over, under } = compare({ 'a.ts': 3, 'b.ts': 2 }, { 'a.ts': 4, 'b.ts': 1, 'c.ts': 1 });
  assert.deepEqual(over, [{ file: 'a.ts', was: 3, now: 4 }, { file: 'c.ts', was: 0, now: 1 }]);
  assert.deepEqual(under, [{ file: 'b.ts', was: 2, now: 1 }]);
});
