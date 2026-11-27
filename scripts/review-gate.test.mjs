// review-gate.mjs: evaluate() on hand-made PR data. No network calls.
import { test } from 'node:test';
import assert from 'node:assert/strict';

// The module reads a token when it loads; a dummy one keeps it off `gh`.
process.env.GH_TOKEN ||= 'test-token-not-used';
const { evaluate } = await import('./review-gate.mjs');

const HEAD = 'abcdef0123456789abcdef0123456789abcdef01';
const OLD = '1111111111111111111111111111111111111111';

function input(over = {}) {
  return {
    pr: { state: 'open', draft: false, head: { sha: HEAD }, user: { login: 'author' } },
    comments: [{ user: { login: 'elarasu' }, created_at: '2026-11-27T10:00:00Z', body: `REVIEW GREEN @ ${HEAD.slice(0, 8)}\nLooks fine.` }],
    reviews: [{ user: { login: 'maintainer' }, state: 'APPROVED', commit_id: HEAD, submitted_at: '2026-11-27T10:05:00Z', body: '' }],
    files: [{ filename: 'packages/cli/src/index.ts' }],
    checkRuns: [{ name: 'build', status: 'completed', conclusion: 'success', started_at: '2026-11-27T09:00:00Z' }],
    statuses: [],
    reviewers: ['elarasu'],
    ...over,
  };
}

test('passes with a verdict for the head, a non-author approval and green checks', () => {
  const r = evaluate(input());
  assert.equal(r.state, 'success', JSON.stringify(r));
});

test('waits when the verdict names an older head', () => {
  const r = evaluate(input({ comments: [{ user: { login: 'elarasu' }, created_at: '2026-11-27T10:00:00Z', body: `REVIEW GREEN @ ${OLD.slice(0, 8)}` }] }));
  assert.equal(r.state, 'pending');
});

test('ignores a verdict from an account that is not a listed reviewer', () => {
  const r = evaluate(input({ comments: [{ user: { login: 'someone' }, created_at: '2026-11-27T10:00:00Z', body: `REVIEW GREEN @ ${HEAD}` }] }));
  assert.equal(r.state, 'pending');
});

test('a later REVIEW CHANGES for the head blocks', () => {
  const comments = [
    ...input().comments,
    { user: { login: 'elarasu' }, created_at: '2026-11-27T11:00:00Z', body: `**REVIEW CHANGES @ \`${HEAD.slice(0, 10)}\`**` },
  ];
  const r = evaluate(input({ comments }));
  assert.equal(r.state, 'failure');
});

test('the author approving their own PR does not count', () => {
  const r = evaluate(input({ reviews: [{ user: { login: 'author' }, state: 'APPROVED', commit_id: HEAD, submitted_at: '2026-11-27T10:05:00Z', body: '' }] }));
  assert.equal(r.state, 'pending');
});

test('a latest CHANGES_REQUESTED review blocks', () => {
  const reviews = [...input().reviews, { user: { login: 'other' }, state: 'CHANGES_REQUESTED', commit_id: HEAD, submitted_at: '2026-11-27T10:06:00Z', body: '' }];
  assert.equal(evaluate(input({ reviews })).state, 'failure');
});

test('a failed check blocks and a running one waits', () => {
  assert.equal(evaluate(input({ checkRuns: [{ name: 'build', status: 'completed', conclusion: 'failure' }] })).state, 'failure');
  assert.equal(evaluate(input({ checkRuns: [{ name: 'build', status: 'in_progress', conclusion: null }] })).state, 'pending');
});

test('its own review-gate status and check run are ignored', () => {
  const r = evaluate(input({
    checkRuns: [...input().checkRuns, { name: 'review-gate', status: 'completed', conclusion: 'failure' }],
    statuses: [{ context: 'review-gate', state: 'failure' }],
  }));
  assert.equal(r.state, 'success');
});

test('waits when no CI has reported on the head', () => {
  assert.equal(evaluate(input({ checkRuns: [] })).state, 'pending');
});

test('a PR that changes the gate is left for a human', () => {
  for (const f of ['scripts/review-gate.mjs', '.github/workflows/review-gate.yml']) {
    assert.equal(evaluate(input({ files: [{ filename: f }] })).state, 'failure');
  }
});

test('draft and closed PRs block', () => {
  assert.equal(evaluate(input({ pr: { ...input().pr, draft: true } })).state, 'failure');
  assert.equal(evaluate(input({ pr: { ...input().pr, state: 'closed' } })).state, 'failure');
});
