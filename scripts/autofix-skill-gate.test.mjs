// The autofix-issues skill must not merge, and must act only on trusted
// authors' issues (security review, 2026-11-10). These checks read the skill
// text itself, so an edit that brings back a merge step or drops the author
// filter fails CI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SKILL = join(dirname(fileURLToPath(import.meta.url)), '..', '.claude', 'skills', 'autofix-issues', 'SKILL.md');
const text = readFileSync(SKILL, 'utf8');
const TRUSTED = ['OWNER', 'MEMBER', 'COLLABORATOR'];

/** Fenced code blocks, each with the heading it sits under. */
function codeBlocks(md) {
  const out = [];
  let heading = '';
  const lines = md.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/^#{2,3} /.test(lines[i])) heading = lines[i];
    if (/^\s*```/.test(lines[i])) {
      const body = [];
      for (i++; i < lines.length && !/^\s*```/.test(lines[i]); i++) body.push(lines[i]);
      out.push({ heading, body: body.join('\n') });
    }
  }
  return out;
}

/** The `--jq '…'` filter of a `gh api` command (single-quoted, may span lines). */
function jqFilter(block) {
  const m = /--jq '([\s\S]*?)'/.exec(block);
  return m ? m[1].replace(/\\\n/g, '\n') : undefined;
}

test('no command in the skill merges, approves or enables auto-merge a PR', () => {
  for (const { heading, body } of codeBlocks(text)) {
    assert.doesNotMatch(body, /\bgh pr merge\b/, `merge command under ${heading}`);
    assert.doesNotMatch(body, /\bgh pr review\b[^\n]*--approve/, `approval under ${heading}`);
    assert.doesNotMatch(body, /enablePullRequestAutoMerge|mergePullRequest/, `GraphQL merge under ${heading}`);
  }
  assert.match(text, /Never merge or approve a PR/);
});

test('every issue listing in §1a and §1b filters on a trusted author association', () => {
  const listings = codeBlocks(text).filter(b => /^### 1[ab]\./.test(b.heading) && /gh (api 'repos\/[^']*\/issues|issue list)/.test(b.body));
  assert.ok(listings.length >= 3, `expected the §1a, §1b and sast-only listings, found ${listings.length}`);
  for (const { heading, body } of listings) {
    assert.doesNotMatch(body, /gh issue list/, `gh issue list has no author association (${heading})`);
    for (const a of TRUSTED) assert.match(body, new RegExp(`author_association == "${a}"`), `${a} missing under ${heading}`);
  }
});

test('the §1a and §1b filters keep trusted authors only and drop pull requests', { skip: spawnSync('jq', ['--version']).status !== 0 && 'jq not installed' }, () => {
  const issue = (number, author_association, labels = [], extra = {}) => ({ number, title: `t${number}`, body: 'b', user: { login: `u${number}` }, author_association, labels: labels.map(name => ({ name })), ...extra });
  const page = [
    issue(1, 'OWNER'), issue(2, 'MEMBER'), issue(3, 'COLLABORATOR'),
    issue(4, 'CONTRIBUTOR'), issue(5, 'FIRST_TIME_CONTRIBUTOR'), issue(6, 'NONE', ['agent-ok']),
    issue(7, 'MEMBER', [], { pull_request: { url: 'x' } }),
    issue(8, 'MEMBER', ['autofix-skip']),
  ];
  const listings = codeBlocks(text).filter(b => /^### 1[ab]\./.test(b.heading) && /gh api 'repos\/[^']*\/issues/.test(b.body));
  assert.ok(listings.length >= 3, `expected the §1a, §1b and sast-only listings, found ${listings.length}`);
  for (const { heading, body } of listings) {
    const r = spawnSync('jq', ['-c', jqFilter(body)], { input: JSON.stringify(page), encoding: 'utf8' });
    assert.equal(r.status, 0, `${heading}: ${r.stderr}`);
    const kept = r.stdout.trim().split('\n').filter(Boolean).map(l => JSON.parse(l).number);
    assert.ok(kept.every(n => n <= 3 || n === 8), `${heading} kept an untrusted issue or a PR: ${kept}`);
    assert.ok(!kept.includes(4) && !kept.includes(5) && !kept.includes(6) && !kept.includes(7));
    assert.ok(kept.includes(1) && kept.includes(2) && kept.includes(3), `${heading} dropped a trusted issue: ${kept}`);
  }
});
