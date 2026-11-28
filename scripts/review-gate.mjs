#!/usr/bin/env node
// Review gate for cognium-dev PRs (fails closed). Same logic as cognium-ai scripts/review-gate.mjs.
//
// A PR may be merged only when, for its CURRENT head SHA:
//   1. the PR is open and not a draft;
//   2. an independent reviewer (REVIEW_GATE_REVIEWERS, default "elarasu") has
//      posted a verdict whose first line is `REVIEW GREEN @ <sha>` for this
//      head, and no later `REVIEW CHANGES @ <sha>` for it;
//   3. no reviewer's latest formal review is CHANGES_REQUESTED, and someone
//      other than the author has APPROVED this head;
//   4. every check run and commit status on this head has finished and none
//      failed (neutral/skipped are fine);
//   5. the PR does not change the gate itself (that needs a human merge).
// Anything missing, pending or erroring is a block: exit code 1.
//
// Usage:
//   node scripts/review-gate.mjs <pr-number> [--repo owner/name] [--status]
//   --status  also writes the `review-gate` commit status on the head SHA
//             (used by .github/workflows/review-gate.yml).
// Token: GH_TOKEN or GITHUB_TOKEN, else `gh auth token`.
//
// Merging after a pass: always pin the head you checked, so a push in between
// aborts the merge:
//   gh pr merge <n> --repo <owner/name> --squash --delete-branch --match-head-commit <sha>

import { execFileSync } from 'node:child_process';

const CONTEXT = 'review-gate';
const GATE_FILES = ['scripts/review-gate.mjs', '.github/workflows/review-gate.yml'];
const VERDICT = /^\s*\**\s*REVIEW (GREEN|CHANGES)\s*@\s*`?([0-9a-f]{7,40})`?/i;
const BAD_CONCLUSIONS = new Set(['failure', 'cancelled', 'timed_out', 'action_required', 'startup_failure', 'stale']);

function parseArgs(argv) {
  const out = { pr: null, repo: process.env.GITHUB_REPOSITORY || 'cogniumhq/cognium-dev', status: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--repo') out.repo = argv[++i];
    else if (a === '--status') out.status = true;
    else if (/^\d+$/.test(a)) out.pr = Number(a);
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!out.pr) throw new Error('usage: review-gate.mjs <pr-number> [--repo owner/name] [--status]');
  return out;
}

function token() {
  const t = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (t) return t;
  return execFileSync('gh', ['auth', 'token'], { encoding: 'utf8' }).trim();
}

const TOKEN = token();
const API = process.env.GITHUB_API_URL || 'https://api.github.com';

async function gh(path, init = {}) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
  });
  if (!res.ok) throw new Error(`GitHub ${init.method || 'GET'} ${path} -> ${res.status}`);
  return res.status === 204 ? null : res.json();
}

async function all(path) {
  const items = [];
  for (let page = 1; page <= 20; page++) {
    const sep = path.includes('?') ? '&' : '?';
    const body = await gh(`${path}${sep}per_page=100&page=${page}`);
    const list = Array.isArray(body) ? body : body.check_runs || body.statuses || [];
    items.push(...list);
    if (list.length < 100) return items;
  }
  throw new Error(`too many pages for ${path}`);
}

const shaMatches = (short, head) => head.toLowerCase().startsWith(short.toLowerCase());

export function evaluate({ pr, comments, reviews, files, checkRuns, statuses, reviewers }) {
  const head = pr.head.sha;
  const author = pr.user.login.toLowerCase();
  const blocks = [];
  const pending = [];
  const notes = [];

  if (pr.state !== 'open') blocks.push(`PR is ${pr.state}`);
  if (pr.draft) blocks.push('PR is a draft');

  // 5. Gate files
  const touched = files.map((f) => f.filename).filter((f) => GATE_FILES.includes(f));
  if (touched.length) blocks.push(`PR changes the review gate (${touched.join(', ')}): a human must review and merge it`);

  // 2. Independent verdict for this head
  const verdicts = [];
  for (const c of comments) verdicts.push({ who: c.user.login, at: c.created_at, body: c.body || '' });
  for (const r of reviews) verdicts.push({ who: r.user.login, at: r.submitted_at, body: r.body || '' });
  const forHead = verdicts
    .filter((v) => reviewers.includes(v.who.toLowerCase()))
    .map((v) => ({ ...v, m: v.body.match(VERDICT) }))
    .filter((v) => v.m && shaMatches(v.m[2], head))
    .sort((a, b) => new Date(a.at) - new Date(b.at));
  const last = forHead.at(-1);
  if (!last) {
    pending.push(`no independent review verdict (REVIEW GREEN @ ${head.slice(0, 8)}) from ${reviewers.join('/')} for the current head`);
  } else if (last.m[1].toUpperCase() !== 'GREEN') {
    blocks.push(`latest independent verdict on ${head.slice(0, 8)} is REVIEW CHANGES (${last.who}, ${last.at})`);
  } else {
    notes.push(`independent review GREEN on ${head.slice(0, 8)} by ${last.who} at ${last.at}`);
  }

  // 3. Formal reviews: latest state per reviewer
  const latest = new Map();
  for (const r of reviews) {
    if (!['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(r.state)) continue;
    const prev = latest.get(r.user.login);
    if (!prev || new Date(r.submitted_at) >= new Date(prev.submitted_at)) latest.set(r.user.login, r);
  }
  for (const [who, r] of latest) if (r.state === 'CHANGES_REQUESTED') blocks.push(`${who} requested changes (${r.submitted_at})`);
  const approvedHead = reviews.some((r) => r.state === 'APPROVED' && r.commit_id === head && r.user.login.toLowerCase() !== author);
  if (!approvedHead) pending.push(`no APPROVED review on head ${head.slice(0, 8)} from someone other than the author`);

  // 4. Checks on this head
  const runs = new Map();
  for (const r of checkRuns) {
    if (r.name === CONTEXT) continue;
    const prev = runs.get(r.name);
    if (!prev || new Date(r.started_at || 0) >= new Date(prev.started_at || 0)) runs.set(r.name, r);
  }
  for (const r of runs.values()) {
    if (r.status !== 'completed') pending.push(`check "${r.name}" is ${r.status}`);
    else if (BAD_CONCLUSIONS.has(r.conclusion)) blocks.push(`check "${r.name}" concluded ${r.conclusion}`);
  }
  const seen = new Set();
  for (const s of statuses) {
    if (s.context === CONTEXT || seen.has(s.context)) continue; // newest first
    seen.add(s.context);
    if (s.state === 'pending') pending.push(`status "${s.context}" is pending`);
    else if (s.state !== 'success') blocks.push(`status "${s.context}" is ${s.state}`);
  }
  if (runs.size === 0 && seen.size === 0) pending.push(`no CI has reported on head ${head.slice(0, 8)}`);

  const state = blocks.length ? 'failure' : pending.length ? 'pending' : 'success';
  return { head, state, blocks, pending, notes };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [owner, name] = args.repo.split('/');
  const base = `/repos/${owner}/${name}`;
  const reviewers = (process.env.REVIEW_GATE_REVIEWERS || 'elarasu')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

  const pr = await gh(`${base}/pulls/${args.pr}`);
  const head = pr.head.sha;
  if (args.status) {
    statusTarget = { base, head };
    await gh(`${base}/statuses/${head}`, {
      method: 'POST',
      body: JSON.stringify({ state: 'pending', context: CONTEXT, description: 'review gate running' }),
    });
  }
  const [comments, reviews, files, checkRuns, statuses] = await Promise.all([
    all(`${base}/issues/${args.pr}/comments`),
    all(`${base}/pulls/${args.pr}/reviews`),
    all(`${base}/pulls/${args.pr}/files`),
    all(`${base}/commits/${head}/check-runs?filter=latest`),
    all(`${base}/commits/${head}/statuses`),
  ]);
  const result = evaluate({ pr, comments, reviews, files, checkRuns, statuses, reviewers });

  // Re-read the head: if it moved while we looked, the answer is stale.
  const again = await gh(`${base}/pulls/${args.pr}`);
  if (again.head.sha !== head) {
    result.state = 'failure';
    result.blocks.push(`head moved from ${head.slice(0, 8)} to ${again.head.sha.slice(0, 8)} during the check; re-run`);
  }

  const verdict = result.state === 'success' ? 'PASS' : result.state === 'pending' ? 'WAIT' : 'BLOCK';
  console.log(`review-gate #${args.pr} @ ${head.slice(0, 8)}: ${verdict}`);
  for (const b of result.blocks) console.log(`  block: ${b}`);
  for (const p of result.pending) console.log(`  wait:  ${p}`);
  for (const n of result.notes) console.log(`  ok:    ${n}`);
  if (result.state === 'success') console.log(`  merge only with: gh pr merge ${args.pr} --repo ${args.repo} --squash --delete-branch --match-head-commit ${head}`);

  if (args.status) {
    const description = (result.blocks[0] || result.pending[0] || result.notes[0] || verdict).slice(0, 140);
    await gh(`${base}/statuses/${head}`, {
      method: 'POST',
      body: JSON.stringify({ state: result.state, context: CONTEXT, description }),
    });
  }
  process.exit(result.state === 'success' ? 0 : 1);
}

let statusTarget = null; // { base, head } once known, so an error can still mark the head red

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(async (err) => {
    console.error(`review-gate: BLOCK (error, failing closed): ${err.message}`);
    if (statusTarget) {
      try {
        await gh(`${statusTarget.base}/statuses/${statusTarget.head}`, {
          method: 'POST',
          body: JSON.stringify({ state: 'error', context: CONTEXT, description: `gate error: ${err.message}`.slice(0, 140) }),
        });
      } catch { /* the status stays non-green either way */ }
    }
    process.exit(1);
  });
}
