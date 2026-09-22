---
name: merge-agent-prs
description: Part 3 of the cognium-dev autofix loop. Squash-merge agent PRs that have a Part 2 approve on the current head SHA and green required CI. Never write product code, never release. Use for the scheduled merger, or invoke by name. Runs with no questions.
---

# Merge Agent PRs — Part 3 of the autofix loop

Squash-merge open **agent** pull requests on `cogniumhq/cognium-dev` that have
already passed Part 2 (`.claude/skills/review-agent-prs/SKILL.md`) and whose
required GitHub checks are green. One invocation = one sweep.

**This skill merges only.** It never writes product code, never pushes new
commits, never force-resolves conflicts, and never runs `release.sh` /
`npm publish`. Release stays human.

## Provenance

Drafted 2026-09-22. The techspec Part 1 cron (`cognium-dev-autofix`) stops at a
labelled PR with `Refs #n` so an auto-closing keyword cannot retire the issue
before anyone reviews the fix. The local `autofix-issues` skill still
auto-merges behind a corpus differential — that is a **different lane**. This
skill is the cloud/human-merge gate: Part 2 approve + CI green → squash.

**This directory is tracked in git** (`.gitignore` is `.claude/*` +
`!.claude/skills/`). A scheduled run only needs: *run the `merge-agent-prs`
skill; never ask questions; if preconditions fail, report and stop.*

## Autonomy contract

- **Never ask the user anything.** Skip the PR rather than ask.
- Idempotent: safe to run every 15 min. Already-merged PRs drop out.
- **Merge only.** No product diffs. No rebase-and-force. No tags.
- Do not flip Part 1 from `Refs` to `Closes` from this skill. That flip is a
  separate, explicit commit to the Part 1 prompt + `autofix-issues` skill,
  only after this automation has been merging cleanly.

## 0. Preconditions

1. `cwd` = repo root of `cogniumhq/cognium-dev`.
2. `gh auth status` must be logged in with **merge permission**. If
   `gh pr merge` 403s, comment once "Part 3: merge blocked, needs a human"
   and stop. Do not retry with `--admin`.
3. Working tree clean. Do not merge from a dirty checkout.

## 0b. Discovery must fail LOUDLY

Same wrapper as Part 1 / Part 2 — an unanswered query is not "nothing to
merge":

```
r() {
  for i in 1 2 3 4 5; do
    out=$("$@" 2>&1)
    if ! echo "$out" | grep -qiE "error connecting|connection reset|read tcp|502 Bad Gateway|503 Service|504 Gateway|timed out|could not resolve|API rate limit|API_UNREACHABLE"; then
      echo "$out"; return 0
    fi
    sleep 12
  done
  echo "API_UNREACHABLE"; return 1
}
```

Do **not** match generic `5[0-9][0-9] ` (see `review-agent-prs` / issue #213).
Any failed query → "discovery unreliable: GitHub API unreachable" and STOP.

## 1. Discover candidate PRs

```
gh pr list --repo cogniumhq/cognium-dev --state open --limit 50 \
  --json number,title,headRefName,isDraft,mergeable,url,labels,statusCheckRollup,reviews
```

Keep a PR if **all** of:

- base is `main`
- not a draft
- head ref starts with `agent/fix-` **or** title starts with `agent: fix`
- `mergeable` is `MERGEABLE` (skip `CONFLICTING` / `UNKNOWN`)

**Label-blind queue.** Do not require `agent-pr` — cloud Part 1 often cannot
apply it. `agent/fix-*` / `agent: fix` is the queue.

Never merge a non-agent PR (dependabot, `fix/` heads, human drafts such as
the #447-style work).

Cap: **at most 3 PRs per run**, oldest first.

If zero remain after §2–§3 filters: exit "No agent PRs ready for Part 3."

## 2. Part 2 must have approved THIS head SHA

```
HEAD=$(gh pr view <n> --repo cogniumhq/cognium-dev --json headRefOid -q .headRefOid)
```

Require a review on that SHA whose body starts with `## Part 2 review` and
whose state is `APPROVED`.

`agent-review-pass` is supporting evidence, not a substitute — labels can
lag a new push. A Part 2 approve on a **stale** SHA does not count.

If Part 2 has requested changes on this SHA (`agent-review-fail` or a
`CHANGES_REQUESTED` review starting `## Part 2 review`): skip. Do not merge
over a live request-changes.

## 3. Required CI must be green on THIS SHA

Read `statusCheckRollup` for the head. Every required check must be
`SUCCESS`. If any is `PENDING` / `QUEUED` / `IN_PROGRESS`, skip (do not
merge, do not "fix" CI). If any is `FAILURE` / `CANCELLED` / `TIMED_OUT`,
comment one line naming the red check and skip.

Required checks from `.github/workflows/ci.yml` (names as they appear on
the PR):

- `lint`
- `build + typecheck`
- `test — circle-ir`
- `test — cli`
- `test — mcp-server`
- `test — project-profile-detect`
- `self-scan (SAST)`
- `dependency audit`
- `pack dry-run`

If the rollup lists additional required checks (branch protection can grow),
those are required too — do not hard-code a closed set that ignores new
required contexts. The list above is the 2026-09-22 baseline.

## 4. Conflicts

If `mergeable` is `CONFLICTING`:

```
gh pr comment <n> --repo cogniumhq/cognium-dev -b "Part 3: conflicts with main — Part 1 must re-open."
```

If the token allows, label the linked issues `agent-blocked` +
`autofix-skip` and remove `agent-in-progress`. **Do not rebase. Do not
force-resolve.** Conflict resolution is a judgement this loop must not make
unattended (same rule as Part 1 §7).

## 5. Merge

```
gh pr merge <n> --repo cogniumhq/cognium-dev --squash --delete-branch
```

No `--admin`. If GitHub refuses (permission, ruleset, required review from
someone else): comment "Part 3: merge blocked, needs a human" and leave the
PR open. Stop retrying that PR for this sweep.

### After a successful squash

Part 1 PRs use `Refs #n`, so squash-merge will **not** auto-close issues.
Close each linked issue yourself:

```
gh issue comment <n> --repo cogniumhq/cognium-dev -b "Shipped in cogniumhq/cognium-dev#<pr>."
gh issue close <n> --repo cogniumhq/cognium-dev --reason completed
gh issue edit <n> --repo cogniumhq/cognium-dev --remove-label agent-in-progress
```

A leftover `agent-in-progress` halts every later Part 1 sweep. A squash that
closes the issue still does not strip labels.

Do not remove `agent-pr` from the (now closed) PR — it is historical.

For a cognium-ai `sast-only` issue linked as `Fixes cogniumhq/cognium-ai#n`:
comment the PR link on that issue. Do not close it; that is the cognium-ai
team's call.

For a cognium-dev **child** whose body has `Parent: cogniumhq/cognium-ai#<p>`:
comment the PR + child number on the parent. If the parent has no remaining
open children, add: *"Engine side complete for this ticket (children: …,
shipped in cognium-dev#<prs>). Remaining non-engine parts are back with
cognium-ai."* Do not remove `needs-sast` and do not close the parent.

## 6. Report

- **Merged:** PR numbers + issues closed.
- **Skipped:** waiting on CI / waiting on Part 2 / conflicts / no permission.
- **Remaining open agent PRs:** include unlabeled `agent: fix` titles, not
  just `label:agent-pr` (that query is often 0 while PRs sit open).
- Confirm no merged issue still carries `agent-in-progress`.
- If nothing ready: "No agent PRs ready for Part 3."

## Never

- Never merge a PR without a Part 2 `## Part 2 review` APPROVE on **this** SHA.
- Never merge when any required check is red or still running.
- Never merge a non-agent PR.
- Never run `release.sh`, `npm publish`, or create tags.
- Never commit to `main`, force-push, or rebase-and-force.
- Never resolve merge conflicts.
- Never use `gh pr merge --admin`.
- Never close a cognium-ai parent issue.
- Never ask a question — skip the PR.
