---
name: review-agent-prs
description: Part 2 of the cognium-dev autofix loop. Review open agent PRs (head agent/fix-* or title "agent: fix") on cogniumhq/cognium-dev — approve or request changes, never push or merge. Use for the scheduled reviewer, or invoke by name. Runs with no questions.
---

# Review Agent PRs — Part 2 of the autofix loop

Review open **agent** pull requests on `cogniumhq/cognium-dev`. Approve when the
diff is in-boundary and tested; request changes otherwise. One invocation = one
sweep. Designed to run unattended after Part 1 (`autofix-issues`) opens a PR.

**This skill reviews only.** It never pushes, never merges, never runs
`release.sh`, and never edits product code. Merge is Part 3
(`.claude/skills/merge-agent-prs/SKILL.md`).

## Provenance

Drafted 2026-09-22 from the cloud Part 1 / Part 2 / Part 3 split in
`techspec/skills/cognium-dev-autofix.md` (Eyal, 2026-09-10) and the running
Part 1 skill (`.claude/skills/autofix-issues/SKILL.md`). Part 1's cloud cron
stops at a labelled PR with `Refs #n`; this skill is the missing review gate
before Part 3 may squash-merge.

**This directory is tracked in git** (`.gitignore` is `.claude/*` +
`!.claude/skills/`). A scheduled run only needs: *run the `review-agent-prs`
skill; never ask questions; if preconditions fail, report and stop.*

## Autonomy contract

- **Never ask the user anything.** Skip the PR rather than ask.
- Idempotent: safe to run every 15 min. A PR already reviewed on the **current
  head SHA** is skipped.
- **Review only.** No commits, no force-push, no merge, no `release.sh`, no
  `npm publish`.
- Never introduce LLM/AI naming into review text as a product feature (repo
  `CLAUDE.md` Pillar I boundary). "Part 2 review" is the section heading; do
  not describe the engine as an LLM verifier.

## 0. Preconditions

1. `cwd` = repo root of `cogniumhq/cognium-dev`.
2. `gh auth status` must be logged in with **pull-requests: write** (submit
   reviews, comment, add `agent-review-pass` / `agent-review-fail`). If a
   mutation 403s, report the 403 and continue the rest of the review in the
   run transcript — do not treat the PR as missing.
3. Ensure the review-state labels exist (idempotent, home-repo only):
   ```
   R=cogniumhq/cognium-dev
   mklabel() { gh label list --repo $1 --json name -q '.[].name' | grep -qx "$2" \
     || gh label create "$2" --repo $1 --color "$3" --description "$4"; }
   mklabel $R agent-review-pass 0E8A16 "Part 2 approved the current head SHA"
   mklabel $R agent-review-fail D93F0B "Part 2 requested changes"
   ```
4. Working tree should be clean. If it is dirty with work you cannot account
   for, stop and report — do not check out a PR on top of it.

## 0b. Discovery must fail LOUDLY

An unanswered `gh` query is not an empty queue. Wrap every `gh` call:

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

Do **not** match a generic `5[0-9][0-9] ` — issue titles in this repo have
contained "512 cells", and that discarded a successful payload as
`API_UNREACHABLE`. Any failed query → report "discovery unreliable: GitHub API
unreachable" and STOP. Never report "no agent PRs" from a failed query.

## 1. Discover candidate PRs

```
gh pr list --repo cogniumhq/cognium-dev --state open --limit 50 \
  --json number,title,headRefName,isDraft,url,labels,reviews,commits
```

Keep a PR if **all** of:

- base is `main`
- not a draft
- head ref starts with `agent/fix-` **or** title starts with `agent: fix`
- not already merged/closed

**Label-blind queue.** Cloud Part 1 often cannot apply `agent-pr` (token 403).
Do not require that label. Treat `agent/fix-*` / `agent: fix` as the queue.
If `agent-pr` is present, that is sufficient too.

Drop a PR that already has a Part 2 review on the **current head SHA**: a
review whose body starts with `## Part 2 review` and whose `commit_id` equals
`gh pr view <n> --json headRefOid -q .headRefOid`. A review on a stale SHA
does not count — re-review.

Cap: **at most 3 PRs per run**, oldest first (`createdAt`).

If zero remain: exit "No agent PRs waiting for Part 2."

## 2. Check out the PR (read-only)

```
git fetch origin pull/<n>/head:review-<n>
git checkout review-<n>
```

Do not create `agent/fix-*` branches. Do not commit. Delete `review-<n>` at
the end of the sweep (`git checkout main && git branch -D review-<n>`).

## 3. Review the diff

Read the PR body, `git diff origin/main...HEAD`, and the linked issues.

### 3a. Body contract

The body MUST contain, per issue: **what was wrong**, **what changed**, **how
it was tested**; the exact test command and a pass summary; `Refs #n` (not
`Closes` — Part 3 owns closing until that flip is explicit). Missing any of
these → request changes, do not invent the missing section.

### 3b. In-boundary

Approve only if the diff is confined to `packages/circle-ir/` and/or
`packages/cli/` (plus tests next to the change).

**Request changes** if the diff touches any of:

- `packages/mcp-server/`, `packages/project-profile-detect/`
- `.github/workflows/`, `release.sh`, packaging/publish, new dependencies
- a public export from `packages/circle-ir/src/index.ts` or a CLI flag's meaning
- any LLM/AI identifier, `--llm-*` flag, or "LLM verify / adjudicator" language

Estimated core-logic diff **> ~200 lines** → request changes ("grew beyond
minor — needs a human").

### 3c. Tests

Each linked issue must have a test that would have failed before the fix.
A characterization test that was flipped to the corrected expectation is
acceptable if its header comment said to do that. Deleting a characterization
test → request changes.

### 3d. Precision fixes

A precision fix (sink narrowing, sanitizer credit, FP removal) may be
approved **only** when the body pastes a `GATE: PASS` bench-diff table from
`.claude/skills/autofix-issues/bench-diff.mts` showing zero true-positive
loss. Missing table → request changes. Cloud Part 1 is not supposed to open
precision PRs without corpora; if one arrives anyway, this is the gate.

### 3e. Re-run tests when cheap

If the claimed command is the package suite / typecheck and the tree builds,
re-run it. Require: no new failures vs the PR body's pass summary. If you
cannot run it (missing bun, missing `node_modules`, no time), say so in the
review and **do not APPROVE**.

### 3f. Consumer-visible behaviour

The PR body must state anything a consumer would notice (exit-code change,
a finding that stops being reported, a severity change). If the diff has
one and the body is silent → request changes.

Watch for suppressions that drop the **only** finding for a real bug
(Part 1's rule: suppress where another finding already covers the defect).

## 4. Verdict

Every review body **must** start with:

```
## Part 2 review

head: <full SHA>
```

Then the checklist and the one-paragraph verdict.

- **APPROVE**
  ```
  gh api repos/cogniumhq/cognium-dev/pulls/<n>/reviews -f event=APPROVE -f body="$(cat <<'EOF'
  ## Part 2 review

  head: <sha>

  …
  EOF
  )"
  gh pr comment <n> --repo cogniumhq/cognium-dev -b "Part 2: approve on <sha>. Ready for Part 3 once CI is green."
  gh pr edit <n> --repo cogniumhq/cognium-dev --add-label agent-review-pass --remove-label agent-review-fail
  ```
  You may APPROVE while CI is still pending. You must **not** APPROVE if CI
  on this SHA is already red. Part 3 waits for green.

- **REQUEST CHANGES**
  ```
  gh api repos/cogniumhq/cognium-dev/pulls/<n>/reviews -f event=REQUEST_CHANGES -f body="…"
  gh pr edit <n> --repo cogniumhq/cognium-dev --add-label agent-review-fail --remove-label agent-review-pass
  ```
  One paragraph per defect. No style nits. Do not try to fix the PR.

- **Out of boundary** — REQUEST CHANGES, and if the token allows, label the
  linked issues `agent-blocked` with "Part 2: out of boundary — will not
  approve". Do not close the PR.

If label/review mutations 403, still write the verdict in the run report and
retry the comment once. Do not loop.

## 5. Report

- **Approved:** PR numbers + head SHAs.
- **Changes requested:** PR → one-line reason.
- **Skipped:** already reviewed on this SHA / draft / not an agent PR.
- **Lock-adjacent:** do not touch `agent-in-progress` on issues; that is Part 1.
- If nothing eligible: "No agent PRs waiting for Part 2."

Then `git checkout main` and delete any `review-<n>` branches.

## Never

- Never merge, push, force-push, or commit.
- Never dismiss someone else's review.
- Never approve a precision fix without `GATE: PASS` in the PR body.
- Never approve when CI on this SHA is already red.
- Never review a non-agent PR (human drafts, dependabot, `fix/` heads).
- Never add an `agent-*` label to a cognium-ai issue.
- Never ask a question — skip or request changes.
