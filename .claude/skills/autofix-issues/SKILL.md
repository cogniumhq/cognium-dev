---
name: autofix-issues
description: Autonomously triage open GitHub issues for cognium-dev, label cognium-ai issues that need engine work (sast-only / needs-sast) and mirror their engine sub-defects as cognium-dev child issues, fix strictly SAST-only bugs with upgraded tests, and batch auto-merge. Use for scheduled or unattended issue cleanup. Runs with no questions.
---

# Autofix Issues — autonomous SAST issue triage & fix

Sweep the open issues of `cogniumhq/cognium-dev` **and** `cogniumhq/cognium-ai`, critically
triage them, label cognium-ai tickets that need engine work (`sast-only` for pure engine
defects, `needs-sast` for mixed tickets — whose engine sub-defects are mirrored as
cognium-dev child issues), fix the **strictly SAST-only + minor** ones here with tests
(precision fixes gated by a benchmark differential), and batch-merge. One invocation = one
sweep. Designed to run unattended on a schedule.

## Provenance

Two specs merged 2026-09-10: this repo's running skill (SAST boundary, benchmark differential,
cross-repo cognium-ai triage, auto-merge) and `techspec/skills/cognium-dev-autofix.md`
(Eyal, 2026-09-10 — `agent-*` labels, pending-PR cap, concurrency lock, batch of 3,
`agent/fix-N` branches, rebase-conflict abort, explicit boundary exclusions, Buzz notify).
`techspec` is read-only from here per `CLAUDE.md`; nothing was written back to it. One
deliberate divergence is flagged inline at §8 step 4 (auto-merge).

**This directory is tracked in git** as of 2026-09-10. `.gitignore` was narrowed from `.claude/`
to `.claude/*` + `!.claude/skills/`, so this file and the §7 scorer `bench-diff.mts` travel with a
clone while `settings.local.json` stays per-user. Before that, a session had to be handed the whole
procedure verbatim in its prompt and a fresh clone could not run §7 at all. A scheduled run now
only needs: *run the `autofix-issues` skill*. The corpora the scorer reads are still local-only
(`circle-ir-ai`), so a runner without them must skip precision fixes per §2.

## Autonomy contract

- **Never ask the user anything.** Do not pause for confirmation. Accept every default
  y/n prompt as its safe default (proceed on benign prompts; decline anything that would
  do extra destructive/irreversible work). If a step genuinely cannot proceed without a
  human decision, **skip that issue** (§2) rather than ask.
- Idempotent: safe to run every 30 min. Handled issues drop out via issue-closing PRs;
  declined issues are excluded via the `autofix-skip` label; cognium-ai issues already
  labeled `sast-only` or `needs-sast` are not re-triaged.
- **Scope boundary (CRITICAL): this repo's lane is strictly SAST-only issues.** An issue is
  eligible only if it is a defect in the *deterministic analysis* (see §2). Anything else —
  however small — is out of boundary and must **not** be picked up. Do not stretch the
  definition to fill a batch; an empty sweep is the correct outcome when nothing is SAST-only.
- **Repo boundary (CRITICAL):** never modify any *file* outside
  `/Users/eyal/work/cogniumhq/cognium-dev`. The **only** permitted action on
  `cogniumhq/cognium-ai` is GitHub issue metadata via `gh`: adding the `sast-only` /
  `needs-sast` labels and comments. Never clone, edit, branch, push, open PRs, or run
  installs there.
  Never introduce LLM/AI concepts, dependencies, or naming anywhere (see repo `CLAUDE.md`).

## 0. Preconditions

1. `cwd` = repo root.
2. Working tree must be clean. Run `git status --porcelain`; if it has unrelated changes,
   **stop and report** — do not fix on top of someone's WIP.
3. `git fetch --prune origin && git checkout main && git pull --ff-only origin main`.
   `--prune` first, and it matters: this lane deletes merged branches, so a long-lived
   workspace accumulates remote-tracking refs for branches that no longer exist. If the pull is
   **not** a fast-forward, do not merge or reset — exit and report, that needs a human.
   Housekeeping, safe to skip if empty:
   `git branch --merged main | grep -E '^\s+(agent/fix-|autofix/)' | xargs -r git branch -d`
4. `gh auth status` must be logged in.
5. Ensure the lane + run-state labels exist (idempotent). The `agent-*` set comes from
   the techspec spec (`techspec/skills/cognium-dev-autofix.md`, Eyal 2026-09-10) and is
   **home-repo only** — never apply an `agent-*` label to cognium-ai.
   ```
   R=cogniumhq/cognium-dev
   mklabel() { gh label list --repo $1 --json name -q '.[].name' | grep -qx "$2" \
     || gh label create "$2" --repo $1 --color "$3" --description "$4"; }
   mklabel $R agent-in-progress 0E8A16 "Picked up by the current autofix run (concurrency lock)"
   mklabel $R agent-pr          1D76DB "Has an open autofix PR awaiting merge"
   mklabel $R agent-declined    D93F0B "Judged out of boundary by autofix; not attempted"
   mklabel $R agent-blocked     B60205 "Autofix attempted and could not land; see comment"
   mklabel $R agent-ok          FBCA04 "Explicitly cleared for autofix"
   ```
   Why both vocabularies: `autofix-skip` remains the opt-out marker, but it conflated two very
   different states — "never attempted, out of boundary" and "attempted and it broke". A review
   of all 20 skipped issues on 2026-09-10 could not tell those apart without reading every
   comment. `agent-declined` and `agent-blocked` split them; keep applying `autofix-skip`
   alongside so discovery stays a single query.

6. Ensure the two lane labels exist on both repos (idempotent):
   ```
   for r in cogniumhq/cognium-dev cogniumhq/cognium-ai; do
     gh label list --repo $r --json name -q '.[].name' | grep -qx sast-only \
       || gh label create sast-only --repo $r --color 0E8A16 \
            --description "Pure deterministic SAST defect; owned by the cognium-dev lane"
     gh label list --repo $r --json name -q '.[].name' | grep -qx needs-sast \
       || gh label create needs-sast --repo $r --color FBCA04 \
            --description "Mixed ticket; engine sub-defects owned by cognium-dev lane"
   done
   ```

## 0b. Guardrails — check these before discovering anything

From the techspec spec. Each is a hard exit, not a warning; report the reason and stop.

- **Pending-PR cap.** Count open PRs labeled `agent-pr`. If **>= 5**, exit:
  "Skipped: 5+ agent PRs pending merge." Auto-merge (§8) normally keeps this at zero, so a
  non-zero count means merges are being refused — the cap stops the queue growing behind it.
  ```
  gh pr list --repo cogniumhq/cognium-dev --state open --label agent-pr --json number --jq 'length'
  ```
- **Concurrency lock, with a 2-hour expiry.** Two sweeps fixing the same file is how you get a
  half-reverted tree, so a live lock is a hard exit. But a lock left by a *dead* run must not
  halt the loop forever — a healthy sweep finishes in minutes, so anything held past 2 h (four
  missed cycles at the 30-minute cadence) is stale and this sweep clears it with an audit trail.
  ```
  gh issue list --repo cogniumhq/cognium-dev --state open --label agent-in-progress --json number --jq '.[].number'
  # for each, when was the label applied?
  gh api repos/cogniumhq/cognium-dev/issues/<n>/timeline --paginate \
    --jq '[.[] | select(.event=="labeled" and .label.name=="agent-in-progress") | .created_at] | max'
  # older than 2h → clear it and say so:
  gh issue comment <n> -b "autofix: clearing a stale \`agent-in-progress\` (held >2 h; prior run did not complete)."
  gh issue edit <n> --remove-label agent-in-progress
  ```
  Any lock **newer** than 2 h → exit "Skipped: previous run still in progress."

  Use the REST `timeline` endpoint, **not** `gh issue view --json timelineItems` — that field does
  not exist (`gh issue view --json` with no value prints the valid list, and `timelineItems` is not
  in it), so the earlier form errored and the expiry silently never fired. Review fix, 2026-09-10.

  (Supersedes an earlier rule here that said never to clear a stale lock. That was wrong for an
  unattended loop: its failure mode is a permanent halt, and the 2-hour bound makes clearing
  safe because no healthy run holds the lock that long. Review fix, 2026-09-10.)

## 1. Discover candidate issues

### 1a. cognium-dev (home repo)

```
gh issue list --repo cogniumhq/cognium-dev --state open --limit 100 \
  --json number,title,labels,body \
  --jq '[.[] | select(.labels|map(.name)|((index("autofix-skip")) or (index("agent-declined")) or (index("agent-blocked")) or (index("agent-in-progress")))|not)]'
```
An issue labeled **`agent-ok`** is pre-cleared: still apply the §2 boundary test (the SAST
boundary is not negotiable), but do not defer it for being merely *unfamiliar* — a human has
already vouched that it is wanted.

### 1b. cognium-ai (cross-repo triage: pure-SAST vs. mixed vs. not ours)

```
gh issue list --repo cogniumhq/cognium-ai --state open --limit 200 \
  --json number,title,labels,body \
  --jq '[.[] | select((.labels|map(.name)|(index("sast-only") or index("needs-sast")))|not)]'
```
(Do **not** exclude cognium-ai's `autofix-skip` here: that label is set by cognium-ai's own
skill for issues outside *its* layer, which is exactly where engine issues land. Also note
`gh issue list --search "-label:x"` returns nothing on these repos — filter with `--jq`.)
Read each one **in full** (body + comments; the last comment often reassigns the defect)
against the §2 definition and sort it into one of three buckets:

- **Pure SAST** — the whole defect reproduces in circle-ir/CLI alone (no cognium-ai code,
  LLM, MCP, harness, or product layer). Label `sast-only` + one comment. These are fixed
  here directly and closed by the PR (`Fixes cogniumhq/cognium-ai#n`).
- **Mixed / needs engine work** — the ticket is not ours as a whole (LLM verify, corpus
  report, trust product, umbrella…) but names **concrete engine sub-defects**: a specific
  sink/source/sanitizer registration, taint-propagation shape, pass or metric misfiring,
  or anchor/line bug, attributable to circle-ir rather than to LLM affirmation or
  circle-ir-ai filters. **Verify each sub-defect against the registry** (`grep` the
  method/class in `config-loader.ts` / the language plugin) before accepting it — corpus
  tickets routinely blame the engine for shapes that are not registered at all (those are
  LLM-discovery artifacts) or that are already fixed. Then:
  1. For each verified sub-defect that has no open cognium-dev issue yet, **file a
     cognium-dev child issue**: title `[from cognium-ai#<n>] <engine defect>`, labels
     `bug,sast-only`, body with `Parent: cogniumhq/cognium-ai#<n>`, the registry location,
     a self-contained minimal fixture, expected vs. actual, and the acceptance rule.
  2. Label the parent `needs-sast` and comment once, listing the child issues and stating
     the protocol: *engine side is worked in cognium-dev; when every child is closed the
     lane comments back and the remainder stays with cognium-ai.*
- **Not SAST** — no label, no comment. Leave it for the cognium-ai team (that repo's
  `autofix-skip` belongs to its own skill — never add it from this sweep).

Then merge the candidate pool: all 1a issues (this now includes the mirrored children)
**plus** every cognium-ai issue carrying `sast-only`:
```
gh issue list --repo cogniumhq/cognium-ai --state open --limit 200 --label sast-only \
  --json number,title,labels,body
```
`needs-sast` parents are **never** fixed directly — only their cognium-dev children are.

Drop any issue that already has an **open PR** referencing it
(`gh pr list --repo cogniumhq/cognium-dev --search "<#n> in:body"` for home issues;
`--search "cognium-ai#<n> in:body"` for cognium-ai ones).

## 2. Triage each candidate — keep only STRICTLY SAST-ONLY + MINOR

Read the issue critically (title, body, labels, referenced files/fixtures).

**SAST-only → eligible.** A defect in the *deterministic analysis itself*: false positives
(FP), false negatives (FN), and bugs in analysis passes, the sink/source/sanitizer
registries, taint propagation, severity, software-quality metrics, or the CLI's rendering
of findings (text/JSON/SARIF). It must reproduce with circle-ir or the CLI alone on a
fixture. Detection passes that target AI-security topics (e.g. `prompt_injection`, `aisec`
fixtures) **are deterministic SAST and are in boundary.**

A **cognium-ai `sast-only` issue** is eligible on the same terms, and is fixed **here** (the
engine lives in circle-ir). It counts as SAST-only only when the issue supplies, or trivially
implies, a fixture you can run through circle-ir directly. If the reproduction needs
cognium-ai's pipeline, harness, or scoring to observe, it is **not** pure SAST: remove the
`sast-only` label if this sweep added it, and leave it.

**OUT of boundary → `autofix-skip` + comment the reason (home repo only):**
- Anything that is not analysis correctness: packaging/release/versioning, CI, npm
  publishing, marketplace/plugin listings, docs, `packages/mcp-server`,
  `packages/project-profile-detect`, build tooling, dependency bumps.
- LLM/AI *infrastructure or product features*: hosted/streamable MCP servers, any LLM/AI
  dependency, `--llm-*` flags, "LLM verify/adjudicate", ChatGPT/Codex hosting (e.g. #296).
- Tracking / umbrella / meta issues (label `tracking`, or title `[tracking]`/`[umbrella]`).
- `question`, `needs-decision`, `wontfix`, `duplicate`, `invalid`, `documentation`-only.

**Hard out-of-boundary, from the techspec spec — any one of these disqualifies regardless of
how small the diff looks.** Label `agent-declined` + `autofix-skip`, comment one sentence, move on:
- A schema change or data migration.
- Auth, security-control, or payment code (as *product* code — analysing such code is our job;
  editing our own auth/payment paths is not).
- A **new dependency** (circle-ir depends only on `web-tree-sitter` and `yaml`; see
  `principles.md`).
- A **public API change** — anything altering an export from `packages/circle-ir/src/index.ts`
  or a CLI flag's meaning. `tests/public-entry-exports.test.ts` guards the export surface.
- An estimated diff **> ~200 lines** of core logic (§6 keeps its tighter ~150-line abort too).

**NOT MINOR → `agent-declined` + `autofix-skip` + comment "deferred: needs design / too large":**
- Major refactors, new subsystems/passes, cross-cutting API changes.
- "architect depth" or large-N sweeps (phrases like "35 live", "512 cells",
  "modern ecosystem sinks", top-N sweeps).
- No reproducible signal (no fixture, no concrete expected-vs-actual).
- Requires a product/scope/severity-policy decision.

**Precision fixes (sink narrowing, sanitizer credit, FP removal) are eligible** — but
"no new test failures" is NOT a sufficient gate for them, because dropping a true positive
fails no existing test. They may proceed only when the language has a local corpus for the
§7 benchmark differential (Java: OWASP + SecuriBench; Python: BenchmarkPython; C#:
Juliet-C#; JS/TS: nodegoat + juice-shop + dvna). A precision fix for a language with no
local corpus is NOT minor → skip with reason "no local benchmark gate".

**When unsure whether it is minor, treat it as NOT minor and skip.** Bias toward leaving
hard or ambiguous issues for humans. It is always acceptable for a sweep to fix nothing.

To skip, record WHICH kind of skip it is — a review of all 20 skipped issues on 2026-09-10 was
slowed badly by `autofix-skip` alone not distinguishing these:
```
# never attempted (out of boundary / not minor):
gh issue comment <n> -b "<one-line reason>" && gh issue edit <n> --add-label agent-declined --add-label autofix-skip
# attempted, could not land (see §7):
gh issue comment <n> -b "<failure summary>" && gh issue edit <n> --add-label agent-blocked --add-label autofix-skip --remove-label agent-in-progress
```
Always state the reason in the comment. A future sweep — or a human review — re-reads these, and
**a skip reason can go stale**: several written 2026-09-01 said "precision-risky" before the §7
benchmark differential existed, and four of them were fixable once it did. Cite the *specific*
blocker (a missing fixture, an absent corpus, a pending decision), never a general vibe.

## 3. Select a batch

From the eligible set, take **up to 3**, oldest first, then smallest and clearest. Fewer is
fine. (Was 5; the techspec spec sets 3 and a smaller batch keeps the benchmark differential in
§7 attributable — with five fixes in one branch a single corpus delta cannot be pinned to a
commit.) If none are eligible, go straight to §9 and report "no eligible issues".

**Take the lock immediately**, before branching, so a concurrent run bails at §0b:
```
gh issue edit <n> --repo cogniumhq/cognium-dev --add-label agent-in-progress
```
Every exit path after this point MUST remove it — §7 abandonment, §8 failure, and §9 all do.
A stale `agent-in-progress` halts later sweeps until the §0b 2-hour expiry clears it — the
intended failure direction (stop rather than double-fix), self-healing rather than permanent.

## 4. Branch

Name the branch after the issues it fixes, not the clock — a reviewer can then tell what a
branch is for without opening it (techspec spec):
```
git checkout -b agent/fix-12-15-18     # the issue numbers, joined by -
```

## 5. Baseline the tests (regression guard)

`main` is **not** fully green today, so regression = *new* failures, not absolute red.
Before touching code, for each package an issue will affect, capture a baseline:

- Map issue → package. Nearly all are `packages/circle-ir`; findings-rendering issues →
  `packages/cli`. (`packages/mcp-server` and `packages/project-profile-detect` are out of
  boundary per §2 — an issue that maps there should already have been skipped.)
- Run that package's suite and save the failing-test set to a scratch file, e.g.
  `cd packages/circle-ir && npm test 2>&1 | tee "$SCRATCH/autofix-baseline-circle-ir.txt"`
  (`$SCRATCH` = the session scratchpad directory; never `/tmp`).
  Record pass/fail counts and the names of any failing tests.

## 6. Fix each issue (one commit per issue)

Follow the package's `CLAUDE.md` conventions:
- **Sinks/sources/sanitizers:** edit `DEFAULT_SOURCES` / `DEFAULT_SINKS` /
  `DEFAULT_SANITIZERS` in `src/analysis/config-loader.ts`, or the plugin
  `getBuiltinSources()/getBuiltinSinks()`. Never register a duplicate
  `(class, method, cwe)` across both surfaces — `sink-registry-contract.test.ts` enforces it.
- **Add or upgrade tests**: a test that fails before the fix and passes after. Put it in
  the package `tests/` tree next to sibling cases.
- **Keep the diff localized.** If a fix grows past ~150 lines of core logic, adds new
  files/subsystems, or fans out across many modules: `git reset --hard` that fix,
  `autofix-skip` the issue with reason "grew beyond minor", and continue.
- Commit per issue: `git commit -m "fix(<area>): <summary> (#<n>)"` with a body line
  `Fixes #<n>` so the eventual squash-merge auto-closes it. For a cognium-ai issue use the
  fully qualified form in both places: `(cognium-ai#<n>)` in the subject and
  `Fixes cogniumhq/cognium-ai#<n>` in the body.

After **each** fix, re-run the affected package suite. Require: the issue's new test now
passes **and** the failing-test set is still ⊆ the baseline (no new failures). If a fix
regresses and isn't trivially fixable, revert just that commit, `autofix-skip` the issue,
and move on.

## 7. Final verification (whole batch)

- Run the full suite for every affected package.
- `npm run typecheck` and `npm run build` for each touched package.
- Require: **no new test failures vs. baseline**, typecheck clean, build clean.
- **Benchmark differential (mandatory for any precision fix).** Use the scorer that ships
  with this skill — do not reinvent it:
  `bun .claude/skills/autofix-issues/bench-diff.mts` (`pretree` / `snapshot` / `diff`).
  Corpora live read-only under `/Users/eyal/work/cogniumhq/cognium-ai/circle-ir-ai/`
  (never write there). Pick by language of the fix:

  | language | corpus dir (under circle-ir-ai/) | expected CSV | note |
  |---|---|---|---|
  | java | `.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode` + `securibench-micro` | `.owasp-benchmark-java/expectedresults-1.2.csv` | OWASP ≈ 22 min per snapshot |
  | python | `benchmark-python/testcode` | `benchmark-python/expectedresults-0.1.csv` | |
  | csharp | `juliet-csharp` with `--filter 'CWE<nn>_'` for the fix's CWE (46k files total) | none | |
  | javascript / typescript | `nodegoat`, `juice-shop`, `dvna` | none | small; no TP labels → treat every removal as review |
  | go / rust / bash / html | none local | — | **not eligible for a precision auto-fix** |

  Procedure (BASE = the main SHA the branch started from):
  ```
  BENCH="$SCRATCH/bench"; mkdir -p "$BENCH"
  # 1. pre-fix tree, cached per BASE so later issues in the batch reuse it
  [ -d "$BENCH/pre-$BASE" ] || bun .claude/skills/autofix-issues/bench-diff.mts pretree $BASE "$BENCH/pre-$BASE"
  [ -f "$BENCH/<corpus>-$BASE.json" ] || bun .claude/skills/autofix-issues/bench-diff.mts snapshot <corpus-dir> "$BENCH/<corpus>-$BASE.json" --src "$BENCH/pre-$BASE/packages/circle-ir/src"
  # 2. post-fix tree = working tree (HEAD of the autofix branch, after the commit)
  bun .claude/skills/autofix-issues/bench-diff.mts snapshot <corpus-dir> "$BENCH/<corpus>-<issue>.json"
  # 3. gate — --allow is a regex over "sink_type@" naming ONLY the FP shape this fix targets
  bun .claude/skills/autofix-issues/bench-diff.mts diff "$BENCH/<corpus>-$BASE.json" "$BENCH/<corpus>-<issue>.json" --expected <csv> --allow '^nosql_injection@'
  ```
  The scorer exits 0 and prints `GATE: PASS` only when there is **no removal on a
  real=true file** and **every removal matches `--allow`**. Corpora without an expected CSV
  pass only when every removal matches `--allow`. Paste the `summary:` line and every
  `REMOVED`/`ADDED` row into the PR body. On `GATE: FAIL`: revert that commit, `autofix-skip`
  the issue with reason "benchmark gate: <summary line>", and continue. Signature = one
  `sink_type@source_line->sink_line` per `ir.taint.flows` entry, so this measures exactly
  what the CLI reports; it is a delta tool, not the official TPR/FPR number.
- **Rebase onto latest main before judging anything** (techspec spec — never verify a stale
  tree): `git fetch origin && git rebase origin/main`. **On conflict: abort, do not resolve.**
  ```
  git rebase --abort
  ```
  Then label every picked issue `agent-blocked` (+ `autofix-skip`, remove `agent-in-progress`),
  comment the conflicting paths, delete the branch, and exit via §9. Force-resolving someone
  else's conflict is exactly the kind of judgement this loop must not make unattended.
- If anything is red that wasn't red in the baseline: do **not** merge. Revert the
  offending commit(s), re-verify. If still red, `git checkout main`, delete the branch,
  label the picked issues `agent-blocked` + `autofix-skip`, remove `agent-in-progress`,
  comment the failure summary, and go to §9.

## 8. Deliver — PR + auto-merge

Only if §7 passed and at least one fix survived:

1. `git push -u origin <branch>`.
2. Open the PR (base `main`), labelled `agent-pr` so the §0b cap can see it. Title and body
   shape from the techspec spec:
   ```
   gh pr create --repo cogniumhq/cognium-dev --base main --head <branch> --label agent-pr \
     --title "agent: fix #a, #b, #c" \
     --body "<see required body sections below>"
   ```
   The body MUST contain, per issue: **what was wrong**, **what changed**, **how it was tested**;
   then the **exact test command and its pass summary**; then a `Closes #<n>` line for each. Keep
   the §7 benchmark differential table — that is this repo's addition and the reason a precision
   fix is trustworthy at all.
3. Auto-merge squash (closes the linked issues, deletes the branch):
   ```
   gh pr merge <pr> --repo cogniumhq/cognium-dev --squash --delete-branch
   ```
4. If the merge is refused (permission/classifier): leave the PR open (it keeps `agent-pr`, so
   §0b's cap counts it), comment "ready — auto-merge blocked, needs a manual merge", remove
   `agent-in-progress` from the issues, and report it in §9.

   > **Known policy divergence — auto-merge.** The techspec spec scopes Part 1 to *opening* a PR
   > and says auto-merge is Part 3, "not in this spec" — i.e. that design wants a human to merge.
   > This skill auto-merges, and that behaviour is retained deliberately: it is what has been
   > running, the user has repeatedly asked for merges to happen unattended, and eight fixes have
   > shipped that way behind the §7 gate. The merged-in guardrails (pending-PR cap, concurrency
   > lock, rebase-conflict abort) are what make it safe rather than merely fast. **If the intent
   > is human-merge, delete step 3 and stop at the labelled PR — nothing else needs to change.**
5. **Release the lock** on every issue in the batch, merged or not:
   ```
   gh issue edit <n> --repo cogniumhq/cognium-dev --remove-label agent-in-progress
   ```
   A squash-merge that closes the issue does not remove labels from it, and a leftover
   `agent-in-progress` halts every future sweep at §0b.
6. **Notify (Buzz — stub until configured).** Append to the PR body under a `## Buzz` heading the
   message that would be posted:
   `PR ready: <url> — fixes #a #b #c — tests: <n> passed`
   If `BUZZ_PRIVATE_KEY`, `BUZZ_RELAY_URL` and `BUZZ_CHANNEL` are all set in the environment,
   also run:
   ```
   buzz messages create --channel "$BUZZ_CHANNEL" --content "<that message>"
   ```
   Never invent the channel or key; absent env vars mean stub-only.
7. For each cognium-ai issue in the batch, comment the PR link on it
   (`gh issue comment <n> --repo cogniumhq/cognium-ai -b "Fixed in cogniumhq/cognium-dev#<pr>"`).
   If the cross-repo `Fixes` line did not auto-close it, leave it open — closing it is the
   cognium-ai team's call.
8. For each merged **child** issue, comment on its `needs-sast` parent
   (`Parent:` line in the child body) with the PR link and the child number. Then check
   whether the parent has any remaining open children (`gh issue list --repo
   cogniumhq/cognium-dev --state open --search "cognium-ai#<n> in:body"`); if none, add
   one final comment: *"Engine side complete for this ticket (children: …, shipped in
   cognium-dev#<prs>). Remaining non-engine parts are back with cognium-ai."* Do not
   remove `needs-sast` and do not close the parent.
9. `git checkout main && git pull --ff-only origin main`.

## 9. Report

Print a compact summary:
- **Merged:** issues + PR number (prefix cognium-ai ones as `cognium-ai#<n>`).
- **Labeled on cognium-ai:** `sast-only` → numbers; `needs-sast` → numbers with their new
  cognium-dev child issues (or "none").
- **Benchmark differentials:** per precision fix, corpus + removed/added signature counts.
- **Skipped:** issue → reason (labeled `autofix-skip`).
- **Abandoned:** issue → reason (fix attempted but couldn't land), labelled `agent-blocked`.
- **Declined:** issue → reason (never attempted, out of boundary), labelled `agent-declined`.
- **Lock state:** confirm no issue still carries `agent-in-progress`, and report the open
  `agent-pr` count so the next run's §0b cap is predictable.
- If nothing was eligible: say so in one line.

## Never

- Never touch a sibling repo's files or anything outside `cognium-dev`. On cognium-ai the
  only allowed actions are the `sast-only` / `needs-sast` labels and comments — never
  `autofix-skip`, never close, never code.
- Never pick up an issue that is not strictly SAST-only, no matter how small.
- Never add LLM/AI dependencies, flags, option names, or docs (repo boundary).
- Never commit directly to `main` or force-push `main`. Always branch → PR → squash-merge.
- Never merge when the full suite has any failure not present in the baseline.
- Never merge a precision fix without the §7 benchmark differential showing zero TP loss.
- Never fix a `needs-sast` parent directly — only its cognium-dev children.
- Never close/edit an issue you didn't fix, beyond adding `autofix-skip` + a reason comment.
- Never ask the user a question — skip the issue instead.
- Never leave `agent-in-progress` on an issue at exit; it halts every later sweep.
- Never clear an `agent-in-progress` lock that is **younger than 2 h** — that is a live run, and
  clearing it is how two sweeps end up editing the same file. Past 2 h, §0b clears it with a
  comment; the age check is what separates the two cases, so never skip it.
- Never force-resolve a rebase conflict; abort and mark `agent-blocked` (§7).
- Never add an `agent-*` label to a cognium-ai issue — that vocabulary is home-repo only.
- Never invent Buzz credentials; without all three env vars the notification is stub-only.
