# The reviewer

An adversary between the thing that writes code and the thing that merges it. It runs on every
non-draft pull request, reads the diff, and posts a real GitHub review.

## Why it is a workflow and not a bot account

Machine PRs here are opened by one account, and **GitHub refuses a review on your own pull
request**. A reviewer running under that same account could only ever leave a *comment* — and a
comment is forgeable by any other automation using the same credentials, including whatever wants
to merge.

A workflow runs as `github-actions[bot]`: a different identity. So `gh pr review` works,
`reviewDecision` is real, and GitHub ties the review to the commit it was given on, which means a
later push invalidates it without anyone having to remember.

It also **removes** a capability. `contents: read`, `pull-requests: write`, nothing else — the
reviewer cannot edit the code it is reviewing. A reviewer that *cannot* write is better than one
that merely does not.

## The three files, and which one you rewrite

| file | portable? | what it is |
|---|---|---|
| `rules.md` | **yes — copy unchanged** | review craft: what an approval must contain, what to look hardest at, what is not your job |
| `repo.md` | **no — write your own** | this repository's risk map: which paths are dangerous, what they cost, who decides them |
| `review.mjs` | **yes — copy unchanged** | fetches the diff, asks the model, posts the verdict |

Keeping craft and local knowledge in separate files is the whole point. A reviewer whose judgement
and whose repo trivia are tangled together cannot be moved to another repo without a rewrite.

## Adopting it in another repository

1. Copy `rules.md`, `review.mjs` and `.github/workflows/reviewer.yml`. Change nothing in them.
2. **Write your own `repo.md`.** Do not copy conformis's — its risk map is about check-set packs
   and an evaluation kernel, which will be wrong and confidently so somewhere else. Three things
   belong in it: which paths are dangerous and why, what that repo actually gets wrong (from real
   defects, not imagined ones), and who decides what.
   Without it the reviewer still works, says so in its review, and is weaker than it looks.
3. Add the model key as a repository secret (`META_KEY`).
4. The workflow runs on every non-draft pull request (drafts are skipped until marked ready).
5. Point `runs-on` at a runner that repo can use. **It needs Node and nothing else** — the script
   talks to GitHub over REST rather than through the `gh` binary, which is not on every runner and
   was what broke the first run of this.

## What it cannot do, and why that is stated everywhere

The available key is for an OpenAI-shaped `/v1/chat/completions` endpoint, so the reviewer is **one
call with a diff in it**, not an agent. It cannot open a file outside the diff, run a test, or check
a claim against the rest of the tree.

The reviewer that preceded this ran `git grep` to enumerate call sites, read a diff's *removed*
lines to decide whether a new test would still pass when reverted, and hand-checked a regex against
malformed input — those were its best findings, and none are possible here.

So every review carries a footer saying so, and the prompt says it too. **An approval means "nothing
wrong is visible in this diff", not "this was verified."** A review that looks thorough and is not
is worse than one that admits its reach.

If an Anthropic-compatible endpoint (`/v1/messages`) ever becomes available, the agentic reviewer
can come back and this becomes the fallback.

## A requested change fails the check

`REQUEST_CHANGES` exits non-zero, so the pull request is visibly red rather than carrying a green
tick beside a review asking for work. **A gate whose refusal looks like success is not a gate.**

It stays red while the request stands: push a fix and the reviewer re-runs; an approval turns it
green. Where the block is the risk map rather than a defect — a path this repository reserves for a
person — red is still correct, because it is a human's to clear and a green tick would say
otherwise.

## Three failure modes, made loud

- **No key** — the job says so in the step summary rather than passing quietly.
- **A run that posts no review — fails.** That shape looks green while the queue waits for a review
  nobody is going to write.
- **An unreadable verdict — requests changes, never approves**, and says so in the footer.
  Defaulting the other way lets unreviewed code merge on a malformed response. A reviewer whose
  silence is consent is not a gate.

A diff past `MAX_DIFF` (180k characters) is truncated, and both the prompt and the posted review say
so — a silent cut would have the model judging a change it never saw.

## Before you turn on branch protection

A `GITHUB_TOKEN` approval **does not satisfy GitHub's own required-approvals rule**. Where the merge
gate is client-side this does not matter. It will the day protection is enabled, and that is a bad
day to find out.

## Nothing green without a review behind it

Two paths end red, and only one of them means the change is bad:

- **The reviewer requested changes.** It stays red while the request stands. Red here can also
  mean the risk map sent the change to a person — that is the map working, not a defect.
- **`META_KEY` is not set.** No review could be posted, so the check cannot be green. Set the
  secret or delete the workflow; a green check with nothing behind it is the failure this
  whole thing exists to prevent.

## The repository must let Actions approve

GitHub refuses an `APPROVE` review from the Actions identity unless **Settings -> Actions ->
General -> "Allow GitHub Actions reviews to approve pull requests"** is on. Without it the POST
comes back:

```
422 GitHub Actions is not permitted to approve pull requests.
```

This is the worst failure shape available to a review gate: the reviewer can block and never
clear, so anything reading `reviewDecision` holds every pull request forever waiting on an
approval that is being refused out of sight. Check it before trusting the gate:

```sh
gh api repos/<owner>/<repo>/actions/permissions/workflow --jq .can_approve_pull_request_reviews
```

When it is off, the reviewer still records its approval as a comment review and the check stays
green — it read the change and found nothing blocking — but `reviewDecision` will not say
APPROVED, so a merge gate reading that field keeps holding the PR. The review says so in its own
text. That is the safe direction, not a working configuration.

## Testing a change to the reviewer

`node --check` is not enough — it parses, so it passes a script with a missing import, and the
first run that noticed was a red check on a real PR. Run it against a real pull request with a
dead key instead. It builds the whole prompt and stops at the 401, so every binding resolves and
nothing is posted:

```sh
GH_TOKEN=$(gh auth token) PR=<n> REPO=<owner>/<repo> \
  HEAD_SHA=$(gh pr view <n> --json headRefOid --jq .headRefOid) \
  BASE_SHA=$(gh pr view <n> --json baseRefOid --jq .baseRefOid) \
  META_KEY=dead node .github/reviewer/review.mjs
```

A 401 from the endpoint is the pass. Anything earlier is the bug.

