#!/usr/bin/env bash
# The release-readiness check "ci-green": the repository's CI workflow (CI_WORKFLOW, default ci.yml)
# passed on the candidate's exact commit. rc-tag.yml checks the same before it tags; the review
# checks it again so the verdict carries the evidence (the run's id and URL).
# Vendored from the release-readiness template (ci-green.sh), upstream commit 831c665.
#
# Where the runs come from:
#   CI_RUNS_FILE   a GitHub "list workflow runs" response for the commit (the review workflow
#                  fetches it in a step of its own, so the candidate's code never sees a token);
#   otherwise GH_TOKEN and REPO (owner/name): the script asks the API itself (local use).
#   Neither: fail; a review that cannot show CI passed does not pass this check.
# Every run is checked against the commit, the workflow file and its conclusion, so a response for
# another commit or another workflow never passes.
#   bash scripts/ci-green.sh [<sha>]        # default: HEAD (the review runs at the candidate)
set -euo pipefail
CI_WORKFLOW=${CI_WORKFLOW:-ci.yml}
sha=${1:-$(git rev-parse HEAD)}
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo "ci-green: '$sha' is not a 40-hex commit"; exit 1; }
if [[ -n ${CI_RUNS_FILE:-} ]]; then
  [[ -f $CI_RUNS_FILE ]] || { echo "ci-green: CI_RUNS_FILE $CI_RUNS_FILE not found"; exit 1; }
  runs=$(cat "$CI_RUNS_FILE"); from=$CI_RUNS_FILE
elif [[ -n ${GH_TOKEN:-} && -n ${REPO:-} ]]; then
  api=${GITHUB_API_URL:-https://api.github.com}
  runs=$(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
    "$api/repos/$REPO/actions/workflows/$CI_WORKFLOW/runs?head_sha=$sha&status=success&per_page=20") \
    || { echo "ci-green: could not list $CI_WORKFLOW runs for $sha"; exit 1; }
  from="the API"
else
  echo "ci-green: no CI_RUNS_FILE and no GH_TOKEN with REPO; cannot show $CI_WORKFLOW passed on $sha"
  exit 1
fi
printf '%s' "$runs" | SHA=$sha WF=$CI_WORKFLOW FROM=$from node -e '
let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
  const { SHA, WF, FROM } = process.env;
  let j; try { j = JSON.parse(s); } catch { console.log(`ci-green: ${FROM} is not JSON`); process.exit(1); }
  const runs = Array.isArray(j.workflow_runs) ? j.workflow_runs : [];
  const ok = runs.filter((r) => r.head_sha === SHA && r.conclusion === "success"
    && typeof r.path === "string" && (r.path === `.github/workflows/${WF}` || r.path.startsWith(`.github/workflows/${WF}@`)));
  if (!ok.length) {
    console.log(`ci-green: no successful ${WF} run on ${SHA} (${runs.length} run(s) in ${FROM}, none for this commit and workflow)`);
    process.exit(1);
  }
  const r = ok[0];
  console.log(`ci-green: ${WF} passed on ${SHA}: run ${r.id} (${r.event}) ${r.html_url || ""}`.trim());
});'
