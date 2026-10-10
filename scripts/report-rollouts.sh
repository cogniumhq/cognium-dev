#!/usr/bin/env bash
# Reports one npm publish to Cursor Rollouts. A skipped or failed report never
# fails the caller. Sourced by release.sh.
#
# Direct invocation is for tests:
#   REPO_ROOT=... CURSOR_API_KEY=... scripts/report-rollouts.sh <service> <action> [outcome] [message]

report_rollouts() {
  local service="$1" action="$2" outcome="${3:-}" failure_message="${4:-}"
  local reporter="$REPO_ROOT/scripts/report-rollouts-deployment.sh" status=0
  [[ -n "${CURSOR_API_KEY:-}" ]] || {
    warn "CURSOR_API_KEY is not set; Rollouts will not record this release"
    return 0
  }
  if [[ -z "$service" || "$service" == */* ]]; then
    warn "Rollouts service must be a single slug (got '$service'); report skipped"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    warn "curl and jq are required to report this release; Rollouts report skipped"
    return 0
  fi
  CHANGE_MONITOR_ENV="npm" \
  CHANGE_MONITOR_SERVICE="$service" \
  DEPLOY_VERSION="$(git rev-parse HEAD 2>/dev/null || true)" \
  DEPLOY_ACTOR="release.sh:$service:npm" \
  DEPLOY_OUTCOME="$outcome" \
  DEPLOY_FAILURE_MESSAGE="$failure_message" \
    bash "$reporter" "$action" || status=$?
  [[ "$status" -eq 0 ]] || warn "Rollouts deployment report returned $status; release continues"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  if ! declare -F warn >/dev/null 2>&1; then
    warn() { echo "! $1"; }
  fi
  report_rollouts "$@"
fi
