#!/usr/bin/env bash
# Exit 0 only when every named check on $SHA succeeded.
set -euo pipefail

deadline=$((SECONDS + 2400))

split() {
  local IFS=','
  read -r -a "$2" <<< "$1"
}

split "$STATIC" static_checks
split "$DYNAMIC" dynamic_checks
wanted=("${static_checks[@]}" "${dynamic_checks[@]}")

conclusion_of() {
  local name="$1"
  gh api "repos/${REPO}/commits/${SHA}/check-runs?per_page=100" \
    | jq -r --arg name "$name" '
        [.check_runs[] | select(.name == $name)]
        | sort_by(.started_at // "")
        | last
        | if . == null then "missing"
          elif .status != "completed" then "pending"
          else .conclusion
          end
      '
}

while true; do
  pending=()
  failed=()
  for name in "${wanted[@]}"; do
    result="$(conclusion_of "$name")"
    case "$result" in
      success) ;;
      missing|pending) pending+=("$name ($result)") ;;
      *) failed+=("$name ($result)") ;;
    esac
  done

  if ((${#failed[@]} > 0)); then
    echo "Conformis failed:"
    printf '  %s\n' "${failed[@]}"
    exit 1
  fi
  if ((${#pending[@]} == 0)); then
    echo "Conformis passed."
    printf '  static: %s\n' "${static_checks[@]}"
    printf '  dynamic: %s\n' "${dynamic_checks[@]}"
    exit 0
  fi
  if ((SECONDS >= deadline)); then
    echo "Conformis timed out waiting for:"
    printf '  %s\n' "${pending[@]}"
    exit 1
  fi
  echo "Waiting: ${pending[*]}"
  sleep 30
done
