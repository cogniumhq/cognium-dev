#!/usr/bin/env bash
# Exit 0 only when every named check on $SHA succeeded.
# A check that is still running stays pending and is polled until the deadline.
# A name that never appears stays missing and fails after a short grace period,
# so a typo, a blank entry, or a renamed ci.yml job does not wait out the deadline.
set -euo pipefail

deadline=$((SECONDS + 2400))
missing_grace=$((SECONDS + 180))

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# Split a comma-separated list. Whitespace around each entry is removed.
# An empty entry is kept so a blank STATIC or DYNAMIC value fails as missing.
split() {
  local IFS=','
  local -a raw=()
  local -n dest="$2"
  local part
  read -r -a raw <<< "$1"
  dest=()
  if ((${#raw[@]} == 0)); then
    dest+=("")
    return
  fi
  for part in "${raw[@]}"; do
    dest+=("$(trim "$part")")
  done
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
  missing=()
  failed=()
  for name in "${wanted[@]}"; do
    result="$(conclusion_of "$name")"
    case "$result" in
      success) ;;
      pending) pending+=("$name") ;;
      missing) missing+=("${name:-<empty>}") ;;
      *) failed+=("$name ($result)") ;;
    esac
  done

  if ((${#failed[@]} > 0)); then
    echo "Conformis failed:"
    printf '  %s\n' "${failed[@]}"
    exit 1
  fi
  if ((${#missing[@]} > 0 && SECONDS >= missing_grace)); then
    echo "Conformis failed: check name never reported:"
    printf '  %s\n' "${missing[@]}"
    exit 1
  fi
  if ((${#pending[@]} == 0 && ${#missing[@]} == 0)); then
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
  echo "Waiting:"
  if ((${#pending[@]} > 0)); then
    printf '  pending: %s\n' "${pending[@]}"
  fi
  if ((${#missing[@]} > 0)); then
    printf '  missing: %s\n' "${missing[@]}"
  fi
  sleep 30
done
