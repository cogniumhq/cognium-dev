#!/usr/bin/env bash
# branch-check — the git-branching skill's check (techspec skills/git-branching/SKILL.md).
#
# No network, no state; safe to re-run. Exit 0 = pass (warnings go to stderr), 1 = fail, 2 = usage.
#
#   check.sh <ref>                      check a branch or tag name
#   check.sh --base <target> <ref>      also check a PR's target branch (<ref> is the PR head)
#   check.sh --pre-push [remote [url]]  git pre-push hook mode: reads "<local ref> <local sha>
#                                       <remote ref> <remote sha>" lines on stdin; with no stdin
#                                       lines, checks a push of the current branch to the same name
#   check.sh --candidate <rc-branch> <sha> [remote]
#                                       rc-tag mode: <sha> may become the candidate the rc/ branch
#                                       names only if it is on <remote>/<base>, or (a hotfix, patch
#                                       Z >= 1) on the newest <remote>/release/<track>-X.Y.W with
#                                       W < Z (the release it patches). Needs those remote-tracking refs
#                                       fetched (ci/rc-tag.yml does it); fails closed otherwise.
#   check.sh --release-actor            release gate (ci/release-tag.yml, ci/branch-check.yml):
#                                       pass only if ACTOR and TRIGGERING_ACTOR are both listed in
#                                       RELEASE_ACTORS (comma-separated logins). On a re-run GitHub
#                                       keeps github.actor as the first dispatcher and sets
#                                       github.triggering_actor to the person re-running; both
#                                       must be release actors.
#
# <ref> may be refs/heads/<branch>, refs/tags/<tag>, or a bare branch name (use refs/tags/<tag>
# or --tag <tag> for a tag). Installed as .git/hooks/pre-push (a copy or a symlink named
# pre-push), it runs in --pre-push mode by itself.
#
# Environment:
#   RELEASE_ACTOR_ALLOWED=1   the pusher is the control tower track; only then is a release tag
#                             <track>-v<ver> (no -rc.N) allowed. CI sets it from the repo variable
#                             RELEASE_ACTORS (ci/branch-check.yml); nobody else sets it.
#   BRANCH_CHECK_ROLES        extra role names, space-separated, accepted as <track> (e.g. "a11y").
#   BRANCH_CHECK_STRICT=1     treat warnings as failures (for after the roll-out).
#   BRANCH_CHECK_BASE         the base branch (default main; master on a fork that keeps upstream's
#                             name): PRs target it, nobody pushes to it, candidates come from it.

set -euo pipefail

# Track folder names in techspec tracks/ (kept by the control tower).
TRACKS="business conformis control-tower cortex engine execution k8s-pack operations surfaces"
# Role names accepted alone as <track> (the part after the dot in <track>.<role>).
ROLES="a11y agent aonx architecture canon change cognium controldeck coordinator deps doors evidence
fleet flow gateway github graph kernel launch mac platform registry sandbox security spec specifica
supply chore loop ${BRANCH_CHECK_ROLES:-}"
# chore and loop (12 Nov 2026): the Loop's own work, loop/<topic> (Make, Ship and Run plumbing) and
# chore/<group>-<nn> (a chore run's branch); see SKILL.md "The three loops".
# Prefixes in use today that pass with a warning.
BOT_PREFIXES="dependabot renovate cursor claude"

ZERO=0000000000000000000000000000000000000000
# The base branch (0.4.9): one setting, default main. The workflows pass their `BASE:` here.
MAIN=${BRANCH_CHECK_BASE:-main}
VER='[0-9]+\.[0-9]+\.[0-9]+'
ID='[a-z][a-z0-9.-]*'
BAD='[[:space:]~^:?*[\]'

fails=0
warns=0

fail() { echo "branch-check: FAIL: $*" >&2; fails=$((fails + 1)); }
warn() { echo "branch-check: WARN: $*" >&2; warns=$((warns + 1)); }

usage() {
  sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

in_list() { # in_list <word> <list...>
  local w=$1; shift
  local x
  local -a words
  read -r -d '' -a words <<<"$*" || true # the lists span lines
  for x in "${words[@]}"; do [[ $x == "$w" ]] && return 0; done
  return 1
}

known_track() { # a track folder, a role, or <track>.<role>
  local t=$1
  in_list "$t" "$TRACKS" && return 0
  in_list "$t" "$ROLES" && return 0
  if [[ $t == *.* ]] && in_list "${t%%.*}" "$TRACKS"; then return 0; fi
  return 1
}

check_branch() {
  local b=$1
  if [[ -z $b ]]; then fail "empty branch name"; return; fi
  if [[ $b == "$MAIN" ]]; then return; fi
  if [[ $b == *..* || $b == */ || $b == /* || $b == *//* || $b =~ $BAD ]]; then
    fail "'$b' is not a valid branch name"; return
  fi
  local first=${b%%/*}
  case $first in
    rc)
      # rc/<track>-<ver>-rc.<N>: asks CI to cut the candidate tag <track>-v<ver>-rc.<N> (§5).
      if [[ $b =~ ^rc/($ID)-($VER)-rc\.([1-9][0-9]*)$ ]]; then
        local t=${BASH_REMATCH[1]}
        known_track "$t" || warn "'$b': '$t' is not a track or role name"
      else
        fail "'$b': rc/ is reserved for rc/<track>-<ver>-rc.<N>, N from 1 (e.g. rc/a11y-1.8.0-rc.1)"
      fi
      return ;;
    release|hotfix)
      if [[ $b =~ ^(release|hotfix)/($ID)-($VER)$ ]]; then
        local t=${BASH_REMATCH[2]}
        known_track "$t" || warn "'$b': '$t' is not a track or role name (legacy $first/<name>-<ver> form; use $first/<track>-<ver>)"
      else
        fail "'$b': $first/ is reserved for $first/<track>-<ver> (e.g. $first/a11y-1.8.0)"
      fi
      return ;;
  esac
  if [[ $b != */* ]]; then
    fail "'$b' has no '<track>/' prefix; name work branches <track>/<topic> (e.g. a11y/fix-contrast)"
    return
  fi
  local topic=${b#*/}
  if in_list "$first" "$BOT_PREFIXES"; then
    warn "'$b': $first/ is a tool's default prefix; prefer <track>/<topic>"
    return
  fi
  if known_track "$first"; then
    [[ $topic =~ ^[a-z0-9][a-z0-9._/-]*$ ]] \
      || warn "'$b': use lower-case letters, digits, '.', '_', '-' in the topic"
    return
  fi
  warn "'$b': '$first' is not a track or role name (legacy <area>/<topic> form; use <track>/<topic>)"
}

check_tag() {
  local t=$1
  if [[ $t =~ ^($ID)-v($VER)-rc\.([0-9]+)$ ]]; then
    known_track "${BASH_REMATCH[1]}" || warn "tag '$t': '${BASH_REMATCH[1]}' is not a track or role name"
    return
  fi
  if [[ $t =~ ^($ID)-v($VER)$ ]]; then
    known_track "${BASH_REMATCH[1]}" || warn "tag '$t': '${BASH_REMATCH[1]}' is not a track or role name"
    if [[ ${RELEASE_ACTOR_ALLOWED:-0} != 1 ]]; then
      fail "tag '$t' is a release tag; only the control tower track cuts it (cut '$t-rc.N' for a candidate)"
    fi
    return
  fi
  warn "tag '$t' is not <track>-v<ver>-rc.N or <track>-v<ver> (legacy form)"
}

check_base() { # check_base <base> <head branch>
  local base=$1 head=$2
  if [[ $head == rc/* ]]; then
    fail "'$head' is an rc/ branch: it only asks CI for a candidate tag and is never a PR head"
    return
  fi
  [[ $base == "$MAIN" ]] && return
  if [[ $base =~ ^release/($ID)-($VER)$ && $head =~ ^hotfix/($ID)-($VER)$ ]]; then
    local bt hb
    bt=$(sed -E 's#^release/(.*)-[0-9]+\.[0-9]+\.[0-9]+$#\1#' <<<"$base")
    hb=$(sed -E 's#^hotfix/(.*)-[0-9]+\.[0-9]+\.[0-9]+$#\1#' <<<"$head")
    [[ $bt == "$hb" ]] || fail "hotfix '$head' targets '$base' of another track"
    return
  fi
  fail "PR from '$head' targets '$base'; PRs target $MAIN (only hotfix/<track>-<ver> may target release/<track>-<ver>)"
}

check_ref() {
  local r=$1
  case $r in
    refs/tags/*) check_tag "${r#refs/tags/}" ;;
    refs/heads/*) check_branch "${r#refs/heads/}" ;;
    refs/*) fail "'$r' is not a branch or a tag" ;;
    *) check_branch "$r" ;;
  esac
}

pre_push() {
  local lines=() line
  if [[ ! -t 0 ]]; then
    while IFS= read -r line; do [[ -n $line ]] && lines+=("$line"); done
  fi
  if ((${#lines[@]} == 0)); then
    local cur upstream
    cur=$(git symbolic-ref --quiet --short HEAD) || { fail "detached HEAD: nothing to check"; return; }
    upstream=$(git rev-parse --verify --quiet "refs/remotes/${1:-origin}/$cur" || echo "$ZERO")
    lines=("refs/heads/$cur $(git rev-parse HEAD) refs/heads/$cur $upstream")
  fi
  local lsha rref rsha
  for line in "${lines[@]}"; do
    read -r _ lsha rref rsha <<<"$line"
    # main and master stay refused whatever the base branch is
    if [[ $rref == "refs/heads/$MAIN" || $rref == refs/heads/main || $rref == refs/heads/master ]]; then
      fail "push to '${rref#refs/heads/}' refused: never push to $MAIN; push a branch and open a PR"
      continue
    fi
    if [[ $lsha == "$ZERO" ]]; then # a delete
      [[ $rref == refs/tags/* ]] && fail "deleting tag '${rref#refs/tags/}' refused: tags are never moved or deleted"
      continue
    fi
    check_ref "$rref"
    [[ $rsha == "$ZERO" ]] && continue
    if [[ $rref == refs/tags/* ]]; then
      fail "tag '${rref#refs/tags/}' already exists on the remote: tags are never moved"
      continue
    fi
    if [[ $rref == refs/heads/rc/* ]]; then
      fail "'${rref#refs/heads/}' already exists on the remote: an rc/ branch is pushed once (cut rc.N+1)"
      continue
    fi
    if ! git cat-file -e "$rsha^{commit}" 2>/dev/null; then
      fail "push to '${rref#refs/heads/}' refused: the remote has commits you do not have (fetch and merge, never force)"
    elif ! git merge-base --is-ancestor "$rsha" "$lsha"; then
      fail "push to '${rref#refs/heads/}' refused: it is a force-push (rewrites pushed history); merge origin/$MAIN in instead of rebasing"
    fi
  done
}

candidate() { # candidate <rc-branch> <sha> [remote]
  local b=${1#refs/heads/} sha=$2 remote=${3:-origin}
  # Each version part is at most 9 digits, so bash arithmetic (64-bit) never wraps: a branch
  # release/a11y-1.7.18446744073709551617 must not read as patch 1 (review of 0.4.0, round 1).
  if [[ ! $b =~ ^rc/($ID)-([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})-rc\.([1-9][0-9]{0,8})$ ]]; then
    fail "'$b' is not rc/<track>-<ver>-rc.<N> (each number at most 9 digits)"; return
  fi
  local t=${BASH_REMATCH[1]} x=${BASH_REMATCH[2]} y=${BASH_REMATCH[3]} z=${BASH_REMATCH[4]}
  if [[ ! $remote =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ || $remote == *..* ]]; then
    fail "'$remote' is not a remote name"; return
  fi
  if [[ ! $sha =~ ^[0-9a-f]{7,64}$ ]]; then
    fail "'$sha' is not a commit sha"; return
  fi
  if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
    fail "commit '$sha' is not in this clone"; return
  fi
  if git rev-parse --verify --quiet "refs/remotes/$remote/$MAIN" >/dev/null \
    && git merge-base --is-ancestor "$sha" "refs/remotes/$remote/$MAIN"; then
    echo "branch-check: candidate $sha is on $remote/$MAIN" >&2
    return
  fi
  if ((10#$z >= 1)); then
    # A hotfix candidate X.Y.Z comes from the newest release/<track>-X.Y.W on <remote> with W < Z
    # (normally W = Z-1, the release the hotfix patches; the newest, so a shipped W's fix is never
    # dropped). Only branches on <remote> count, read by exact name: another track's branch,
    # another minor, a newer patch, a fork's branch (never a ref under refs/remotes/<remote>/) or
    # a tag alone is refused.
    local ref name w best=-1 bestref=""
    while IFS= read -r ref; do
      name=${ref#"refs/remotes/$remote/release/"}
      [[ $name == "$t-$x.$y."* ]] || continue
      w=${name#"$t-$x.$y."}
      [[ $w =~ ^(0|[1-9][0-9]{0,8})$ ]] || continue # at most 9 digits: no overflow
      ((10#$w < 10#$z && 10#$w > best)) || continue
      best=$((10#$w)) bestref=$ref
    done < <(git for-each-ref --format='%(refname)' "refs/remotes/$remote/release/")
    if [[ -n $bestref ]] && git merge-base --is-ancestor "$sha" "$bestref"; then
      echo "branch-check: candidate $sha is on ${bestref#refs/remotes/} (a hotfix candidate)" >&2
      return
    fi
    if [[ -n $bestref ]]; then
      fail "candidate $sha for '$b' is on neither $remote/$MAIN nor ${bestref#refs/remotes/}, the newest release branch it may patch; cut a candidate from $MAIN, or a hotfix candidate from that release branch"
      return
    fi
    fail "candidate $sha for '$b' is on neither $remote/$MAIN nor any $remote/release/$t-$x.$y.W branch (W < $z); cut a candidate from $MAIN, or a hotfix candidate from the release branch it patches"
    return
  fi
  fail "candidate $sha for '$b' is not on $remote/$MAIN (a .0 version is never a hotfix)"
}

release_actor() { # ACTOR, TRIGGERING_ACTOR, RELEASE_ACTORS from the environment
  local -a actors
  IFS=',' read -r -a actors <<<"${RELEASE_ACTORS:-}"
  listed() { local a; for a in "${actors[@]}"; do [[ -n $a && $a == "$1" ]] && return 0; done; return 1; }
  if [[ -z ${ACTOR:-} || -z ${TRIGGERING_ACTOR:-} ]]; then
    fail "release gate: ACTOR and TRIGGERING_ACTOR must both be set (github.actor, github.triggering_actor)"
  elif ! listed "$ACTOR"; then
    fail "release gate: '$ACTOR' (github.actor) is not in RELEASE_ACTORS"
  elif ! listed "$TRIGGERING_ACTOR"; then
    fail "release gate: '$TRIGGERING_ACTOR' (github.triggering_actor; a re-run of '$ACTOR''s run) is not in RELEASE_ACTORS"
  else
    echo "branch-check: release actor '$ACTOR' (triggered by '$TRIGGERING_ACTOR')" >&2
  fi
}

main() {
  local mode=ref base="" ref=""
  # A bare branch name, as merge-back-report.sh --main checks it, never a ref or a reserved prefix
  # (the same test as the templates' BASE check).
  if ! [[ $MAIN =~ ^[A-Za-z0-9_][A-Za-z0-9._/-]*$ && $MAIN != *..* && $MAIN != */ && ! $MAIN =~ ^(refs|rc|release|hotfix)/ ]]; then
    echo "branch-check: FAIL: BRANCH_CHECK_BASE '$(printf '%q' "$MAIN")' is not a base branch name (a bare branch, not rc/, release/ or hotfix/)" >&2
    exit 1
  fi
  [[ $(basename "$0") == pre-push ]] && mode=pre-push
  if [[ $mode == pre-push ]]; then pre_push "$@"
  else
    while (($#)); do
      case $1 in
        --pre-push) mode=pre-push; shift; break ;;
        --candidate) [[ $# -ge 3 && $# -le 4 ]] || usage; mode=candidate; shift; break ;;
        --release-actor) [[ $# -eq 1 ]] || usage; mode=release-actor; shift; break ;;
        --base) [[ $# -ge 2 ]] || usage; base=$2; shift 2 ;;
        --tag) [[ $# -ge 2 ]] || usage; ref="refs/tags/$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) [[ -z $ref ]] || usage; ref=$1; shift ;;
      esac
    done
    if [[ $mode == pre-push ]]; then
      pre_push "$@"
    elif [[ $mode == candidate ]]; then
      candidate "$@"
    elif [[ $mode == release-actor ]]; then
      release_actor
    else
      [[ -n $ref ]] || usage
      check_ref "$ref"
      if [[ -n $base ]]; then
        [[ $ref == refs/tags/* ]] && usage
        check_base "${base#refs/heads/}" "${ref#refs/heads/}"
      fi
    fi
  fi
  if [[ ${BRANCH_CHECK_STRICT:-0} == 1 ]] && ((warns > 0)); then
    fail "$warns warning(s) with BRANCH_CHECK_STRICT=1"
  fi
  if ((fails > 0)); then
    echo "branch-check: $fails failure(s); see techspec skills/git-branching/SKILL.md" >&2
    exit 1
  fi
  if ((warns > 0)); then echo "branch-check: OK ($warns warning(s))" >&2
  else echo "branch-check: OK" >&2; fi
}

main "$@"
