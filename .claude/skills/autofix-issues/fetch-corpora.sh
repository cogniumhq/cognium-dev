#!/usr/bin/env bash
# fetch-corpora — pinned public benchmark corpora for the autofix §7 gate.
#
#   CORPUS_ROOT=<dir> fetch-corpora.sh fetch [language...]
#       Clone every corpus that is missing under $CORPUS_ROOT at its pinned commit.
#       An existing directory is never modified: it is only verified.
#   CORPUS_ROOT=<dir> fetch-corpora.sh check [language...]
#       Verify each corpus is present and at its pinned commit. Read-only.
#   fetch-corpora.sh list
#       Print the pin table.
#
# language is one of: java python javascript csharp (javascript also covers typescript).
# With no language, every corpus is processed. Exit code 0 only when every requested
# corpus is present and matches its pin; anything else prints the reason and exits 1,
# so a precision fix is never gated on a missing or drifted corpus.
#
# Corpora are fetched next to the repo, never committed to it.
set -euo pipefail

# language|directory|repository|commit
PINS='
java|.owasp-benchmark-java|https://github.com/OWASP-Benchmark/BenchmarkJava.git|07160be1b8b8bd9fe9a440d7fa91862ef659b102
java|securibench-micro|https://github.com/too4words/securibench-micro.git|6a5a72488ea830d99f9464fc1f0562c4f864214b
python|benchmark-python|https://github.com/OWASP-Benchmark/BenchmarkPython.git|f1291485808b66e20ddb6b01b10dc71b3df8c8ba
javascript|nodegoat|https://github.com/OWASP/NodeGoat.git|c5cb68a7084e4ae7dcc60e6a98768720a81841e8
javascript|juice-shop|https://github.com/juice-shop/juice-shop.git|6244c59a47ba4436cb00e9ad9c565bb2056582ec
javascript|dvna|https://github.com/appsecco/dvna.git|9ba473add536f66ac9007966acb2a775dd31277a
'
# Juliet C# 1.3 is a NIST SARD archive, not a git repository, so it has no commit to
# pin. Until an archive URL and SHA-256 are recorded here, it is reported as unavailable
# and C# precision fixes stay ineligible.
UNPINNED_LANGS='csharp'

die() { echo "fetch-corpora: $*" >&2; exit 1; }

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  list) printf '%s\n' "$PINS" | sed '/^$/d' | tr '|' '\t'; exit 0 ;;
  fetch|check) ;;
  *) die "usage: CORPUS_ROOT=<dir> fetch-corpora.sh fetch|check [language...]  |  fetch-corpora.sh list" ;;
esac

[ -n "${CORPUS_ROOT:-}" ] || die "CORPUS_ROOT is not set. Point it at a directory outside this repository."
case "$CORPUS_ROOT" in /*) ;; *) die "CORPUS_ROOT must be an absolute path (got '$CORPUS_ROOT')." ;; esac

wanted() { # $1 = language of a pin row; true when it was requested (or nothing was)
  [ ${#LANGS[@]} -eq 0 ] && return 0
  local l; for l in "${LANGS[@]}"; do [ "$l" = "$1" ] && return 0; done
  return 1
}

LANGS=()
for l in "$@"; do
  [ "$l" = "typescript" ] && l="javascript"
  case "$l" in java|python|javascript|csharp) LANGS+=("$l") ;; *) die "unknown language '$l' (java python javascript csharp)" ;; esac
done

fail=0
for l in $UNPINNED_LANGS; do
  if [ ${#LANGS[@]} -gt 0 ] && wanted "$l"; then
    echo "MISSING  $l: no pinned corpus is defined yet" >&2; fail=1
  fi
done

if [ "$cmd" = "fetch" ]; then mkdir -p "$CORPUS_ROOT"; fi

while IFS='|' read -r lang dir repo sha; do
  [ -n "$lang" ] || continue
  wanted "$lang" || continue
  dest="$CORPUS_ROOT/$dir"
  if [ ! -e "$dest" ]; then
    if [ "$cmd" = "check" ]; then echo "MISSING  $dir ($lang): not under \$CORPUS_ROOT" >&2; fail=1; continue; fi
    echo "fetch    $dir @ ${sha:0:7}"
    tmp="$dest.partial.$$"
    rm -rf "$tmp"
    git init -q "$tmp"
    git -C "$tmp" remote add origin "$repo"
    if git -C "$tmp" fetch -q --depth 1 origin "$sha" && git -C "$tmp" -c advice.detachedHead=false checkout -q FETCH_HEAD; then
      mv "$tmp" "$dest"
    else
      rm -rf "$tmp"; echo "FAILED   $dir: could not fetch $sha from $repo" >&2; fail=1; continue
    fi
  fi
  head="$(git -C "$dest" rev-parse HEAD 2>/dev/null || true)"
  if [ "$head" != "$sha" ]; then
    echo "DRIFT    $dir: at ${head:-<not a git checkout>}, pinned $sha" >&2; fail=1; continue
  fi
  if [ -n "$(git -C "$dest" status --porcelain 2>/dev/null)" ]; then
    echo "DIRTY    $dir: working tree differs from the pinned commit" >&2; fail=1; continue
  fi
  echo "ok       $dir @ ${sha:0:7}"
done <<EOF_PINS
$PINS
EOF_PINS

[ "$fail" -eq 0 ] || die "one or more corpora are unavailable; do not run the §7 gate on them."
