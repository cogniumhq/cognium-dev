#!/usr/bin/env bash
# fetch-corpora — pinned public benchmark corpora for the autofix §7 gate.
#
#   CORPUS_ROOT=<dir> fetch-corpora.sh fetch [language...]
#       Fetch every corpus that is missing under $CORPUS_ROOT at its pin.
#       An existing directory is never modified: it is only verified.
#   CORPUS_ROOT=<dir> fetch-corpora.sh check [language...]
#       Verify each corpus is present and matches its pin. Read-only.
#   fetch-corpora.sh list
#       Print the pin tables.
#
# language is one of: java python javascript csharp go rust bash (javascript also covers
# typescript). With no language, every corpus is processed. Exit code 0 only when every
# requested corpus is present and matches its pin; anything else prints the reason and
# exits 1, so a precision fix is never gated on a missing or drifted corpus.
#
# Corpora are fetched next to the repo, never committed to it.
#
# LICENCE: semgrep/semgrep-rules is under a restrictive licence (Semgrep Rules License
# v1.0). It is a LOCAL benchmark only: scan it under $CORPUS_ROOT, never copy any of its
# files, rules or test snippets into this repository (not as fixtures, not in tests).
set -euo pipefail

# Git pins.  language|directory|repository|commit|paths the gate scores (informational,
# each must exist; empty = whole tree)
PINS='
java|.owasp-benchmark-java|https://github.com/OWASP-Benchmark/BenchmarkJava.git|07160be1b8b8bd9fe9a440d7fa91862ef659b102|
java|securibench-micro|https://github.com/too4words/securibench-micro.git|6a5a72488ea830d99f9464fc1f0562c4f864214b|
python|benchmark-python|https://github.com/OWASP-Benchmark/BenchmarkPython.git|f1291485808b66e20ddb6b01b10dc71b3df8c8ba|
javascript|nodegoat|https://github.com/OWASP/NodeGoat.git|c5cb68a7084e4ae7dcc60e6a98768720a81841e8|
javascript|juice-shop|https://github.com/juice-shop/juice-shop.git|6244c59a47ba4436cb00e9ad9c565bb2056582ec|
javascript|dvna|https://github.com/appsecco/dvna.git|9ba473add536f66ac9007966acb2a775dd31277a|
go|gosec|https://github.com/securego/gosec.git|71577268350e1e0f2f1491de1ef53f1227b43c1f|testutils
go|semgrep-rules|https://github.com/semgrep/semgrep-rules.git|9bbf021d0acffa3095fcffd17b2bc7787eb4796d|go
rust|semgrep-rules|https://github.com/semgrep/semgrep-rules.git|9bbf021d0acffa3095fcffd17b2bc7787eb4796d|rust
bash|semgrep-rules|https://github.com/semgrep/semgrep-rules.git|9bbf021d0acffa3095fcffd17b2bc7787eb4796d|bash
'
# Archive pins (no git history to pin, so the archive bytes are pinned instead).
# language|directory|url|sha256|size in bytes
# fetch downloads, verifies size + SHA-256, unzips into $CORPUS_ROOT/<directory> and
# writes $MARKER there: the archive hash plus a hash of every extracted file. check
# recomputes the file hash, so a corpus with local edits, added or deleted files fails.
ARCHIVES='
java|juliet-java|https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip|d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60|76798417
csharp|juliet-csharp|https://samate.nist.gov/SARD/downloads/test-suites/2020-08-01-juliet-test-suite-for-csharp-v1-3.zip|2e6dbac4741fb020a0b1c2db69e98aed165987df2bd70bd51f7c8c5302c8e8f8|68976634
'
MARKER='.fetch-corpora-pin'
# Languages with no pinned corpus (reported MISSING when requested). None at the moment.
UNPINNED_LANGS=''
KNOWN_LANGS='java python javascript csharp go rust bash'

die() { echo "fetch-corpora: $*" >&2; exit 1; }

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  list)
    printf 'git pins (language, directory, repository, commit, paths):\n'
    printf '%s\n' "$PINS" | sed '/^$/d' | tr '|' '\t'
    printf '\narchive pins (language, directory, url, sha256, bytes):\n'
    printf '%s\n' "$ARCHIVES" | sed '/^$/d' | tr '|' '\t'
    exit 0 ;;
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
  case " $KNOWN_LANGS " in *" $l "*) LANGS+=("$l") ;; *) die "unknown language '$l' ($KNOWN_LANGS)" ;; esac
done

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
tree_hash() { # hash of every file (path + content) under $1, excluding the marker
  (cd "$1" && find . -type f ! -path "./$MARKER" -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | cut -d' ' -f1)
}

fail=0
for l in $UNPINNED_LANGS; do
  if [ ${#LANGS[@]} -gt 0 ] && wanted "$l"; then
    echo "MISSING  $l: no pinned corpus is defined yet" >&2; fail=1
  fi
done

if [ "$cmd" = "fetch" ]; then mkdir -p "$CORPUS_ROOT"; fi

while IFS='|' read -r lang dir repo sha paths; do
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
  if [ -n "$paths" ] && [ ! -d "$dest/$paths" ]; then
    echo "MISSING  $dir ($lang): pinned commit has no $paths/" >&2; fail=1; continue
  fi
  echo "ok       $dir${paths:+/$paths} ($lang) @ ${sha:0:7}"
done <<EOF_PINS
$PINS
EOF_PINS

while IFS='|' read -r lang dir url sum size; do
  [ -n "$lang" ] || continue
  wanted "$lang" || continue
  dest="$CORPUS_ROOT/$dir"
  if [ ! -e "$dest" ]; then
    if [ "$cmd" = "check" ]; then echo "MISSING  $dir ($lang): not under \$CORPUS_ROOT" >&2; fail=1; continue; fi
    echo "fetch    $dir <- $url"
    tmp="$dest.partial.$$"; zip="$tmp.zip"
    rm -rf "$tmp" "$zip"
    if ! curl -fsSL --retry 3 -o "$zip" "$url"; then
      rm -f "$zip"; echo "FAILED   $dir: could not download $url" >&2; fail=1; continue
    fi
    got_size="$(wc -c < "$zip" | tr -d ' ')"; got_sum="$(sha256_of "$zip")"
    if [ "$got_size" != "$size" ] || [ "$got_sum" != "$sum" ]; then
      rm -f "$zip"; echo "FAILED   $dir: archive is $got_size bytes sha256 $got_sum, pinned $size bytes $sum" >&2; fail=1; continue
    fi
    mkdir -p "$tmp"
    if ! unzip -q "$zip" -d "$tmp"; then
      rm -rf "$tmp" "$zip"; echo "FAILED   $dir: could not unzip $zip" >&2; fail=1; continue
    fi
    rm -f "$zip"
    printf 'url=%s\narchive_sha256=%s\ntree_sha256=%s\n' "$url" "$sum" "$(tree_hash "$tmp")" > "$tmp/$MARKER"
    mv "$tmp" "$dest"
  fi
  if [ ! -f "$dest/$MARKER" ]; then
    echo "DRIFT    $dir: no $MARKER (not fetched by this script); remove it and fetch again" >&2; fail=1; continue
  fi
  rec_sum="$(sed -n 's/^archive_sha256=//p' "$dest/$MARKER")"
  rec_tree="$(sed -n 's/^tree_sha256=//p' "$dest/$MARKER")"
  if [ "$rec_sum" != "$sum" ]; then
    echo "DRIFT    $dir: extracted from archive ${rec_sum:-<unknown>}, pinned $sum" >&2; fail=1; continue
  fi
  if [ -z "$rec_tree" ] || [ "$(tree_hash "$dest")" != "$rec_tree" ]; then
    echo "DIRTY    $dir: files differ from the pinned archive" >&2; fail=1; continue
  fi
  echo "ok       $dir ($lang) @ sha256:${sum:0:12}"
done <<EOF_ARCHIVES
$ARCHIVES
EOF_ARCHIVES

[ "$fail" -eq 0 ] || die "one or more corpora are unavailable; do not run the §7 gate on them."
