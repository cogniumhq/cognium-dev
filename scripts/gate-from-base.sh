#!/usr/bin/env bash
# gate-from-base.sh <base-ref> <out-dir> [config]: copy the release-readiness gate as it is on the base
# branch (main, or the release/<track>-* branch a hotfix candidate is on) into <out-dir>, so the review
# runs the base's reviewer against the base's gate and a candidate cannot weaken its own gate (0.4.0).
# Copies, with `git show <base-ref>:<path>` only (no file of the candidate is read or run):
#   the config (default .release-readiness.json), the files it names (benchmark.record, waivers),
#   .loop/benchmarks.json, and scripts/release-readiness.mjs (the reviewer itself).
# A path the config names must be relative, without "..", "." parts or a leading "/"; anything else
# is refused (exit 1). A file missing on the base is skipped (the review then abstains or fails as it
# would for any missing file); a base with no config exits 1.
# Exit 0 = copied, 1 = refused or no config, 2 = usage.
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: gate-from-base.sh <base-ref> <out-dir> [config]" >&2; exit 2; }
ref=$1 out=$2 cfg=${3:-.release-readiness.json}
ok_path() { [[ $1 =~ ^[A-Za-z0-9_.][A-Za-z0-9_./-]*$ ]] && [[ ! $1 =~ (^|/)\.\.?(/|$) ]] && [[ $1 != */ ]]; }
ok_path "$cfg" || { echo "gate-from-base: config path $cfg refused" >&2; exit 1; }
git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || { echo "gate-from-base: $ref is not a commit" >&2; exit 1; }
[ ! -e "$out" ] || [ -z "$(ls -A "$out" 2>/dev/null)" ] || { echo "gate-from-base: $out is not empty" >&2; exit 1; }
mkdir -p "$out"
copy() {   # copy <path>: from the base, if it is there; never through a symlink on the base
  local p=$1 mode
  mode=$(git ls-tree "$ref" -- "$p" | awk '{print $1}')
  [ -n "$mode" ] || return 0
  [ "$mode" = 100644 ] || [ "$mode" = 100755 ] || { echo "gate-from-base: $p on $ref is not a regular file ($mode)" >&2; exit 1; }
  mkdir -p "$out/$(dirname "$p")"
  git show "$ref:$p" > "$out/$p"
}
copy "$cfg"
[ -f "$out/$cfg" ] || { echo "gate-from-base: $ref has no $cfg" >&2; exit 1; }
# The paths the config names, read as data (JSON.parse; nothing in the file is run).
names=$(node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
  for (const p of [c?.benchmark?.record, c?.waivers]) if (typeof p==="string" && p) console.log(p);' "$out/$cfg")
while IFS= read -r p; do
  [ -n "$p" ] || continue
  ok_path "$p" || { echo "gate-from-base: the base's config names $p, refused" >&2; exit 1; }
  copy "$p"
done <<< "$names"
copy .loop/benchmarks.json
copy scripts/release-readiness.mjs
echo "gate-from-base: the gate of $(git rev-parse --short "$ref") copied to $out"
