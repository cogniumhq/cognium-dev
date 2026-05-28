#!/usr/bin/env bash
# release.sh — Coordinated monorepo release for circle-ir + cognium-dev
# Usage: ./release.sh <patch|minor|major>
#
# Both packages share a synchronized version stream. Each invocation:
#   1. Bumps packages/circle-ir and packages/cli to the same new version
#   2. Updates packages/cli's circle-ir dep to the new ^version
#   3. Opens both CHANGELOGs for review
#   4. Verifies (typecheck, build, test, dry-run publish)
#   5. Creates a single commit + two tags (circle-ir-vX, cognium-dev-vX)
#   6. Pushes branch + tags, creates two GitHub releases
#   7. Publishes circle-ir, then cognium-dev (CLI depends on lib)

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────────
BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${BLUE}→${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}!${NC} $1"; }
die()     { echo -e "${RED}✗${NC} $1"; exit 1; }
confirm() { read -p "$1 [y/N] " -n 1 -r; echo; [[ $REPLY =~ ^[Yy]$ ]]; }

# ── Argument ────────────────────────────────────────────────────────────────────
if [[ $# -ne 1 ]] || [[ ! "$1" =~ ^(patch|minor|major)$ ]]; then
  echo "Usage: ./release.sh <patch|minor|major>"
  exit 1
fi
BUMP=$1

# Run from repo root regardless of where the user invokes it
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

LIB_DIR="packages/circle-ir"
CLI_DIR="packages/cli"

# ── Prerequisites ───────────────────────────────────────────────────────────────
info "Checking prerequisites..."
command -v bun  >/dev/null 2>&1 || die "bun not found"
command -v node >/dev/null 2>&1 || die "node not found"
command -v npm  >/dev/null 2>&1 || die "npm not found"
command -v gh   >/dev/null 2>&1 || die "GitHub CLI (gh) not found — brew install gh"
gh auth status  >/dev/null 2>&1 || die "Not authenticated with GitHub CLI — run: gh auth login"
npm whoami      >/dev/null 2>&1 || die "Not logged in to npm — run: npm login"
success "Prerequisites OK"

# ── Clean working tree ──────────────────────────────────────────────────────────
if [[ -n $(git status --porcelain) ]]; then
  warn "Uncommitted changes detected:"
  git status --short
  confirm "Continue anyway?" || exit 1
fi

# ── Version sync check ──────────────────────────────────────────────────────────
LIB_OLD=$(node -p "require('./$LIB_DIR/package.json').version")
CLI_OLD=$(node -p "require('./$CLI_DIR/package.json').version")
if [[ "$LIB_OLD" != "$CLI_OLD" ]]; then
  warn "Versions out of sync: circle-ir=$LIB_OLD, cognium-dev=$CLI_OLD"
  confirm "Continue anyway? (new version will be derived from circle-ir)" || exit 1
fi
info "Current version: $LIB_OLD"

# ── Typecheck (early fail) ──────────────────────────────────────────────────────
info "Running typecheck across workspaces..."
npm run typecheck
success "Typecheck passed"

# ── Bump both packages in sync ──────────────────────────────────────────────────
info "Bumping circle-ir ($BUMP)..."
(cd "$LIB_DIR" && npm version "$BUMP" --no-git-tag-version >/dev/null)
NEW_VERSION=$(node -p "require('./$LIB_DIR/package.json').version")
success "circle-ir: $LIB_OLD → $NEW_VERSION"

info "Bumping cognium-dev to $NEW_VERSION..."
(cd "$CLI_DIR" && npm version "$NEW_VERSION" --no-git-tag-version --allow-same-version >/dev/null)
success "cognium-dev: $CLI_OLD → $NEW_VERSION"

# ── Update CLI's circle-ir dep ──────────────────────────────────────────────────
info "Updating $CLI_DIR/package.json: circle-ir → ^$NEW_VERSION"
node -e "
  const fs = require('fs');
  const p = '$CLI_DIR/package.json';
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  j.dependencies['circle-ir'] = '^$NEW_VERSION';
  fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
"
success "CLI dep pinned to ^$NEW_VERSION"

# ── Sync root lockfile ──────────────────────────────────────────────────────────
info "Syncing root package-lock.json..."
npm install --package-lock-only --silent
success "Lockfile synced"

# ── CHANGELOG review ────────────────────────────────────────────────────────────
LIB_TAG="circle-ir-v$NEW_VERSION"
CLI_TAG="cognium-dev-v$NEW_VERSION"
LIB_LAST_TAG=$(git describe --tags --abbrev=0 --match "circle-ir-v*" 2>/dev/null || echo "")
CLI_LAST_TAG=$(git describe --tags --abbrev=0 --match "cognium-dev-v*" 2>/dev/null || echo "")
TODAY=$(date +%Y-%m-%d)

prepend_changelog() {
  local dir=$1 last_tag=$2 path=$3
  if [[ -n "$last_tag" ]]; then
    COMMITS=$(git log "$last_tag"..HEAD --pretty=format:"- %s" --no-merges -- "$dir" || echo "")
  else
    COMMITS=$(git log --pretty=format:"- %s" --no-merges -- "$dir" | head -20)
  fi
  local entry="## [$NEW_VERSION] - $TODAY

### Changes

${COMMITS:-"- (no commits since last release)"}
"
  local entry_file tmp
  entry_file=$(mktemp); tmp=$(mktemp)
  printf '%s\n' "$entry" > "$entry_file"
  awk -v entry_file="$entry_file" '
    /^## \[/ && !inserted {
      while ((getline line < entry_file) > 0) print line
      inserted=1
    }
    { print }
  ' "$path" > "$tmp"
  mv "$tmp" "$path"
  rm "$entry_file"
}

info "Pre-populating CHANGELOGs from git log..."
prepend_changelog "$LIB_DIR" "$LIB_LAST_TAG" "$LIB_DIR/CHANGELOG.md"
prepend_changelog "$CLI_DIR" "$CLI_LAST_TAG" "$CLI_DIR/CHANGELOG.md"

info "Opening circle-ir CHANGELOG for review..."
${EDITOR:-vi} "$LIB_DIR/CHANGELOG.md"
info "Opening cognium-dev CHANGELOG for review..."
${EDITOR:-vi} "$CLI_DIR/CHANGELOG.md"
success "CHANGELOGs updated"

# ── Build + test ────────────────────────────────────────────────────────────────
info "Building both packages..."
npm run build
success "Build OK"

info "Running tests..."
npm test
success "Tests pass"

# Confirm CLI built binary reports the right version
node "$CLI_DIR/dist/cli.js" version | grep -q "$NEW_VERSION" \
  || die "Built CLI reports wrong version (expected $NEW_VERSION)"

# ── Dry-run publishes ───────────────────────────────────────────────────────────
info "npm publish --dry-run for circle-ir..."
(cd "$LIB_DIR" && npm publish --dry-run)
info "npm publish --dry-run for cognium-dev..."
(cd "$CLI_DIR" && npm publish --dry-run)
success "Dry-runs OK"

# ── Commit + tag + push ─────────────────────────────────────────────────────────
info "Committing release..."
git add -A
git commit -m "chore: release circle-ir@$NEW_VERSION and cognium-dev@$NEW_VERSION"
git tag "$LIB_TAG"
git tag "$CLI_TAG"

confirm "Push branch + tags $LIB_TAG, $CLI_TAG to origin?" || die "Aborted before push"
git push origin HEAD
git push origin "$LIB_TAG" "$CLI_TAG"
success "Pushed"

# ── GitHub releases ─────────────────────────────────────────────────────────────
extract_notes() {
  local path=$1
  awk "/^## \[$NEW_VERSION\]/{found=1; next} found && /^## \[/{exit} found{print}" "$path"
}

info "Creating GitHub release $LIB_TAG..."
LIB_NOTES=$(extract_notes "$LIB_DIR/CHANGELOG.md")
gh release create "$LIB_TAG" --title "circle-ir $NEW_VERSION" --notes "$LIB_NOTES"

info "Creating GitHub release $CLI_TAG..."
CLI_NOTES=$(extract_notes "$CLI_DIR/CHANGELOG.md")
gh release create "$CLI_TAG" --title "cognium-dev $NEW_VERSION" --notes "$CLI_NOTES"
success "GitHub releases created"

# ── npm publish ─────────────────────────────────────────────────────────────────
echo ""
warn "About to publish to npm. CLI depends on lib, so circle-ir must be published FIRST."
warn "If 2FA is on, you'll be prompted for an OTP per publish."
echo ""

confirm "Publish circle-ir@$NEW_VERSION to npm?" || die "Aborted before publish"
(cd "$LIB_DIR" && npm publish)
success "circle-ir@$NEW_VERSION published"

# Brief pause so the npm registry catches up before CLI publishes
sleep 5

confirm "Publish cognium-dev@$NEW_VERSION to npm?" || die "Aborted before CLI publish — circle-ir already live; run 'cd $CLI_DIR && npm publish' manually"
(cd "$CLI_DIR" && npm publish)
success "cognium-dev@$NEW_VERSION published"

# ── Done ────────────────────────────────────────────────────────────────────────
echo ""
success "Release $NEW_VERSION complete!"
echo ""
echo "  circle-ir:    https://www.npmjs.com/package/circle-ir/v/$NEW_VERSION"
echo "  cognium-dev:  https://www.npmjs.com/package/cognium-dev/v/$NEW_VERSION"
echo "  GitHub (lib): https://github.com/cogniumhq/cognium-dev/releases/tag/$LIB_TAG"
echo "  GitHub (cli): https://github.com/cogniumhq/cognium-dev/releases/tag/$CLI_TAG"
