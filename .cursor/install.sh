#!/usr/bin/env bash
# Cloud Agent bootstrap for cognium-dev.
#
# Idempotent: safe to re-run against a warm checkout or cached snapshot.
set -euo pipefail

BUN_VERSION="1.3.11"

# bun is required by the monorepo but is not part of the base image:
#   - packages/cli and packages/project-profile-detect run their suites under
#     `bun test`
#   - packages/cli's build shells out to `bun build` (scripts/build.mjs)
# The pinned version matches .github/workflows/ci.yml (oven-sh/setup-bun).
if ! command -v bun >/dev/null 2>&1 || [ "$(bun -v 2>/dev/null || true)" != "$BUN_VERSION" ]; then
  export BUN_INSTALL="$HOME/.bun"
  curl -fsSL https://bun.sh/install | bash -s "bun-v${BUN_VERSION}"
  # Symlink onto a PATH dir so bun is visible to every shell (login or not),
  # not just ones that source ~/.bashrc.
  if command -v sudo >/dev/null 2>&1; then
    sudo ln -sf "$HOME/.bun/bin/bun" /usr/local/bin/bun
    sudo ln -sf "$HOME/.bun/bin/bunx" /usr/local/bin/bunx
  fi
fi
export PATH="$HOME/.bun/bin:$PATH"

# Workspace dependencies (npm workspaces).
npm ci

# `build:all`, not `build`: plain `build` is tsc-only and leaves
# packages/circle-ir/dist/wasm empty, which makes every circle-ir test abort on
# a missing tree-sitter grammar. build:all also produces the browser/core
# bundles and copies the grammars into dist/wasm. Downstream packages
# (cli, mcp-server) resolve circle-ir / project-profile-detect through their
# built dist entrypoints, so this must run before their suites work.
npm run build:all
