# Releasing cognium-dev

`cognium-dev` and `circle-ir` ship as a **synchronized version stream** from this monorepo. There is no per-package release — both packages share one version, one commit, two tags (`circle-ir-vX.Y.Z` and `cognium-dev-vX.Y.Z`), and one workflow.

## Canonical release flow

From the repo root:

```bash
./release.sh patch    # or minor / major
```

`release.sh` handles:

1. Prerequisite check (`bun`, `node`, `npm`, `gh`, npm + GitHub auth)
2. Synchronized version bump for both packages
3. Pinning the CLI's `circle-ir` dep to `^<NEW_VERSION>`
4. Lockfile sync
5. CHANGELOG entry pre-population from git log (opens both for review)
6. `npm run build` + `npm test`
7. Built-CLI smoke test (`node packages/cli/dist/cli.js version`)
8. `npm publish --dry-run` for both packages
9. Commit + two tags (`circle-ir-vX.Y.Z`, `cognium-dev-vX.Y.Z`)
10. Branch + tag push
11. GitHub releases for both tags (notes pulled from each package's CHANGELOG)
12. `npm publish` — **circle-ir first, then cognium-dev** (CLI depends on lib)

See [`release.sh`](../../release.sh) for the authoritative implementation.

## Principles enforced

- **Version sync** — Both packages always carry the same version. Do not bump one in isolation; doing so will be caught by the script and require an explicit confirmation.
- **CHANGELOG required** — Each release writes an entry to both `packages/circle-ir/CHANGELOG.md` and `packages/cli/CHANGELOG.md`.
- **No manual npm publish** — Manual publishes bypass the dry-run, tag, and GitHub release steps. Use `release.sh`.

## Standalone binaries / Homebrew

Standalone binary builds (`bun run build:standalone`) and Homebrew formula publishing are **not** part of the current release flow. The `bun-darwin-arm64` / `bun-linux-x64` / etc. compile targets still work for ad-hoc builds, but no release artifact pipeline is wired up. Restart that work in a follow-up if needed.

## Troubleshooting

- **`npm whoami` fails** → `npm login`
- **`gh auth status` fails** → `gh auth login`
- **Versions out of sync at script start** → script will warn and offer to continue using `circle-ir`'s version as the source of truth
- **Built CLI reports wrong version after build** → check `packages/cli/src/version.ts` was rewritten by `npm version`; the script asserts this and aborts otherwise
