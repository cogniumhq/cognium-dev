# Publishing circle-ir

`circle-ir` is **not published independently**. It ships in lock-step with `cognium-dev` as a synchronized version stream via the monorepo's root `release.sh`.

## Canonical release flow

From the repo root:

```bash
./release.sh patch    # or minor / major
```

This bumps both packages to the same new version, builds, tests, dry-run publishes, commits, tags (`circle-ir-vX.Y.Z` **and** `cognium-dev-vX.Y.Z`), pushes, creates GitHub releases, and publishes to npm in the correct order (`circle-ir` first, then `cognium-dev`).

See [`release.sh`](../../release.sh) and [`packages/cli/RELEASE.md`](../cli/RELEASE.md) for details.

## Why no per-package publish

- The CLI pins `circle-ir` to `^<NEW_VERSION>` matching its own version. Releasing the library independently breaks that invariant.
- Users on `cognium-dev@X.Y.Z` know they get `circle-ir@^X.Y.Z` — zero version-pin ambiguity.
- Single tag stream per release (two tags, same version) keeps GitHub release notes coherent.

## Prerequisites

- npm publish access to **both** `circle-ir` and `cognium-dev` packages
- `npm login` complete (`npm whoami` should succeed)
- `gh auth login` complete (`gh auth status` should succeed)

## Manual publish (emergency only)

If `release.sh` fails partway, you can finish manually — but note that `circle-ir` MUST be published before `cognium-dev`, otherwise the CLI's install will fail:

```bash
# After tags + GitHub releases exist and dry-runs passed
(cd packages/circle-ir && npm publish)
(cd packages/cli && npm publish)
```

Verify post-publish:

```bash
npm view circle-ir version
npm view cognium-dev version
```

## Troubleshooting

- **`npm publish` returns 403** → token expired or you lack publish rights on the package
- **`cognium-dev@X.Y.Z` install fails with "circle-ir@^X.Y.Z not found"** → CLI was published before lib; republish or yank the CLI version
- **Version mismatch between packages** → never patch this by republishing one package; cut the next version with `./release.sh patch` instead
