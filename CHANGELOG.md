# Changelog

Every release is published with detailed notes on the
[GitHub Releases](https://github.com/cogniumhq/cognium-dev/releases) page.

This project follows [Semantic Versioning](https://semver.org/).

## Per-package changelogs

Published packages and the Cursor plugin maintain their own detailed changelogs:

- **circle-ir** — [`packages/circle-ir/CHANGELOG.md`](packages/circle-ir/CHANGELOG.md)
  ([npm](https://www.npmjs.com/package/circle-ir))
- **cognium-dev** (CLI) — [`packages/cli/CHANGELOG.md`](packages/cli/CHANGELOG.md)
  ([npm](https://www.npmjs.com/package/cognium-dev))

`@cognium/mcp-server` and the Cursor / Claude plugin moved to
[cogniumhq/cognium-mcp](https://github.com/cogniumhq/cognium-mcp) after
`@cognium/mcp-server` 0.2.0, with their history. Their changelogs continue
there:

- **@cognium/mcp-server** — [`packages/mcp-server/CHANGELOG.md`](https://github.com/cogniumhq/cognium-mcp/blob/main/packages/mcp-server/CHANGELOG.md)
  ([npm](https://www.npmjs.com/package/@cognium/mcp-server))
- **Cursor / Claude plugin** — [`plugins/cognium-dev/CHANGELOG.md`](https://github.com/cogniumhq/cognium-mcp/blob/main/plugins/cognium-dev/CHANGELOG.md)

Both packages ship in lockstep from this monorepo. The version in a
release tag (`vX.Y.Z`) applies to both.
