# Contributing to cognium-dev

Thanks for your interest in improving cognium-dev. This document covers how
to set up the repo, where to file things, and the conventions we hold code
and commits to.

## Ground rules

- **Deterministic core.** `circle-ir` is Pillar I of the Cognium
  architecture — pure static analysis, zero LLM dependencies. No LLM /
  AI-named flags, options, comments, or identifiers may land in
  `circle-ir` or the `cognium-dev` CLI. See
  [`packages/circle-ir/CLAUDE.md`](packages/circle-ir/CLAUDE.md) and
  [`packages/cli/CLAUDE.md`](packages/cli/CLAUDE.md) for the exact
  boundary. If a knob is genuinely needed for a downstream LLM
  consumer, name it generically (e.g. `includeSpeculative`,
  `confidence`) — never `--llm-*`.
- **Browser + Node.js.** `circle-ir` runs in both environments. No
  Node.js-specific APIs (`process`, `fs`, `path`, `child_process`,
  `os`) in library code. Only allowed runtime dependencies:
  `web-tree-sitter`, `yaml`.
- **TypeScript strict.** All code uses TypeScript strict mode. No `any`
  without justification.
- **Unit test coverage ≥75%.** Run
  `npm run test:coverage` in `packages/circle-ir` before submitting.

## Prerequisites

- Node.js **≥ 20.19.0**
- npm 10+ (workspaces)
- macOS / Linux / WSL

## Setup

```bash
git clone https://github.com/cogniumhq/cognium-dev.git
cd cognium-dev
npm install         # installs both workspace packages
npm run build       # builds circle-ir + cli
npm test            # runs all tests (~4000)
npm run typecheck   # strict typecheck across workspaces
```

## Where to file things

- **Bug reports, feature requests, regressions:**
  [GitHub Issues](https://github.com/cogniumhq/cognium-dev/issues)
- **Security vulnerabilities:** private — see
  [`SECURITY.md`](SECURITY.md). Do **not** open a public issue.
- **Design proposals / open-ended questions:**
  [GitHub Discussions](https://github.com/cogniumhq/cognium-dev/discussions)
- **Code changes:** open a PR against `main`. Small, focused PRs merge
  faster than sprawling ones — split when in doubt.

## Commit convention

We follow [Conventional Commits](https://www.conventionalcommits.org/).
Recent history:

```
feat(circle-ir): modern taint sources — GraphQL/gRPC/cache/JWT (3.170.0)
fix(circle-ir): iterative tree walks to prevent stack overflow on deep ASTs (3.48.0)
perf(circle-ir): T2-D Java buildResolutionContext cache — 3.173.0 (#254)
chore: release circle-ir@3.171.0 and cognium-dev@3.171.0
```

Prefixes we use: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`,
`chore`. Include the affected package in parens (`feat(circle-ir):`,
`fix(cli):`). Reference the issue number when applicable
(`(#254)`).

## DCO / CLA

We do **not** require a CLA. Contributions are accepted under the
project's [MIT License](LICENSE) — by opening a PR you assert that
you have the right to license your contribution under those terms.

## Adding a new analysis pass

1. Look up the pass number, `rule_id`, CWE, and SARIF level in
   [`packages/circle-ir/docs/PASSES.md`](packages/circle-ir/docs/PASSES.md).
2. Create `packages/circle-ir/src/analysis/passes/<rule_id>-pass.ts`
   implementing `AnalysisPass<T>`.
3. Register the pass in `packages/circle-ir/src/analyzer.ts` (per-file)
   or in `CrossFilePass` (project-level).
4. Add tests in `packages/circle-ir/tests/analysis/passes/<rule_id>.test.ts`.
5. Update the pass row in `docs/PASSES.md` from `phase-N` → `shipped`.
6. Update [`packages/circle-ir/CHANGELOG.md`](packages/circle-ir/CHANGELOG.md).

## Adding a taint source or sink

- Sources: `packages/circle-ir/configs/sources/<framework>.yaml`
- Sinks: `packages/circle-ir/configs/sinks/<category>.yaml`

Each entry declares: method/class/annotation, taint or vuln type, CWE
mapping, severity, and vulnerable argument positions. Add a test
fixture in `packages/circle-ir/tests/` covering the new pattern
before submitting.

## Adding a language

1. Add the Tree-sitter WASM grammar under `packages/circle-ir/wasm/`.
2. Create a plugin in `packages/circle-ir/src/languages/plugins/<lang>.ts`
   extending `BaseLanguagePlugin`.
3. Add source/sink configs under
   `packages/circle-ir/configs/{sources,sinks}/`.
4. Add end-to-end tests exercising representative sources and sinks.

## Running the CLI locally

```bash
cd packages/cli
bun run dev scan ../../packages/circle-ir/tests/fixtures/java/simple
```

## Release process

Releases are cut by maintainers via `npm version` from each workspace
package, then published to npm and tagged (`vX.Y.Z`). Every release
appears at [GitHub Releases](https://github.com/cogniumhq/cognium-dev/releases).
See [`CHANGELOG.md`](CHANGELOG.md).

## Code of Conduct

By participating you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).
