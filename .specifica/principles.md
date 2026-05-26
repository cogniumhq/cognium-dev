# Principles

Cross-cutting rules for the cognium-dev project.

---

## Architecture

- **Browser + Node.js compatible** — circle-ir MUST run in both browser and Node.js environments. No Node.js-specific APIs (`process`, `fs`, `path`, `child_process`, `os`) in library code.
- **Minimal dependencies** — circle-ir depends only on `web-tree-sitter` and `yaml`. CLI depends only on `circle-ir`.
- **No LLM dependencies** — circle-ir is pure deterministic SAST. LLM-enhanced analysis belongs in a separate `circle-ir-ai` package.

## Code Quality

- **TypeScript strict mode** — All code uses strict TypeScript. No `any` types without explicit justification.
- **Unit test coverage ≥75%** — All new code must have unit tests. Run coverage reports to verify threshold.
- **SARIF 2.1.0 alignment** — All findings conform to SARIF schema for CI/CD integration.

## Naming

- **cognium-dev** — The CLI and npm package name for the SAST tool.
- **circle-ir** — The core SAST library name. Unchanged.
- **Pillar I** — Vulnerability finding (the only pillar cognium-dev implements).

## Retired Terms

- ~~cognium~~ — Use `cognium-dev` for the CLI product.
- ~~cognium-engine~~ — Superseded by `cognium-ai` + `cognium-dev` split.

## Communication

- Error messages include actionable fix suggestions.
- CLI output is colored for terminal readability.
- SARIF output enables GitHub/GitLab integration.
