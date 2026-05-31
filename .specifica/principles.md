# Principles

Cross-cutting rules for the cognium-dev project.

---

## Architecture

- **Browser + Node.js compatible** — circle-ir MUST run in both browser and Node.js environments. No Node.js-specific APIs (`process`, `fs`, `path`, `child_process`, `os`) in library code.
- **Minimal dependencies** — circle-ir depends only on `web-tree-sitter` and `yaml`. CLI depends only on `circle-ir`.
- **No LLM dependencies** — circle-ir is pure deterministic SAST. LLM-enhanced analysis belongs in a separate `circle-ir-ai` package.
- **Synchronized version stream** — `circle-ir` and `cognium-dev` always share the same version number and ship together; the CLI's `circle-ir` dependency is always pinned to `^X.Y.Z` matching its own version. Use `./release.sh <patch|minor|major>` at the repo root — never bump a single package in isolation.
- **Runtime config lives in TypeScript** — Two TS surfaces are consulted at runtime: `DEFAULT_SOURCES` / `DEFAULT_SINKS` / `DEFAULT_HEADER_RULES` in `packages/circle-ir/src/analysis/config-loader.ts` (language-agnostic), and `LanguagePlugin.getBuiltinSources()` / `getBuiltinSinks()` in `src/languages/plugins/<lang>.ts` (language-specific). YAML under `configs/` is documentation / external-export only and is NOT loaded at runtime. When adding a language-specific pattern (Python, JS, etc.) the plugin builtin is usually the right home. See ADR-004 (design.md) — consolidation is tracked in `tasks.md`.

## Code Quality

- **TypeScript strict mode** — All code uses strict TypeScript. No `any` types without explicit justification.
- **Unit test coverage ≥75%** — All new code must have unit tests. Run coverage reports to verify threshold.
- **SARIF 2.1.0 alignment** — All findings conform to SARIF schema for CI/CD integration.
- **Pass/metric counts cite `packages/circle-ir/docs/PASSES.md`** — never duplicate counts in `README.md`, `CLAUDE.md`, `spec.md`, or `design.md`. Link to PASSES.md instead.

## Project Knowledge

- **`.specifica/<version>/tasks.md` is canonical for project-level work** — releases, infra, GitHub issues, milestones. `packages/circle-ir/TODO.md` is the library-internal pass/metric roadmap. They do not overlap; cite the right one for the right question.

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
