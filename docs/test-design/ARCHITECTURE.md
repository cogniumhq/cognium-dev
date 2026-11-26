# cognium-dev Test Architecture & SAST Pyramid

## 1. System Surfaces & Entry Points

| Surface | Entry | Downstream consumers |
|---|---|---|
| CLI (`packages/cli`) | `cognium-dev scan|recheck|deadcode|reach|entries|depcalls|sbom|metrics` | GitHub Actions (SARIF upload), `conformis.yml` gate, local CI |
| Engine (`packages/circle-ir`) | `analyzeProject`, graph-facts, taint passes | CLI, `code-facts`, `cognium-ai` (sibling) |
| Code facts (`packages/code-facts`) | `runPathSetDiff`, `runDependencyCalls`, `runRemedyClass` | CLI graph-facts commands, `cognium-ai` remediation |
| Project profile (`packages/project-profile-detect`) | `detectProjectProfiles` | CLI scan → circle-ir `AnalyzerOptions.projectProfile` |
| HTML index (`packages/html-index`) | route/field extractors | `conformis` a11y packs, CLI resource wiring |

MCP server and editor plugin live in **cogniumhq/cognium-mcp** (out of tree); this repo owns the scan engine and CLI wire formats.

## 2. Test Pyramid Inventory

### L1 — Unit & invariant tests

- **circle-ir**: 800+ Vitest/Bun suites — taint passes, stable IDs, resolution, graph-facts, parser recovery, abstain/safe-mirror cases per pass family.
- **code-facts / html-index / project-profile-detect**: Vitest/Bun — pure classifiers, remedy-class matching, Maven/Gradle parse, env/shape resolution.
- **cli**: Bun unit tests — formatters, suppressions, args, registry, recheck algebra, SARIF schema conformance (Ajv vendored schema).

### L2 — Hermetic CLI & contract E2E (in-process Bun.spawn)

- **`packages/cli/tests/e2e.test.ts`**: subprocess scan text/json/sarif, exit codes 0/1/2, profiles, cross-file suppressions, size ceiling.
- **`graph-facts.test.ts` / `depcalls.test.ts` / `recheck.test.ts`**: full CLI loopback on temp trees (TypeScript, Java, Python, Go, OSGi).
- **`symlink-scan.test.ts`**, **`stdout-drain.test.ts`**, **`scan-npm-manifests.test.ts`**: walk safety, pipe backpressure, lockfile context.
- **Gaps addressed**: **recheck JSON envelope → conformis RX-1/RX-2** (`tests/e2e/recheck-envelope-conformis.test.ts`).
- **Remaining**: deeper **project-profile** edge cases beyond the first wire suite.

### L3 — Browser, container & scheduled E2E

- **Bench corpora** (`bench/`, nightly `gates-nightly/`): Juliet, OWASP, CVE gates — long-running; not for short QE sessions.
- **CI on `grace`**: matrix `test — circle-ir|cli|project-profile-detect` + self-scan job names consumed by `conformis-gate.sh`.
- **L3 blueprint**: Playwright N/A for this repo; container pins live in conformis/controldeck consumers, not cognium-dev.

## 3. Cross-Repo Wire Contracts

| Sibling | Producer (cognium-dev) | Consumer | Risk |
|---|---|---|---|
| **conformis** | SARIF 2.1.0, check run names in `ci.yml` | `conformis.yml` + supply-chain packs | Invalid SARIF drops entire code-scan upload; renamed checks break gate |
| **cognium-ai** | Shared `circle-ir` version pin, scan JSON/SARIF shape | `cognium-ai` CLI/MCP scan | Schema drift on `project_profile` / severity policy |
| **cognium-mcp** | Engine behavior documented in README | MCP `scan` tool | Exit code & SARIF field parity with CLI |
| **controldeck** | Finding ingestion expects stable rule IDs | Tower surfaces | `abstain` → `pass` or silent truncation mis-ranks repos |

## 4. E2E Framework Architecture (Hermetic L2)

- **Runner**: Bun `bun test` per package; root `npm test` fans out workspaces.
- **Harness**: `Bun.spawn(['bun','run', cli.ts, ...])` with fixtures under `tests/fixtures` or `mkdtemp` trees; `NO_COLOR=1`.
- **Exit codes**: `0` clean / `1` findings / `2` usage or env (`controldeck-harness` aligned for recheck `3` = unknown).
- **SARIF**: vendored OASIS 2.1.0 schema in `tests/fixtures/sarif-schema-2.1.0.json`; hermetic — no network.
- **Grace CI**: self-hosted `grace` runs full matrix; QE agents run package-scoped suites locally before PR.

## 5. Prioritized Flow Backlog

| Priority | Flow | Layer | Status |
|---|---|---|---|
| P0 | `project-profile-scan-wire` | L2 hermetic CLI | Covered |
| P1 | `recheck-envelope-conformis` | L2 + cross-repo | **Covered** (this PR) |
| P2 | `code-facts-cli-parity` | L2 | `depcalls` covered; remedy-class CLI surface thin |
| P3 | `sarif-github-code-scanning` | L2+L3 doc | `sarif-conformance.test.ts`; upload action wiring needs maintainer CI doc |