# Tasks — MVP

**Open work items for cognium-dev MVP.**

---

## In Progress

(none)

## Open — High Priority

- [ ] **Residual Python FPs on OWASP BenchmarkPython** (follow-up to Issue #4, post-3.23.5)
  - Current on 3.23.5: TPR 81.2%, **FPR 12.6%**, F1 80.0%, 91 FPs / 1230 tests (target FPR ≤ 2%)
  - Breakdown: codeinj (18), xpathi (17), pathtraver (14), redirect (12), xxe (10), xss (9), ldapi (7), trustbound (2), cmdi (2), deserialization (7 residual after `yaml.safe_load` carve-out)
  - Hypothesis: same safe-variant-over-matching pattern as `yaml.safe_load` repeats in other Python plugin sink methods (`PythonPlugin.getBuiltinSinks()`); audit each category's sink list against the safe-API surface
  - Must precede any 3.24.0 framework expansion to avoid stacking confounds
  - Cross-ref: `cogniumhq/circle-ir-ai#75`

- [ ] **Consolidate Python sink source-of-truth** (architectural, surfaced by Issue #4 fix)
  - Current state: Python sinks live in THREE places — `configs/sinks/python.json`, `config-loader.ts::DEFAULT_SINKS`, and `PythonPlugin.getBuiltinSinks()` in `src/languages/plugins/python.ts`. Only the last is consulted at runtime for the language path
  - ADR-004 + `principles.md` currently claim `config-loader.ts` is THE runtime source-of-truth — this is incomplete for language-plugin-driven sinks (it's a 3-way split, not 2-way)
  - Action: either (a) collapse plugin `getBuiltinSinks()` into `DEFAULT_SINKS`, or (b) update ADR-004 + principles to honestly describe the 3-way model and pick a canonical one per language
  - Triggered by 7834e19 — fix landed in plugin, not config-loader

- [ ] **GitHub Action `cognium-dev/scan@v1` marketplace listing**
  - Owner: —
  - Status: `packages/cli/action.yml` rebranded to `cognium-dev` (npm name, CLI binary, SARIF category) in d0957b6 — usable today as `cogniumhq/cognium-dev/packages/cli@cognium-dev-vX.Y.Z`
  - Remaining: extract to standalone `cognium-dev/scan` repo, tag `v1`, publish marketplace listing

- [ ] **Java benchmarks** — Publish comparison vs Snyk/Checkmarx/Semgrep
  - Owner: —
  - Due: Phase 1 (May 2026)

## Open — Medium Priority

- [ ] **Cross-instance field-binding propagation** (Jenkins / general engine gap)
  - `this.field = param` in one method → `other.field` read in another method on an aliased instance
  - Required to close the remaining CWE-Bench-Java Jenkins `ReadTrustedStep.run()` path end-to-end
  - Engine-level (DFG cross-instance reasoning), not a YAML/config change

- [ ] **TSX / JSX parsing** (follow-up to 3.24.0)
  - 3.24.0 ships pure-TS only via `tree-sitter-typescript.wasm`. `.tsx` files still hit the JS grammar path (the broken pre-3.24.0 behavior for inline-object-type params) — and JSX additionally produces ERROR nodes the JS grammar cannot recover from
  - Action: bundle `tree-sitter-tsx.wasm` (also shipped by `tree-sitter-typescript@0.23.2`, ~1.45 MB), dispatch `.tsx` to it from the language plugin, mirror the `required_parameter` / `optional_parameter` work for any TSX-only param node shapes
  - Test coverage: add `tests/extractors/types-tsx.test.ts` with JSX-element-returning components

- [ ] **Interface extraction enrichment** (follow-up to 3.24.0)
  - The TS grammar now produces `interface_declaration` nodes, but `extractJavaScriptTypes` only walks `class_declaration` / `function_declaration` / named arrow funcs. Interfaces currently fall on the floor
  - Action: extend `extractJavaScriptTypes` (`src/core/extractors/types.ts`) to emit `interface_declaration` as `TypeInfo` with `kind: 'interface'`, populating `fields` from `property_signature` and `methods` from `method_signature`
  - Needed for cross-instance taint analysis when the type contract is declared as an interface

- [ ] **Generic / union / intersection type surfacing** (follow-up to 3.24.0)
  - `generic_type`, `union_type`, `intersection_type` nodes are now present in the TS-grammar tree but not converted into IR fields. `ParameterInfo.type` currently stores the raw source slice; structured representation would let passes reason about `Array<T>` vs `T[]`, nullable unions, etc.
  - Lower priority than the two above; defer until a pass actually needs structured TS type info

- [ ] **Framework coverage expansion** (proposed 3.25.0+)
  - JS/TS: Next.js API routes, TypeORM sinks, narrow `.value` dom_input source
  - Python: Jinja2 XSS sinks; additional MyBatis/Django ORM raw query patterns
  - Java: Micronaut, Quarkus
  - Rust: Axum extractor refinement, SQLx, Reqwest
  - All YAML-only except dom_input narrowing

- [ ] **Secret scanning** — Implement `scan_secrets` pass
  - Maps to: cognium-ai MCP `scan_secrets`
  - CWE: CWE-798 (hardcoded credentials)

- [ ] **Dependency analysis** — CVE matching, SBOM generation
  - Maps to: cognium-ai MCP `analyze_dependencies`
  - Formats: CycloneDX, SPDX

- [ ] **Supply chain risk** — Slopsquatting detection, package trust
  - Maps to: cognium-ai MCP `find_supply_chain_risk`

## Open — Low Priority

- [ ] **CI/CD pipeline** — GitHub Actions for monorepo builds
- [ ] **Pre-commit hooks** — Lint, typecheck, test on commit

## Completed

- [x] **Release 3.25.0** — version-bump-only re-publish issued ~40s after 3.24.0 to ensure a clean npm publish window; no source, config, or pass-pipeline changes. CHANGELOG auto-prepend records "(no commits since last release)" for both packages. Substantive changes for this stream are entirely in 3.24.0. (4168550, 2026-06-02)
- [x] **Release 3.24.0** — TS parser fix for Issue #5: ship real `tree-sitter-typescript.wasm` (v0.23.2), remove both `typescript → javascript` grammar redirects in `core/parser.ts`, add `required_parameter` / `optional_parameter` handling in `extractJSParameters`, populate `ParameterInfo.type` for TS code. 6 new regression tests in `tests/extractors/types-typescript.test.ts`; full suite 1810 passing, 0 failing. `.tsx` / JSX, interface IR enrichment, and generic-type surfacing tracked as separate follow-ups. (20df02f, 2026-06-02)
- [x] **Release 3.23.5** — source-side fix for Issue #4: `yaml.safe_load` removed from `PythonPlugin.getBuiltinSinks()`; `yaml.unsafe_load` + `yaml.full_load` added as CWE-502 sinks. OWASP BenchmarkPython delta: deser FP 24→7, FPR 14.8%→12.6%, F1 78.6%→80.0%. Closes #4 (source-side) and #6 (direct-to-main review). Residual 91 FPs tracked separately. (7834e19 + 2cd9032, 2026-05-30)
- [x] **Release 3.23.4** — documentation-only release: `PUBLISHING.md` + `RELEASE.md` rewrites pointing to root `release.sh`, `action.yml` rebrand to `cognium-dev`, README benchmark table split by language with BenchmarkPython qualification, `.gitignore` adds `.claude/`. No engine/taint-config changes. Known issue #4 (Python FPR 14.8%) carries forward. (7b679ad, 2026-05-30)
- [x] **Pre-populated CHANGELOG entries** — committed before `release.sh` ran so the auto-prepend produced a single canonical entry per package (c6bbd71, 2026-05-30)
- [x] **Pass-count consolidation** — README + CLAUDE no longer duplicate pass/metric counts; both link to `packages/circle-ir/docs/PASSES.md` (d0957b6, 2026-05-29)
- [x] **Release docs refresh** — Rewrote `packages/cli/RELEASE.md` and `packages/circle-ir/PUBLISHING.md` as pointers to root `release.sh`; dropped stale Homebrew + per-platform binary + `v*`-trigger workflow content (d0957b6, 2026-05-29)
- [x] **GitHub Action rebrand** — `packages/cli/action.yml` renamed to "cognium-dev SAST scan"; npm package + CLI binary + SARIF category switched from `cognium` → `cognium-dev`; README CI example points to actual usable path (d0957b6, 2026-05-29)
- [x] **Release 3.23.3** — `@DataBoundConstructor` method-level annotation source matcher; new `method_annotation` field on `SourcePattern`; closes source-side of #1 (2026-05-28)
- [x] **Release 3.23.2** — Jenkins `SCMFileSystem.child(String)` path-traversal sink (CVE-2022-25175 sink side) (2026-05-28)
- [x] **Release 3.23.1** — closed #3 (sink misclassifications); 20 wrong-type sink entries removed (2026-05-28)
- [x] **Release 3.23.0** — initial monorepo npm publish stream (2026-05-28)
- [x] **Monorepo hygiene** — root `release.sh`, dropped stale per-package lockfiles (2026-05-28)
- [x] **Monorepo structure** — Set up workspace with preserved git history (2026-05-26)
- [x] **CLI rebrand** — Rename cognium → cognium-dev (2026-05-26)
- [x] **Shared tsconfig** — Create base TypeScript config (2026-05-26)
- [x] **CLAUDE.md** — Combined guidance document (2026-05-26)
- [x] **GitHub repo setup** — Push to cogniumhq/cognium-dev (2026-05-26)
- [x] **Archive old repos** — circle-ir → archived, cognium → cognium-sast-cli archived (2026-05-26)
- [x] **Documentation review** — Update all README/docs for monorepo (2026-05-26)
- [x] **MyBatis ORM sinks** — Add 12 MyBatis mapper SQL injection sinks (2026-05-26)
- [x] **Issue migration** — Transfer CWE-Bench issue from archived repo (2026-05-26)

---

## Open Issues

(none open)

(#1, #2, #3 closed as of 3.23.3; #4, #6 closed as of 3.23.5; #5 closed as of 3.24.0; 3.25.0 was a version-bump-only re-publish)

---

## Phase Milestones (from techspec)

| Phase | Milestone | Status |
|-------|-----------|--------|
| Phase 1 (May 2026) | Java benchmarks published | Pending |
| Phase 1 (Aug 2026) | 1000-repo PR campaign | Pending |
| Phase 1 (Aug 2026) | GitHub Action GA | Pending |
| Phase 2 (Q4 2026) | 5-language production | Pending |
| Phase 3 (Q1 2027) | On-prem GA | Pending |
