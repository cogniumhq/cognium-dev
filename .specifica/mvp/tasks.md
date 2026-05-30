# Tasks — MVP

**Open work items for cognium-dev MVP.**

---

## In Progress

(none)

## Open — High Priority

- [ ] **Python over-flagging on OWASP BenchmarkPython** (Issue #4, opened 2026-05-30)
  - Reproduced on circle-ir 3.23.3: TPR 81.2%, **FPR 14.8%**, F1 78.6%, 115 FPs / 1230 tests
  - Smoking gun: `yaml.safe_load()` flagged as CWE-502 deserialization sink (it's the safe API)
  - Pattern likely repeats in codeinj (CWE-94, 18 FPs), xpathi (CWE-643, 17 FPs), redirect (CWE-601, 12 FPs), xxe (CWE-611, 10 FPs), pathtraver (CWE-22, 14 FPs)
  - YAML-only fix: audit `configs/sinks/deserialization.yaml`, `code_injection.yaml`, `xpath.yaml`, `redirect.yaml`, `xxe.yaml`, `xss.yaml`, `ldap.yaml`, `path.yaml` for safe-variant carve-outs
  - Target: 3.23.4 patch release; must land before any 3.24.0 framework expansion to avoid stacking confounds
  - Cross-ref: `cogniumhq/circle-ir-ai#75`

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

- [ ] **Framework coverage expansion** (proposed 3.24.0)
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

- [#4](https://github.com/cogniumhq/cognium-dev/issues/4) — Python over-flagging on OWASP BenchmarkPython (FPR 14.8%); tracked under High Priority above

(#1, #2, #3 all closed as of 3.23.3)

---

## Phase Milestones (from techspec)

| Phase | Milestone | Status |
|-------|-----------|--------|
| Phase 1 (May 2026) | Java benchmarks published | Pending |
| Phase 1 (Aug 2026) | 1000-repo PR campaign | Pending |
| Phase 1 (Aug 2026) | GitHub Action GA | Pending |
| Phase 2 (Q4 2026) | 5-language production | Pending |
| Phase 3 (Q1 2027) | On-prem GA | Pending |
