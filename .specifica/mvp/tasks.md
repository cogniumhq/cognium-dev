# Tasks — MVP

**Open work items for cognium-dev MVP.**

---

## In Progress

(none)

## Open — High Priority

- [ ] **Publish to npm** — Publish `circle-ir` and `cognium-dev` packages
  - Owner: —
  - Ready: Monorepo complete

- [ ] **GitHub Action** — Create `cognium-dev/scan@v1` action
  - Owner: —
  - See: `packages/cli/action.yml` (exists, needs update for new name)

- [ ] **Java benchmarks** — Publish comparison vs Snyk/Checkmarx/Semgrep
  - Owner: —
  - Due: Phase 1 (May 2026)

- [ ] **Fix misclassified sinks** — Clean up auto-mined CVE sink entries
  - Issue: [#3](https://github.com/cogniumhq/cognium-dev/issues/3)
  - Files: sql.yaml, path.yaml, code_injection.yaml
  - Priority: Medium (incorrect labels, not false negatives)

## Open — Medium Priority

- [ ] **CWE-Bench-Java improvements** — Add missing sinks for better recall
  - Issue: [#2](https://github.com/cogniumhq/cognium-dev/issues/2)
  - Add: `SCMFileSystem.child()` (path traversal), refine Jenkins sources

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

| # | Title | Priority | Labels |
|---|-------|----------|--------|
| [#2](https://github.com/cogniumhq/cognium-dev/issues/2) | CWE-Bench-Java engine misses | Medium | enhancement |
| [#3](https://github.com/cogniumhq/cognium-dev/issues/3) | Misclassified sinks from auto-mined CVE | Medium | bug, cleanup |

---

## Phase Milestones (from techspec)

| Phase | Milestone | Status |
|-------|-----------|--------|
| Phase 1 (May 2026) | Java benchmarks published | Pending |
| Phase 1 (Aug 2026) | 1000-repo PR campaign | Pending |
| Phase 1 (Aug 2026) | GitHub Action GA | Pending |
| Phase 2 (Q4 2026) | 5-language production | Pending |
| Phase 3 (Q1 2027) | On-prem GA | Pending |
