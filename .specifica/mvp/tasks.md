# Tasks — MVP

**Open work items for cognium-dev MVP.**

---

## In Progress

- [ ] **Monorepo setup** — Combine circle-ir + CLI repos ✅ DONE
  - Owner: —
  - Completed: 2026-05-26

## Open — High Priority

- [ ] **Publish to npm** — Publish `circle-ir` and `cognium-dev` packages
  - Owner: —
  - Blocked by: Monorepo setup

- [ ] **GitHub Action** — Create `cognium-dev/scan@v1` action
  - Owner: —
  - See: `packages/cli/action.yml` (exists, needs update for new name)

- [ ] **Java benchmarks** — Publish comparison vs Snyk/Checkmarx/Semgrep
  - Owner: —
  - Due: Phase 1 (May 2026)

## Open — Medium Priority

- [ ] **Secret scanning** — Implement `scan_secrets` pass
  - Maps to: cognium-ai MCP `scan_secrets`
  - CWE: CWE-798 (hardcoded credentials)

- [ ] **Dependency analysis** — CVE matching, SBOM generation
  - Maps to: cognium-ai MCP `analyze_dependencies`
  - Formats: CycloneDX, SPDX

- [ ] **Supply chain risk** — Slopsquatting detection, package trust
  - Maps to: cognium-ai MCP `find_supply_chain_risk`

## Open — Low Priority

- [ ] **README updates** — Update for monorepo structure
- [ ] **CI/CD pipeline** — GitHub Actions for monorepo builds
- [ ] **Pre-commit hooks** — Lint, typecheck, test on commit

## Completed

- [x] **Monorepo structure** — Set up workspace with preserved git history
- [x] **CLI rebrand** — Rename cognium → cognium-dev
- [x] **Shared tsconfig** — Create base TypeScript config
- [x] **CLAUDE.md** — Combined guidance document

---

## Phase Milestones (from techspec)

| Phase | Milestone | Status |
|-------|-----------|--------|
| Phase 1 (May 2026) | Java benchmarks published | Pending |
| Phase 1 (Aug 2026) | 1000-repo PR campaign | Pending |
| Phase 1 (Aug 2026) | GitHub Action GA | Pending |
| Phase 2 (Q4 2026) | 5-language production | Pending |
| Phase 3 (Q1 2027) | On-prem GA | Pending |
