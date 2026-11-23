# Flow: project-profile-scan-wire

## Diagram

```
CLI scan <dir>
    → detectProjectProfiles (@cognium/project-profile-detect)
    → Map<file, shape/env> → circle-ir analyzeProject
    → ScanResult + vuln.profile
    → formatJSON.project_profile | formatSARIF.run.properties.projectProfile
    → GitHub Code Scanning / cognium-ai consumers
```

## Cross-Repo & Trust Boundaries

- **Producer**: `packages/cli` + `packages/project-profile-detect` (same monorepo workspace).
- **Consumer**: SARIF upload (GitHub), `cognium-ai` severity policy (sibling), conformis static packs (indirect via SARIF rule IDs).
- **Trust risk**: Mis-labeling `src/test` as `production` inflates or hides findings; omitting `project_profile` on directory scans looks like a complete production scan.

## E2E Harness Design

| Level | Model | Fixtures | Assertions |
|---|---|---|---|
| L2 hermetic | Bun.spawn CLI on temp Maven tree | `pom.xml` (spring-boot parent), `src/main` vuln servlet, `src/test` clean file | JSON + SARIF module tables, per-finding `profile`, `--no-project-profile` / forced profile flags |

Exit codes: findings present → `1`; explain-only → `0`.

## Ranked Risks

1. **R1 — Env axis wrong under multi-module tree** (`server/test` vs `server/production`).
2. **R2 — JSON/SARIF drift** (modules in JSON but missing `run.properties.projectProfile`).
3. **R3 — Silent omission** when `--no-project-profile` still emits profile attribution (fail-open).
4. **R4 — Force flag ignored** (`--project-profile library/production` must override detection).
5. **R5 — SARIF finding `properties.profile` missing** while JSON carries `vuln.profile`.

## Test Cases

| ID | Title | Risk | Level | Expected |
|---|---|---|---|---|
| TA-project-profile-scan-wire-1 | JSON finding profiles distinguish envs | R1 | L2-hermetic-e2e | `vulnerabilities[].profile` includes `*/production` and `*/test` |
| TA-project-profile-scan-wire-2 | SARIF carries run-level `projectProfile` | R2 | L2-hermetic-e2e | `runs[0].properties.projectProfile.modules` length ≥ 1 |
| TA-project-profile-scan-wire-3 | SARIF finding `properties.profile` on main vuln | R5 | L2-hermetic-e2e | profile matches `server/production` (or forced override) |
| TA-project-profile-scan-wire-4 | `--no-project-profile` omits summary | R3 | L2-hermetic-e2e | no `project_profile` / no SARIF `projectProfile` |
| TA-project-profile-scan-wire-5 | Forced `--project-profile library/production` | R4 | L2-hermetic-e2e | every finding `profile` uses forced `library/` shape (env still path-derived) |

## Runner / CI

```bash
cd packages/cli && bun test tests/e2e/project-profile-scan-wire.test.ts
```

Root: `npm run test -w packages/cli` (included in matrix job `test — cli`).