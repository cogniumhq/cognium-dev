# cognium-dev — the risk map

| path | a mistake costs | how to review |
|---|---|---|
| `packages/circle-ir/` | all downstream scans | **deep** |
| `packages/cli/` | customer SARIF and Actions | **deep** |
| `packages/code-facts/`, `html-index/`, `project-profile-detect/` | conformis packs | **deep** on schema versions |
| `.github/workflows/` | fork safety, benches | **REQUEST_CHANGES, owner** |

## What ships broken here

- Security false negatives without benchmark narrative.
- SARIF / fingerprint drift.
- Non-deterministic CLI output.

## Who decides

- Pass inventory and CWE mapping: **engine owner**.
- Workflow and reviewer config: **owner**.