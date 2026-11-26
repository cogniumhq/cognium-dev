# Flow: recheck-envelope-conformis

## Diagram

```
cognium-dev CLI `recheck --baseline … [--expect-gone …]`
    → cognium-recheck@0.4 JSON (findings, verdicts, targets, fixed, noNewHigh, partialFiles, skipped)
    → conformis C3 engine fact (application/vnd.cognium.recheck+json)
    → code-security/javascript RX-1 (finding-gone) + RX-2 (no-new-high) observe()
```

## Cross-Repo & Trust Boundaries

- **Producer**: `packages/cli` `recheck` command (`packages/cli/src/recheck.ts`).
- **Consumer**: `cogniumhq/conformis` `service/src/checks/evaluate.ts` (`rx1`, `rx2` over `RECHECK` media type); packs `code-security-ts/fix/RX-1-finding-gone.yaml`, `RX-2-no-new-high.yaml`.
- **Trust risk**: `abstain` must not become `pass` when a target is `gone` only because `declaration-removed` (G1 re-key); `fixed: pass` with `noNewHigh: fail` must not slip through RX-1; skipped changed files must surface in RX-2 observations (0.1.1+) so a skipped scan is not read as “no new highs.”

## E2E Harness Design

| Level | Model | Fixtures | Assertions |
|---|---|---|---|
| L2 hermetic | `Bun.spawn` CLI on temp Java/Python trees | Same servlet trees as `recheck.test.ts`; Python parse-error tree | Mirror conformis `rx1`/`rx2` field reads on stdout JSON (schema, targets, fixed, verdicts, partialFiles, skipped) |

Exit codes: `0` clean fix check; `1` `fixed` or `noNewHigh` fail; `3` any `unknown` verdict.

## Ranked Risks

1. **R1 — Schema / baseline gate**: conformis refuses reports without `verdicts` or with unknown `schema`.
2. **R2 — RX-1 target drift**: `targets[]`, `fixed`, and per-target `verdict`/`reason` must match what `rx1` maps (including `rekeyed` derivation for `declaration-removed`).
3. **R3 — RX-2 new-high parity**: every `new-high` verdict must appear in `rx2` observation; `noNewHigh` must agree.
4. **R4 — Undecided targets**: `unknown` / `not-in-baseline` targets populate `undecided` and must not read as fixed.
5. **R5 — Partial / skipped wire**: `partialFiles[].file` and non-`not present` `skipped` entries must be coercible to file lists for RX-2.

## Test Cases

| ID | Title | Risk | Level | Expected |
|---|---|---|---|---|
| TA-recheck-envelope-conformis-1 | Baseline report is conformis-readable | R1 | L2-hermetic-e2e | `schema` `@0.4`, `verdicts` array after baseline compare |
| TA-recheck-envelope-conformis-2 | RX-1 pass path on real fix | R2 | L2-hermetic-e2e | mirrored `obs.fixed === 'pass'`, target `gone` + `fixed: true` |
| TA-recheck-envelope-conformis-3 | RX-1 fail on fake fix | R2 | L2-hermetic-e2e | `obs.fixed === 'fail'`, `open` names still-present key |
| TA-recheck-envelope-conformis-4 | RX-2 new-high mirrors `noNewHigh` | R3 | L2-hermetic-e2e | `obs.newHigh.length === 1` when `noNewHigh === 'fail'` |
| TA-recheck-envelope-conformis-5 | Parse guard surfaces partial + undecided | R4,R5 | L2-hermetic-e2e | `partialFiles` lists broken file; RX-1 `undecided` non-empty |

## Runner / CI

```bash
cd packages/cli && bun test tests/e2e/recheck-envelope-conformis.test.ts
```

Cross-repo contract source: `conformis/service/src/checks/evaluate.ts` (`RECHECK`, `rx1`, `rx2`) at sibling default branch (verified read-only this run).