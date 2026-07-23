# circle-ir perf baseline

Reference numbers for the current `main` build. Compare a candidate
change's numbers against these; a > 15 % median-throughput regression
across ≥ 3 back-to-back runs is the "worth investigating" signal.

Update this file any time a perf-affecting change lands.

## Current baseline

- **Engine**: `circle-ir@3.178.0` + commit [`6d28db3`](https://github.com/cogniumhq/cognium-dev/commit/6d28db3) (#260 fix, unreleased).
- **Captured**: 2026-07-23.
- **Node**: v24.16.0.
- **Platform**: darwin-arm64 (M-class).
- **Iterations per tier**: 3 (median reported).
- **Harness**: [`packages/circle-ir/perf/harness.mjs`](./harness.mjs).
- **Command**: `node perf/harness.mjs --json`.

| Tier   | Files | LOC   | Wall (median / min / max) | Throughput (median)  | RSSΔ (median) |
|--------|------:|------:|--------------------------:|---------------------:|--------------:|
| small  |     1 |    30 |         4.75 / 3.89 / 5.85 ms |     6 316 LOC/s |       3.31 MB |
| medium |    30 |  1456 |    100.39 / 98.72 / 117.6 ms |    14 503 LOC/s |       2.33 MB |
| large  |   200 | (not yet baselined) | — | — | — |

**Notes:**

- Small-tier throughput is dominated by fixed pipeline overhead (parse
  + graph build + one round of every pass). Not a useful measure of
  engine-code changes; useful as a regression trip-wire on the
  overhead itself.
- Medium-tier throughput (~14.5 K LOC/s) is the primary comparison
  point until the large tier is baselined. Comparable-ish to the
  #254 deep-dive's medium-tier number (`auth0/java-jwt`: 20.7 K LOC/s
  at 4453 LOC across 49 files) — synthetic code density is denser
  than real Java (more tokens per LOC), so lower throughput on the
  synthetic corpus is expected.
- Large tier not yet in the baseline; follow-up on #263.

## Historical reference (from the #254 deep-dive, 2026-07-15)

Different corpus, different harness, different date — kept as a
reference point for the shape of the shipped optimisations, not for
apples-to-apples comparison with the numbers above.

| Corpus                       | Files | LOC     | Wall (cold / warm)     | Throughput   |
|------------------------------|------:|--------:|------------------------|--------------|
| synthetic Java (SQLi)        |     1 |      34 | 28.5 / 6.5 ms          | ~5.2 K LOC/s |
| `auth0/java-jwt`             |    49 |   4 453 | 215 ms                 | 20.7 K LOC/s |
| `langchain4j` (500-file sub) |   500 |  55 996 | 2957 ms                | 18.9 K LOC/s |

The #254 baseline was captured on `circle-ir@3.170.0`. Between then
and today's baseline (3.178.0 + #260), the following perf work
shipped: T1 H1+H7+H8 (3.171.0), T2 nodeCache reuse T2-A+C (3.172.0),
T2-D `buildResolutionContext` cache (3.173.0), T1#5
`receiverMightBeClass` memo (3.177.0), T2#7 language-filter hoist
(3.177.0), T2#10 `walkBackwardDefs` memo (3.177.0), T1#2 constant-prop
tree-walk fusion (3.177.0), T2#9 `buildCFG` Bash+Go nodeCache reuse
(3.177.0). Direct wall-clock comparison against the historical numbers
requires running the historical harness on today's build (deferred —
see the "real-corpus support" follow-up on #263).
