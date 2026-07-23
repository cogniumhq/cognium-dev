# circle-ir perf harness

Reproducible wall-clock + throughput + memory numbers for the built
engine, so perf work can be validated against a baseline instead of
shipped with the "not independently measured" hedge.

Landed for **cognium-dev #263**.

## Running

```bash
# From packages/circle-ir/:
npm run build          # populate dist/ (harness imports from dist/)
node perf/harness.mjs             # small + medium tiers, human-readable
node perf/harness.mjs --json      # machine-readable JSON to stdout
node perf/harness.mjs --large     # add the large tier (slower)
node perf/harness.mjs --tier=medium --iters=5   # focused re-run
```

Flags:

- `--json` — emit JSON to stdout (default: human-readable summary on
  stderr, nothing on stdout).
- `--large` — add the 200-file large tier (skipped by default because
  it dominates run time).
- `--tier=<small|medium|large>` — run exactly one tier.
- `--iters=<n>` — override iteration count per tier (default 3; medians
  reported).

## Fixtures

The harness generates **deterministic synthetic Java** at runtime — no
external corpora, no checked-in binary blobs.

- **small** (1 file, ~30 LOC) — a servlet-shaped controller with one
  tainted SQLi flow and one safely-parameterised branch. Exercises
  the core pipeline end-to-end at minimal cost.
- **medium** (30 files, ~1.5K LOC) — a mix of 5 shape variants (SQLi,
  path traversal, XSS, command injection, safe parameterised).
  Generated with a deterministic seed per file so the corpus is
  identical across runs.
- **large** (200 files, ~10K LOC) — the medium generator applied to
  200 seeds, off by default via `--large`.

## Rationale for synthetic fixtures

The 3.170.0 deep-dive (#254) originally ran against curated OSS
corpora (auth0/java-jwt, 500-file langchain4j subset) that were never
checked in. Every subsequent perf commit shipped without wall-clock
validation because the harness was gone.

Synthetic-and-deterministic solves the checked-in-corpus problem
directly:

- Reproducible without a large binary blob in the repo.
- Every run produces the same corpus — throughput deltas are
  attributable to engine change, not fixture drift.
- Extensible: real-corpus support (`--corpus <dir>` flag) is a
  follow-up on #263 for when we want direct comparison against the
  original langchain4j numbers.

## Interpreting the output

Each tier reports:

- `wallMs (median | min | max)` over N iterations
- `throughputLocPerSec` from the median wall-clock
- `rssDeltaMb` — process RSS growth during the tier's file batch,
  from `process.memoryUsage()` before/after

Comparisons: track median throughput per tier. A regression is a
consistent > 15 % drop in the median across ≥ 3 back-to-back runs
against the current `BASELINE.md`.

## Baseline

Current baseline is in [`BASELINE.md`](./BASELINE.md). Update it any
time a substantive perf-affecting change lands; the file is the
reference point for "is this a regression?"

## Not yet landed on #263

- Large-tier baseline capture (baseline currently covers small +
  medium only).
- CI perf gate that fails PRs when median large-tier throughput drops
  > 15 % vs baseline. Needs someone to own the policy.
- `--corpus <dir>` flag for real-repo runs.
- Per-pass timing summary (the engine already emits per-pass timings
  under `globalThis.__circleIrPassTiming`; harness should aggregate).
