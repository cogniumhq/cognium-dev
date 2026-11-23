# Graph-store benchmarks

## `t6-parity.mts` — T6 on `facts@2` against circle-ir's graph walk

```
npm run build
bun bench/graph-store/t6-parity.mts <java-tree> [--seeds 50] [--rng 1] [--out result.json]
```

Builds the tree's Java graph the way `cognium-dev entries --facts-arrow --facts-scheme facts@2` does, decodes the `facts@2` Arrow relations, and compares the producer walk over them (`T6Graph`) with circle-ir's own walk over the same graph:

- **blast radius** and **impacted tests** for `--seeds` `method` declarations drawn with a fixed PRNG (`--rng`), tier by tier, against `blastRadius` / `impactedTests`;
- **reach from declared entries** against `reach()`: exactly, once entry `constructors` are left out (`facts@2` has no column for them), and the remaining gap, checked to be what the constructor roots alone reach.

It prints a JSON summary (sizes, edge counts, timings, parity) and exits 1 on any difference. With `--out` it also writes every seed's result.
