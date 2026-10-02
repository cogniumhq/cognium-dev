# bench — navigation and resolution benchmarks

Scripts that produce the resolver's published numbers. Not part of any
published package. Run from the repo root after `npm run build:all`
(`build` alone omits `dist/wasm/`, so the parsers are missing):

    export CIRCLE_IR=$PWD/packages/circle-ir/dist/index.js

    node bench/probe.mjs <repo>              # timings, and the resolve-all tier counts
    node bench/h2h.mjs <repo>                # ripgrep vs findCallers, head to head
    node bench/honest.mjs <repo>             # findCallers split by tier + re-parse timing
    node bench/nav.mjs <repo>                # the navigation index: per-tier answers,
                                             #   unresolved reasons, and a whole-repo census
    node bench/unresolved-audit.mjs <repo>   # the call sites resolveCall does not answer,
                                             #   sampled with a recorded seed
    node bench/unresolved-classify.mjs <repo> <audit.json>
                                             # each sampled site with the evidence needed
                                             #   to classify it, and a proposed reason

Java only (`.java` walk). `h2h.mjs` and `honest.mjs` carry target names for one
specific repository in a `targets` array; edit it for another. Both shell out to
ripgrep — set `RG` to a binary if `rg` is not on `PATH`, or the floor column
reads zero and that zero is an environment artefact, not a result.

## Reproducing the unresolved-site audit

    node bench/unresolved-audit.mjs <repo> > audit.json        # SEED=20261002 N=200 by default
    node bench/unresolved-classify.mjs <repo> audit.json > classified.json

`unresolved-audit.mjs` enumerates call sites in a stable order (files sorted by
path, calls in IR order) and samples with a seeded PRNG, so the same seed gives
the same sample. `unresolved-classify.mjs` *proposes* a reason per site from
fixed rules and records the evidence for each; the proposal is not a
determination — every site in a reported sample is read by a human, and the
classifier's own text says where its rules over-approximate.

One rule worth knowing: "is the target inside the searched tree?" is answered
twice, once from `circle-ir`'s symbol table and once from a regex index built
without it. Where the two disagree, the extractor has a gap — which is how the
missing `record` support was found.
