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

## SAST accuracy (`bench/sast/`)

The scripts behind the published detection numbers. Each one scores a
`cognium-dev scan` JSON report, so it measures the CLI users install, not a
library call with extra configuration. Every number in the READMEs states its
version and comes from these commands.

    npm install -g cognium-dev@<version>
    export CIRCLE_IR=$(npm root -g)/cognium-dev/node_modules/circle-ir/dist/index.js

### OWASP BenchmarkJava 1.2: all 2,740 cases

    cd BenchmarkJava
    cognium-dev scan . --format json --category security -l java > owasp.json
    node bench/sast/score-owasp.mjs expectedresults-1.2.csv owasp.json

Scorecard rule: a test case is flagged when any finding in its file carries the
category's CWE. TPR over the 1,415 vulnerable cases, FPR over the 1,325 safe
ones. `--list fp|fn --cat <category>` names the cases.

### Juliet Test Suite for Java 1.3: `_01` cases, method level

    mkdir juliet01 && find juliet/src/testcases -name '*_01.java' -exec cp {} juliet01/ \;
    cd juliet01
    cognium-dev scan . --format json --category security -l java \
      --disable-pass require-entry-path > juliet.json
    node bench/sast/score-juliet.mjs juliet.json \
      --cwes CWE78,CWE80,CWE81,CWE83,CWE89,CWE90,CWE643,CWE23,CWE36

`bad()` is a true positive when a finding with the directory's CWE lands inside
it. Each `good*()` method (`goodG2B`, `goodB2G`, `goodN`; not the `good()`
dispatcher) is a false positive when one does. Omit `--cwes` for all fourteen
supported CWEs.

`require-entry-path` is disabled because every Juliet `_01` file has a `main()`,
which counts as an entry point, and `main` reaches `bad()` only through
reflection in the harness base class. With the gate on, the CLI drops every
`bad()` flow, so it measures the harness rather than the engine.

### SecuriBench Micro: 123 annotated cases

    cd securibench-micro/src/securibench/micro
    cognium-dev scan . --format json --category security -l java > sb.json
    node bench/sast/score-securibench.mjs . sb.json

Expected count: the file's `@servlet vuln_count`. A vulnerable file is a TP when
its distinct taint-finding sink lines reach that count, and a partial (credited
0.5) when some but not all are found. A file with `vuln_count = "0"` is a false
positive when anything fires.

### CWE-Bench-Java: 120 real CVEs

    node bench/sast/score-cwe-bench-java.mjs "$(npm root -g)/cognium-dev/dist/cli.js" \
      cwe-bench-java projects out --concurrency 4 --timeout-min 15

`projects/<project_slug>` is each project checked out at the vulnerable tag in
`data/project_info.csv`. A project is detected when a finding with its CWE lands
inside a fix method's line range (`data/fix_info.csv`, re-anchored by method
name). A project that is missing, times out, or fails to scan counts as a miss.
