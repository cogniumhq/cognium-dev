# Design — MVP

**How cognium-dev is organized.**

---

## Monorepo Structure

```
cognium-dev/
├── packages/
│   ├── circle-ir/          # Core SAST library (npm: circle-ir)
│   │   ├── src/
│   │   │   ├── core/       # Parsing, IR generation (Tree-sitter)
│   │   │   ├── analysis/   # Taint + quality passes
│   │   │   ├── graph/      # CodeGraph, DominatorGraph, etc.
│   │   │   ├── languages/  # Language plugins
│   │   │   └── types/      # TypeScript definitions
│   │   ├── configs/        # YAML source/sink definitions
│   │   ├── docs/           # SPEC.md, PASSES.md, ARCHITECTURE.md
│   │   └── wasm/           # Tree-sitter grammars
│   │
│   └── cli/                # CLI wrapper (npm: cognium-dev)
│       └── src/
│           ├── cli.ts      # Command routing, file collection
│           ├── formatters.ts # Text, JSON, SARIF output
│           └── utils/      # Colors, spinner, args (zero-dep)
│
├── .specifica/             # Project knowledge (this folder)
├── package.json            # npm workspace root
└── tsconfig.base.json      # Shared TypeScript config
```

## Analysis Pipeline

Six-phase taint analysis per file (canonical pass registry: [`packages/circle-ir/docs/PASSES.md`](../../packages/circle-ir/docs/PASSES.md)):

1. **TaintMatcherPass** — Config-based source/sink extraction
2. **ConstantPropagationPass** — Variable value tracking, dead code detection
3. **LanguageSourcesPass** — Framework-specific sources (Spring, Flask, etc.)
4. **SinkFilterPass** — False-positive elimination
5. **TaintPropagationPass** — DFG-based flow verification
6. **InterproceduralPass** — Cross-method taint tracking

Plus additional quality, reliability, performance, maintainability, and architecture passes — see PASSES.md for canonical counts and status.

## Key Design Decisions

### ADR-001: Monorepo over multi-repo
- **Decision:** Combine circle-ir and CLI in one repo
- **Rationale:** Atomic commits, shared tooling, version sync
- **Trade-off:** Slightly more complex build

### ADR-002: npm workspaces over pnpm/yarn
- **Decision:** Use npm workspaces
- **Rationale:** Most portable, no additional tooling
- **Trade-off:** `workspace:*` syntax not available (use `*`)

### ADR-003: Bun for CLI builds
- **Decision:** CLI built with Bun, not tsc
- **Rationale:** Faster builds, standalone binary support
- **Trade-off:** Requires Bun runtime for development

### ADR-004: Runtime config in `config-loader.ts`, not YAML
- **Decision:** Runtime source-of-truth for taint patterns is TypeScript code, not YAML. Three surfaces exist; exactly one is canonical:
  1. **Canonical — `DEFAULT_SOURCES` / `DEFAULT_SINKS` / `DEFAULT_SANITIZERS` / `DEFAULT_HEADER_RULES`** in `packages/circle-ir/src/analysis/config-loader.ts`. Language-agnostic by default; a pattern whose method name collides across ecosystems is scoped with `languages: ['python']`. Every new source/sink goes here.
  2. **Supplement — `LanguagePlugin.getBuiltinSources()` / `getBuiltinSinks()`** in `src/languages/plugins/<lang>.ts`. Reserved for language-specific patterns that have **no** counterpart in (1); also the extension point for third-party plugins. `TaintMatcherPass` merges these *after* the canonical registry.
  3. **Not runtime — `configs/**`.** Documentation and a published export for downstream tools. Nothing in `src/` reads it; `configs/README.md` says so in the shipped package and `npm run config:drift` measures the divergence.
- **Rationale:** Browser-compatible (no `fs`); tree-shakeable; statically typed; works in WASM/Cloudflare Workers without filesystem. Naming one canonical surface removes the "which of the three did I just edit?" question that Issue #4 exposed.
- **Constraint:** the same `(class, method, cwe)` must never be registered in both runtime surfaces. `findSinks` dedupes by `location:line:cwe` and replaces only on strictly-higher confidence, so a duplicate is invisible: the losing copy silently absorbs edits. The duplicate-free invariant is locked by `tests/languages/sink-registry-contract.test.ts` (sinks, and identical-metadata sources — `findSources` has no dedup at all, so an identical duplicate emits the same TaintSource twice).
- **Trade-off:** callers who pass `AnalyzerOptions.taintConfig` replace the canonical registry entirely while still receiving plugin builtins — an asymmetry inherited from the merge order. Left as-is: collapsing the plugin surface into `DEFAULT_SINKS` would change behaviour for that API path with no benchmark evidence that anyone depends on it.

### ADR-005: Synchronized version stream
- **Decision:** circle-ir and cognium-dev share one version number, bumped together via root `release.sh`.
- **Rationale:** Eliminates dep-pin ambiguity; one tag stream; users on `cognium-dev@X.Y.Z` know exactly which library they're running.
- **Trade-off:** A library-only bug fix forces a CLI version bump too. Acceptable cost.

## Configuration

### Taint Sources/Sinks
YAML files in `packages/circle-ir/configs/`:
- `sources/` — HTTP params, cookies, env vars, DB results
- `sinks/` — SQL, command exec, XSS, path traversal

### Per-Project Config
`cognium.config.json`:
```json
{
  "passes": { "dependencyFanOut": { "threshold": 50 } },
  "disabledPasses": ["naming-convention"],
  "severity": ["critical", "high"]
}
```

## Output Formats

| Format | Use Case |
|--------|----------|
| Text | Terminal output, human review |
| JSON | Programmatic consumption |
| SARIF 2.1.0 | GitHub/GitLab CI integration |
