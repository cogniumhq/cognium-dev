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

Six-phase taint analysis per file:

1. **TaintMatcherPass** — Config-based source/sink extraction
2. **ConstantPropagationPass** — Variable value tracking, dead code detection
3. **LanguageSourcesPass** — Framework-specific sources (Spring, Flask, etc.)
4. **SinkFilterPass** — False-positive elimination
5. **TaintPropagationPass** — DFG-based flow verification
6. **InterproceduralPass** — Cross-method taint tracking

Plus 34 additional quality/metric passes.

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
