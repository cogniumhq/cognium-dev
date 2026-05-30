# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**cognium-dev** is the Cognium Static Application Security Testing (SAST) platform. It implements **Pillar I (Vulnerability Finding)** of the Cognium architecture — deterministic security analysis with zero LLM dependencies.

This is a monorepo containing:
- **`packages/circle-ir`** — Core SAST library (npm: `circle-ir`)
- **`packages/cli`** — Command-line interface (npm: `cognium-dev`)

## Architecture

```
cognium-dev/
├── packages/
│   ├── circle-ir/          # Core SAST library
│   │   ├── src/            # 36K LOC TypeScript
│   │   ├── configs/        # YAML source/sink definitions
│   │   ├── docs/           # SPEC.md, PASSES.md, ARCHITECTURE.md
│   │   └── wasm/           # Tree-sitter grammars
│   │
│   └── cli/                # CLI wrapper
│       └── src/            # 2.1K LOC TypeScript
│
├── package.json            # Workspace root
└── tsconfig.base.json      # Shared TypeScript config
```

## Development Guardrails

- **Browser + Node.js compatible (CRITICAL)** — circle-ir MUST run in both environments. No Node.js-specific APIs (`process`, `fs`, `path`, `child_process`, `os`) in library code.
- **TypeScript strict mode** — All code must use strict TypeScript. No `any` types without justification.
- **Unit test coverage ≥75%** — Run `npm run test:coverage` in packages/circle-ir to verify.
- **Minimal dependencies** — circle-ir only depends on `web-tree-sitter` and `yaml`. CLI only depends on `circle-ir`.

## Build Commands

```bash
# From repository root
npm install                 # Install all workspace dependencies
npm run build               # Build both packages
npm run test                # Run all tests
npm run typecheck           # Type check all packages

# From packages/circle-ir
npm run build               # TypeScript compile
npm run build:all           # Full build (tsc + browser + core bundles)
npm run test                # Run tests
npm run test:coverage       # Run with coverage report

# From packages/cli
bun run build               # Build CLI for npm
bun run build:standalone    # Build standalone binary
bun run dev scan <path>     # Run CLI in development mode
```

## Key Components

### circle-ir (SAST Library)

Analysis passes (security, reliability, performance, maintainability, architecture) and software quality metrics are enumerated in the canonical registry: [`packages/circle-ir/docs/PASSES.md`](./packages/circle-ir/docs/PASSES.md). Do **not** duplicate pass or metric counts in this file — link to PASSES.md.

**Languages** — Java, JavaScript/TypeScript, Python, Go, Rust, Bash, HTML.

**Benchmark scores:**
- OWASP Benchmark (Java): 100% TPR, 0% FPR
- Juliet Test Suite (Java): 100% (156/156 cases)
- SecuriBench Micro (Java): 97.7% TPR
- OWASP BenchmarkPython: 81.2% TPR, 14.8% FPR on 3.23.3 — tracked as Issue #4; FPs concentrated in deserialization/codeinj/xpathi/xxe due to safe-variant over-matching (`yaml.safe_load`, etc.). Target 3.23.4.

### CLI

Thin wrapper providing:
- Command-line interface (`cognium-dev scan`, `cognium-dev metrics`)
- Output formats: Text (colored), JSON, SARIF 2.1.0
- Zero-dependency utilities (colors, spinner, arg parsing)
- Cross-file taint path rendering

## Testing

```bash
# circle-ir (1799 tests, vitest)
cd packages/circle-ir && npm test

# CLI (bun test)
cd packages/cli && bun test
```

## Adding Analysis Passes

1. Look up the pass in `packages/circle-ir/docs/PASSES.md` for canonical number, rule_id, CWE
2. Create `packages/circle-ir/src/analysis/passes/<rule_id>-pass.ts`
3. Register in `packages/circle-ir/src/analyzer.ts`
4. Add tests in `packages/circle-ir/tests/analysis/passes/`
5. Update `PASSES.md` status to `shipped`

## Configuration

**Taint sources/sinks** are defined in YAML:
- `packages/circle-ir/configs/sources/` — HTTP params, cookies, env vars, DB results
- `packages/circle-ir/configs/sinks/` — SQL, command exec, XSS, path traversal

**Per-project config** via `cognium.config.json`:
```json
{
  "passes": { "dependencyFanOut": { "threshold": 50 } },
  "disabledPasses": ["naming-convention"],
  "severity": ["critical", "high"]
}
```

## Key Documentation

- `packages/circle-ir/docs/SPEC.md` — Circle-IR 3.0 specification
- `packages/circle-ir/docs/PASSES.md` — Pass + metric registry with CWEs
- `packages/circle-ir/docs/ARCHITECTURE.md` — System design and ADRs
- `packages/circle-ir/TODO.md` — Phase-based action plan
- `packages/cli/README.md` — User-facing CLI documentation

## Relationship to Cognium Platform

This repo implements the deterministic layer of **cognium-dev** (the AppSec product). Per the techspec:

- **cognium-dev** = pure SAST, Pillar I only, AppSec buyer
- **cognium-ai** = semantic engine with all 3 pillars (shares same engine, exposes more MCPs)

Raw IR signals available for circle-ir-ai (LLM-enhanced analysis):
- `ir.types`, `ir.calls`, `ir.cfg`, `ir.dfg`, `ir.taint`
- All `SastFinding` objects produced by the pass pipeline (see [`PASSES.md`](./packages/circle-ir/docs/PASSES.md))
- All software quality metrics (see [`PASSES.md`](./packages/circle-ir/docs/PASSES.md))
