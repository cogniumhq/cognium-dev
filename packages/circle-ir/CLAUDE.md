# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Guardrails

- **Browser + Node.js compatible (CRITICAL)** - circle-ir MUST run in both browser and Node.js environments without any issues. No Node.js-specific APIs (`process`, `fs`, `path`, `child_process`, `os`, etc.) anywhere in library code. No npm dependencies that require Node.js. Only allowed dependencies: `web-tree-sitter`, `yaml`. The logger uses a zero-dependency console-based implementation with dependency injection (`setLogger()`) so consumers can inject pino or other loggers from their own packages.
- **TypeScript throughout** - All code must be written in TypeScript with strict mode enabled. No `any` types without explicit justification.
- **Unit test coverage ≥75%** - All new code must have unit tests. Run coverage reports to verify threshold before merging.
- **Universal core library** - The core library (`src/core/`, `src/analysis/`, `src/types/`) must be environment-agnostic. Platform-specific code belongs only in entry points (`src/browser.ts`).
- **circle-ir spec alignment** - All IR types and structures must conform to `docs/SPEC.md`. When implementing new features, update the spec's Implementation Status table (TypeScript column) accordingly.

## Project Overview

circle-ir is the core TypeScript SAST library for taint analysis and software quality metrics. It detects data-flow vulnerabilities (SQL injection, XSS, path traversal, …) and produces code quality findings (dead code, resource leaks, N+1 queries, …) and metrics (cyclomatic complexity, CBO, Halstead, …) using Tree-sitter for parsing.

**Scope boundary:**
- circle-ir: SAST passes + metrics — all deterministic, $0, no LLM
- circle-ir-ai: LLM-enhanced passes, clustering, semantic understanding — separate package

**Data available for circle-ir-ai:**
The following raw IR signals are always available for LLM-based analysis:
- `ir.types` — all classes, methods, fields with line ranges
- `ir.calls` — all call sites with method names, receivers, arguments
- `ir.cfg` — full control flow graph (blocks + edges)
- `ir.dfg` — data flow graph (defs, uses, chains)
- `ir.taint` — sources, sinks, sanitizers identified by static analysis
- `result.findings` — all SastFindings from the 40-pass pipeline
- `result.metrics` — 24 software quality metrics

**Passes removed from default pipeline (signals available for circle-ir-ai):**
- `MissingGuardDomPass` — dominator-based auth guard detection; false positives with framework-level auth. Use `ir.calls` + `DominatorGraph` to rebuild.
- `FeatureEnvyPass` — method accesses external objects more than own class; fires on legitimate delegation. Use `ir.calls` to compute call counts.

**Canonical references:**
- [`docs/PASSES.md`](docs/PASSES.md) — every pass and metric with canonical number, `rule_id`, CWE, SARIF level, and status
- [`TODO.md`](TODO.md) — phase-based action plan; use pass numbers from PASSES.md when referring to work items

## Build Commands

```bash
npm run build           # Compile TypeScript to dist/
npm run build:browser   # Bundle for browser (ESM) -> dist/browser/circle-ir.js
npm run build:core      # Bundle core library (ESM + CJS) -> dist/core/
npm run build:all       # Run all builds

npm run typecheck       # Type check without emitting
npm test                # Run all tests
npm run test:watch      # Run tests in watch mode
npm run test:coverage   # Run tests with coverage report (must be ≥75%)
```

## Architecture

For detailed architecture, see:
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Full system architecture
- **[docs/SPEC.md](docs/SPEC.md)** - Circle-IR specification
- **[docs/PASSES.md](docs/PASSES.md)** - Canonical pass + metric registry (numbers, CWEs, status)

**Multi-target build system:**
- Node.js build via `tsc` (ES2022, strict mode)
- Browser bundle via esbuild (ESM format)
- Core library bundle for universal environments

**Source structure:**
- `src/core/` - Parsing and IR generation using web-tree-sitter
- `src/analysis/` - Taint flow analysis engine + all AnalysisPass implementations
- `src/analysis/passes/` - Individual pass modules (TaintMatcherPass, ConstantPropagationPass, …)
- `src/analysis/html/` - HTML web extraction preprocessor (script extraction, attribute security checks, result merging)
- `src/graph/` - CodeGraph (lazy indexes), AnalysisPipeline, ProjectGraph, analysis-pass interface
- `src/types/` - TypeScript type definitions (`SastFinding`, `MetricValue`, `PassCategory`, …)
- `src/languages/` - Language plugins (Java, JavaScript, Python, Go, Rust, Bash, HTML)
- `src/resolution/` - Cross-file resolution, SymbolTable, TypeHierarchyResolver
- Entry point: `src/browser.ts` (browser-specific initialization)

**Analysis pipeline:**
`analyze()` runs 6 sequential `AnalysisPass` implementations through `AnalysisPipeline`. Each pass:
1. Declares `readonly name` (result key) and `readonly category: PassCategory`
2. Reads prior pass results via `context.getResult(name)`
3. Emits `SastFinding` objects via `context.addFinding(finding)`
4. Returns a typed result stored in the `PipelineRunResult.results` Map

Current passes (all `category = 'security'`):
`TaintMatcherPass` → `ConstantPropagationPass` → `LanguageSourcesPass` → `SinkFilterPass` → `TaintPropagationPass` → `InterproceduralPass`

**Configuration-driven analysis:**
The `configs/` directory contains YAML definitions for taint sources and sinks:

- `configs/sources/` - Taint sources (HTTP params, headers, cookies, env vars, DB results, file I/O)
- `configs/sinks/` - Dangerous operations (SQL injection, command execution, XSS, path traversal, deserialization, LDAP/XPath injection)

Each config entry specifies: method/class/annotation, vulnerability type, CWE mapping, severity level, and which argument positions are tainted.

**Key design patterns:**
- Taint tracking from sources to sinks with sanitizer support
- Annotation-based source detection (Spring: @RequestParam, @RequestBody; JAX-RS: @QueryParam, @PathParam)
- Severity levels: critical, high, medium, low

**Runtime configuration (v3.16.0+):**
The `analyze()` function accepts `passOptions` and `disabledPasses` for per-project customization:

```typescript
await analyze(code, path, lang, {
  passOptions: {
    dependencyFanOut: { threshold: 50 },
    unboundedCollection: { skipPatterns: ['results', 'cache'] },
  },
  disabledPasses: ['naming-convention'],
});
```

CLI tools can use `cognium.config.json` for project-level configuration with passes, suppressions, severity filters, and category filters. See `docs/ARCHITECTURE.md` ADR-006 for details.

## Key Analysis Components

1. **Constant Propagation Engine** (`src/analysis/constant-propagation.ts`)
   - Tracks variable values through assignments
   - Detects dead code via condition evaluation
   - Per-key collection taint tracking (map.put/map.get)
   - **List index tracking**: Precisely tracks list.add/remove/get operations with index shifting
   - Iterative refinement with fixpoint approach
   - Conservative taint preservation in conditional branches
   - **Inter-procedural analysis**: Tracks methods that always return constants, sanitized values, or their parameters

2. **Taint Flow Analysis** (`src/analysis/taint-propagation.ts`)
   - Source-to-sink path detection
   - Integration with constant propagation for false positive elimination
   - Sanitizer recognition (PreparedStatement, ESAPI, escapeHtml, etc.)
   - Array taint propagation (e.g., `{param}` initializer)

3. **DFG Verifier** (`src/analysis/dfg-verifier.ts`)
   - Verifies data flow paths between sources and sinks
   - Used for flow confirmation

4. **Path Finder** (`src/analysis/path-finder.ts`)
   - Finds taint paths through the DFG
   - Generates human-readable path descriptions

## Circle-IR Specification

The IR format is defined in `docs/SPEC.md` (Circle-IR 3.0). Key structures:

- **Meta** - File metadata, language, LOC, hash
- **Types** - Classes, interfaces, enums with methods and fields
- **Calls** - Method invocations with arguments and receivers
- **CFG** - Control flow graph (blocks + edges)
- **DFG** - Data flow graph (defs + uses)
- **Taint** - Sources, sinks, and sanitizers
- **Imports/Exports** - Cross-file resolution

The spec includes an Implementation Status table tracking Python (reference) vs TypeScript (this repo) progress. Update the TypeScript column when implementing features.

**Implementation phases from spec:**
1. **Phase 1 (Core)**: Meta, Types, Calls, CFG, DFG, Taint sources/sinks, Imports
2. **Phase 2 (Enhanced)**: Exports, Call resolution, Sanitizers, DFG chains
3. **Phase 3 (LLM Integration)**: Unresolved items, Enriched metadata, Findings
4. **Phase 4 (Project-Level)**: Cross-file analysis, Type hierarchy, Taint paths

## Test Coverage

- 1423+ tests passing
- 75%+ coverage required
- See `TODO.md` for areas needing additional test coverage

## Architecture Review Checklist

When reviewing or modifying circle-ir, verify these requirements:

### Independence (Critical)
- [ ] **Browser + Node.js compatible** - No Node.js-specific APIs (`process`, `fs`, `path`, `child_process`, `os`) in library code. Must run in browser and Cloudflare Workers.
- [ ] **No AI/LLM dependencies** - circle-ir must NOT depend on any LLM libraries (OpenAI, Anthropic, etc.)
- [ ] **No external package imports** - Only import from within circle-ir; never from other packages not listed in dependencies
- [ ] **Minimal dependencies** - Only allowed: `web-tree-sitter`, `yaml`. No Node.js-only packages. Logger is zero-dependency with DI via `setLogger()`.

### Language Abstraction
- [ ] **Plugin-based architecture** - All language-specific code in `src/languages/plugins/`
- [ ] **No hardcoded language checks** in core analysis (except necessary AST handling)
- [ ] **Configuration-driven** - Source/sink patterns in `configs/`, not hardcoded

### Code Quality
- [ ] **No dead code** - Remove unused exports, commented code blocks, unused files
- [ ] **No temporary files** - No `.tmp`, `.temp`, `.bak` files committed
- [ ] **No build artifacts** - `dist/`, `*.tgz`, `coverage/` must be gitignored

### Documentation
- [ ] **README.md** - API documentation and usage examples
- [ ] **docs/SPEC.md** - Circle-IR specification (update Implementation Status when adding features)
- [ ] **docs/ARCHITECTURE.md** - System design and ADRs
- [ ] **docs/PASSES.md** - Pass + metric registry (update status column when implementing or shipping a pass)
- [ ] **CHANGELOG.md** - Version history with semver
- [ ] **TODO.md** - Phase-based action plan (check off items as passes are implemented)

### Testing
- [ ] **Coverage ≥75%** - Run `npm run test:coverage` to verify
- [ ] **All tests pass** - Run `npm test` before committing
- [ ] **Key areas tested** - See TODO.md for coverage gaps to address

### Release Readiness
- [ ] **Semver compliance** - Version in package.json follows semantic versioning
- [ ] **npm-ready** - package.json has: name, version, description, main, types, exports, repository, license
- [ ] **Clean build** - `npm run build:all` succeeds without errors

## Language Support

**Supported Languages**: Java, JavaScript/TypeScript, Python, Go, Rust, Bash/Shell, HTML

For detailed status, benchmark scores, and pending improvements, see [TODO.md](TODO.md#language-support).

## Common Tasks

### Adding a New Taint Source
1. Add pattern to `configs/sources/<framework>.yaml` or create new file
2. Include: method/class, taint type, severity, CWE mapping
3. Add test case in `tests/` directory
4. Update TODO.md if part of a larger effort

### Adding a New Taint Sink
1. Add pattern to `configs/sinks/<category>.yaml` (sql, command, xss, path, etc.)
2. Include: method signature, CWE, severity, vulnerable argument positions
3. Add test case in `tests/` directory
4. Update CHANGELOG.md

### Adding a New Analysis Pass

1. Look up the pass in `docs/PASSES.md` to get its canonical number, `rule_id`, CWE, `category`, and SARIF `level`
2. Create `src/analysis/passes/<rule_id>-pass.ts` implementing `AnalysisPass<YourResultType>`
   - Set `readonly name = '<rule_id>'` and `readonly category = '<PassCategory>'`
   - Call `context.addFinding(finding)` for each `SastFinding` emitted — do NOT return findings in the result type
   - Check `docs/PASSES.md §F` for required graphs; only query what the pass actually needs
3. Register the pass in `analyze()` (`src/analyzer.ts`) if it runs per-file, or in `CrossFilePass` if project-level
4. Add tests in `tests/analysis/passes/<rule_id>.test.ts`
5. Update `docs/PASSES.md` status from `phase-1/phase-4` → `shipped`
6. Check the item off in `TODO.md`
7. Update `CHANGELOG.md`

**SastFinding construction example:**
```typescript
context.addFinding({
  id: `${this.name}-${graph.ir.meta.file}-${line}`,
  pass: this.name,
  category: this.category,
  rule_id: this.name,      // matches docs/PASSES.md rule_id
  cwe: 'CWE-561',          // from docs/PASSES.md CWE column
  severity: 'low',
  level: 'warning',        // from docs/PASSES.md level column
  message: 'Dead code: block is unreachable from any entry point',
  file: graph.ir.meta.file,
  line,
  snippet,
});
```

### Adding Language Support
1. Create plugin in `src/languages/plugins/<language>.ts` extending `BaseLanguagePlugin`
2. Add Tree-sitter WASM grammar to `wasm/` directory
3. Create source configs in `configs/sources/<language>.json`
4. Create sink configs in `configs/sinks/<language>.json`
5. Add comprehensive tests
6. Update TODO.md with completion status
