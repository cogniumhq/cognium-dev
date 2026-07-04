# Circle-IR Architecture & Design Decisions

This document outlines the key architectural decisions that make Circle-IR a high-performance, adaptive SAST tool.

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Design Principles](#core-design-principles)
3. [Key Architectural Decisions](#key-architectural-decisions)
   - [ADR-001: Constant Propagation Engine](#adr-001-constant-propagation-engine)
   - [ADR-002: Dynamic Pattern Discovery](#adr-002-dynamic-pattern-discovery)
   - [ADR-003: LLM-Augmented Analysis](#adr-003-llm-augmented-analysis)
   - [ADR-004: Configuration-Driven Taint Patterns](#adr-004-configuration-driven-taint-patterns)
   - [ADR-005: Multi-Target Build System](#adr-005-multi-target-build-system)
   - [ADR-006: Runtime Pass Configuration](#adr-006-runtime-pass-configuration)
   - [ADR-007: Pillar I — zero LLM in cognium-dev](#adr-007-pillar-i--zero-llm-in-cognium-dev)
   - [ADR-008: Project Profile + Library-API Tag Interaction](#adr-008-project-profile--library-api-tag-interaction)
4. [Analysis Pipeline](#analysis-pipeline)
5. [Benchmark Performance](#benchmark-performance)

---

## System Overview

Circle-IR is a static application security testing (SAST) tool that performs taint analysis to detect data flow vulnerabilities. It tracks data from user-controlled sources (HTTP inputs, environment variables, etc.) to dangerous sinks (SQL queries, command execution, etc.).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Circle-IR Pipeline                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Source Code                                                             │
│       │                                                                  │
│       ▼                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────┐     │
│  │  Tree-sitter │───▶│  AST Extraction  │───▶│  IR Generation      │     │
│  │  Parser      │    │  (Types, Calls)  │    │  (CFG, DFG, Meta)   │     │
│  └─────────────┘    └──────────────────┘    └─────────────────────┘     │
│                                                        │                 │
│                                                        ▼                 │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Analysis Engine                               │    │
│  │  ┌───────────────┐  ┌──────────────┐  ┌─────────────────────┐   │    │
│  │  │   Constant    │  │   Pattern    │  │   Taint Analysis    │   │    │
│  │  │  Propagation  │─▶│  Discovery   │─▶│   & Propagation     │   │    │
│  │  └───────────────┘  └──────────────┘  └─────────────────────┘   │    │
│  │         │                  │                     │               │    │
│  │         ▼                  ▼                     ▼               │    │
│  │  ┌───────────────┐  ┌──────────────┐  ┌─────────────────────┐   │    │
│  │  │  Dead Code    │  │     LLM      │  │  False Positive     │   │    │
│  │  │  Elimination  │  │ Verification │  │    Filtering        │   │    │
│  │  └───────────────┘  └──────────────┘  └─────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│                           ┌───────────────┐                              │
│                           │   Findings    │                              │
│                           │  (SARIF/JSON) │                              │
│                           └───────────────┘                              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Core Design Principles

### 1. Zero False Positives Over Maximum Coverage
We prioritize **precision over recall**. A finding that is reported should be a real vulnerability. This is achieved through:
- Constant propagation to eliminate safe assignments
- Dead code detection to skip unreachable sinks
- Sanitizer recognition to identify security controls

### 2. Adaptive Pattern Discovery
Rather than relying solely on hardcoded patterns, the system **learns and discovers** new vulnerability patterns during analysis using:
- Heuristic-based detection from method signatures
- LLM verification for confidence boosting
- Cross-file pattern accumulation

### 3. Configuration-Driven Extensibility
All taint sources, sinks, and sanitizers are defined in configuration, allowing:
- Easy addition of new vulnerability patterns
- Framework-specific customization
- Organization-specific rules

### 4. Environment Agnostic Core
The core analysis library works in any JavaScript environment:
- Node.js for CLI usage
- Browser for web-based analysis
- Cloudflare Workers for serverless deployment

---

## Key Architectural Decisions

### ADR-001: Constant Propagation Engine

**Status:** Implemented
**Impact:** +50% TPR improvement on OWASP Benchmark

#### Context
Many SAST tools produce false positives because they don't track whether a variable has been assigned a safe constant value before reaching a sink.

#### Decision
Implement a sophisticated constant propagation engine that:
1. Tracks variable values through assignments
2. Evaluates conditional expressions to detect dead code
3. Maintains per-key taint tracking for collections (maps, lists)
4. Performs inter-procedural analysis for method return values

#### Implementation

```typescript
// src/analysis/constant-propagation.ts

interface ConstantPropagatorResult {
  symbols: Map<string, ConstantValue>;      // Variable → constant value
  tainted: Set<string>;                      // Tainted variable names
  unreachableLines: Set<number>;             // Dead code lines
  sanitizedVars: Set<string>;                // Variables that were sanitized
  taintedArrayElements: Map<string, Set<number>>; // Array index tracking
}
```

#### Key Features

**Dead Code Detection:**
```java
// Before: FP - both branches flagged
if (false) {
    stmt.execute(userInput);  // Unreachable - not flagged
}

// Constant condition evaluation
String mode = "safe";
if (mode.equals("unsafe")) {
    stmt.execute(userInput);  // Unreachable - not flagged
}
```

**Strong Updates:**
```java
String query = request.getParameter("q");  // Tainted
query = "SELECT * FROM users";              // Constant - overwrites taint
stmt.execute(query);                        // Safe - not flagged
```

**Collection Tracking:**
```java
Map<String, String> params = new HashMap<>();
params.put("safe", "constant");
params.put("unsafe", request.getParameter("x"));

stmt.execute(params.get("safe"));    // Safe - not flagged
stmt.execute(params.get("unsafe"));  // Dangerous - flagged
```

#### Consequences
- OWASP Benchmark improved from ~50% to 100%
- Eliminated ~50% of false positives
- Added ~800 lines of analysis code

---

### ADR-002: Dynamic Pattern Discovery

**Status:** Implemented
**Impact:** Adaptive detection of unknown vulnerability patterns

#### Context
Hardcoded patterns cannot cover all possible vulnerability scenarios. New frameworks, custom code, and evolving attack vectors require constant pattern updates.

#### Decision
Implement a heuristic-based pattern discovery system that:
1. Analyzes method signatures to identify potential sources/sinks
2. Uses confidence scoring for discovered patterns
3. Optionally verifies with LLM for higher confidence
4. Caches patterns for cross-file accumulation

#### Implementation

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Heuristic     │────▶│  LLM Verify     │────▶│  Pattern Cache  │
│   Discovery     │     │  (optional)     │     │  (runtime)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        └───────────────────────┴───────────────────────┘
                                │
                        ┌───────▼───────┐
                        │   Analyzer    │
                        │  (uses all)   │
                        └───────────────┘
```

#### Heuristic Rules

**Source Detection:**
| Pattern | Type | Confidence |
|---------|------|------------|
| `get(Parameter\|Header\|Cookie)*` | http_param | 0.9 |
| `read(Line\|String\|Object)*` | io_input | 0.8 |
| `parse\|decode\|deserialize*` | io_input | 0.7 |
| Parameter type: `HttpServletRequest` | http_param | 0.8 |
| Annotation: `@RequestParam` | http_param | 0.95 |

**Sink Detection:**
| Pattern | Type | CWE | Confidence |
|---------|------|-----|------------|
| `execute(Query\|Update\|Sql)*` | sql_injection | CWE-89 | 0.9 |
| `exec\|run\|spawn\|system*` | command_injection | CWE-78 | 0.9 |
| `read\|write\|open*File` | path_traversal | CWE-22 | 0.8 |
| `eval\|compile*Expression` | code_injection | CWE-94 | 0.9 |

**Class Context Boosting:**
```typescript
// Class name patterns boost confidence
*Controller  → source: +0.2, sink: +0.1
*Handler     → source: +0.1, sink: +0.15
*Processor   → source: +0.1, sink: +0.2
*File/*Path  → sink (path_traversal): +0.25
*Sql/*Jdbc   → sink (sql_injection): +0.3
```

#### Usage

```typescript
const result = await analyze(code, filePath, 'java', {
  enablePatternDiscovery: true,
  patternConfidenceThreshold: 0.6,  // Use patterns with ≥60% confidence
});
```

#### Consequences
- Adapts to new codebases automatically
- Reduces manual pattern maintenance
- Cross-file pattern accumulation improves accuracy over time

---

### ADR-003: LLM-Augmented Analysis

**Status:** Out of scope for circle-ir core — moved to **circle-ir-ai**
**Impact:** circle-ir remains $0, deterministic, and zero-dependency

#### Context
Heuristic-based detection can produce false positives. Human-level reasoning can distinguish true vulnerabilities from false positives.

#### Decision
LLM integration (enrichment, verification, pattern validation) is **not** part of this library. circle-ir produces deterministic `SastFinding[]` output that a separate package (`circle-ir-ai`) can post-process with LLM reasoning. This keeps circle-ir:
- Zero-cost to run
- Deterministic and reproducible
- Free of API keys and network dependencies
- Safe to run in sandboxed / air-gapped environments

The CWE-Bench-Java scores in the Benchmark section below that require LLM are circle-ir-ai results, not circle-ir results.

---

### ADR-004: Configuration-Driven Taint Patterns

**Status:** Implemented
**Impact:** Extensibility, framework-specific support

#### Context
Different frameworks and organizations have different vulnerability patterns. Hardcoding all patterns is unmaintainable.

#### Decision
Define all taint patterns in configuration:

```typescript
// Source pattern
{
  method: 'getParameter',
  class: 'HttpServletRequest',
  type: 'http_param',
  severity: 'high',
  return_tainted: true
}

// Sink pattern
{
  method: 'executeQuery',
  class: 'Statement',
  type: 'sql_injection',
  cwe: 'CWE-89',
  severity: 'critical',
  arg_positions: [0]
}

// Sanitizer pattern
{
  method: 'setString',
  class: 'PreparedStatement',
  removes: ['sql_injection']
}
```

#### Pattern Categories

**Sources (400+ patterns):**
- HTTP: parameters, headers, cookies, body, path
- I/O: file input, environment, command line
- Database: query results
- Deserialization: XML, JSON, object streams

**Sinks (300+ patterns):**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XSS (CWE-79)
- Code Injection (CWE-94)
- LDAP Injection (CWE-90)
- XPath Injection (CWE-643)
- SSRF (CWE-918)
- Deserialization (CWE-502)

**Sanitizers (100+ patterns):**
- PreparedStatement (SQL)
- ESAPI encoding (XSS)
- Path normalization (Path Traversal)
- Input validation

---

### ADR-005: Multi-Target Build System

**Status:** Implemented
**Impact:** Universal deployment

#### Context
The tool needs to run in multiple environments: CLI, browser, serverless.

#### Decision
Use a multi-target build system:

```
src/
├── core/           # Environment-agnostic (no Node.js APIs)
├── analysis/       # Pure analysis logic
├── types/          # TypeScript definitions
├── browser.ts      # Browser entry point
├── worker.ts       # Cloudflare Worker entry point
└── cli/            # Node.js CLI
```

#### Build Targets

| Target | Format | Use Case |
|--------|--------|----------|
| Node.js | ES2022 | CLI, scripts, servers |
| Browser | ESM bundle | Web UI, in-browser analysis |
| Core | ESM + CJS | Universal library bundle |

```bash
npm run build           # Node.js
npm run build:browser   # Browser bundle
npm run build:core      # Core library (ESM + CJS)
npm run build:all       # All targets
```

---

### ADR-006: Runtime Pass Configuration

**Status:** Implemented (v3.16.0)
**Impact:** Per-project customization without code changes

#### Context
Different codebases have different characteristics. A CLI tool may legitimately have high fan-out, while an analyzer orchestrator intentionally imports many passes. Static thresholds cause false positives; disabling passes entirely loses valuable checks.

#### Decision
Add runtime configuration via `PassOptions` and `disabledPasses`:

```typescript
// API-level configuration
await analyze(code, path, lang, {
  passOptions: {
    dependencyFanOut: { threshold: 50 },
    unboundedCollection: { skipPatterns: ['results', 'cache'] },
  },
  disabledPasses: ['naming-convention', 'missing-public-doc'],
});
```

```json
// Project-level configuration (cognium.config.json)
{
  "passes": {
    "naming-convention": false,
    "dependency-fan-out": { "threshold": 50 }
  },
  "suppressions": [
    { "pass": "god-class", "file": "src/analyzer.ts", "reason": "Orchestrator by design" }
  ]
}
```

#### Key Features

**Per-Pass Options:**
- Thresholds: `dependency-fan-out.threshold`, future passes can add their own
- Skip patterns: `unbounded-collection.skipPatterns` for legitimate growing collections
- Regex patterns: `naming-convention.classPattern` for custom naming rules

**Suppressions:**
- Suppress by pass name (all findings from that pass)
- Suppress by pass + file (all findings in that file)
- Suppress by pass + file + line (specific finding)
- Documented reasons for audit trail

#### Implementation

Passes receive options via `PassContext`:

```typescript
class DependencyFanOutPass implements AnalysisPass {
  run(ctx: PassContext): DependencyFanOutResult {
    const threshold = ctx.passOptions?.dependencyFanOut?.threshold ?? 20;
    // ... use threshold
  }
}
```

CLI tools (e.g., cognium) load `cognium.config.json` and pass options to `analyze()`.

### ADR-007: Pillar I — zero LLM in cognium-dev

**Status:** Accepted (2026-06-23, locked in 3.94.0).

**Context.** cognium-dev is the deterministic SAST layer of the Cognium
platform. LLM-aware functionality lives in the separate `circle-ir-ai` /
`cognium-ai` repos which consume `circle-ir` as a library. Prior agent-
generated work drifted toward LLM-themed identifiers (`--llm-verify`,
`llmVerify` option, "LLM verifier" docstrings) inside this repo despite
the architectural boundary, triggering a course correction in 3.94.0.

**Decision.** No LLM concepts may surface anywhere in cognium-dev:

- No `--llm-*` CLI flags.
- No `llm*` option names on `AnalyzerOptions` or any pass option struct.
- No "LLM verify / verifier / adjudicator / AI" wording in source,
  comments, help text, CHANGELOGs, docs, or test fixtures.
- API surfaces that downstream LLM consumers need (e.g. opt-in to
  speculative findings) are named generically: `includeSpeculative`,
  `confidence`, `speculative`.

**Consequences.**

- Future agents adding any flag/option/doc mentioning "LLM" must stop and
  rename before committing. The guardrail is restated in `CLAUDE.md`
  (root, `packages/circle-ir`, `packages/cli`) and surfaced in
  `docs/SPEC.md` and `docs/PASSES.md`.
- Two legacy LLM-themed identifiers predate this ADR and remain in the
  public API for back-compat: `discoveryMethod: 'static' | 'llm'`
  (`generateFindings`, added 3.45.0) and the `LLMVerificationResult`
  exported type. Both are deprecation candidates for the next major
  bump.
- The downstream consumer pattern is: cognium-dev emits a richer signal
  stream (e.g. `confidence: 'medium'` findings); `circle-ir-ai` opts in
  via the generically-named library option and applies LLM adjudication
  before user presentation.

**Reference.** Sprint 36 retro / 3.94.0 release notes; `CLAUDE.md`.

---

### ADR-008: Project Profile + Library-API Tag Interaction

**Status:** Accepted (2026-06-24, design locked for Sprint 48 / 3.106.0). Implementation pending.

**Context.** Sprint 47 (3.105.0) introduced the
`library-api-surface:caller-responsibility` tag on `SastFinding` /
`TaintSink` / `TaintFlowInfo` and a uniform downgrade hook
(`applyLibraryApiSurfaceDowngrade`) that drops tagged CRIT/HIGH findings
to MEDIUM/warning regardless of project shape. This addressed three
specific code-injection false-positive classes (#161 JEXL/Handlebars,
#165 SPI `Class.forName`, #168 JDK ClassLoader override) but is a
flat per-callsite gate with no project-context awareness.

Sprint 48 generalises this via the `analyzeOptions.projectProfile` API
proposed in `#169` (project profile architecture). Profile values follow
a 5×5 matrix `{library, application, cli, server, plugin} × {production,
dev, sample, benchmark, test}` with the default `unknown` preserving
3.105.0 behavior. The profile is **caller-supplied** — circle-ir never
reads the filesystem (Pillar I + browser/Node compatibility); cognium-dev
CLI and circle-ir-ai each own their own detector and pass the result in.

**Detection contract (caller side, hybrid shape + publication).** Real
codebases mix library and application shapes within a single repository
(e.g. LanguageTool: `languagetool-core` is published library, `-server`
is application, `-dev/*` is dev tooling; or a Spring Boot monorepo with
internal `core-utils` modules that *look* library-shaped but ship only
inside one app). Shape alone is insufficient — an internal helper has
the threat model of the application that consumes it, not of a library
with unknown external callers.

The detection algorithm therefore composes two signals per module:

1. **Shape** ∈ `{library, application, cli, server, plugin}` derived from
   plugins (`java-library`, `application`, `spring-boot`, etc.),
   `module-info.java` exports, and `main()` count in non-test source.
2. **Published-externally** ∈ `{true, false, unknown}` derived from
   `<distributionManagement>` URLs (Maven) or `publishing { repositories
   { maven { url } } }` blocks (Gradle). **Strict** matching only —
   the URL must point to a known public registry
   (`repo.maven.apache.org`, `oss.sonatype.org`,
   `central.sonatype.com`, `repo1.maven.org`, etc.). Corporate Nexus /
   Artifactory URLs are deliberately *not* treated as published; the
   threat model for a corporate-internal-only artifact is closer to an
   application than to an open-source library.

Composition rule:
```
if shape == 'library' AND published == true:    profile = library/<env>
if shape == 'library' AND published == false:   profile = application/<env>  // scenario 4
if shape == 'library' AND published == unknown: profile = unknown            // fail safe
otherwise:                                      profile = <shape>/<env>
```

**Granularity** is per-module (any directory containing a `pom.xml`,
`build.gradle`, or `build.gradle.kts` defines a module boundary; files
belong to the nearest enclosing module). Sub-path overrides within a
module (e.g. `samples/**` inside a library module) are **not supported
in v1** — users who need that granularity supply explicit
`profileOverrides` in `cognium.config.json`.

**Failure mode.** When detection is ambiguous (shape unclear, publication
unknown, conflicting signals), the resolved profile is `unknown`, which
yields zero behavior change vs 3.105.0. The system never silently
"upgrades" relaxation; misdetection costs alert priority only on the
*relaxed* side, never recall on the strict side.

The two mechanisms must compose cleanly. Three orthogonal axes govern
the composition:

**Decision.** Tagged-finding behavior under each project profile follows
the **C-Yes-Yes** policy:

1. **Severity transform under `library` profile (D1 = C, "CRIT-protected
   bucketing"):**
   ```
   CRITICAL → MEDIUM    (preserves RCE-shape alarm; never drops further)
   HIGH     → LOW
   MEDIUM   → LOW
   LOW      → LOW       (no-op)
   ```
   Rationale: a tagged CRITICAL is still a literal RCE shape and warrants
   human review even when the callsite lives at a library API boundary.
   Dropping it to LOW (or suppressing entirely) creates an unacceptable
   silent-FN risk if the profile detector misfires.

2. **Sink-type gate (D2 = Yes):** the profile downgrade applies **only**
   to a fixed sink-type allowlist. The allowlist captures sinks where
   "library API boundary" is a semantically defensible reason to relax
   severity:
   ```
   DOWNGRADE_ELIGIBLE = {
     code_injection,            // Class.forName, eval, compile, dispatch
     template_injection,        // Handlebars/Velocity/Freemarker compile
     xpath_injection,           // XPath.compile from caller-supplied expr
     sql_injection-when-builder // Stage 13 *Dialect/*SqlBuilder class gate
   }
   ```
   Sinks **outside** the allowlist (`command_injection`,
   `path_traversal`, `deserialization`, `ssrf`, `xxe`, `ldap_injection`,
   `header_injection`, `log_injection`, etc.) ignore the profile signal
   entirely — a library that calls `Runtime.exec(userInput)` or
   `ObjectInputStream.readObject(userInput)` is a bug regardless of
   project shape.

3. **Application-profile restoration (D3 = Yes):** under
   `application` profile, tagged findings are **restored** to their
   pre-Sprint-47 severity. This requires preserving the original
   severity on the finding (new field `original_severity?: string` or
   equivalent) before the Sprint 47 downgrade runs. Rationale:
   `application` profile means the analysed project IS the caller, so
   the "caller bears the trust" argument inverts — these findings
   become the user's responsibility to investigate, not someone else's.
   Without restoration, `application` profile would behave identically
   to `unknown`, defeating its purpose for the tagged subset.

**Composition order** (post-pipeline, pre-output):

```
findings
  → applyConfidenceFilter           (existing)
  → applyLibraryApiSurfaceDowngrade (Sprint 47 — uniform CRIT/HIGH → MED)
  → applyProjectProfileTransform    (Sprint 48 — NEW; see policy above)
  → applyPerFileFindingCap          (existing)
```

The profile transform runs **after** Sprint 47's uniform downgrade so it
can either (a) downgrade further (library), (b) restore (application),
or (c) no-op (unknown). The `original_severity` field is set by the
uniform downgrade hook so the profile transform has a value to restore.

**Consequences.**

- **No silent finding loss.** Tagged findings are never dropped — they
  are only moved between severity tiers. Detection misfire (profile
  detector says `library` when it's actually `application`) costs alert
  priority, not visibility.
- **New finding field.** `SastFinding.original_severity?: string` is
  added to support restoration. Browser/SARIF/JSON consumers see it as
  optional metadata; CLI text formatter does not surface it directly.
- **Allowlist is curated.** The `DOWNGRADE_ELIGIBLE` set lives in a
  single constant alongside the downgrade hook. New sink types default
  to "not eligible" — adding a sink type requires an explicit decision.
- **Profile is opaque to passes.** Passes do not consult `projectProfile`
  directly in v1; only the post-processing transform reads it. This
  keeps the per-pass code stable and concentrates profile-conditional
  logic in one place. Pass-level profile awareness can be added
  incrementally if specific passes need it.
- **Reversible.** Both the downgrade and the restoration are pure
  functions over the findings array. A consumer that doesn't want
  profile-conditional behavior passes `projectProfile: 'unknown'` (or
  omits it) and gets identical 3.105.0 output.

**v1 implementation choices (Sprint 48 / 3.106.0).**

- **Signal precedence within a module** (resolves multi-signal ambiguity):
  1. `spring-boot` plugin → `server`
  2. `application` plugin OR exactly one `main()` in non-test src → `application`
  3. `java-library` plugin OR `module-info.java` with `exports` → `library` (then publication check)
  4. `<packaging>maven-plugin</packaging>` OR Gradle `java-gradle-plugin` plugin → `plugin`
  5. multiple `main()` methods AND no application/server plugin → `cli`
  6. otherwise → `unknown`
  Higher-precedence rules short-circuit lower ones.

- **Env axis precedence** (path-based, applied per file within a module):
  1. file path matches `**/test/**` or `**/*Test.java` → `test`
  2. file path matches `**/benchmark/**` or `**/jmh/**` → `benchmark`
  3. file path matches `**/samples/**`, `**/examples/**`, `**/demo/**` → `sample`
  4. module directory or ancestor path matches `**/dev/**`, `**/dev-tools/**` → `dev`
  5. otherwise → `production`

- **User visibility**: cognium-dev CLI prints a per-module detected-profile
  header above the findings section (`Profiles: core=library/production,
  server=server/production, dev=cli/dev`). SARIF emits `properties.profile`
  on each result; JSON emits `vulnerabilities[].profile`. No per-finding
  text badge — the header carries the context once.

- **Test profile**: `env=test` is **no-op** in v1 — the existing
  test-file heuristic in individual passes already handles test-source
  exclusion. The env value is set and surfaced in output but no
  pass-level behavior depends on it. Reserved for future refinement.

- **Detection cache**: per-scan in-memory only. Detection runs once
  during cognium-dev's pre-scan project walk and the resolved
  `Map<file, profile>` lives for the duration of the scan. No
  persistence to disk in v1 — pom/gradle parse cost on a 30-module
  repo is sub-second on real hardware. Revisit if telemetry shows
  otherwise.

- **Override grammar**: `cognium.config.json` accepts a
  `profileOverrides` map keyed by **glob patterns** (relative to repo
  root), values are `<shape>/<env>` strings. Globs match using the
  same `**`/`*` semantics as the existing `exclude` field. Override
  wins over auto-detection. CLI flag `--profile=<shape>/<env>` applies
  to the entire scan and wins over both auto-detection and config
  overrides.

- **Pass-level profile awareness**: v1 ships **only** the tag-hook
  interaction described above. Individual analysis passes do not
  consult `projectProfile` directly. Adding per-pass profile awareness
  (e.g. a future `resource-leak` that ignores library API boundaries)
  is a pure additive change that doesn't reopen the ADR.

**Observability output (3.150.1, #235).** The resolved profile is now
surfaced on the IR so downstream consumers (cognium-ai#189 Tier 2
audit, cognium-ai#130 profile detector, ledger tooling) can verify
what the transform actually saw without re-running detection:

- `Meta.projectProfile?: ProjectProfile` — populated by `analyze()`
  when the caller supplies `options.projectProfile`. Value is exactly
  what `makeProfileResolver` returned for this file (may be
  `'unknown'` when a per-file `Map` did not cover the file). Absent
  when the caller omits the option, preserving 3.106.0–3.150.0 output
  shape.
- `ProjectMeta.projectProfileSummary?: ProjectProfileSummary` —
  populated by `analyzeProject()` under the same condition. Rollup
  shape:
  ```
  {
    byShape: Record<ProjectShape | 'unknown', number>,
    byEnv:   Record<ProjectEnv   | 'unknown', number>,
    totalFiles: number,
  }
  ```
  Buckets are always initialised to zero for every enum value, so
  consumers can index without existence checks. `unknown` collects
  files that either resolved to the literal `'unknown'` profile or
  were absent from the per-file map.

Both fields are pure observability — no downgrade decision is derived
from them. They exist so a Tier 2 auditor can look at `scan.json` and
answer "which files did the engine treat as library callers?" without
having to reconstruct the resolver externally.

**Source-side scoping (3.151.0, #236).** With `Meta.projectProfile`
now populated on every per-file IR, the pipeline gained a companion
gate to the post-hoc `applyProjectProfileTransform` severity
downgrade: `LibraryProfileSourceGatePass` (canonical rule_id
`library-profile-source-gate`, category `security`).

The pass runs between `SourceSemanticsPass` and `SinkFilterPass` and,
when `graph.ir.meta.projectProfile` begins with `library/`, drops
speculative sources — `interprocedural_param` and
`constructor_field` — from `graph.ir.taint.sources` before any flow
generator sees them. Concrete anchors (`http_param`, `env_input`,
`db_input`, `file_input`, etc.) are preserved unconditionally.

Motivation. `TaintMatcher` emits an `interprocedural_param` source
for every public method parameter (the "this parameter MIGHT receive
attacker-controlled data at some caller" seed). Under
`application/*` the assumption is defensible: unresolved callers
eventually reduce to entry points the application owns. Under
`library/*` it is systematically wrong — the callers are downstream
consumers, and the correct trust-boundary answer is "the consumer's
threat model, not ours". In the 22-repo harness audit
`external_taint_escape` (CWE-668) alone accounted for ~35% of Tier 2
H+C findings; those flows are synthesised in Scenario B of
`InterproceduralPass` from `interprocedural_param` seeds, so removing
the seeds removes the whole class of finding at the source-side
without touching the sink pipeline.

Interaction with existing gates:

- **#128 entry-point gate** — method-level classifier
  (`classifyEntryPointTier` in `entry-point-detection.ts`) that
  suppresses Scenario A `TIER_3_LIBRARY_API` flows. Still runs
  under application shapes where the coarse profile signal is
  unavailable or insufficient.
- **#138 source-semantics gate** — per-source tagger (constant / SPI
  / demoPath) that runs immediately before this pass. Its tags are
  preserved for observability even when the source is subsequently
  dropped.
- **This pass (#236)** — profile-level guard. When the caller
  declares the whole project a library, the presumption of external
  callers is turned off wholesale, avoiding the per-method
  false-negative risk of #128 on library API surfaces.

Guardrails:

- No-op when profile is absent, `'unknown'`, or non-library shape.
  Callers that skip profile detection get the exact 3.150.1 output.
- Guarded on `disabledPasses.has('library-profile-source-gate')` at
  the pipeline registration site.
- Only speculative source types are eligible for the drop. Any future
  concrete source type must be omitted from the eligible-types set.

**Reference.** `#169` (project profile architecture), Sprint 47 release
notes (3.105.0), Sprint 48 design discussion (this ADR),
`#235` (Sprint 51 / 3.150.1 — observability output fields),
`#236` (Sprint 52 / 3.151.0 — source-side scoping under `library/*`).

---

## Analysis Pipeline

`analyze()` runs a single `AnalysisPipeline` of **36 sequential `AnalysisPass` implementations**. Each pass declares a `category: PassCategory` and can emit `SastFinding` objects via `context.addFinding()`.

```
Source Code
    │
    ▼
Tree-sitter parse → AST
    │
    ▼
IR Extraction → Types, Calls, CFG, DFG, Imports/Exports
    │
    ▼
CodeGraph (lazy indexes: callsByMethod, defsByVar, usesAtLine, loopBodies, …)
    │
    ▼
AnalysisPipeline (36 passes, sequential)
    │
    ├─── Security (passes 1–6) ─────────────────────────────────────────────
    │    ├─ 1. TaintMatcherPass          — match source/sink configs + TypeHierarchy
    │    ├─ 2. ConstantPropagationPass   — track variable values, detect dead code
    │    ├─ 3. LanguageSourcesPass       — enrich sources using language plugin
    │    ├─ 4. SinkFilterPass            — filter sinks using constant propagation
    │    ├─ 5. TaintPropagationPass      — enumerate source→sink paths via DFG
    │    └─ 6. InterproceduralPass       — cross-method taint tracking
    │
    ├─── Reliability (passes 7–22) ─────────────────────────────────────────
    │    ├─ 7. DeadCodePass              — CFG BFS; unreachable blocks
    │    ├─ 8. MissingAwaitPass          — unawaited async calls (JS/TS)
    │    ├─ 9. NullDerefPass             — null source dereferenced without guard
    │    ├─10. ResourceLeakPass          — resource opened, not closed on all paths
    │    ├─11. UncheckedReturnPass       — return value of critical op discarded
    │    ├─12. InfiniteLoopPass          — CFG cycle with no exit edge
    │    ├─13. DoubleClosePass           — resource closed twice (CWE-675)
    │    ├─14. UseAfterClosePass         — method called after close() (CWE-672)
    │    ├─15. UnhandledExceptionPass    — throw/raise without try/catch
    │    ├─16. BroadCatchPass            — catch(Exception) / bare except
    │    ├─17. SwallowedExceptionPass    — catch block silently discards exception
    │    ├─18. VariableShadowingPass     — inner scope shadows outer binding
    │    ├─19. LeakedGlobalPass          — accidental global assignment (JS/Python)
    │    ├─20. UnusedVariablePass        — declared variable with no reads
    │    ├─21. MissingGuardDomPass       — sensitive op not dominated by auth check (CWE-285)
    │    └─22. CleanupVerifyPass         — cleanup doesn't post-dominate acquisition (CWE-772)
    │
    ├─── Performance (passes 23–27) ────────────────────────────────────────
    │    ├─23. NPlusOnePass              — DB/HTTP calls inside loopBodies()
    │    ├─24. SyncIoAsyncPass           — blocking I/O inside async function
    │    ├─25. StringConcatLoopPass      — string += inside loop (O(n²) allocs)
    │    ├─26. RedundantLoopComputationPass — loop-invariant .length/.size() hoisting
    │    ├─27. UnboundedCollectionPass   — collection grows in loop with no size cap
    │    ├─28. SerialAwaitPass           — sequential awaits with no dependency (JS/TS)
    │    └─29. ReactInlineJsxPass        — inline object/function in JSX props (JS/TS)
    │
    ├─── Maintainability (passes 30–32) ────────────────────────────────────
    │    ├─30. MissingPublicDocPass      — public API without doc comment
    │    ├─31. TodoInProdPass            — TODO/FIXME/HACK in non-test files
    │    └─32. StaleDocRefPass           — doc comment references missing symbol
    │
    └─── Architecture (passes 33–36) ───────────────────────────────────────
         ├─33. CircularDependencyPass    — cycle in import graph (Tarjan SCC)
         ├─34. OrphanModulePass          — file with no incoming imports
         ├─35. DependencyFanOutPass      — module imports 20+ others
         ├─36. DeepInheritancePass       — inheritance chain > 5 levels
         ├─  . MissingOverridePass       — overrides parent without @Override (Java)
         └─  . UnusedInterfaceMethodPass — interface method never called in-file
    │
    ▼
PipelineRunResult
    ├─ results: Map<passName, passResult>  — per-pass structured output
    └─ findings: SastFinding[]             — all findings from passes 7–36
    │
    ▼
CircleIR output
    ├─ taint.flows   — security taint flows (from passes 1–6)
    ├─ findings      — quality findings (from passes 7–36)
    └─ metrics       — FileMetrics with 24 software quality metrics (MetricRunner)
```

**For multi-file analysis**, `analyzeProject()` runs the full 36-pass pipeline on each file independently, then uses `ProjectGraph` → `CrossFilePass` to surface taint flows that span file boundaries, returning a `ProjectAnalysis` with `taint_paths`, `cross_file_calls`, and `type_hierarchy`.

See [docs/PASSES.md](PASSES.md) for the canonical pass registry with rule IDs, CWEs, and status.

---

## Benchmark Performance

### Summary
| Benchmark | TPR | FPR | Score | Notes |
|-----------|-----|-----|-------|-------|
| **OWASP Benchmark** | 100% | 0% | **+100%** | circle-ir static only |
| **Juliet Test Suite** | 100% | 0% | **+100%** | circle-ir static only |
| **SecuriBench Micro** | 97.7% | 6.7% | **+91.0%** | circle-ir static only |
| **CWE-Bench-Java** | 81.7% | - | **+81.7%** | circle-ir-ai (LLM-assisted) |
| **CWE-Bench-Java** | 42.5% | - | **+42.5%** | circle-ir static only |

### OWASP Benchmark v1.2 (Perfect Score)
- **2740 test cases, 0 false negatives, 0 false positives**
- Perfect on all 11 categories: sqli, cmdi, xss, pathtraver, ldapi, xpathi, trustbound, hash, crypto, weakrand, securecookie

### Juliet Test Suite (Perfect Score)
- **156 test cases across 9 CWEs**
- Perfect on: CWE-23, CWE-36, CWE-78, CWE-79/80/81/83, CWE-89, CWE-90, CWE-643

### SecuriBench Micro
| Category | TPR | FPR |
|----------|-----|-----|
| basic | 100% | N/A |
| arrays | 100% | 0% |
| inter | 100% | N/A |
| datastructures | 100% | N/A |
| collections | 84.6% | 100% |
| aliasing | 83.3% | N/A |
| pred | 100% | 40% |
| sanitizers | 100% | 66.7% |

FPs primarily from: correlated predicates, custom sanitizers, strong updates.

### CWE-Bench-Java (120 Projects with LLM Discovery)
| CWE | TPR | Count |
|-----|-----|-------|
| CWE-022 (Path Traversal) | 85.5% | 47/55 |
| CWE-078 (Command Injection) | 76.9% | 10/13 |
| CWE-079 (XSS) | 87.1% | 27/31 |
| CWE-094 (Code Injection) | 66.7% | 14/21 |
| **Overall (Claude Opus Discovery)** | **81.7%** | **98/120** |

**Comparison:**
- Circle-IR + Claude Opus: 81.7% (98/120)
- IRIS + GPT-4: 45.8% (55/120)
- CodeQL: 22.5% (27/120)

---

## Future Directions

1. **Broader framework coverage:** Python Jinja2/Django template sinks, Next.js server actions, TypeORM query builder patterns — adding these config entries would eliminate the remaining SecuriBench false negatives.
2. **Type resolution improvements:** Java generic-type receiver inference (`List<T>` element access, `Optional<T>.get()`) to reduce false negatives in heavily generic codebases; tracked in `src/languages/java.ts`.
3. **Cognitive complexity metric:** McCabe cyclomatic complexity is already present; adding Sonar's cognitive complexity scoring would improve the `bug_hotspot_score` composite.
4. **IDE integration:** VS Code / IntelliJ Language Server Protocol (LSP) extension exposing circle-ir findings inline as you type.
5. **Ruby language plugin:** Tree-sitter grammar exists; adding a Ruby plugin would cover the remaining popular web-framework ecosystem (Rails). Go support shipped in v3.22.0 with net/http, Gin, Echo, Fiber, and Chi framework detection.

See [TODO.md](../TODO.md) for the phase-based roadmap.

---

## References

- [Pass & Metric Registry](./PASSES.md)
- [Circle-IR Specification](./SPEC.md)
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/)
- [CWE Database](https://cwe.mitre.org/)
