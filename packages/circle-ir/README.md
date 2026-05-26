# circle-ir

![Trust Score](https://raw.githubusercontent.com/cogniumhq/circle-ir/badges/trust-badge.svg)
![Quality Score](https://raw.githubusercontent.com/cogniumhq/circle-ir/badges/quality-badge.svg)

A high-performance Static Application Security Testing (SAST) library for detecting security vulnerabilities through taint analysis, and code quality findings through an extensible 36-pass analysis pipeline. Works in Node.js and browsers.

## Features

- **Taint Analysis**: Track data flow from sources (user input) to sinks (dangerous operations)
- **Multi-language Support**: Java, JavaScript/TypeScript, Python, Go, Rust, Bash/Shell, HTML
- **High Accuracy**: 100% on OWASP Benchmark, 100% on Juliet Test Suite, 97.7% TPR on SecuriBench Micro
- **36-Pass Pipeline**: 19 security taint passes + 17 reliability/performance/maintainability/architecture quality passes
- **Metrics Engine**: 24 software quality metrics (cyclomatic complexity, Halstead, CBO, RFC, LCOM, DIT, and 4 composite scores)
- **Cross-File Analysis**: `analyzeProject()` surfaces taint flows that span multiple files
- **Universal**: Works in Node.js and browsers with environment-agnostic core
- **Zero External Dependencies**: Core analysis runs without network calls or external services
- **Browser Compatible**: Tree-sitter WASM for universal parsing
- **Configuration-Driven**: YAML/JSON patterns for sources, sinks, and sanitizers

## Installation

```bash
npm install circle-ir
```

## Quick Start

### Node.js

```typescript
import { initAnalyzer, analyze } from 'circle-ir';

// Initialize the analyzer
await initAnalyzer();

// Analyze Java code
const result = await analyze(code, 'MyClass.java', 'java');

// Security taint flows
for (const flow of result.taint.flows || []) {
  console.log(`Found ${flow.sink_type} vulnerability`);
  console.log(`  Source: line ${flow.source_line}`);
  console.log(`  Sink: line ${flow.sink_line}`);
}

// Quality findings from all 36 analysis passes
for (const finding of result.findings || []) {
  console.log(`[${finding.severity}] ${finding.rule_id} at line ${finding.line}`);
  console.log(`  ${finding.message}`);
  if (finding.fix) console.log(`  Fix: ${finding.fix}`);
}

// Software quality metrics
const m = result.metrics;
if (m) {
  console.log(`Cyclomatic complexity: ${m.cyclomatic_complexity}`);
  console.log(`Maintainability index: ${m.maintainability_index}`);
  console.log(`CBO (coupling):        ${m.CBO}`);
}
```

### Browser

```html
<script type="module">
import { initAnalyzer, analyze } from './dist/browser/circle-ir.js';

await initAnalyzer({
  wasmPath: './wasm/web-tree-sitter.wasm',
  languagePaths: {
    java: './wasm/tree-sitter-java.wasm'
  }
});

const result = await analyze(code, 'Test.java', 'java');
console.log(result);
</script>
```

## API Reference

### `initAnalyzer(options?)`

Initialize the analyzer. Must be called before `analyze()`.

```typescript
interface AnalyzerOptions {
  wasmPath?: string;           // Path to web-tree-sitter.wasm
  languagePaths?: {            // Paths to language WASM files
    java?: string;
    javascript?: string;
    python?: string;
    rust?: string;
  };
  taintConfig?: TaintConfig;   // Custom taint configuration
  passOptions?: PassOptions;   // Per-pass configuration (thresholds, patterns)
  disabledPasses?: string[];   // Passes to skip (e.g., ['naming-convention'])
}

interface PassOptions {
  dependencyFanOut?: {
    threshold?: number;        // Max imports before flagging (default: 20)
  };
  unboundedCollection?: {
    skipPatterns?: string[];   // Variable names to ignore
  };
  namingConvention?: {
    classPattern?: string;     // Regex for class names
    methodPattern?: string;    // Regex for method names
  };
}
```

**Example: Configuring passes at runtime**

```typescript
await initAnalyzer({
  passOptions: {
    dependencyFanOut: { threshold: 50 },
    unboundedCollection: { skipPatterns: ['results', 'items', 'cache'] },
  },
  disabledPasses: ['naming-convention', 'missing-public-doc'],
});
```

### `analyze(code, filePath, language, options?)`

Analyze a single file and return Circle-IR output.

```typescript
const result = await analyze(code, 'File.java', 'java');

// Result contains:
result.meta       // File metadata
result.types      // Classes, methods, fields
result.calls      // Method invocations
result.cfg        // Control flow graph
result.dfg        // Data flow graph
result.taint      // Taint sources, sinks, flows
result.imports    // Import statements
result.exports    // Exported symbols
result.findings   // SastFinding[] from all 36 analysis passes
result.metrics    // FileMetrics — 24 software quality metrics (always populated)
```

### `analyzeProject(files, options?)`

Analyze multiple files together to detect cross-file taint flows.

```typescript
import { analyzeProject } from 'circle-ir';

const result = await analyzeProject([
  { code: controllerCode, filePath: 'UserController.java', language: 'java' },
  { code: serviceCode,    filePath: 'UserService.java',    language: 'java' },
  { code: daoCode,        filePath: 'UserDao.java',        language: 'java' },
]);

// Per-file analysis (same as analyze() per file)
for (const { file, analysis } of result.files) {
  console.log(`${file}: ${analysis.taint.flows?.length ?? 0} intra-file flows`);
}

// Cross-file taint paths (the key deliverable)
for (const path of result.taint_paths) {
  console.log(`Cross-file ${path.sink.type}: ${path.source.file} → ${path.sink.file}`);
  console.log(`  Confidence: ${path.confidence.toFixed(2)}, CWE: ${path.sink.cwe}`);
}

// Resolved inter-file method calls
console.log(`${result.cross_file_calls.length} cross-file calls resolved`);

// Project metadata
console.log(`${result.meta.total_files} files, ${result.meta.total_loc} LOC`);
```

### `analyzeForAPI(code, filePath, language, options?)`

Simplified API response format suitable for REST APIs.

```typescript
const response = await analyzeForAPI(code, 'File.java', 'java');

// Response format:
{
  success: true,
  analysis: {
    sources: [...],
    sinks: [...],
    vulnerabilities: [...]
  },
  meta: {
    parseTimeMs: 15,
    analysisTimeMs: 42,
    totalTimeMs: 57
  }
}
```

## Supported Languages

| Language | Parser | Frameworks |
|----------|--------|------------|
| **Java** | tree-sitter-java | Spring, JAX-RS, Servlet API |
| **JavaScript/TypeScript** | tree-sitter-javascript | Express, Fastify, Koa, Node.js |
| **Python** | tree-sitter-python | Flask, Django, FastAPI |
| **Go** | tree-sitter-go | net/http, Gin, Echo, Fiber, Chi |
| **Rust** | tree-sitter-rust | Actix-web, Rocket, Axum |
| **Bash/Shell** | tree-sitter-bash | Shell scripts (.sh, .bash, .zsh, .ksh) |
| **HTML** | tree-sitter-html | Web extraction preprocessor (.html, .htm, .xhtml) |

HTML is handled as a preprocessor: `<script>` blocks are extracted and analyzed as JavaScript, inline event handlers are analyzed as JS snippets, and 8 attribute-level security checks (missing noopener, javascript: URIs, missing sandbox/SRI, mixed content, etc.) run directly on the HTML AST.

### Multi-Language Examples

```typescript
// Analyze JavaScript
const jsResult = await analyze(jsCode, 'server.js', 'javascript');

// Analyze Python
const pyResult = await analyze(pyCode, 'app.py', 'python');

// Analyze Go
const goResult = await analyze(goCode, 'main.go', 'go');

// Analyze Rust
const rsResult = await analyze(rsCode, 'main.rs', 'rust');

// Analyze HTML (extracts scripts, checks attributes)
const htmlResult = await analyze(htmlCode, 'index.html', 'html');
```

## Detected Security Vulnerabilities

| Type | CWE | Severity | Description |
|------|-----|----------|-------------|
| SQL Injection | CWE-89 | Critical | User input in SQL queries |
| Command Injection | CWE-78 | Critical | User input in system commands |
| Deserialization | CWE-502 | Critical | Untrusted deserialization |
| XXE | CWE-611 | Critical | XML external entity injection |
| Code Injection | CWE-94 | Critical | Dynamic code execution |
| XSS | CWE-79 | High | User input in HTML output |
| Path Traversal | CWE-22 | High | User input in file paths |
| SSRF | CWE-918 | High | Server-side request forgery |
| LDAP Injection | CWE-90 | High | User input in LDAP queries |
| XPath Injection | CWE-643 | High | User input in XPath queries |
| NoSQL Injection | CWE-943 | High | User input in NoSQL queries |
| Open Redirect | CWE-601 | Medium | User controls redirect destination |
| Log Injection | CWE-117 | Medium | User input in logs |
| Trust Boundary | CWE-501 | Medium | Data crosses trust boundary |
| External Taint | CWE-668 | Medium | External input reaches sensitive sink |
| Weak Random | CWE-330 | Low | Weak random number generator |
| Weak Hash | CWE-327 | Low | Weak hashing algorithm |
| Weak Crypto | CWE-327 | Low | Weak cryptographic algorithm |
| Insecure Cookie | CWE-614 | Low | Cookie without Secure/HttpOnly flags |

## Configuration

### Taint Sources/Sinks (YAML)

Custom taint sources, sinks, and sanitizers can be configured via YAML:

```yaml
# configs/sources/custom.yaml
sources:
  - method: getUserInput
    class: CustomInputHandler
    type: http_param
    severity: high
    tainted_args: [return]
```

### Project Configuration (JSON)

Create a `cognium.config.json` in your project root to configure passes and suppressions:

```json
{
  "version": "1.0",
  "include": ["src/**/*.ts"],
  "exclude": ["**/node_modules/**", "**/dist/**"],

  "passes": {
    "naming-convention": false,
    "missing-public-doc": false,
    "dependency-fan-out": { "threshold": 50 },
    "unbounded-collection": {
      "skipPatterns": ["results", "items", "cache"]
    }
  },

  "suppressions": [
    {
      "pass": "serial-await",
      "file": "src/init.ts",
      "reason": "Sequential init required - cannot parallelize"
    },
    {
      "pass": "god-class",
      "file": "src/analyzer.ts",
      "reason": "Main orchestrator - high coupling by design"
    }
  ],

  "severity": "low",
  "categories": ["security", "reliability", "performance"]
}
```

**Configuration options:**

| Field | Description |
|-------|-------------|
| `passes` | Per-pass config: `false` to disable, or `{options}` for thresholds |
| `suppressions` | Array of `{pass, file?, line?, reason}` to suppress findings |
| `severity` | Minimum severity to report: `critical`, `high`, `medium`, `low` |
| `categories` | Categories to include: `security`, `reliability`, `performance`, `maintainability`, `architecture` |

## SAST Findings & Quality Passes

The 36-pass pipeline emits `SastFinding[]` via `result.findings`. Each finding is SARIF 2.1.0-aligned:

```typescript
interface SastFinding {
  id: string;           // e.g. "dead-code-42"
  rule_id: string;      // e.g. "dead-code"
  category: PassCategory; // 'security' | 'reliability' | 'performance' | 'maintainability' | 'architecture'
  severity: string;     // 'critical' | 'high' | 'medium' | 'low'
  level: SarifLevel;    // 'error' | 'warning' | 'note' | 'none'
  message: string;
  file: string;
  line: number;
  cwe?: string;         // e.g. "CWE-561"
  fix?: string;         // Instance-specific remediation hint
  evidence?: Record<string, unknown>;
}
```

**Pass categories** (see [docs/PASSES.md](docs/PASSES.md) for the full registry with all 36 rule IDs and CWEs):

| Category | Passes | Example rule_ids |
|----------|--------|-----------------|
| `security` (19) | Taint matching, propagation, inter-procedural | _(produces `taint.flows`)_ |
| `reliability` (16) | Resource management, control flow, exception handling | `null-deref`, `resource-leak`, `infinite-loop`, `double-close`, `use-after-close`, `missing-guard-dom`, `cleanup-verify`, `unhandled-exception`, `broad-catch`, `swallowed-exception` |
| `performance` (5) | Loop efficiency, async patterns | `n-plus-one`, `redundant-loop-computation`, `unbounded-collection`, `serial-await`, `react-inline-jsx` |
| `maintainability` (3) | Documentation, markers | `missing-public-doc`, `todo-in-prod`, `stale-doc-ref` |
| `architecture` (6) | Coupling, inheritance, interface contracts | `circular-dependency`, `orphan-module`, `dependency-fan-out`, `deep-inheritance`, `missing-override`, `unused-interface-method` |

## Metrics Engine

`result.metrics` is always populated with 24 software quality metrics:

```typescript
interface FileMetrics {
  // Complexity
  cyclomatic_complexity: number;  // v(G) per method average
  WMC: number;                    // Weighted methods per class
  halstead_volume: number;        // Halstead volume
  halstead_difficulty: number;
  halstead_effort: number;
  halstead_bugs: number;

  // Size
  LOC: number;                    // Lines of code
  NLOC: number;                   // Non-blank lines
  comment_density: number;        // Comment lines / total lines
  function_count: number;

  // Coupling
  CBO: number;                    // Coupling between objects
  RFC: number;                    // Response for a class

  // Inheritance
  DIT: number;                    // Depth of inheritance tree
  NOC: number;                    // Number of children

  // Cohesion
  LCOM: number;                   // Lack of cohesion in methods

  // Documentation
  doc_coverage: number;           // Fraction of public APIs documented

  // Composite scores (0–100)
  maintainability_index: number;
  code_quality_index: number;
  bug_hotspot_score: number;
  refactoring_roi: number;
}
```

## Key Analysis Features

- **Constant Propagation**: Eliminates false positives by tracking variable values and detecting dead code
- **DFG-Based Verification**: Uses data flow graphs to verify end-to-end taint flows
- **Inter-Procedural Analysis**: Tracks taint across method boundaries
- **Sanitizer Recognition**: Detects PreparedStatement, ESAPI, escapeHtml, and other sanitizers
- **Collection Tracking**: Precise taint tracking through List/Map operations with index shifting
- **Dominator Tree Analysis**: Powers `missing-guard-dom` (CWE-285) and `cleanup-verify` (CWE-772) via post-dominator computation
- **TypeHierarchy Resolution**: `PreparedStatement.executeQuery()` matches `Statement`-level sink configs — no duplicate config entries needed
- **Exception Flow Graph**: Tracks try/catch structure for `unhandled-exception`, `broad-catch`, `swallowed-exception`

## Benchmark Results

All scores below are for **circle-ir static analysis only** (no LLM).

| Benchmark | Score | Details |
|-----------|-------|---------|
| **OWASP Benchmark** | +100% | TPR 100%, FPR 0% (1415 test cases) |
| **Juliet Test Suite** | +100% | 156/156 test cases, 9 CWEs |
| **SecuriBench Micro** | 97.7% TPR | 105/108 vulns detected, 6.7% FPR |
| **CWE-Bench-Java** | 42.5% | 51/120 real-world CVEs (vs CodeQL 22.5%, IRIS+GPT-4 45.8%) |
| **Bash Synthetic** | 68.2% TPR | 15 TP, 9 TN, 0 FP on 31 synthetic test cases |

## Documentation

- [Pass & Metric Registry](docs/PASSES.md) - Canonical list of every pass and metric with rule_id, CWE, and status
- [Circle-IR Specification](docs/SPEC.md) - IR format specification
- [Architecture Guide](docs/ARCHITECTURE.md) - Detailed system architecture
- [Changelog](CHANGELOG.md) - Version history
- [TODO](TODO.md) - Phase-based roadmap

## License

MIT
