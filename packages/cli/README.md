# cognium-dev

[![npm version](https://img.shields.io/npm/v/cognium-dev.svg)](https://www.npmjs.com/package/cognium-dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/cogniumhq/cognium-dev/blob/main/LICENSE)
[![OWASP Benchmark](https://img.shields.io/badge/OWASP%20BenchmarkJava-90.0%25%20TPR%2C%203.0%25%20FPR-green)](https://github.com/cogniumhq/cognium-dev#benchmark-results)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-available-blue?logo=github)](https://github.com/marketplace/actions/cognium-dev-scan)
![Trust Score](https://raw.githubusercontent.com/cogniumhq/cognium-dev/badges/trust-badge.svg)
![Quality Score](https://raw.githubusercontent.com/cogniumhq/cognium-dev/badges/quality-badge.svg)

Static Application Security Testing CLI for detecting security vulnerabilities via taint tracking.

## Installation

### npm (recommended)

```bash
npm install -g cognium-dev
```

### Standalone binary

Download from [GitHub Releases](https://github.com/cogniumhq/cognium-dev/releases).

**Note:** When using the standalone binary, place the `wasm/` directory in the same location as the binary.

## Quick Start

```bash
# Scan a single file
cognium-dev scan src/app.java

# Scan a directory
cognium-dev scan ./src

# Scan with specific language
cognium-dev scan api.py --language python

# Output as JSON
cognium-dev scan ./src --format json

# Show only critical vulnerabilities
cognium-dev scan ./src --severity critical

# Security findings only (skip quality/reliability passes)
cognium-dev scan ./src --category security

# Exclude specific CWEs (e.g. weak crypto noise)
cognium-dev scan ./src --exclude-cwe CWE-327,CWE-330

# Exclude test files
cognium-dev scan ./src --exclude-tests

# Software quality metrics
cognium-dev metrics ./src
cognium-dev metrics ./src --category complexity,coupling --format json
```

## Commands

### `cognium-dev scan <path>`

Scan files or directories for security vulnerabilities.

```bash
cognium-dev scan <path> [options]

Options:
  -l, --language <lang>      Force language (java|javascript|typescript|python|go|rust|bash|html|csharp)
  -f, --format <format>      Output format (text|json|sarif) [default: text]
  --threads <n>              Parallel analysis threads [default: 4]
  --severity <level>         Filter by severity:
                               - Single level: minimum severity (e.g., "high" shows high+critical)
                               - Multiple levels: exact match (e.g., "critical,high" shows only those)
                               - Valid levels: low, medium, high, critical
  --category <cats>          Filter by ISO 25010 category (comma-separated):
                               security, reliability, performance, maintainability, architecture
  --exclude-cwe <cwes>       Exclude specific CWEs (comma-separated, e.g. CWE-330,CWE-327)
  --exclude-tests            Exclude test files and directories
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress progress output
  -v, --verbose              Show detailed output
```

**Examples:**

```bash
# Scan entire project
cognium-dev scan ./src

# Show only critical and high severity issues
cognium-dev scan ./src --severity critical,high

# Exclude test files and show only critical issues
cognium-dev scan ./src --exclude-tests --severity critical

# Security findings only (skip quality/reliability passes)
cognium-dev scan ./src --category security

# Reliability + performance findings only
cognium-dev scan ./src --category reliability,performance

# Exclude weak-crypto and weak-random findings
cognium-dev scan ./src --exclude-cwe CWE-327,CWE-330

# Generate SARIF report for CI/CD
cognium-dev scan ./src --format sarif --output results.sarif

# Scan with verbose output
cognium-dev scan ./src -v

# Quiet mode (no progress, only results)
cognium-dev scan ./src -q
```

### `cognium-dev init`

Initialize a configuration file in your project.

```bash
cognium-dev init
```

Creates a `cognium.config.json` with customizable rules.

### `cognium-dev metrics <path>`

Report software quality metrics for files or directories.

```bash
cognium-dev metrics <path> [options]

Options:
  -l, --language <lang>      Analyze only files for the given language
  -f, --format <format>      Output format (text|json) [default: text]
  --category <cats>          Filter metric categories (comma-separated):
                               complexity, size, coupling, inheritance,
                               cohesion, documentation, duplication
  --exclude-tests            Skip test files and directories
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress per-file progress output
```

**Examples:**

```bash
# Show all metrics for a directory
cognium-dev metrics ./src

# Complexity and coupling metrics only
cognium-dev metrics ./src --category complexity,coupling

# JSON output for tooling integration
cognium-dev metrics ./src --format json --output metrics.json

# Java files only, skip tests
cognium-dev metrics ./src --language java --exclude-tests
```

**Sample output:**

```
src/UserController.java
  Complexity
    cyclomatic_complexity : 8.2
    WMC                   : 41
    halstead_volume       : 3820.4

  Size
    LOC                   : 182
    NLOC                  : 156
    function_count        : 9

  Coupling
    CBO                   : 6
    RFC                   : 22

  Composite Scores
    maintainability_index : 68.4 / 100
    code_quality_index    : 71.2 / 100
    bug_hotspot_score     : 32.1 / 100
    refactoring_roi       : 45.0 / 100
```

Available metrics: `cyclomatic_complexity`, `WMC`, `halstead_volume`, `halstead_difficulty`, `halstead_effort`, `halstead_bugs`, `LOC`, `NLOC`, `comment_density`, `function_count`, `CBO`, `RFC`, `DIT`, `NOC`, `LCOM`, `doc_coverage`, `maintainability_index`, `code_quality_index`, `bug_hotspot_score`, `refactoring_roi`.

### `cognium-dev version`

Display version information.

```bash
cognium-dev version
```

## Output Format

Cognium provides helpful, actionable output for each vulnerability found:

```
/path/to/VulnerableApp.java
  [!!!] sql_injection (Critical) [CWE-89]
      Line 45: sql_injection vulnerability: tainted data flows from line 42 to line 45
      User input is used in SQL query without sanitization
      → Fix: Use PreparedStatement with parameterized queries instead of string concatenation
  [!!] xss (High) [CWE-79]
      Line 78: xss vulnerability: tainted data flows from line 76 to line 78
      User input is rendered in HTML without proper encoding
      → Fix: Use HTML encoding/escaping functions before rendering user input in web pages

Found 2 vulnerability(ies) in 1 file(s)
```

**Clean code = silent output:** When no vulnerabilities are found, cognium stays quiet (Unix philosophy: no news is good news).

Use `-v` flag to see all scanned files including clean ones.

### Output streams (stdout vs stderr)

`cognium-dev` follows the standard CLI convention: machine-readable payload on **stdout**, diagnostics on **stderr**.

| Output | Stream | Notes |
|--------|--------|-------|
| `--format json` document | **stdout** | Pure JSON starting at character 1. No banner, no preamble. Safe to pipe directly to `jq`, `json_pp`, etc. |
| `--format sarif` document | **stdout** | Pure SARIF 2.1.0 JSON. Same contract as `--format json`. |
| `--format text` report | **stdout** | The human-readable report (default). |
| Status lines (`Loaded config: …`, `Suppressed N finding(s) …`, `Results written to …`) | **stderr** | |
| Spinner animation and final status (`✔ Scanned N file(s)`) | **stderr** | |
| Error messages and usage hints | **stderr** | |
| Library log output (cross-file phase markers, budget warnings, etc.) | **stderr** | Silent by default; enable with `--log-level <level>` or `COGNIUM_LOG_LEVEL`. |
| Findings instrumentation (`CIRCLE_IR_INSTRUMENT_FINDINGS=1`) | **stderr** | JSONL `[finding] …` / `[findings-summary] …` lines. |

The stdout contract for `--format json` and `--format sarif` is **stable**: pure parseable payload, version included inside the JSON object (not as a stdout preamble). Consumers can safely pipe stdout to a parser without skip-the-first-line idioms.

```bash
# Safe — stdout is pure JSON
cognium-dev scan ./src --format json | jq '.summary'

# Status lines and warnings on stderr, JSON on stdout
cognium-dev scan ./src --format json > results.json 2> scan.log
```

If you previously relied on a `tail -n +2` or `split("\n",1)[1]` idiom against pre-3.89.2 builds, drop it — there is no longer a stdout banner to skip.

## Detected Vulnerabilities

| Type | CWE | Severity | Description |
|------|-----|----------|-------------|
| SQL Injection | CWE-89 | Critical | User input in SQL queries |
| Command Injection | CWE-78 | Critical | User input in system commands |
| Deserialization | CWE-502 | Critical | Untrusted deserialization |
| XXE | CWE-611 | Critical | XML external entity injection |
| Cross-Site Scripting (XSS) | CWE-79 | High | User input in HTML output |
| Path Traversal | CWE-22 | High | User input in file paths |
| SSRF | CWE-918 | High | Server-side request forgery |
| LDAP Injection | CWE-90 | High | User input in LDAP queries |
| XPath Injection | CWE-643 | High | User input in XPath queries |
| NoSQL Injection | CWE-943 | High | User input in NoSQL queries |
| Code Injection | CWE-94 | Critical | Dynamic code execution |
| Open Redirect | CWE-601 | Medium | User controls redirect destination |
| Log Injection | CWE-117 | Medium | User input in logs |
| Trust Boundary | CWE-501 | Medium | Data crosses trust boundary |
| External Taint Escape | CWE-20 | Medium | External input reaches sensitive sink |
| Weak Random | CWE-330 | Low | Weak random number generator |
| Weak Hash | CWE-327 | Low | Weak hashing algorithm |
| Weak Crypto | CWE-327 | Low | Weak cryptographic algorithm |
| Insecure Cookie | CWE-614 | Low | Cookie without security flags |

## Code Quality Analysis

In addition to security vulnerabilities, `cognium-dev scan` runs 17 code quality passes and reports findings in five ISO 25010 categories:

| Category | Rule IDs | Example Issues |
|----------|----------|----------------|
| **Reliability** | `null-deref`, `resource-leak`, `unchecked-return`, `dead-code`, `variable-shadowing`, `leaked-global`, `unused-variable`, `infinite-loop`, `double-close`, `use-after-close`, `unhandled-exception`, `broad-catch`, `swallowed-exception`, `missing-guard-dom`, `cleanup-verify` | Null pointer dereferences, unclosed streams, swallowed exceptions |
| **Performance** | `n-plus-one`, `redundant-loop-computation`, `unbounded-collection`, `serial-await`, `react-inline-jsx` | N+1 DB queries, unnecessary work inside loops |
| **Maintainability** | `missing-public-doc`, `todo-in-prod`, `stale-doc-ref` | Missing Javadoc/JSDoc, TODO comments in production code |
| **Architecture** | `circular-dependency`, `orphan-module`, `dependency-fan-out`, `deep-inheritance`, `missing-override`, `unused-interface-method` | Circular imports, overly deep class hierarchies |

Quality findings appear alongside security findings in text output with their category tag:

```
src/UserService.java
  [!!] sql_injection (Critical) [CWE-89]
      ...
  [!] null-deref [reliability] (High) [CWE-476]
      Line 34: Return value of findById() is dereferenced without a null check
      → Fix: Check for null before dereferencing or use Optional<T>
  [i] missing-public-doc [maintainability] (Low)
      Line 12: Public method processRequest() has no Javadoc

Found 1 security finding(s) in 1 file(s)
Also found 2 code quality finding(s) in 1 file(s)
```

**Exit codes:** The CLI exits `1` only when **security** findings are present (so CI pipelines gate on vulnerabilities without being blocked by documentation or style findings). Quality-only scans exit `0`.

Filter to security findings only: `cognium-dev scan ./src --category security`

## Supported Languages

| Language | Extensions | Frameworks |
|----------|------------|------------|
| Java | `.java` | Spring, JAX-RS, Servlet |
| JavaScript | `.js`, `.mjs` | Express, Fastify, Node.js |
| TypeScript | `.ts`, `.tsx` | Express, Fastify, Node.js |
| Python | `.py` | Flask, Django, FastAPI |
| Go | `.go` | net/http, Gin, Echo, Fiber, Chi |
| Rust | `.rs` | Actix-web, Rocket, Axum |
| Bash | `.sh`, `.bash` | Shell scripts |
| HTML | `.html`, `.htm` | Web extraction preprocessor |
| C#/.NET _(Preview)_ | `.cs` | ASP.NET Core, ADO.NET (EF Core not yet verified) |

> **C#/.NET is Preview** (since 4.0.0). Straight-line taint
> analysis across 10 CWE families (SQLi, command injection, path traversal,
> SSRF, code injection, XSS, deserialization, LDAP, XPath, XXE). Not yet
> benchmark-verified — expect gaps in branch/alias precision and detector breadth.

## Configuration

Create `cognium.config.json` in your project root:

```json
{
  "include": ["src/**/*.java", "src/**/*.ts"],
  "exclude": ["**/test/**", "**/node_modules/**"],
  "severity": "medium",
  "rules": {
    "sql-injection": "error",
    "xss": "error",
    "command-injection": "error",
    "path-traversal": "warn"
  }
}
```

## Severity Filtering

Cognium supports flexible severity filtering to focus on what matters:

### Minimum Severity (Single Value)

Shows vulnerabilities at or above the specified level:

```bash
# Show only critical
cognium-dev scan ./src --severity critical

# Show high and critical
cognium-dev scan ./src --severity high

# Show medium, high, and critical
cognium-dev scan ./src --severity medium
```

### Exact Severity Match (Comma-Separated)

Shows only the specified severity levels:

```bash
# Show only critical and high
cognium-dev scan ./src --severity critical,high

# Show only medium
cognium-dev scan ./src --severity medium

# Show low and medium
cognium-dev scan ./src --severity low,medium
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install cognium
        run: npm install -g cognium
      - name: Run security scan
        run: cognium-dev scan ./src --format sarif --output results.sarif --severity high
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: node:20
  script:
    - npm install -g cognium
    - cognium-dev scan ./src --format json --output gl-sast-report.json --severity high
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Pre-commit Hook

Prevent commits with critical vulnerabilities:

```bash
#!/bin/sh
# .git/hooks/pre-commit

if ! cognium-dev scan . --severity critical --quiet; then
  echo "❌ Commit blocked: Critical security vulnerabilities found"
  exit 1
fi
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No security findings (quality-only findings do not trigger exit 1) |
| 1 | One or more security vulnerabilities found |
| 2 | Error during analysis |

Use exit codes in CI/CD to fail builds when security vulnerabilities are detected:

```bash
# Fail build on any security finding
cognium-dev scan ./src || exit 1

# Fail build only on critical/high security findings
cognium-dev scan ./src --severity high || exit 1

# Fail build only on critical security findings
cognium-dev scan ./src --severity critical || exit 1

# Never fail on quality-only issues (always exit 0 for docs/style findings)
cognium-dev scan ./src --category reliability,performance,maintainability,architecture; echo "Quality scan done (exit $?)"
```

## Performance

Cognium is built for speed:

- **Parallel analysis**: Process multiple files concurrently (configurable with `--threads`)
- **Zero dependencies**: Only one runtime dependency (`circle-ir`)
- **Native performance**: Powered by tree-sitter WASM parsers
- **Lean binary**: ~58MB standalone binary includes all dependencies

## Architecture

- **CLI**: Lightweight wrapper with zero-dependency utilities
- **Core Engine**: [circle-ir](https://github.com/cogniumhq/cognium-dev/tree/main/packages/circle-ir) - High-performance SAST library
- **Dependencies**: Only 1 runtime dependency (circle-ir)

## Data handling

cognium-dev is fully deterministic and runs entirely on your machine: source code is not sent to Cognium or any third-party service. Optional AI-assisted analysis is a separate product, [cognium-ai](https://cognium.net), which can send code snippets to a configured model endpoint; use cognium-dev (or cognium-ai with AI-assisted mode off and no remote engine configured) for air-gapped scanning.

## Benchmark Results

Measured on cognium-dev **4.12.0**, the CLI as published. Fully deterministic.

| Benchmark | TPR | FPR | Scope and rule |
|-----------|-----|-----|----------------|
| OWASP BenchmarkJava 1.2 | 90.0% | 3.0% | All 2,740 cases; scorecard rule (file-level CWE match) |
| Juliet Test Suite 1.3 | 99.4% | 21.9% | `_01` cases of 9 injection CWEs; `bad()` vs `good*()` methods; `require-entry-path` disabled |
| SecuriBench Micro | 88.0% | 6.7% | 123 annotated cases; found sink lines vs `vuln_count` |
| CWE-Bench-Java | 32.5% (39/120) | n/a | 120 real CVEs; a finding of the CVE's CWE inside the fix method |

### Reproducing Benchmarks

Each number above comes from a `cognium-dev scan` JSON report and a scoring script in this repository. For example, OWASP:

```bash
npm install -g cognium-dev
git clone https://github.com/OWASP-Benchmark/BenchmarkJava
cd BenchmarkJava
cognium-dev scan . --format json --category security -l java > owasp.json
node <cognium-dev repo>/bench/sast/score-owasp.mjs expectedresults-1.2.csv owasp.json
```

The scoring rule and command for every benchmark are in [`bench/README.md`](https://github.com/cogniumhq/cognium-dev/blob/main/bench/README.md#sast-accuracy-benchsast).

## Links

- [GitHub](https://github.com/cogniumhq/cognium-dev)
- [circle-ir (Core Engine)](https://github.com/cogniumhq/cognium-dev/tree/main/packages/circle-ir)
- [Website](https://cognium.dev)

## License

MIT
