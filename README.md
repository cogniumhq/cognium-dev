# cognium-dev

**Static Application Security Testing (SAST) platform for detecting security vulnerabilities through taint analysis.**

[![npm version](https://img.shields.io/npm/v/cognium-dev.svg)](https://www.npmjs.com/package/cognium-dev)
[![npm version](https://img.shields.io/npm/v/circle-ir.svg)](https://www.npmjs.com/package/circle-ir)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Overview

cognium-dev is a high-performance SAST tool that detects security vulnerabilities across 7 programming languages using deterministic taint analysis. It provides:

- **19 security passes** — SQL injection, XSS, command injection, path traversal, SSRF, and more
- **17 quality passes** — Null dereference, resource leaks, dead code, N+1 queries
- **24 software metrics** — Cyclomatic complexity, coupling, cohesion, maintainability index
- **SARIF 2.1.0 output** — Native GitHub/GitLab CI integration

### Benchmark Results

| Benchmark | Score |
|-----------|-------|
| OWASP Benchmark | **100% TPR, 0% FPR** |
| Juliet Test Suite | **100%** (156/156 cases) |
| SecuriBench Micro | **97.7% TPR** |

---

## Installation

### CLI (recommended)

```bash
npm install -g cognium-dev
```

### Library

```bash
npm install circle-ir
```

---

## Quick Start

### Scan a project

```bash
cognium-dev scan ./src
```

### Scan with specific options

```bash
# Output as SARIF for CI integration
cognium-dev scan ./src --format sarif --output results.sarif

# Filter by severity
cognium-dev scan ./src --severity critical,high

# Filter by category
cognium-dev scan ./src --category security
```

### Generate metrics

```bash
cognium-dev metrics ./src
```

### List available passes

```bash
cognium-dev list-passes
cognium-dev list-passes security
```

---

## Supported Languages

| Language | Status | Frameworks |
|----------|--------|------------|
| Java | ✅ Production | Spring, JAX-RS, Servlet API |
| JavaScript | ✅ Production | Express, Fastify, Koa |
| TypeScript | ✅ Production | Express, Fastify, Koa |
| Python | ✅ Production | Flask, Django, FastAPI |
| Go | ✅ Production | net/http, Gin, Echo, Fiber |
| Rust | ✅ Production | Actix-web, Rocket, Axum |
| Bash | ✅ Production | Shell scripts |
| HTML | ✅ Production | Security attributes |

---

## Packages

This monorepo contains two packages:

| Package | Description | npm |
|---------|-------------|-----|
| [`cognium-dev`](./packages/cli) | CLI for scanning and metrics | [![npm](https://img.shields.io/npm/v/cognium-dev.svg)](https://www.npmjs.com/package/cognium-dev) |
| [`circle-ir`](./packages/circle-ir) | Core SAST library | [![npm](https://img.shields.io/npm/v/circle-ir.svg)](https://www.npmjs.com/package/circle-ir) |

---

## Configuration

Create a `cognium.config.json` in your project root:

```json
{
  "severity": ["critical", "high"],
  "categories": ["security", "reliability"],
  "passes": {
    "dependency-fan-out": { "threshold": 30 }
  },
  "disabledPasses": ["todo-in-prod"],
  "exclude": ["**/test/**", "**/vendor/**"]
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run cognium-dev scan
  uses: cognium-dev/scan@v1
  with:
    path: ./src
    format: sarif
    output: results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: cognium-dev
        name: cognium-dev scan
        entry: cognium-dev scan
        language: system
        types: [file]
        pass_filenames: false
```

---

## Library Usage

```typescript
import { initAnalyzer, analyze, analyzeProject } from 'circle-ir';

// Initialize (required once)
await initAnalyzer();

// Analyze a single file
const result = await analyze(code, 'app.java', 'java');
console.log(result.findings);

// Analyze a project (cross-file taint tracking)
const project = await analyzeProject(files);
console.log(project.taint_paths);
```

---

## Documentation

- [CLI Documentation](./packages/cli/README.md)
- [Library Documentation](./packages/circle-ir/README.md)
- [Analysis Passes](./packages/circle-ir/docs/PASSES.md)
- [Circle-IR Specification](./packages/circle-ir/docs/SPEC.md)
- [Architecture](./packages/circle-ir/docs/ARCHITECTURE.md)

---

## Development

```bash
# Install dependencies
npm install

# Build all packages
npm run build

# Run tests
npm test

# Type check
npm run typecheck
```

---

## License

MIT © [Cognium Labs](https://cognium.dev)
