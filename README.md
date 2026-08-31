# cognium-dev

**Static Application Security Testing (SAST) platform for detecting security vulnerabilities through taint analysis.**

[![npm version](https://img.shields.io/npm/v/cognium-dev.svg)](https://www.npmjs.com/package/cognium-dev)
[![npm version](https://img.shields.io/npm/v/circle-ir.svg)](https://www.npmjs.com/package/circle-ir)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Overview

cognium-dev is a high-performance SAST tool that detects security vulnerabilities across 7 programming languages using deterministic taint analysis. It provides:

- **Security passes** — SQL injection, XSS, command injection, path traversal, SSRF, and more
- **Quality passes** — Null dereference, resource leaks, dead code, N+1 queries
- **Software quality metrics** — Cyclomatic complexity, coupling, cohesion, maintainability index
- **SARIF 2.1.0 output** — Native GitHub/GitLab CI integration

Full inventory of passes and metrics: [`packages/circle-ir/docs/PASSES.md`](./packages/circle-ir/docs/PASSES.md).

### Benchmark Results

| Benchmark | Language | Score |
|-----------|----------|-------|
| OWASP Benchmark | Java | **100% TPR, 0% FPR** |
| Juliet Test Suite | Java | **100%** (156/156 cases) |
| SecuriBench Micro | Java | **97.7% TPR** |
| OWASP BenchmarkPython | Python | 81.2% TPR, 14.8% FPR (3.23.3 — over-flagging on safe sinks, [#4](https://github.com/cogniumhq/cognium-dev/issues/4)) |

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

| Package | Description | Distribution |
|---------|-------------|--------------|
| [`cognium-dev`](./packages/cli) | CLI for scanning and metrics | [![npm](https://img.shields.io/npm/v/cognium-dev.svg)](https://www.npmjs.com/package/cognium-dev) |
| [`circle-ir`](./packages/circle-ir) | Core SAST library | [![npm](https://img.shields.io/npm/v/circle-ir.svg)](https://www.npmjs.com/package/circle-ir) |
| [`@cognium/mcp-server`](./packages/mcp-server) | MCP server (Cursor, Claude Desktop, Claude Code) | [![npm](https://img.shields.io/npm/v/@cognium/mcp-server.svg)](https://www.npmjs.com/package/@cognium/mcp-server) |
| [Cursor / Claude plugin](./plugins/cognium-dev) | Cognium SAST plugin (skills, rules, commands, agent + MCP) | Cursor Marketplace, Claude Code community, OpenAI skills-only (not listed until submitted) |

---

## Cursor / Claude Code plugin

Scan a project from Cursor or Claude Code through the existing MCP server, then explain findings and propose defensive fixes.

- Plugin package: [`plugins/cognium-dev`](./plugins/cognium-dev) (identifier `cognium-dev`, MIT)
- Cursor marketplace: [`.cursor-plugin/marketplace.json`](./.cursor-plugin/marketplace.json)
- Claude marketplace: [`.claude-plugin/marketplace.json`](./.claude-plugin/marketplace.json) (`/plugin marketplace add cogniumhq/cognium-dev` then `/plugin install cognium-dev@cognium`)
- OpenAI: skills-only until a public HTTPS MCP exists — [`plugins/cognium-dev/openai/README.md`](./plugins/cognium-dev/openai/README.md)
- Submit: [Cursor](https://cursor.com/marketplace/publish) · [Claude community](https://platform.claude.com/plugins/submit) · [OpenAI](https://developers.openai.com/plugins/guides/submit-claude-plugin)

Requires **Node.js ≥ 20.19.0**. No API keys. Listings are not live until Cognium Labs submits them.

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
  uses: cogniumhq/cognium-dev/packages/cli@cognium-dev-v3.23.3
  with:
    path: ./src
    format: sarif
    output: results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

The action's SARIF upload is built in — set `upload-sarif: true` (default) and grant `security-events: write` permission to the workflow token. A standalone `cognium-dev/scan@v1` marketplace listing is on the roadmap; until then, pin to a tag of this repository.

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
- [MCP server](./packages/mcp-server/README.md)
- [Cognium SAST plugin](./plugins/cognium-dev/README.md)
- [OpenAI skills-only notes](./plugins/cognium-dev/openai/README.md)
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
