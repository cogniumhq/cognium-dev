# Spec — MVP

**What cognium-dev is and what it delivers.**

---

## Product Definition

cognium-dev is the **pure-SAST product** for AppSec buyers. It implements **Pillar I (Vulnerability Finding)** of the Cognium platform — deterministic security analysis with zero LLM dependencies.

## Scope

### In Scope

- Static taint analysis for security vulnerabilities (SQLi, XSS, command injection, path traversal, SSRF, etc.)
- Code quality findings (null deref, resource leaks, dead code, N+1 queries, etc.)
- Software quality metrics (cyclomatic complexity, coupling, cohesion, maintainability)
- Multi-language support: Java, JavaScript/TypeScript, Python, Go, Rust, Bash, HTML
- CLI distribution (npm package, standalone binaries)
- SARIF output for CI/CD integration
- GitHub Action for PR scanning

### Out of Scope (cognium-ai territory)

- LLM-enhanced analysis
- Pillar II: Spec verification
- Pillar III: Performance optimization
- Semantic clustering
- CISO dashboards (Phase 2+)

## Constraints

- Must run in browser and Node.js (Cloudflare Workers compatibility)
- No runtime dependencies beyond `web-tree-sitter` and `yaml`
- Test coverage ≥75%

## Acceptance Criteria

- [ ] Java SAST benchmarks published (vs Snyk, Checkmarx, Semgrep)
- [x] OWASP Benchmark (Java): 100% TPR, 0% FPR ✓
- [x] Juliet Test Suite (Java): 100% pass rate (156/156) ✓
- [x] SecuriBench Micro (Java): 97.7% TPR ✓
- [ ] OWASP BenchmarkPython: TPR ≥ 95%, FPR ≤ 2% — current on 3.23.5: TPR 81.2%, **FPR 12.6%** (Issue #4 source-side closed; 91 residual FPs tracked in tasks.md)
- [ ] GitHub Action `cognium-dev/scan@v1` available
- [x] npm packages published: `circle-ir`, `cognium-dev` ✓ (current 3.23.5)
- [x] Monorepo structure established ✓
- [x] GitHub repository live: cogniumhq/cognium-dev ✓
