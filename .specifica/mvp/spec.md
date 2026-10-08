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
- [x] OWASP BenchmarkJava 1.2 (all 2,740 cases, scorecard rule): 90.0% TPR / 3.0% FPR on 4.12.0 ✓ — earlier 100%/0% counted only vulnerable cases
- [ ] Juliet Java 1.3 (9 injection CWEs, method level): 99.4% TPR / 21.9% FPR on 4.12.0 — FPR target open (#614)
- [x] SecuriBench Micro (123 cases): 88.0% TPR / 6.7% FPR on 4.12.0 — earlier 97.7% credited co-occurrence
- Method + scripts: bench/README.md (#611). Quote no number without version and rule.
- [ ] OWASP BenchmarkPython: TPR ≥ 95%, FPR ≤ 2% — **criterion is not measurable as stated.** The official runner scores file-level source/sink co-occurrence without consulting `taint.flows`, so a file with a correctly sanitized sink still counts as a positive and no engine change can clear it. Engine-side flow-level FPR is **0.0%** as of 88284d9 (72 → 0, zero TP loss); the official co-occurrence figure will read ~11%. Re-express against flow-based scoring, or close after the circle-ir-ai runner is fixed (tracked in tasks.md, same root cause as #265)
- [ ] GitHub Action `cognium-dev/scan@v1` available
- [x] npm packages published: `circle-ir`, `cognium-dev` ✓ (current 3.23.5)
- [x] Monorepo structure established ✓
- [x] GitHub repository live: cogniumhq/cognium-dev ✓
