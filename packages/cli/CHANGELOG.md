# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.27.0] - 2026-06-04

### Changes

- (no commits since last release)

## [3.26.0] - 2026-06-04

### Changes

- feat(circle-ir): scan-secrets pass (#90, CWE-798) — 3.26.0 staging

## [3.26.0] - 2026-06-03

### Changed

- **circle-ir upgraded 3.25.0 → 3.26.0** — adds the `scan-secrets` security pass (Pass #90, CWE-798) detecting hardcoded credentials across all 7 supported languages. Two layers: ~16 high-confidence provider patterns (AWS `AKIA…`, GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, Stripe `sk_live_`/`pk_live_`, OpenAI `sk-…`, Anthropic `sk-ant-…`, Slack `xox[baprs]-…`, Google `AIza…`, JWT, PEM private keys, npm `npm_…`) emitting `hardcoded-credential` (critical/error), and Shannon-entropy scan on base64/hex string literals with UUID/hash/placeholder/base64-JSON denylist emitting `hardcoded-credential-entropy` (high/warning). Test-file paths are skipped. Findings dedupe against the legacy Bash detection so existing users see no double-reporting.

### Notes

- Disable per project via `cognium.config.json`: `{ "disabledPasses": ["scan-secrets"] }`. Filter the entropy branch only by excluding the `hardcoded-credential-entropy` rule_id in your downstream tooling.

## [3.25.0] - 2026-06-02

### Changes

- (no commits since last release)

## [3.24.0] - 2026-06-02

### Changes

- docs: pre-write 3.24.0 CHANGELOG entries

## [3.23.5] - 2026-05-30

### Changes

- docs: pre-write 3.23.5 CHANGELOG entries

## [3.24.0] - 2026-05-30

### Changed

- **circle-ir upgraded 3.23.5 → 3.24.0** — TypeScript files now parse with the real tree-sitter-typescript grammar instead of falling back to the JavaScript grammar (closes #5). TS-only constructs in parameter positions — inline object types, optional params, type annotations — no longer cause functions to silently disappear from the IR. Parameter type information is now preserved in the IR for TS code (`ParameterInfo.type`) where it was previously always `null`.

### Notes

- **Behavior change for users scanning TypeScript code:** scans may surface additional findings on `.ts` files compared to 3.23.x, because regions that the JS grammar had silently turned into ERROR nodes (and therefore the analysis pipeline could not see) are now visible. This is a correctness improvement, not a regression.
- **`.tsx` files are still affected by the original limitation.** Full TSX/JSX support is tracked as a follow-up; this release ships pure-TS only.
- No CLI surface, output-format, or flag changes. All existing JS/Java/Python/Go/Rust/Bash/HTML behavior is identical to 3.23.5.

[3.24.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.23.5...cognium-dev-v3.24.0

## [3.23.5] - 2026-05-30

### Changed

- **circle-ir upgraded 3.23.4 → 3.23.5** — `yaml.safe_load` is no longer reported as a CWE-502 deserialization sink, and `yaml.unsafe_load` / `yaml.full_load` are now recognized. Net effect for Python scans: prior false positives on the safe API disappear; the genuinely-unsafe variants are now flagged. Verified on OWASP BenchmarkPython: deserialization FP **24 → 7**, overall FPR **14.8% → 12.6%**, F1 **78.6% → 80.0%**.

### Notes

- This release closes the source-side of Issue #4 (Python over-flagging) and the corresponding direct-to-main review request in Issue #6. The remaining Python FPs (12.6%, target ≤2%) span codeinj / xpathi / pathtraver / redirect / xxe / xss / ldapi / trustbound / cmdi categories — these are tracked as a follow-up.

[3.23.5]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.23.4...cognium-dev-v3.23.5

## [3.23.4] - 2026-05-30

### Changed

- **circle-ir upgraded 3.23.3 → 3.23.4** — documentation-only bump (`PUBLISHING.md` rewritten as a pointer to root `release.sh`; `TODO.md` refreshed). No engine, taint-config, or pass-pipeline changes — CLI scan/metrics behavior is identical to 3.23.3.

### Documentation

- **GitHub Action `action.yml` rebranded** — `name`, `description`, `npm install -g` target, CLI binary invocation, and SARIF category all switched from `cognium` to `cognium-dev`. Marketplace listing `cognium-dev/scan@v1` is still pending; current consumable path is `cogniumhq/cognium-dev/packages/cli@cognium-dev-vX.Y.Z`.
- **`RELEASE.md` rewritten** as a thin pointer to the monorepo root `release.sh`. Dropped stale Homebrew, per-platform binary, and `v*`-tag-triggered workflow content.
- **README benchmark table** now split by language and qualified — adds OWASP BenchmarkPython row noting 81.2% TPR / 14.8% FPR on 3.23.3 (tracked as Issue #4, target 3.23.4).
- **`.gitignore`** — `.claude/` (Claude Code per-user skill configs) now ignored to prevent accidental commits.

### Known issues

- **Python over-flagging** (Issue #4) — 14.8% FPR on OWASP BenchmarkPython carries over to this release. Root cause is safe-variant over-matching in `configs/sinks/deserialization.yaml` and friends (e.g. `yaml.safe_load` flagged as CWE-502). A dedicated YAML sink-audit patch is planned for the next release.

[3.23.4]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.23.3...cognium-dev-v3.23.4

## [3.23.3] - 2026-05-28

### Changed

- **circle-ir upgraded 3.23.2 → 3.23.3** — adds Jenkins `@DataBoundConstructor` taint-source matcher: every parameter of a constructor annotated with `@DataBoundConstructor` is now reported as a high-confidence `http_param` source. Closes the source-side gap of cognium-dev#1 (Jenkins CVE-2022-25175). No CLI behavior change.

[3.23.3]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.23.2...cognium-dev-v3.23.3

## [3.23.2] - 2026-05-28

### Changed

- **circle-ir upgraded 3.23.1 → 3.23.2** — adds Jenkins `SCMFileSystem.child(String)` path-traversal sink (CWE-22), closing the sink side of CWE-Bench-Java miss for `workflow-multibranch-plugin` CVE-2022-25175. No CLI behavior change.

[3.23.2]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.23.1...cognium-dev-v3.23.2

## [3.23.1] - 2026-05-28

### Fixed

- **circle-ir upgraded 3.23.0 → 3.23.1** — removes 20 misclassified sink entries from `sql.yaml`, `path.yaml`, and `code_injection.yaml` that had wrong `type` / `cwe` values. Canonical entries remain in the correct sink files. Improves CWE-mapping accuracy in findings with no loss of detection coverage. Closes cognium-dev#3.

[3.23.1]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.23.0...cognium-dev-v3.23.1

## [3.23.0] - 2026-05-28

### Changed

- **Version aligned with `circle-ir`** — jumped from `1.8.3` to `3.23.0` so the CLI version always matches the underlying SAST engine. Going forward, both packages share a synchronized version stream.
- **circle-ir upgraded 3.22.3 → 3.23.0** — adds MyBatis ORM SQL injection sinks (12 mapper method patterns: `insert`, `update`, `select*`, `delete*`); raises Node engine to `>=20.19.0`; documents browser-safe dynamic import pattern.
- **Pinned `circle-ir` dependency** from `*` to `^3.23.0` for reproducible npm installs.
- **Node engine** raised to `>=20.19.0` (was `>=18.0.0`) — aligns with the underlying `circle-ir` library and the toolchain we test against.

[3.23.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v1.8.3...cognium-dev-v3.23.0

## [1.6.5] - 2026-04-15

### Fixed

- **circle-ir upgraded 3.18.4 → 3.18.5** — fixes runtime matching for cssText/textContent property sinks and Rust `Response::builder().header()` builder pattern

[1.6.5]: https://github.com/cogniumhq/cognium/compare/v1.6.4...v1.6.5

## [1.6.4] - 2026-04-15

### Changed

- **circle-ir upgraded 3.18.3 → 3.18.4** — adds style.textContent sink, JSON.parse() sanitizer, Rust Redirect::see_other/to/temporary/permanent sinks, warp::reply::html() variant; fixes invalid css_injection SinkType

[1.6.4]: https://github.com/cogniumhq/cognium/compare/v1.6.3...v1.6.4

## [1.6.3] - 2026-04-15

### Fixed

- **circle-ir upgraded 3.18.2 → 3.18.3** — fixes property-based taint source matching (location.hash, event.data, document.referrer now correctly detected); fixes invalid SourceType values in JS configs

[1.6.3]: https://github.com/cogniumhq/cognium/compare/v1.6.2...v1.6.3

## [1.6.2] - 2026-04-15

### Changed

- **circle-ir upgraded 3.18.1 → 3.18.2** — adds localStorage/sessionStorage sources, CSS style property sinks, Axum Html + HeaderValue sinks, Rust html_escape/ammonia sanitizers, Java ESAPI Encoder + Jsoup.clean sanitizers

[1.6.2]: https://github.com/cogniumhq/cognium/compare/v1.6.1...v1.6.2

## [1.6.1] - 2026-04-15

### Fixed

- **circle-ir upgraded 3.18.0 → 3.18.1** — setAttribute only flags dangerous attributes (on*, style, srcdoc); Bash literal detection eliminates hardcoded URL FPs in curl/wget

[1.6.1]: https://github.com/cogniumhq/cognium/compare/v1.6.0...v1.6.1

## [1.6.0] - 2026-04-15

### Changed

- **circle-ir upgraded 3.17.3 → 3.18.0** — adds taint sources/sinks/sanitizers from benchmark report: JS (jQuery XSS, postMessage, document.referrer, JSON.parse/URL sanitizers), Java (CORS CWE-942, Guava Escaper), Rust (stdin, Axum Body, Warp html, redirect sinks), Bash (curl/wget supply-chain sources)

[1.6.0]: https://github.com/cogniumhq/cognium/compare/v1.5.5...v1.6.0

## [1.5.5] - 2026-04-14

### Changed

- **circle-ir upgraded 3.17.2 → 3.17.3** — exports `package.json` subpath so `createRequire` resolution works under strict Node.js module resolution

[1.5.5]: https://github.com/cogniumhq/cognium/compare/v1.5.4...v1.5.5

## [1.5.4] - 2026-04-14

### Fixed

- **WASM path resolution when installed via npm** (fixes #11): Replaced `import.meta.url` relative path with `createRequire` to locate circle-ir's `dist/wasm/` directory. The old approach broke when bun bundled the code because `import.meta.url` pointed to cognium's `dist/cli.js` rather than circle-ir's actual location, and npm hoisting placed circle-ir at a different `node_modules` level.

### Changed

- **circle-ir upgraded 3.17.1 → 3.17.2** — adds `dist/wasm/` to WASM auto-detection fallback chain

[1.5.4]: https://github.com/cogniumhq/cognium/compare/v1.5.3...v1.5.4

## [1.5.3] - 2026-04-14

### Changed

- **circle-ir upgraded 3.17.1 → 3.17.2** — fixes WASM auto-detection in nested node_modules (#11)

[1.5.3]: https://github.com/cogniumhq/cognium/compare/v1.5.2...v1.5.3

## [1.5.2] - 2026-04-14

### Fixed

- **weak_hash CWE mapping** (fixes #13): Changed `weak_hash` sink type from CWE-327 to CWE-328 (Use of Weak Hash). CWE-327 is for broken cryptographic algorithms (DES, RC4), while CWE-328 is specifically for weak hash functions (MD5, SHA-1). This fixes OWASP Benchmark scoring discrepancies when using strict CWE matching.

[1.5.2]: https://github.com/cogniumhq/cognium/compare/v1.5.1...v1.5.2

## [1.5.1] - 2026-04-14

### Changed

- **circle-ir upgraded 3.17.0 → 3.17.1** — documentation updates for HTML language support
- Added `html` to CLI `--language` help text for scan and metrics commands
- Added `tree-sitter-html.wasm` to WASM language paths
- Updated README, action.yml with HTML in supported languages list

[1.5.1]: https://github.com/cogniumhq/cognium/compare/v1.5.0...v1.5.1

## [1.5.0] - 2026-04-13

### Added

- **HTML file scanning** — `cognium scan` now picks up `.html` and `.htm` files
  and analyzes them via circle-ir's new web extraction preprocessor:
  - Inline `<script>` blocks analyzed as JavaScript with correct line mapping
  - 8 HTML attribute-level security checks (missing noopener, javascript: URIs,
    missing sandbox/SRI, mixed content, autocomplete on passwords, etc.)

### Changed

- **circle-ir upgraded 3.16.8 → 3.17.0** — adds HTML language support

[1.5.0]: https://github.com/cogniumhq/cognium/compare/v1.4.6...v1.5.0

## [1.4.6] - 2026-04-08

### Changed

- **circle-ir upgraded 3.16.7 -> 3.16.8** — dependency refresh release,
  no source or behavior changes (web-tree-sitter, esbuild, vitest, @types/node
  patch/minor bumps).
- **Dev dependencies refreshed**: `@types/node` 25.5.0 → 25.5.2.

[1.4.6]: https://github.com/cogniumhq/cognium/compare/v1.4.5...v1.4.6

## [1.4.5] - 2026-04-07

### Changed

- **circle-ir upgraded 3.16.5 -> 3.16.7** — n-plus-one false positive fix:
  - `n-plus-one` no longer flags `Map.get()` / `Map.has()` calls on in-memory
    collections (e.g. `rpoIndex.get()` in graph algorithms). Added receiver
    exclusions for `*Index`, `*Map`, `*Lookup`, `*Dict`, `*By*` suffixes and
    bare-name collections like `idom`, `seen`, `visited`, `memo`, `cache`,
    `registry`.

[1.4.5]: https://github.com/cogniumhq/cognium/compare/v1.4.4...v1.4.5

## [1.4.3] - 2026-04-05

### Added

- **125-test suite** — 94 unit tests (formatters, args parsing, config loading, scan/metrics
  command logic) + 31 e2e tests (CLI subprocess via `Bun.spawn` covering text/json/sarif output,
  exit codes, severity/category/CWE filtering, directory mode, metrics, config integration)
- **`npm run dogfood`** — scans cognium's own `src/` directory with the project config; exits
  non-zero on findings, suitable for CI gating

### Changed

- **circle-ir upgraded 3.16.4 -> 3.16.5** — false positive fixes in 4 analysis passes:
  - `naming-convention`: skip synthetic names (`<module>`, `<anonymous>`)
  - `redundant-loop-computation`: don't flag `.length` in JS/TS (O(1) property access)
  - `unhandled-exception`: source-level try/catch detection fallback when CFG builder
    misses exception edges
  - `unbounded-collection`: skip bounded loops (`for...of`, `for...in`, `.forEach()`)
- **Re-enabled 4 passes** in `cognium.config.json` that were previously disabled due to
  false positives now fixed in circle-ir 3.16.5: `naming-convention`,
  `redundant-loop-computation`, `unhandled-exception`, `unbounded-collection`
- **Release script** now gracefully skips Homebrew formula update when `Formula/cognium.rb`
  is not present

[1.4.3]: https://github.com/cogniumhq/cognium/compare/v1.4.2...v1.4.3

## [1.4.0] - 2026-03-29

### Changed

- **circle-ir upgraded 3.14.0 → 3.15.0** — improved accuracy for three high-impact passes:
  - **`null-deref`** — now recognizes Java assertion guards (`assert x != null`), `Objects.requireNonNull()`, Guava `Preconditions.checkNotNull()`, Spring `Assert.notNull()`, and JUnit/TestNG `assertNotNull()` — reducing false positives when developers use assertion-based or utility-method null checks
  - **`n-plus-one`** — expanded medium-confidence receiver detection with suffix matching (`*Repository`, `*Repo`, `*Dao`, `*Service`, `*Client`, `*Store`, `*Cache`, `*Gateway`, `*Mapper`, etc.) — catches `userRepository.find()` and similar custom repository patterns that were previously missed
  - **`sink-filter` (XSS)** — added sanitizer detection (DOMPurify, sanitizeHtml, escapeHtml, validator.escape, Angular bypassSecurityTrust), string literal suppression (`.innerHTML = "static"` no longer flagged), and constant propagation integration — reducing false positives on safe DOM assignments

### Release notes

Version 1.4.0 brings improved pass accuracy from circle-ir 3.15.0, reducing both false positives and false negatives across null-deref, N+1 query, and XSS detection.

[1.4.0]: https://github.com/cogniumhq/cognium/compare/v1.3.2...v1.4.0

## [1.3.2] - 2026-03-28

### Added

- **6 new analysis passes** via circle-ir 3.13.0 — all surface findings during `cognium scan`:
  - **`blocking-main-thread`** (CWE-1050, warning) — synchronous crypto/hashing operations
    (`pbkdf2Sync`, `scryptSync`, `generateKeyPairSync`) and `*Sync` I/O calls inside HTTP request
    handlers (NestJS decorators, Express `(req, res)`, handler method names); JS/TS only
  - **`excessive-allocation`** (CWE-770, warning) — collection or object allocation inside loop
    bodies (`new Map()`, `new ArrayList<>()`, `list()`, `Vec::new()`); all languages except Bash
  - **`missing-stream`** (performance, note) — whole-file reads without streaming:
    `readFileSync`/`response.text()` (JS/TS), `Files.readAllBytes`/`BufferedReader` (Java),
    `f.read()` (Python); skips methods already using `.pipe()`/`createReadStream`/`for await`
  - **`god-class`** (CWE-1060, warning) — class exceeding 2 of 3 CK metric thresholds:
    WMC > 47, LCOM2 > 0.8, CBO > 14; Java/TS/Python
  - **`naming-convention`** (maintainability, note) — PascalCase classes, camelCase methods,
    UPPER_SNAKE_CASE constants (Java/TS), snake_case methods (Python/Bash/Rust); capped at 20
    findings per file

### Changed

- **circle-ir upgraded 3.12.0 → 3.14.0**

- **`missing-guard-dom` removed from the default scan pipeline** — this pass (added in v1.3.0)
  produced high-severity false positives on any Java codebase using framework-level authorization
  (Spring Security annotations, filter chains, servlet filters). Those guards are not visible as
  intra-method call nodes in the CFG, so every sensitive operation was reported as unguarded
  regardless of actual protection. The underlying analysis is being re-implemented in
  circle-ir-ai with LLM-identified auth guards. `cognium scan` output is unaffected for
  codebases not using that pass; users who were acting on `missing-guard-dom` findings should
  treat prior results with caution.

- **`feature-envy` removed from the default scan pipeline** — the call-count heuristic fired on
  legitimate delegation patterns (facades, controllers, service orchestrators). Requires design
  intent reasoning to distinguish from genuine feature envy; reserved for circle-ir-ai.

- **`serial-await` fix hint is now advisory** — the suggestion no longer prescribes
  `Promise.all()` directly; it reads "verify ordering requirements before parallelising" to
  prevent incorrect refactors where the operations have semantic ordering constraints.

[1.3.2]: https://github.com/cogniumhq/cognium/compare/v1.3.1...v1.3.2

## [1.3.1] - 2026-03-28

### Changed

- **circle-ir upgraded 3.11.0 → 3.12.0** — internal improvements to Java receiver-type
  resolution and test coverage:
  - `JavaPlugin.getReceiverType()` now resolves identifier receivers by walking the parse tree
    once and caching the result (`WeakMap<Tree, Map<string, string>>`). Generic types are stripped
    (`List<String>` → `List`). This improves polymorphic sink matching for Java code that
    declares a variable with a concrete type and later calls methods on it (e.g.
    `PreparedStatement ps = …; ps.executeQuery(q)`).
  - No API changes; all existing cognium commands and output formats are unaffected.

[1.3.1]: https://github.com/cogniumhq/cognium/compare/v1.3.0...v1.3.1

## [1.3.0] - 2026-03-28

### Added

- **Phase 4 analysis passes** via circle-ir 3.11.0 — four new passes now surface findings during
  `cognium scan`:
  - **`missing-guard-dom`** (CWE-285, error) — sensitive operations (delete, drop, executeUpdate,
    grantRole, etc.) not dominated by an authentication/authorization check on all CFG paths (Java)
  - **`cleanup-verify`** (CWE-772, warning) — resource cleanup does not post-dominate acquisition;
    resource is left open on at least one CFG path (Java, Python, JS/TS)
  - **`missing-override`** (warning) — method matches a parent class signature without `@Override`
    annotation; typos in method names go undetected at compile time (Java)
  - **`unused-interface-method`** (note) — interface method never called in this file; potential
    dead API surface (Java, TypeScript)
- **Rich help text for 15 additional passes** — `formatResults` now displays descriptions and
  fix hints for all passes introduced since v1.2.3:
  `infinite-loop`, `double-close`, `use-after-close`, `unhandled-exception`, `broad-catch`,
  `swallowed-exception`, `redundant-loop-computation`, `unbounded-collection`, `serial-await`,
  `react-inline-jsx`, `deep-inheritance`, `missing-guard-dom`, `cleanup-verify`,
  `missing-override`, `unused-interface-method`
- **TypeHierarchy wired into taint matching** (circle-ir 3.11.0) — `PreparedStatement.executeQuery()`
  now correctly matches `Statement`-level sink configs; reduces false negatives in polymorphic
  call chains

### Changed

- **circle-ir upgraded 3.9.8 → 3.11.0** — picks up all reliability, performance, and architecture
  passes from v3.9.9 through v3.11.0, plus OWASP command injection fixes from v3.9.10/v3.10.0
- **TypeScript upgraded 5.7 → 6.0.2** — uses latest type-checker; all strict checks remain clean
- **`@types/node` upgraded 22 → 25**, **`bun-types` upgraded 1.2 → 1.3**

[1.3.0]: https://github.com/cogniumhq/cognium/compare/v1.2.3...v1.3.0

## [1.2.3] - 2026-03-26

### Added

- **`cognium metrics <path>` command** — new subcommand that reports software quality metrics for
  files or directories. Supports all languages supported by `scan`. Metrics include cyclomatic
  complexity, Halstead suite, WMC, LOC/NLOC, comment density, CBO, RFC, DIT, NOC, LCOM, doc
  coverage, and four composite scores (maintainability index, code quality index, bug hotspot
  score, refactoring ROI).
  - `--format text|json` — human-readable grouped output (default) or machine-readable JSON
  - `--category <cats>` — filter to specific metric categories (`complexity`, `size`, `coupling`,
    `inheritance`, `cohesion`, `documentation`, `duplication`); comma-separated
  - `--language <lang>` — analyze only files for the given language
  - `--exclude-tests` — skip test files and directories
  - `-o, --output <file>` — write results to a file instead of stdout
  - `-q, --quiet` — suppress per-file progress output
- **Updated help text** (`cognium --help`) — METRICS section added with all options and examples

[1.2.3]: https://github.com/cogniumhq/cognium/compare/v1.2.2...v1.2.3

## [1.2.2] - 2026-03-26

### Fixed

- **`--language` filter now correctly filters files by extension** — previously `--language typescript`
  collected all supported file types (Java, Python, etc.) because the language flag was used as a
  hint rather than a filter. Now only files matching the requested language extension are collected.
- **Standalone binary detection simplified** — removed the `|| !import.meta.url.includes('node_modules')`
  condition from `isStandalone` that could incorrectly activate standalone WASM search when running
  `node dist/cli.js` in environments where the path doesn't include `node_modules`.
- **Spinner no longer emits control characters in CI** — spinner is now disabled when stdout is not a
  TTY (piped output, CI environments), preventing garbled escape sequences in logs.
- **Per-file progress in spinner** — spinner now shows the current file being scanned and a
  `(N/total)` counter, giving better feedback on large codebases.
- **Async file I/O in file collection** — `collectFiles()` now uses non-blocking `fs/promises`
  (`stat`, `readdir`) instead of synchronous `statSync`/`readdirSync`.

[1.2.2]: https://github.com/cogniumhq/cognium/compare/v1.2.1...v1.2.2

## [1.2.1] - 2026-03-26

### Fixed

- **Zero false positives on TypeScript/library code** — circle-ir upgraded to 3.9.7, which
  eliminates all remaining false positives when scanning TypeScript projects:
  1,542 cross-file `sql_injection`, 8 cross-file `log_injection`, and 4 `external_taint_escape`.
  Root causes: a `matchesSourcePattern` bug that allowed bare `get()` calls to match all
  class-qualified source patterns (Map/HashMap/Properties/Request), and `interprocedural_param`
  sources leaking into cross-file and Scenario-B analyses where they don't belong.
  See [circle-ir CHANGELOG](https://github.com/cogniumhq/circle-ir/blob/main/CHANGELOG.md) for details.

[1.2.1]: https://github.com/cogniumhq/cognium/compare/v1.2.0...v1.2.1

## [1.2.0] - 2026-03-26

### Added

- **`--category` filter** — filter findings by ISO 25010 category. Valid values (comma-separated): `security`, `reliability`, `performance`, `maintainability`, `architecture`. Examples: `--category security` (security findings only), `--category reliability,performance` (both categories). Cross-file taint paths (always `security`) are automatically excluded when `security` is not in the requested categories.

- **Category tags in text output** — non-security findings now show their category in brackets (e.g. `[maintainability]`, `[reliability]`) next to the finding type, making it easy to distinguish code quality issues from security vulnerabilities at a glance.

- **Category-aware summary** — the end-of-scan summary now reports security and code quality findings separately:
  - `Found N security finding(s) in M file(s)` (red)
  - `Found/Also found N code quality finding(s) in M file(s)` (yellow)

### Changed

- **Exit code semantics** — the CLI now exits with code `1` only when security findings are present, and exits `0` for quality-only scans. This allows CI pipelines to gate on security vulnerabilities without being blocked by documentation or style findings.

- **circle-ir upgraded** from 3.9.5 → 3.9.6, which eliminates false positives in `variable-shadowing`, `leaked-global`, and `external_taint_escape` passes (see [circle-ir CHANGELOG](https://github.com/cogniumhq/circle-ir/blob/main/CHANGELOG.md) for details).

[1.2.0]: https://github.com/cogniumhq/cognium/compare/v1.1.0...v1.2.0

## [1.1.0] - 2026-03-25

### Added

- **17 new SAST detection passes** (via circle-ir 3.9.0–3.9.4):
  - **Reliability**: `null-deref` (CWE-476), `resource-leak` (CWE-772),
    `unchecked-return` (CWE-252), `dead-code` (CWE-561),
    `variable-shadowing` (CWE-1109), `leaked-global` (CWE-1109),
    `unused-variable` (CWE-561)
  - **Performance**: `missing-await` (CWE-252), `n-plus-one` (CWE-1049),
    `sync-io-async` (CWE-1050), `string-concat-loop` (CWE-1046)
  - **Architecture**: `circular-dependency` (CWE-1047), `orphan-module`,
    `dependency-fan-out`, `stale-doc-ref`
  - **Maintainability**: `missing-public-doc`, `todo-in-prod`
- **Software metrics engine** (via circle-ir 3.9.5): every scan now populates
  `ir.metrics` with 24 quality metrics — cyclomatic complexity (v(G)/WMC),
  Halstead suite, size (LOC/NLOC), CK coupling (CBO/RFC), inheritance (DIT/NOC),
  cohesion (LCOM), doc_coverage, and four composite scores
  (maintainability_index, code_quality_index, bug_hotspot_score, refactoring_roi).

### Changed

- **circle-ir upgraded** from 3.8.x → 3.9.5

[1.1.0]: https://github.com/cogniumhq/cognium/compare/v1.0.9...v1.1.0

## [1.0.9] - 2026-03-17

### Fixed

- **WASM Path Resolution**: Enhanced standalone binary to search for WASM files in multiple locations:
  - Next to the binary executable
  - Current working directory
  - Parent directory of binary
- **Better Error Messages**: Added detailed error message when WASM files cannot be found, showing all searched locations
- Fixes "ENOENT: no such file or directory, open 'wasm/tree-sitter-*.wasm'" errors when running binary from different directories

### Changed

- Version output now shows "Powered by Cognium Labs" instead of "Powered by circle-ir"

[1.0.9]: https://github.com/cogniumhq/cognium/compare/v1.0.8...v1.0.9

## [1.0.8] - 2026-03-17

### Added

- **Bash Support**: Added support for scanning Bash scripts (.sh, .bash files)
- **GitHub Actions Workflow**: Automated binary builds for macOS (arm64/x64) and Linux (x64) on release
- All WASM language parsers now included: bash, java, javascript, python, rust

### Changed

- Updated help text to include bash in supported languages

[1.0.8]: https://github.com/cogniumhq/cognium/compare/v1.0.7...v1.0.8

## [1.0.7] - 2026-03-17

### Fixed

- **WASM Path Resolution**: Fixed standalone binary WASM file loading by using `process.execPath` instead of `import.meta.url` to locate the binary directory
- Resolves "ENOENT: no such file or directory, open 'wasm/tree-sitter-*.wasm'" errors

[1.0.7]: https://github.com/cogniumhq/cognium/compare/v1.0.6...v1.0.7

## [1.0.6] - 2026-03-17

### Added

- **CWE Exclusion**: New `--exclude-cwe` option to filter out specific CWE types
  - Supports single CWE: `--exclude-cwe CWE-330`
  - Supports multiple CWEs: `--exclude-cwe CWE-330,CWE-327,CWE-20`
  - Can be combined with `--severity` filtering

### Changed

- Updated help text with `--exclude-cwe` examples

[1.0.6]: https://github.com/cogniumhq/cognium/compare/v1.0.5...v1.0.6

## [1.0.5] - 2026-02-18

### Changes

- circle-ir upgrade + --ai removal

[1.0.5]: https://github.com/cogniumhq/cognium/compare/v1.0.4...v1.0.5

## [1.0.4] - 2026-02-17

### Changes

- Patched
  * upgrade circle-ir to latest

[1.0.4]: https://github.com/cogniumhq/cognium/compare/v1.0.3...v1.0.4

## [1.0.0] - 2025-02-11

### Added

- **Initial Release**: AI-powered static analysis CLI
- **Multi-language Support**: Java, JavaScript, TypeScript, Python, Rust
- **Vulnerability Detection**: SQL Injection, XSS, Command Injection, Path Traversal, and more
- **Output Formats**: Text, JSON, SARIF for CI/CD integration
- **Configuration**: Project-level `cognium.config.json` support
- **Parallel Analysis**: Multi-threaded scanning for large codebases
- **Severity Filtering**: Filter results by severity level

### Technical

- Built with Bun for fast startup and standalone binary support
- Powered by circle-ir for accurate taint analysis
- SARIF output for GitHub/GitLab integration

[1.0.0]: https://github.com/cogniumhq/cognium/releases/tag/v1.0.0
