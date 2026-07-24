# Tasks — MVP

**Open work items for cognium-dev MVP.**

---

## In Progress

(none)

## Open — High Priority

- [ ] **Residual Python FPs on OWASP BenchmarkPython** (follow-up to Issue #4, post-3.23.5)
  - Current on 3.23.5: TPR 81.2%, **FPR 12.6%**, F1 80.0%, 91 FPs / 1230 tests (target FPR ≤ 2%)
  - Breakdown: codeinj (18), xpathi (17), pathtraver (14), redirect (12), xxe (10), xss (9), ldapi (7), trustbound (2), cmdi (2), deserialization (7 residual after `yaml.safe_load` carve-out)
  - Hypothesis: same safe-variant-over-matching pattern as `yaml.safe_load` repeats in other Python plugin sink methods (`PythonPlugin.getBuiltinSinks()`); audit each category's sink list against the safe-API surface
  - Must precede any 3.24.0 framework expansion to avoid stacking confounds
  - Cross-ref: `cogniumhq/circle-ir-ai#75`

- [ ] **Consolidate Python sink source-of-truth** (architectural, surfaced by Issue #4 fix)
  - Current state: Python sinks live in THREE places — `configs/sinks/python.json`, `config-loader.ts::DEFAULT_SINKS`, and `PythonPlugin.getBuiltinSinks()` in `src/languages/plugins/python.ts`. Only the last is consulted at runtime for the language path
  - ADR-004 + `principles.md` currently claim `config-loader.ts` is THE runtime source-of-truth — this is incomplete for language-plugin-driven sinks (it's a 3-way split, not 2-way)
  - Action: either (a) collapse plugin `getBuiltinSinks()` into `DEFAULT_SINKS`, or (b) update ADR-004 + principles to honestly describe the 3-way model and pick a canonical one per language
  - Triggered by 7834e19 — fix landed in plugin, not config-loader

- [ ] **GitHub Action `cognium-dev/scan@v1` marketplace listing**
  - Owner: —
  - Status: `packages/cli/action.yml` rebranded to `cognium-dev` (npm name, CLI binary, SARIF category) in d0957b6 — usable today as `cogniumhq/cognium-dev/packages/cli@cognium-dev-vX.Y.Z`
  - Remaining: extract to standalone `cognium-dev/scan` repo, tag `v1`, publish marketplace listing

- [ ] **Java benchmarks** — Publish comparison vs Snyk/Checkmarx/Semgrep
  - Owner: —
  - Due: Phase 1 (May 2026)

## Open — Medium Priority

- [ ] **Cross-instance field-binding propagation** (Jenkins / general engine gap, Issue #1)
  - `this.field = param` in one method → `other.field` read in another method on an aliased instance
  - Required to close the remaining CWE-Bench-Java Jenkins `ReadTrustedStep.run()` path end-to-end (CVE-2022-25175)
  - Engine-level (DFG cross-instance reasoning), not a YAML/config change
  - Audited 2026-06-10: ~420 LOC across `dfg.ts` + `taint-propagation.ts` + `cross-file.ts` + new `field-binding-resolver.ts`. Honest difficulty 7/10. Moderate-to-high regression risk on OWASP 100/100/97.7% TPR benchmarks
  - **Deferred to cognium-ai triage** — if LLM-discovery already covers this CVE, close circle-ir-side as won't-fix; if not, prioritize with explicit benchmark-gate plan. Issue #1 left open pending their call

- [ ] **TSX / JSX parsing** (follow-up to 3.24.0)
  - 3.24.0 ships pure-TS only via `tree-sitter-typescript.wasm`. `.tsx` files still hit the JS grammar path (the broken pre-3.24.0 behavior for inline-object-type params) — and JSX additionally produces ERROR nodes the JS grammar cannot recover from
  - Action: bundle `tree-sitter-tsx.wasm` (also shipped by `tree-sitter-typescript@0.23.2`, ~1.45 MB), dispatch `.tsx` to it from the language plugin, mirror the `required_parameter` / `optional_parameter` work for any TSX-only param node shapes
  - Test coverage: add `tests/extractors/types-tsx.test.ts` with JSX-element-returning components

- [ ] **Interface extraction enrichment** (follow-up to 3.24.0)
  - The TS grammar now produces `interface_declaration` nodes, but `extractJavaScriptTypes` only walks `class_declaration` / `function_declaration` / named arrow funcs. Interfaces currently fall on the floor
  - Action: extend `extractJavaScriptTypes` (`src/core/extractors/types.ts`) to emit `interface_declaration` as `TypeInfo` with `kind: 'interface'`, populating `fields` from `property_signature` and `methods` from `method_signature`
  - Needed for cross-instance taint analysis when the type contract is declared as an interface

- [ ] **Generic / union / intersection type surfacing** (follow-up to 3.24.0)
  - `generic_type`, `union_type`, `intersection_type` nodes are now present in the TS-grammar tree but not converted into IR fields. `ParameterInfo.type` currently stores the raw source slice; structured representation would let passes reason about `Array<T>` vs `T[]`, nullable unions, etc.
  - Lower priority than the two above; defer until a pass actually needs structured TS type info

- [ ] **Framework coverage expansion** (proposed 3.25.0+)
  - JS/TS: Next.js API routes, TypeORM sinks, narrow `.value` dom_input source
  - Python: Jinja2 XSS sinks; additional MyBatis/Django ORM raw query patterns
  - Java: Micronaut, Quarkus
  - Rust: Axum extractor refinement, SQLx, Reqwest
  - All YAML-only except dom_input narrowing

- [ ] **Dependency analysis** — CVE matching, SBOM generation
  - Maps to: cognium-ai MCP `analyze_dependencies`
  - Formats: CycloneDX, SPDX

- [ ] **Supply chain risk** — Slopsquatting detection, package trust
  - Maps to: cognium-ai MCP `find_supply_chain_risk`

## Open — Low Priority

- [ ] **CI/CD pipeline** — GitHub Actions for monorepo builds
- [ ] **Pre-commit hooks** — Lint, typecheck, test on commit

## Completed

- [x] **Release 3.188.0** — Eighth #213 slice — NestJS controller decorator sources. 8 new annotated-parameter DEFAULT_SOURCES entries covering NestJS-specific decorators that shared FastAPI/Spring names did not: @Param('id') → http_path, @Req()/@Request() → http_body (whole request object; taints all req.X reads), @Session() → http_cookie, @Ip() → network_input, @HostParam('sub') → http_path (subdomain of `host` config), @UploadedFile()/@UploadedFiles() → file_input (multer). Registered without languages: filter — NestJS is TS-first but decorator convention appears in some JS projects too. No collision with Java @Param sanitizer at line 2761 (separate loops for sanitizer vs source pattern matching). 4258 pass, 2 skipped, 0 regressions vs 3.187.0. (840c287, 2026-07-24)
- [x] **Release 3.187.0** — Seventh #213 slice — Java sanitizer parity. Completes the sanitizer_kind grid across Java after Python (3.185.0) and JS/Go (3.186.0). Full JDBC 4.x PreparedStatement setter surface — previously only setString/setInt/setLong; extended with setBoolean/setByte/setShort/setDouble/setFloat/setBigDecimal/setNString/setDate/setTime/setTimestamp/setBytes/setBlob/setClob/setNClob/setArray/setRef/setRowId/setSQLXML/setURL/setBinaryStream/setCharacterStream/setAsciiStream/setNCharacterStream/setObject/setNull. Also TypedQuery.setParameter (JPA) and MapSqlParameterSource.addValue (Spring). Third-party libs: Apache Commons Text StringEscapeUtils.escape* full suite + bare aliases for escapeJson/escapeEcmaScript/escapeCsv; Guava HtmlEscapers via Escaper + HtmlEscapers class entries; OWASP HTML sanitizer PolicyFactory.sanitize. Encoder taint barriers: Base64.Encoder.encodeToString/encode + bare aliases (call-expression receiver like Base64.getEncoder() rarely resolves to Encoder type through Java IR, so bare needed), Hex.encodeHexString + bare, MessageDigest.digest — broad removes (sql/command/xss/path/code) because encoded output cannot carry attacker metacharacters. 4253 pass, 2 skipped, 0 regressions vs 3.186.0. (5044a7e, 2026-07-24)
- [x] **Release 3.186.0** — Sixth #213 slice — JS/Node + Go sanitizer coverage, parallel to the 3.185.0 Python slice. JS/Node: `he.encode`/`escape`, `sanitizeHtml` (bare, sanitize-html npm), `xss`/`filterXSS` (xss npm), `escapeHtml`/`escapeHTML` bare, `entities.encode`/`escape`, `xssFilters.inHTMLData`/`inHTMLComment`/`uriInHTMLData` (Yahoo xss-filters), `SqlString.escape`/`escapeId`/`format` (sqlstring npm), `pgFormat.format`/`ident`/`literal` (pg-format npm), `crypto.randomUUID` (+ bare alias) with broad `sql/nosql/command/path/code/xss` removes since typed UUID cannot carry payload, `URLSearchParams.toString`. Go: `regexp.QuoteMeta` (redos + code_injection, mirror of Python re.escape shipped 3.185.0), `bluemonday.Sanitize`/`SanitizeBytes` class-scoped + `Policy` receiver + bare alias (bare needed because `p := bluemonday.UGCPolicy()` doesn't propagate Policy type through Go DFG), `net.ParseIP` (ssrf/command_injection/path_traversal), `sql.Named`. All entries include external_taint_escape in removes so a `res.send(sanitizer(x))` shape does not spuriously report CWE-668 at the sanitizer call site itself. 4246 pass, 2 skipped, 0 regressions vs 3.185.0. (51e9f91, 2026-07-24)
- [x] **Release 3.185.0** — Fifth #213 slice — Python sanitizer coverage. Added ~15 high-value Python sanitizers to DEFAULT_SANITIZERS: urllib.parse `quote`/`quote_plus`/`urlencode` (URL context, ssrf/open_redirect/xss/path_traversal removes) + bare aliases; bleach.linkify (xss) + bare alias; django.utils.html.escape/strip_tags (xss); jinja2/flask escape (xss); xml.sax.saxutils.escape/quoteattr (xss in XML) + full-path receiver alias; re.escape (redos + code_injection — the latter because engine categorizes re.compile(user) as CWE-94 which re.escape neutralizes by stripping metacharacters); SQLAlchemy bare bindparams (sql_injection); psycopg2 sql.Identifier/Literal/Placeholder (sql_injection). Also fixed narrow symmetry gap in `matchesSanitizerPattern`: when pattern specifies `class:` and call has no receiver (bare import), accept if `call.resolution.target` tail-matches `<class>.<method>`. Mirrors source-side handling at line ~1719. Deliberately narrower than source-side change — widening to `receiver_type`/`receiver_type_fqn` matches would activate previously-dormant Java sanitizer entries (e.g. `Path.normalize`) whose semantic scope is broader than their `removes` claims (verified via tests/issue-216-pattern-b-java.test.ts). 4238 pass, 2 skipped, 0 regressions vs 3.184.0. (3484c56, 2026-07-24)
- [x] **Release 3.184.0** — Third + fourth #213 slices. (A) JS/TS `ws.on('message', cb)` callback-parameter sources: new `findJavaScriptCallbackParamSources` text-scan supplement + `buildJavaScriptTaintedVars` seed extension. Event allowlist: `message` / `text` / `binary`. Callback shapes: arrow, function-expr (named/anonymous/generator/async), typed params. FP-guards: lifecycle events (`drain`/`close`/`error`/`connection`/etc.) not on allowlist; `err`/`error` param names excluded even on allowlisted events. Closes the 3.183.0 deferral. (B) Bash stdin/CLI builtin sources: new sections 2b/2c/2d in `findBashTaintSources` covering `read` (per-flag arg-consumption enumerated), `mapfile`/`readarray` (`-t` recognized as no-arg), `getopts` (both `$flag` and `$OPTARG`). FP-guard: function definitions (`read() { … }`) excluded by requiring the line contain no `(`; function *bodies* with real `read x` calls still fire. Additive-only; no reach-map or DFG changes. 4232 pass, 2 skipped, 0 regressions vs 3.183.0. (3b920e4, 2026-07-23)
- [x] **Release 3.183.0** — Second slice of #213 transport-channel matrix — WebSocket handler payload sources across Python (FastAPI/Starlette/Django Channels), Go (gorilla/nhooyr `Conn.ReadMessage`/`NextReader`/`Read`), Java (Jakarta `@OnMessage`, Spring STOMP `@MessageMapping`/`@SubscribeMapping`). Additive-only: 10 DEFAULT_SOURCES patterns (return-tainted or annotated-param shapes) + 3 PYTHON_TAINTED_PATTERNS regex entries so `data = await websocket.receive_text()` adds `data` to `pyTaintedVars`. Deliberately not adding bare `.receive\s*\(` to avoid queue/signal collisions. JS/TS `ws.on('message', cb)` callback-parameter shape deferred (needs new engine plumbing). 4219 pass, 2 skipped, 0 regressions vs 3.182.0. (7311efe, 2026-07-23)
- [x] **Release 3.182.0** — Closed #243 end-to-end with all four Go taint-propagation shapes shipped in a single release: Shape 1 (closure capture) pinned by test; Shape 2 (range-clause loop-carried) via missing `extractGoUses(right, ...)` on range source in `dfg.ts` so `computeChains` links range-subject → loop-var; Shape 3 (opaque-codec roundtrip) via `dfg.ts` dest re-def for `json.Unmarshal` / `xml.Unmarshal` / `yaml.Unmarshal` / `gob.NewDecoder().Decode` + `Unmarshal*` addressable-only receivers, plus companion compound-expression sink-match in `taint-propagation.ts` catching `sink("..." + v)` / `sink(fmt.Sprintf(t, v))` shapes; Shape 4 (package-global store/read) via new `detectGoPackageGlobalFlows` text-scan supplement in `taint-propagation-pass.ts` covering cross-function package-scope taint (preserves local shadowing — `:=` does not fire). 4212 pass, 2 skipped, 0 regressions vs 3.181.0. (c3bbb72, 2026-07-23)
- [x] **Release 3.181.0** — Bundled 3 engine commits since 3.180.0. `#264` `.format_map` extension in Sprint 86 regex (`language-sources-pass.ts:7149`) + discovery-driven rewire of the 3.180.0 `PythonReceiverTaintFormatPass` (was dead code — `ConstantPropagatorResult.tainted` empty for Python; rewired to consume `graph.ir.taint.sources[].variable` and now genuinely acts as a fallback to Sprint 86 for cases outside the Flask/Django/FastAPI framework gate; 053e4af, +1 test). `#261` npm `package.json` plumbing (`DependencyContext.js.packageJson` + `resolveDepFromPackageJson` helper; 8921d19, 17 unit tests, plumbing-only — no clean JS version-safety story). `#213` first transport-channel slice — AWS Lambda / API Gateway `event.*` sources for JS/TS + Python (ecfdabb, 10 property patterns + 6 JS_TAINTED_PATTERNS regex entries, 5 integration tests). API surface addition: `AnalyzerOptions.dependencyContext.js`. **Additionally:** `#264` `%`-operator LHS-taint work CANCELLED (Sprint 86 already implements it; discovered while investigating `.format_map`); `#243` diagnostic posted (Go closure capture already works — ticket assumption wrong; loop-carried range / package-globals / JSON-roundtrip are real gaps but need deeper taint-propagator work, scoped as follow-ups on the ticket). 4204 pass, 2 skipped, 0 regressions vs 3.180.0. (44734de, 2026-07-23)
- [x] **Release 3.180.0** — Bundled 5 commits since 3.179.0. Three more `#261` `dependencyContext` slices: Rust `Cargo.toml` plumbing (354b25c, 12 unit tests; ships without a gate consumer — no clean version-safety story for `serde_yaml`/`bincode`), Gradle version-catalog `libs.versions.toml` (e9640b1, 8 integration tests; third fallback in Gate A after pomXml and direct buildGradle), Gradle `constraints{} + version{strictly}` sub-block form (0e21732, 8 tests; reality-check first showed 6 of 7 "extended forms" were already matched by the direct-form regex). Two more `#264` `format_string` bites: Logger classification decision (stays `log_injection`/CWE-117 with in-code decision note; no new sinks — f351687), new `PythonReceiverTaintFormatPass` for `taintedFmt.format(...)` shapes (eae3391, direct-finding emission via `ctx.addFinding` sidesteps the sink→flow chain; 7 tests). API surface additions: `AnalyzerOptions.dependencyContext.rust`, `AnalyzerOptions.dependencyContext.java.libsVersionsToml`. 4181 pass, 2 skipped, 0 regressions vs 3.179.0. (23d276a, 2026-07-23)
- [x] **Release 3.179.0** — Bundled 5 commits since 3.178.0: `#260` Go fiber `c.Redirect` arg[0] flow-gap fix (root cause was shared-taint-matcher sinkMap-dedup ordering; exact-class-match tiebreaker in `calculateSinkConfidence`), `#263` perf harness + baseline checked in (`packages/circle-ir/perf/{harness.mjs, README.md, BASELINE.md}`), `#264` partial (8 `format_string` sink additions across Java + Go), `#261` Gradle slice (`DependencyContext.java.buildGradle` + Fastjson resolver), `#261` Python slice (`DependencyContext.python.{requirementsTxt,pyprojectToml}` + PyYAML ≥ 6.0 Gate D with per-call unsafe-Loader inspection). API surface additions: `AnalyzerOptions.dependencyContext.java.buildGradle`, `AnalyzerOptions.dependencyContext.python`, `DeserializationSafetyGateResult.droppedPyYaml`. 4146 pass, 2 skipped, 0 regressions vs 3.178.0. (f1b18f7, 2026-07-23)
- [x] **Release 3.178.0** — Bundled `#258` deserialization-safety gate (new `AnalyzerOptions.dependencyContext` capability — Fastjson `*_noneautotype` manifest gate + Jackson polymorphism in-file gate + SnakeYAML SafeConstructor in-file gate; Java-only MVP with Pillar I preserved) and `#143` note-level finding coalescer (additive `labels[]` on `SastFinding`; MVP of the 2026-07-03 reopen, scoped to `level === 'note'` only). 4112 pass, 3 skipped, 0 regressions vs 3.177.0. Both large-group tickets landed as one minor. (f647d0d, 2026-07-23)
- [x] **Release 3.177.0** — Bundled `#254` perf partials (T1#5 `receiverMightBeClass` memo, T2#7 language-filter hoist, T2#10 `walkBackwardDefs` memo, T1#2 constant-prop tree-walk fusion, T2#9 `buildCFG` Bash+Go nodeCache reuse), `#257` Java `code_injection` `*Parser` semantic gate (closes Elide FP), and `#240` ship 2 zero-recall coverage (`deserialization` + `nosql_injection` framework sinks + Go local-receiver type resolver). IR semantic change: Go `CallInfo.receiver` now holds resolved type name for local-variable operands (documented in CLI changelog). 4087 pass, 3 skipped, 0 regressions vs 3.176.0. (86852ec, 2026-07-23)
- [x] **Release 3.34.0** — Runtime-registration extractor Phase 3 (Rust trait dispatch, #15). New `RuntimeRegistration.kind = 'trait_impl'` covers (a) `impl Trait for Type` blocks emitting one registration per method with stdlib / actix / axum / rocket / tokio / serde / unknown classification via last-segment + prefix matching, (b) `inventory::submit! { Plugin::new(...) }` macros as `framework: 'inventory'` with handler from token tree, (c) `#[linkme::distributed_slice]` / `#[distributed_slice]` attributes as `framework: 'linkme'` walking parent siblings to next `static_item` / `function_item`. Rust node cache extended with `attribute_item` + `static_item`. 11 new tests; suite 1895 passing. Closes #15 (Phase 3 of 3 — full runtime-registration roadmap complete). (bbb59c1, 2026-06-10)
- [x] **Release 3.33.0** — Runtime-registration extractor Phase 2 (Python decorators, #15). Records every `@decorator` on `def`/`async def`: Flask/FastAPI routes as `http_route`, `@app.before_request`/`@app.after_request` as `middleware`, `@app.errorhandler` as `event_listener`, `@pytest.fixture`/`@click.command()`/`@property` etc. as `decorator` with framework tags (`pytest`, `click`, `stdlib`, `numba`, `celery`, `django`, `unknown`). Chained decorators emit one registration each. 10 new tests; suite 1884 passing. (a6c74ed, 2026-06-10)
- [x] **Release 3.32.0** — Runtime-registration extractor Phase 1 (JS/TS Express family, #15). New optional IR field `runtime_registrations: RuntimeRegistration[]` recording HTTP routes (`app.METHOD(path, handler)`), middleware (`app.use`, `router.use`), event listeners (`server.on`, `emitter.once`). Handler resolution: named identifier → declaration site, inline arrow → `name: null` at lambda site, member-expression → textual reference. Receiver filtering: express-shaped names or any receiver with framework module imported. 10 new tests; suite 1874 passing. (8fef35b, 2026-06-10)
- [x] **Release 3.31.0** — Java SAST sink expansion: NiFi EL injection (#11, CVE-2023-36542, `PropertyValue.evaluateAttributeExpressions` as `code_injection`/CWE-94/critical) + XWiki rendering pipeline XSS (#10, 5 CVEs — sources `XWikiRequest.getParameter*/getHeader`, sinks `WikiPrinter.print*`, `XHTMLWikiPrinter.print*`, `DefaultBlockRenderer.render`). 4 new regression tests; suite 1864 passing. Closes #10 and #11. (a9039de, 2026-06-09)
- [x] **Release 3.30.0** — Encoding-aware path traversal propagation for Shiro CWE-022 (#8). Decoder methods (`URLDecoder.decode`, `Normalizer.normalize`, etc.) now propagate taint forward rather than sanitize. Closes #8. (b4fb62a, 2026-06-09)
- [x] **Release 3.29.0** — Apache Camel mail path-traversal sink (#12, CVE-2018-8041) + Java enterprise sink-shape FP fix (#14, DBeaver / Dubbo / Ruoyi / JeecgBoot / XXL-JOB). Closes #12 and #14. (2beddea, 2026-06-09)
- [x] **Release 3.28.0** — WASM memory leak fix (#16). Every `analyze()` previously created `new Parser()` and a `Tree`, neither ever `.delete()`'d, causing tree-sitter WASM heap to grow monotonically across 120-project benchmark runs. Both now disposed; static baseline restored. Closes #16. (2026-06-09)
- [x] **Release 3.27.1** — `scan-secrets` pass #90 (CWE-798, #79 in repo bookkeeping). Two-layer hardcoded-credential detection across all 7 languages: ~16 provider-specific regex patterns (AWS AKIA, GitHub ghp_/gho_/ghs_/ghu_/ghr_, Stripe sk_live_/pk_live_, OpenAI sk-, Anthropic sk-ant-, Slack xox[baprs]-, Google AIza, JWT, PEM, npm_) emitting `hardcoded-credential` (critical/error) + Shannon-entropy scan on string literals 20–200 chars (≥4.3 bits/char base64, ≥3.5 bits/char hex) with UUID/hash/placeholder/base64-JSON denylist emitting `hardcoded-credential-entropy` (high/warning). Test-file paths skipped; dedupes against legacy Bash detection via new `PassContext.getFindings?()` accessor. 39 new tests. Versions 3.26.0 and 3.27.0 prepared locally but never published — content shipped as 3.27.1. (947282b, 2026-06-04)
- [x] **Release 3.25.0** — version-bump-only re-publish issued ~40s after 3.24.0 to ensure a clean npm publish window; no source, config, or pass-pipeline changes. CHANGELOG auto-prepend records "(no commits since last release)" for both packages. Substantive changes for this stream are entirely in 3.24.0. (4168550, 2026-06-02)
- [x] **Release 3.24.0** — TS parser fix for Issue #5: ship real `tree-sitter-typescript.wasm` (v0.23.2), remove both `typescript → javascript` grammar redirects in `core/parser.ts`, add `required_parameter` / `optional_parameter` handling in `extractJSParameters`, populate `ParameterInfo.type` for TS code. 6 new regression tests in `tests/extractors/types-typescript.test.ts`; full suite 1810 passing, 0 failing. `.tsx` / JSX, interface IR enrichment, and generic-type surfacing tracked as separate follow-ups. (20df02f, 2026-06-02)
- [x] **Release 3.23.5** — source-side fix for Issue #4: `yaml.safe_load` removed from `PythonPlugin.getBuiltinSinks()`; `yaml.unsafe_load` + `yaml.full_load` added as CWE-502 sinks. OWASP BenchmarkPython delta: deser FP 24→7, FPR 14.8%→12.6%, F1 78.6%→80.0%. Closes #4 (source-side) and #6 (direct-to-main review). Residual 91 FPs tracked separately. (7834e19 + 2cd9032, 2026-05-30)
- [x] **Release 3.23.4** — documentation-only release: `PUBLISHING.md` + `RELEASE.md` rewrites pointing to root `release.sh`, `action.yml` rebrand to `cognium-dev`, README benchmark table split by language with BenchmarkPython qualification, `.gitignore` adds `.claude/`. No engine/taint-config changes. Known issue #4 (Python FPR 14.8%) carries forward. (7b679ad, 2026-05-30)
- [x] **Pre-populated CHANGELOG entries** — committed before `release.sh` ran so the auto-prepend produced a single canonical entry per package (c6bbd71, 2026-05-30)
- [x] **Pass-count consolidation** — README + CLAUDE no longer duplicate pass/metric counts; both link to `packages/circle-ir/docs/PASSES.md` (d0957b6, 2026-05-29)
- [x] **Release docs refresh** — Rewrote `packages/cli/RELEASE.md` and `packages/circle-ir/PUBLISHING.md` as pointers to root `release.sh`; dropped stale Homebrew + per-platform binary + `v*`-trigger workflow content (d0957b6, 2026-05-29)
- [x] **GitHub Action rebrand** — `packages/cli/action.yml` renamed to "cognium-dev SAST scan"; npm package + CLI binary + SARIF category switched from `cognium` → `cognium-dev`; README CI example points to actual usable path (d0957b6, 2026-05-29)
- [x] **Release 3.23.3** — `@DataBoundConstructor` method-level annotation source matcher; new `method_annotation` field on `SourcePattern`; closes source-side of #1 (2026-05-28)
- [x] **Release 3.23.2** — Jenkins `SCMFileSystem.child(String)` path-traversal sink (CVE-2022-25175 sink side) (2026-05-28)
- [x] **Release 3.23.1** — closed #3 (sink misclassifications); 20 wrong-type sink entries removed (2026-05-28)
- [x] **Release 3.23.0** — initial monorepo npm publish stream (2026-05-28)
- [x] **Monorepo hygiene** — root `release.sh`, dropped stale per-package lockfiles (2026-05-28)
- [x] **Monorepo structure** — Set up workspace with preserved git history (2026-05-26)
- [x] **CLI rebrand** — Rename cognium → cognium-dev (2026-05-26)
- [x] **Shared tsconfig** — Create base TypeScript config (2026-05-26)
- [x] **CLAUDE.md** — Combined guidance document (2026-05-26)
- [x] **GitHub repo setup** — Push to cogniumhq/cognium-dev (2026-05-26)
- [x] **Archive old repos** — circle-ir → archived, cognium → cognium-sast-cli archived (2026-05-26)
- [x] **Documentation review** — Update all README/docs for monorepo (2026-05-26)
- [x] **MyBatis ORM sinks** — Add 12 MyBatis mapper SQL injection sinks (2026-05-26)
- [x] **Issue migration** — Transfer CWE-Bench issue from archived repo (2026-05-26)

---

## Open Issues

### GitHub issue ledger (as of 2026-07-24, post-#243 close, post-3.188.0)

| # | Kind | Title | Engine status | Next step |
|---|------|-------|---------------|-----------|
| #146 | FN | Rust & TypeScript cross-file taint unresolved (extends closed #106) | Not started | Rust/TS branches of the #67/#82 work |
| #172 | umbrella | Upstream TPs from top-100 Java testharness sweep | Living ledger; +1 row 2026-07-22 (langchain4j `ShellCommandRunner`, pending-decision) | Append as new TPs discovered |
| #213 | coverage | Taint coverage extension — 512 cells (go/ts/bash + channels + kinds) | **Eight slices shipped.** Slices 1-4 (3.181.0–3.184.0): source coverage — Lambda events, WebSocket handlers (Python/Go/Java + JS/TS), bash builtins. Slices 5-7 (3.185.0–3.187.0): sanitizer_kind grid complete across Python/JS/Go/Java. Slice 8 (3.188.0, 840c287): NestJS controller decorator sources — @Param (route path), @Req/@Request (whole request), @Session, @Ip (client IP), @HostParam (subdomain), @UploadedFile/@UploadedFiles (multer). Shared FastAPI/Spring decorator names (@Body/@Query/@Header/@Cookie/@Form/@File/@Path) were already covered; slice 8 adds only NestJS-unique ones. Registered without languages: filter so both TS-first NestJS and JS-adopting projects benefit. 46 tests total across all slices. Also discovered (3.183.0 investigation): the "nested-property access `event.pathParameters.id` falls through" claim in the first slice's test comment was inaccurate — the actual gap was reach-map exclusion of http_path→command_injection / http_header→command_injection (deliberate FP-control policy), not the JS matcher. | Remaining: additional go/ts source parity cells, bash sanitizer coverage, external harness verification. Real diminishing returns on further slices without external harness scoring. |
| #262 | research | Multi-severity finding-collision data capture (unblocks broader coalesce from #143) | Not started | Rerun `CIRCLE_IR_INSTRUMENT_FINDINGS=1` across OWASP + top-25 Java + Python/JS/Go corpora with severity buckets; produce rule-pair overlap catalog + coalesce-policy recommendation |

### #1 detail (kept from prior version)

**#1** (re-opened 2026-06-10) — Jenkins `@DataBoundConstructor` cross-instance field-binding taint. Sink (3.23.2) + source detection (3.23.3) both shipped; remaining is cross-instance DFG flow analysis (~420 LOC, 7/10 difficulty, moderate-to-high regression risk on OWASP/Juliet/SecuriBench 100/100/97.7% TPR benchmarks). **Deferred to cognium-ai triage** with explicit posted analysis — if LLM-discovery already covers this CVE, close as won't-fix; if not, prioritize with explicit benchmark-gate plan. Cross-instance field-binding propagation shipped 3.39.0 per `TODO.md` — verify closes the Jenkins path end-to-end and close.

### Recently closed
- #243 closed 2026-07-23 (Go taint-propagation shapes — all 4 shipped in one release 3.182.0: closure capture test lock, range-clause loop-carried via `extractGoUses` on range subject, opaque-codec roundtrip via `dfg.ts` dest re-def for json/xml/yaml/gob Unmarshal + Decoder.Decode + companion compound-expression sink-match in `taint-propagation.ts`, package-global store/read via `detectGoPackageGlobalFlows` supplement; 4212 pass 0 regressions; commit c3bbb72)
- #254 closed 2026-07-23 (perf deep-dive umbrella — 9 releases shipped 3.171.0–3.177.0 (T1 H1+H7+H8, T2-A+C, T2-D, T1#5, T2#7, T2#10, T1#2, T2#9, T2#6 bundled); T2#8 subsumed by T2-A/C/D post-shared-nodeCache (measurement showed target phases at ~5% of `analyze()`, refactor cost thousands of LOC across 6+ languages for < 5% savings); perf harness spun out and closed as #263)
- #261 closed 2026-07-23 (dependencyContext extensions — all 4 ecosystems shipped: Gradle direct+catalog+strictly, Python PyYAML ≥ 6.0 gate, Rust plumbing, npm plumbing across 3.179.0/3.180.0/3.181.0; only speculative gate-consumer additions remain for npm+Rust with no clean version-safety stories, and Gradle `platform()` BOM is a deliberate no-op)
- #264 closed 2026-07-23 (format_string coverage — 8 Java+Go sink additions, Logger CWE-117 vs CWE-134 decision, PythonReceiverTaintFormatPass with 3.181.0 rewire, `.format_map` extension across 3.179.0/3.180.0/3.181.0; `%`-operator LHS-taint cancelled as pre-existing in Sprint 86; only variant-coverage matrix rerun remains, blocked on external corpora — same as #262)
- #240 closed 2026-07-23 (zero-recall category coverage — ship 1 (3.175.0 `open_redirect` + `trust_boundary`), ship 2 (3.177.0 `deserialization` + `nosql_injection` + Go local-receiver resolver), fiber-flow residual fixed via #260 6d28db3, `format_string` split out to #264)
- #263 closed 2026-07-23 (perf harness + baseline checked in — `packages/circle-ir/perf/{harness.mjs, README.md, BASELINE.md}`; deterministic synthetic Java fixtures; commit 0104f72; unreleased on main pending next release cut)
- #260 closed 2026-07-23 (Go fiber `c.Redirect` arg[0] flow gap — root cause was sink-dedup ordering, fix is a +0.05 exact-class-match confidence tiebreaker in `calculateSinkConfidence`; commit 6d28db3; unreleased on main pending next release cut)
- #258 closed 2026-07-23 (deserialization-safety gate — Fastjson `*_noneautotype` manifest gate + Jackson polymorphism in-file gate + SnakeYAML SafeConstructor in-file gate; released as circle-ir 3.178.0 / commit de134a5)
- #143 closed 2026-07-23 (note-level finding coalescer — additive `labels[]` on `SastFinding` folds level==='note' groups at same (file, line); MVP of 2026-07-03 reopen; released as circle-ir 3.178.0 / commit a4eb173)
- #257 closed 2026-07-23 (Java code_injection `*Parser` semantic gate — inverse-denylist model; released as circle-ir 3.177.0 / commit fdfd0f7)
- #256 closed 2026-07-22 (sink-shape indirection resolver landed 3.176.0 · e085094 · 4070/4075 tests pass · harness verification deferred)
- #259 closed 2026-07-22 (langchain4j ShellCommandRunner TP → promoted to #172 pending-decision table; no upstream filing)
- #248 closed 3.174.0 (prompt-injection sink category / CWE-1427)
- #255 closed 3.174-window (OSS hygiene files)
- #251 closed (CWE-Bench-Rust F1 drift bisect + pin) → surfaced work in 3.169.0
- #250, #252, #253 closed 3.166.x window (source-line gating, JS entry-point extraction, sanitizer-credit gaps)
- #16 closed 3.28.0 (WASM tree leak), #15 closed 3.34.0 (runtime-registration Phase 1+2+3), #14 + #12 closed 3.29.0, #11 + #10 closed 3.31.0, #8 closed 3.30.0
- #7 / #9 / #13 shuttled to cognium-ai (cognium-ai#73 / #74 / #67) — semantic/harness scope, not deterministic SAST
- #1, #2, #3 closed as of 3.23.3 (initial round); #4 + #6 closed 3.23.5; #5 closed 3.24.0
- #1 later re-opened after cross-instance flow gap surfaced in CWE-Bench-Java retest

---

## Phase Milestones (from techspec)

| Phase | Milestone | Status |
|-------|-----------|--------|
| Phase 1 (May 2026) | Java benchmarks published | Pending |
| Phase 1 (Aug 2026) | 1000-repo PR campaign | Pending |
| Phase 1 (Aug 2026) | GitHub Action GA | Pending |
| Phase 2 (Q4 2026) | 5-language production | Pending |
| Phase 3 (Q1 2027) | On-prem GA | Pending |
