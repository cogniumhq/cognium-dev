# circle-ir Pass & Metric Registry

Single source of truth for every analysis pass and metric in circle-ir.
**This file is the reference — all code, tests, and docs use these canonical identifiers.**

Scope rule: circle-ir contains **SAST passes** (`mode: sast`) and **metrics** only.
Passes marked `mode: sast+llm` belong to **circle-ir-ai** — never add them here.

---

## Field Definitions

| Field | Values | Meaning |
|-------|--------|---------|
| `#` | integer | Canonical pass number (matches COGNIUM_IMPLEMENTATION_GUIDE §4) |
| `rule_id` | kebab-case string | Value used in `SastFinding.rule_id` |
| `category` | `PassCategory` | ISO 25010 category: `security \| reliability \| performance \| maintainability \| architecture` |
| `CWE` | `CWE-NNN` or `—` | Base-level CWE reference; `—` when no applicable CWE |
| `level` | SARIF 2.1.0 | `error` (critical/high) · `warning` (medium) · `note` (low/info) |
| `graphs` | edge types | Comma-separated required graph capabilities |
| `status` | see legend | Current implementation state |

**Status legend:**
- `shipped` — in production, all tests passing
- `phase-1` — next implementation batch (existing graphs only or new cheap graph)
- `phase-2` — metrics engine work
- `phase-4` — requires advanced graph (dominator tree, exception flow, or type hierarchy)
- `llm-only` — circle-ir-ai scope; never implement here

**Graph abbreviations:**
`ast` · `cfg` · `dfg` · `cg` (call graph) · `taint` · `scope` · `imports` · `dom` (dominator tree) · `throws` (exception flow) · `inherit` (type hierarchy)

---

## A. Security Passes (all shipped, category = `security`)

All 19 passes operate on the `taint` graph. SARIF level: `error`.

| # | rule_id | CWE | Description |
|---|---------|-----|-------------|
| 1 | `sql-injection` | CWE-89 | User input in SQL without parameterization |
| 2 | `command-injection` | CWE-78 | User input in shell exec/system |
| 3 | `xss` | CWE-79 | User input in HTML output without encoding |
| 4 | `path-traversal` | CWE-22 | User input in file path operations |
| 5 | `ssrf` | CWE-918 | User input in outbound HTTP URL |
| 6 | `deserialization` | CWE-502 | Untrusted data passed to deserialization |
| 7 | `xxe` | CWE-611 | External entities enabled in XML parser |
| 8 | `ldap-injection` | CWE-90 | User input in LDAP query string |
| 9 | `xpath-injection` | CWE-643 | User input in XPath expression |
| 10 | `nosql-injection` | CWE-943 | User input in NoSQL query |
| 11 | `code-injection` | CWE-94 | User input in eval/exec/ScriptEngine |
| 12 | `open-redirect` | CWE-601 | User input controls HTTP redirect target |
| 13 | `log-injection` | CWE-117 | User input written to log without sanitization |
| 14 | `trust-boundary` | CWE-501 | Tainted data crosses trust boundary (e.g. session write) |
| 15 | `external-taint` | CWE-668 | External input reaches sensitive operation (interprocedural) |
| 16 | `weak-random` | CWE-330 | Math.random / java.util.Random / random.* / math/rand in security context (pattern pass — see §A6) |
| 17 | `weak-hash` | CWE-328 | MD5 or SHA-1 used for security purposes (pattern pass — see §A6) |
| 18 | `weak-crypto` | CWE-327 / CWE-329 / CWE-321 / CWE-326 | Weak ciphers, ECB mode, static/zero IV, hardcoded symmetric key, weak RSA key size (< 2048) (pattern pass — see §A6) |
| 19 | `insecure-cookie` | CWE-614 | Cookie set without Secure or HttpOnly flag (pattern pass — see §A6) |

### A2. HTML Security Passes (category = `security`, HTML files only)

Attribute-level checks on HTML AST. No IR/taint graph required.

| # | rule_id | CWE | level | status | Description |
|---|---------|-----|-------|--------|-------------|
| H1 | `html-missing-noopener` | CWE-1022 | warning | shipped | `<a target="_blank">` missing `rel="noopener"` |
| H2 | `html-javascript-uri` | CWE-79 | error | shipped | `javascript:` URI in href/src/action |
| H3 | `html-missing-sandbox` | CWE-1021 | warning | shipped | `<iframe>` without `sandbox` attribute |
| H4 | `html-mixed-content` | CWE-319 | warning | shipped | HTTP resource loaded (script/link/img/iframe src) |
| H5 | `html-missing-sri` | CWE-353 | warning | shipped | External CDN script/stylesheet without `integrity` |
| H6 | `html-autocomplete-sensitive` | CWE-525 | note | shipped | Sensitive input without `autocomplete="off"` |
| H7 | `html-inline-event-handler` | CWE-79 | note | shipped | Inline `on*` handler (CSP incompatible) |
| H8 | `html-form-action-javascript` | CWE-79 | error | shipped | `<form action="javascript:...">` |

### A3. Security Headers Pass (category = `security`)

Pass #89 `security-headers` inspects HTTP response-header writes
(`setHeader`/`addHeader`/`set`/`header`/`insert_header`) and handler presence.
Emits findings for clickjacking (CWE-1021) and CORS misconfiguration
(CWE-346 / CWE-942). Rule table is defined in `config-loader.ts` as
`DEFAULT_HEADER_RULES` and overridable via `passOptions.securityHeaders.rules`.

| # | rule_id | CWE | level | status | Description |
|---|---------|-----|-------|--------|-------------|
| 89a | `missing-x-frame-options` | CWE-1021 | warning | shipped | HTTP handler does not set `X-Frame-Options` |
| 89b | `x-frame-options-allow-from` | CWE-1021 | warning | shipped | `X-Frame-Options: ALLOW-FROM` is deprecated and browser-unsupported |
| 89c | `missing-csp-frame-ancestors` | CWE-1021 | note | shipped | HTTP handler does not set `Content-Security-Policy` |
| 89d | `cors-wildcard-origin` | CWE-942 | error | shipped | `Access-Control-Allow-Origin: *` permits cross-origin from any site |
| 89e | `cors-null-origin` | CWE-346 | error | shipped | `Access-Control-Allow-Origin: null` exploitable via sandboxed iframes |
| 89f | `cors-http-origin` | CWE-346 | warning | shipped | Allowed origin uses insecure `http://` scheme |
| 89g | `cors-reflected-origin` | CWE-346 | error | shipped | `Access-Control-Allow-Origin` set to a dynamic (non-literal) value |
| 89h | `xfo-csp-mismatch` | CWE-1021 | warning | shipped | `X-Frame-Options` and CSP `frame-ancestors` disagree (e.g. XFO=DENY but CSP allows framing) |

### A4. Secret Scanner Pass (category = `security`)

Pass #90 `scan-secrets` detects hardcoded credentials across all 7
supported languages via two detection layers, with deduplication
against the legacy Bash `hardcoded-credential` detection in
`LanguageSourcesPass`. Test-file paths are skipped (`__tests__/`,
`*.test.*`, `*Test.java`, etc.).

| # | rule_id | CWE | level | status | Description |
|---|---------|-----|-------|--------|-------------|
| 90a | `hardcoded-credential` | CWE-798 | error | shipped | Provider-specific regex hits (AWS AKIA, GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, Stripe `sk_live_`/`pk_live_`, OpenAI `sk-`, Anthropic `sk-ant-`, Slack `xox[baprs]-`, Google `AIza`, JWT, PEM private key, npm `npm_`) |
| 90b | `hardcoded-credential-entropy` | CWE-798 | warning | shipped | Shannon-entropy ≥ 4.3 bits/char (base64) or ≥ 3.5 bits/char (hex) on string literals 20–200 chars; UUID/hash/placeholder/base64-JSON denylisted; threshold lowered by 0.2 when surrounding line names a credential variable |

### A5. Spring4Shell Pass (category = `security`, Java only)

Pass #91 `spring4shell` is a pattern pass (no taint graph required) that detects
the Spring4Shell (CVE-2022-22965) implicit form-data binding RCE shape on
Spring MVC controller methods. Fires when ALL hold: (a) class has `@Controller`
/ `@RestController` / `@ControllerAdvice`, (b) method has a route annotation
(`@RequestMapping` / `@GetMapping` / `@PostMapping` / `@PutMapping` /
`@DeleteMapping` / `@PatchMapping`), (c) a parameter has NO binding annotation
(`@RequestBody` / `@RequestParam` / `@PathVariable` / `@ModelAttribute` /
`@RequestHeader` / `@CookieValue` / `@MatrixVariable` / `@RequestPart` /
`@Valid` / `@Validated` / `@SessionAttribute` / `@RequestAttribute` all
suppress), (d) the parameter type is not a Spring framework type
(`HttpServletRequest`, `Model`, `Principal`, `MultipartFile`, …), (e) the
parameter type is not a scalar (`String`, primitives, `BigDecimal`, `UUID`,
`LocalDate`, …). Complements the existing `code-injection` pass (#11) which
covers explicit `DataBinder.bind()` / `DataBinder.setPropertyValues()` sinks;
Spring4Shell-vulnerable code typically does not make those calls (Spring does
it implicitly), so a taint flow alone misses the shape.

| # | rule_id | CWE | level | status | Description |
|---|---------|-----|-------|--------|-------------|
| 91 | `spring4shell` | CWE-94 | error | shipped | Spring MVC controller method binds a POJO parameter via implicit form-data binding (no `@RequestBody`/`@RequestParam`/`@ModelAttribute`) — vulnerable to CVE-2022-22965 on Spring < 5.3.18 / 5.2.20 |

### A6. Config / Absence Pattern Passes (category = `security`)

Passes #16–#19 + #92 detect **configuration-or-absence vulnerabilities** — the
bad value is a hard-coded constant (or a missing flag), not a tainted value
flowing from a source. Detection inspects call-site literals, argument
expression text, and (for shapes that do not surface as IR calls) the file
source text. These passes do **not** require sources/sinks/sanitizers; they
ran as broken taint-sink registrations before 3.52.0 and have been moved out
of `config-loader.ts` into dedicated `AnalysisPass` implementations.

| # | rule_id | CWE | level | status | Description |
|---|---------|-----|-------|--------|-------------|
| 16 | `weak-random` | CWE-330 | warning | shipped | Non-cryptographic PRNG used (Java `new Random()` / `Math.random` / `ThreadLocalRandom`, Python `random.*`, JS `Math.random`, Go `math/rand` — import-aware to avoid `crypto/rand` FPs). Mirrors gosec G404 / Bandit B311 |
| 17 | `weak-hash` | CWE-328 | warning | shipped | MD2/MD4/MD5/SHA-1 via Java `MessageDigest.getInstance`, Apache Commons `DigestUtils.{md5,sha1}{,Hex}`, Python `hashlib.{md5,sha1,new("md5",…)}`, JS `crypto.createHash`/`createHmac`, Go `crypto/md5` + `crypto/sha1`. Mirrors gosec G401 / Bandit B303 |
| 18 | `weak-crypto` | CWE-327 / CWE-329 / CWE-321 / CWE-326 | error | shipped | Weak symmetric cipher (DES/3DES/RC2/RC4/Blowfish/IDEA/SEED/CAST5) **or** ECB mode (incl. Java AES default = ECB) via Java `Cipher.getInstance`, Python pycryptodome `*.new(...)`/`AES.new(key, MODE_ECB)` and `cryptography.hazmat algorithms.{TripleDES,Blowfish,ARC4,…}`, JS `crypto.createCipher` (deprecated) / `createCipheriv("…-ecb"|"des-…")`, Go `des.NewCipher`/`des.NewTripleDESCipher`/`rc4.NewCipher`. **Java config patterns (issue #87):** static/zero IV (`new IvParameterSpec(new byte[N])`, `"…".getBytes()` → CWE-329), hardcoded symmetric key material (`new SecretKeySpec("…".getBytes(), …)` → CWE-321), weak RSA key size (`KeyPairGenerator.initialize(<2048)` → CWE-326). Mirrors gosec G401/G405 / Bandit B304/B305 |
| 19 | `insecure-cookie` | CWE-614 | warning | shipped | Cookie set without Secure / HttpOnly: Express `res.cookie(name, val, opts)` and Fastify `reply.cookie`, Python Flask/Django/Starlette `response.set_cookie(...)`, Java `new javax.servlet.http.Cookie(...)` without `setSecure(true)` + `setHttpOnly(true)` (text-based heuristic — full DFG-based version requires variable-to-call linkage) |
| 92 | `tls-verify-disabled` | CWE-295 | error | shipped | TLS certificate / hostname verification disabled: Go `tls.Config{InsecureSkipVerify: true}` (source-text scan — composite literals are not IR calls), Python `requests/httpx(verify=False)` + `ssl._create_unverified_context` + module-level `ssl._create_default_https_context` override, JS `rejectUnauthorized: false` in any args + `process.env.NODE_TLS_REJECT_UNAUTHORIZED='0'` assignment, Java `setHostnameVerifier((h,s)->true)` / `NoopHostnameVerifier.INSTANCE` / `AllowAllHostnameVerifier`. Mirrors gosec G402 / Bandit B501/B504/B505 |

---

## B. Reliability Passes (category = `reliability`)

| # | rule_id | CWE | level | graphs | status | Description |
|---|---------|-----|-------|--------|--------|-------------|
| 20 | `null-deref` | CWE-476 | error | dfg, cfg | shipped | Nullable source reaches dereference with no null guard on all CFG paths |
| 21 | `resource-leak` | CWE-772 | error | cfg, dfg | shipped | Resource opened, not closed on at least one exception exit path |
| 22 | `dead-code` | CWE-561 | warning | cfg | shipped | CFG block unreachable from any entry point |
| 23 | `infinite-loop` | CWE-835 | warning | cfg | shipped | CFG loop with no reachable exit edge (back-edge analysis + keyword fallback) |
| 24 | `missing-await` | CWE-252 | warning | ast, cg | shipped | Async function called without `await`; Promise result discarded |
| 25 | `double-close` | CWE-675 | warning | cfg, dfg | shipped | Resource closed twice within the same method — may throw |
| 26 | `use-after-close` | CWE-672 | error | dfg, cfg | shipped | Method call on a resource after it has been closed |
| 28 | `unchecked-return` | CWE-252 | warning | cg, dfg | shipped | Return value ignored where most callers check it (statistical) |
| 48 | `sync-io-async` | CWE-1050 | warning | ast, cg | shipped | Blocking I/O call (`readFileSync`, `requests.get`) inside async function |
| 50 | `string-concat-loop` | CWE-1046 | warning | dfg, cfg | shipped | `string +=` inside loop body (O(n²) allocations) |
| 53 | `missing-guard-dom` | CWE-285 | error | dom, cg | **removed from pipeline** (v3.14.0) | High FP rate in framework-auth codebases; raw signals in `ir.calls`+`ir.cfg`; reserved for circle-ir-ai |
| 54 | `cleanup-verify` | CWE-772 | warning | dom, dfg | shipped | Resource cleanup does not post-dominate its acquisition (Java, Python, JS/TS) |
| 74 | `unhandled-exception` | CWE-390 | warning | cfg | shipped | throw/raise not covered by any try/catch in the same function (JS/TS, Python) |
| 75 | `broad-catch` | CWE-396 | warning | cfg | shipped | catch(Exception) / bare except — catches more than intended (Java, Python) |
| 76 | `swallowed-exception` | CWE-390 | warning | cfg | shipped | Catch block with no throw, log, or return — exception silently discarded |
| 79 | `variable-shadowing` | CWE-1109 | warning | scope | shipped | Inner scope declares same-name variable as outer scope |
| 81 | `leaked-global` | CWE-1109 | warning | scope | shipped | Assignment without declaration (accidental global in JS/Python) |
| 82 | `unused-variable` | CWE-561 | note | scope, dfg | shipped | Variable declared but has no reads on any reachable path |

---

## C. Performance Passes (category = `performance`)

| # | rule_id | CWE | level | graphs | status | Description |
|---|---------|-----|-------|--------|--------|-------------|
| 45 | `n-plus-one` | CWE-1049 | warning | cfg, cg | shipped | DB or external API call inside a loop body |
| 46 | `redundant-loop-computation` | CWE-1050 | note | dfg, cfg | shipped | Loop-invariant `.length`/`.size()`/`Math.*` recomputed every iteration |
| 47 | `unbounded-collection` | CWE-770 | warning | cfg, calls | shipped | Collection grows inside loop with no size check or clear |
| 49 | `unnecessary-object-hotpath` | — | note | cfg, ast | llm-only | Object construction in loop with invariant constructor args |
| P22 | `serial-await` | — | note | dfg, ast | shipped | Sequential awaits with no data dependency (JS/TS only; suggest Promise.all) |
| P33 | `react-inline-jsx` | — | note | ast | shipped | Inline object/function in JSX props (defeats React.memo; JS/TS only) |
| 83 | `blocking-main-thread` | CWE-1050 | warning | ast, cg | shipped | Crypto/*Sync calls inside HTTP request handlers (JS/TS); stalls event loop |
| 84 | `excessive-allocation` | CWE-770 | warning | cfg, ast | shipped | Collection/object allocation inside loop body; GC pressure |
| 85 | `missing-stream` | — | note | ast, cg | shipped | Whole-file / whole-response read without streaming (JS/TS, Java, Python) |

---

## D. Maintainability Passes (category = `maintainability`)

| # | rule_id | CWE | level | graphs | status | Description |
|---|---------|-----|-------|--------|--------|-------------|
| 33 | `stale-doc-ref` | — | note | ast, imports | shipped | Doc comment references a symbol that no longer exists |
| 35 | `missing-public-doc` | — | note | ast | shipped | Public/exported function or type has no doc block |
| 36 | `todo-in-prod` | — | note | ast | shipped | TODO/FIXME/HACK comment in non-test production file |
| 30 | `doc-param-mismatch` | — | warning | ast, dfg | llm-only | @param documented but not in signature, or vice versa |
| 31 | `return-type-mismatch` | — | warning | cfg, ast | llm-only | Doc says "never null" but CFG shows null return path |
| 32 | `throws-mismatch` | — | note | throws, ast | llm-only | @throws documented but unreachable, or thrown but undocumented |
| 34 | `doc-wrong-behavior` | — | warning | depends, ast | llm-only | Graph-derived effects contradict the doc description |
| 37 | `deprecation-no-replacement` | — | note | ast, cg | llm-only | @deprecated with no replacement documented; callers still exist |
| 38 | `inconsistent-error-handling` | — | warning | cg, cfg | llm-only | Most callers use try/catch for a function; one doesn't |
| 39 | `inconsistent-naming` | — | note | ast | llm-only | 95%+ of boolean getters are isX/hasX; outlier uses different pattern |
| 40 | `inconsistent-param-order` | — | note | ast | llm-only | Related functions have different parameter ordering |
| 44 | `magic-numbers` | — | note | ast, dfg | llm-only | Unexplained numeric literal in non-constant context |
| 88 | `naming-convention` | — | note | ast | shipped | Class/method/field names violate language conventions (PascalCase, camelCase, snake_case); I-prefix interface check is opt-in via `passOptions.namingConvention.enforceIPrefix` |

---

## E. Architecture Passes (category = `architecture`)

| # | rule_id | CWE | level | graphs | status | Description |
|---|---------|-----|-------|--------|--------|-------------|
| 62 | `deep-inheritance` | CWE-1086 | warning | types | shipped | Inheritance depth > 5 levels (walks ir.types extends chain) |
| 64 | `missing-override` | — | warning | inherit, ast | shipped | Method matches supertype signature but lacks @Override annotation (Java only) |
| 66 | `unused-interface-method` | — | note | inherit, cg | shipped | Interface method declared but never called through that interface (Java, TS) |
| 68 | `circular-dependency` | CWE-1047 | warning | imports | shipped | Cycle in module/package import graph (Tarjan's SCC) |
| 71 | `orphan-module` | — | note | imports | shipped | File has no incoming imports and is not a declared entry point |
| 72 | `dependency-fan-out` | — | note | imports | shipped | Module imports 20+ other modules (high efferent coupling) |
| 86 | `god-class` | CWE-1060 | warning | cfg, dfg, cg | shipped | Class with high WMC (>47), LCOM2 (>0.8), or CBO (>14) — 2 of 3 thresholds |
| 87 | `feature-envy` | CWE-1060 | note | cg | **removed from pipeline** (v3.14.0) | Fires on legitimate delegation/facade patterns; raw signals in `ir.calls`+`ir.types`; reserved for circle-ir-ai |

---

## F. Implementation Phases Summary

| Phase | Focus | Passes | New graphs |
|-------|-------|--------|------------|
| **0 (done)** | Architecture foundation | — | CodeGraph lazy indexes, AnalysisPipeline, ProjectGraph, CrossFilePass, taxonomy types |
| **1 (done)** | High-impact SAST passes | ~~#22, #24, #45, #35, #36, #20, #21, #28, #48, #50, #79, #81, #82, #33, #68, #71, #72~~ ✓ | scope graph, import graph |
| **2 (done)** | Metrics engine | — (metrics, not passes) | MetricRunner + 9 metric passes; 24 metrics (LOC, NLOC, comment_density, function_count, cyclomatic_complexity, WMC, loop_complexity, condition_complexity, halstead_volume/difficulty/effort/bugs, data_flow_complexity, CBO, RFC, DIT, NOC, LCOM, doc_coverage, maintainability_index, code_quality_index, bug_hotspot_score, refactoring_roi) wired into `analyze()` |
| **4 (done)** | Advanced graphs + passes | ~~#23, #25, #26, #46, #47, #53, #54, #62, #64, #66, #74, #75, #76, P22, P33~~ ✓ | dominator tree, exception flow, type hierarchy wired to taint |
| **5 (done)** | Performance + Architecture + Maintainability | ~~#83, #84, #85, #86, #87, #88~~ ✓ | blocking handler detection, in-loop allocation, whole-file read, god class, feature envy, naming conventions |

> Phase 3 (LLM passes) and Phase 5 (semantic understanding) belong to **circle-ir-ai**.

---

## G. Metric Registry

Standard metric names (use these exact strings in `MetricValue.name`).
All metrics belong to circle-ir — no LLM required.

### Complexity (`MetricCategory = 'complexity'`)

| name | Standard | ISO 25010 | scope | formula / method |
|------|----------|-----------|-------|------------------|
| `v(G)` | McCabe 1976 / IEEE Std 1008 | Maintainability.Testability | function | `edges − nodes + 2` on CFG |
| `essential_complexity` | McCabe 1976 | Maintainability.Analysability | function | `v(G)` after removing structured reducible subgraphs |
| `cognitive_complexity` | SonarSource | Maintainability.Analysability | function | Penalty accumulation on AST nesting + breaks |
| `nesting_depth_max` | — | Maintainability.Analysability | function | Max block nesting depth from AST |
| `nesting_depth_avg` | — | Maintainability.Analysability | function | Average nesting depth across all branches |
| `path_count` | — | Maintainability.Testability | function | Distinct entry→exit paths in CFG |
| `loop_complexity` | — | Maintainability.Analysability | function | Count of back-edges in CFG |
| `condition_complexity` | — | Maintainability.Analysability | function | Count of `&&` / `\|\|` / `!` in branch conditions |
| `halstead_volume` | Halstead 1977 | Maintainability.Analysability | function | `V = N × log₂(n)` where N=total operators+operands, n=unique |
| `halstead_difficulty` | Halstead 1977 | Maintainability.Analysability | function | `D = (n1/2) × (N2/n2)` |
| `halstead_effort` | Halstead 1977 | Maintainability.Analysability | function | `E = D × V` |
| `halstead_bugs` | Halstead 1977 | Reliability.Faultlessness | function | `B = E^(2/3) / 3000` |
| `data_flow_complexity` | — | Maintainability.Analysability | function | Count of def-use chains from DFG |
| `variable_liveness_span` | — | Maintainability.Analysability | function | Avg span (CFG nodes) between def and last use |
| `fan_in_data` | — | Maintainability.Analysability | function | Count of distinct data inputs (DFG reads from outside) |
| `fan_out_data` | — | Maintainability.Analysability | function | Count of distinct data outputs (DFG writes observable outside) |
| `state_mutation_count` | — | Reliability.Faultlessness | function | Count of writes to non-local variables |

### Size (`MetricCategory = 'size'`)

| name | Standard | ISO 25010 | scope |
|------|----------|-----------|-------|
| `LOC` | standard | Maintainability.Analysability | file/function |
| `NLOC` | standard | Maintainability.Analysability | file/function |
| `comment_density` | — | Maintainability.Analysability | file/function |
| `WMC` | CK suite (Chidamber & Kemerer 1994) | Maintainability.Analysability | class |
| `function_count` | — | Maintainability.Analysability | file/class |
| `parameter_count` | — | Maintainability.Analysability | function |
| `statements` | — | Maintainability.Analysability | function |

### Coupling (`MetricCategory = 'coupling'`)

| name | Standard | ISO 25010 | scope |
|------|----------|-----------|-------|
| `CBO` | CK suite | Maintainability.Modularity | class |
| `RFC` | CK suite | Maintainability.Modularity | class |
| `Ca` | Robert Martin | Maintainability.Modularity | function/module |
| `Ce` | Robert Martin | Maintainability.Modularity | function/module |
| `instability` | Robert Martin | Maintainability.Modularity | function/module |
| `import_depth` | — | Maintainability.Modularity | module |
| `dep_graph_density` | — | Maintainability.Modularity | codebase |
| `api_surface_ratio` | — | Maintainability.Modularity | module |
| `internal_reuse` | — | Maintainability.Modularity | codebase |
| `module_cycle_count` | — | Maintainability.Modularity | codebase |

### Inheritance (`MetricCategory = 'inheritance'`)

| name | Standard | ISO 25010 | scope |
|------|----------|-----------|-------|
| `DIT` | CK suite | Maintainability.Reusability | class |
| `NOC` | CK suite | Maintainability.Reusability | class |

### Cohesion (`MetricCategory = 'cohesion'`)

| name | Standard | ISO 25010 | scope |
|------|----------|-----------|-------|
| `LCOM` | CK suite | Maintainability.Modularity | class |
| `LCOM4` | Hitz & Montazeri | Maintainability.Modularity | class |
| `TCC` | Bieman & Kang | Maintainability.Modularity | class |

### Documentation (`MetricCategory = 'documentation'`)

| name | Standard | ISO 25010 | scope |
|------|----------|-----------|-------|
| `doc_coverage` | — | Maintainability.Analysability | file/class |

### Duplication (`MetricCategory = 'duplication'`)

| name | Standard | ISO 25010 | scope |
|------|----------|-----------|-------|
| `duplicate_ratio` | — | Maintainability.Analysability | file/codebase |
| `clone_count` | — | Maintainability.Analysability | codebase |

### Composite Scores

Computed from the primitives above. Not `MetricValue` entries — separate `CompositeScore` type (to be added in Phase 2).

| name | Formula |
|------|---------|
| `maintainability_index` | `171 − 5.2×ln(halstead_volume) − 0.23×v(G) − 16.2×ln(LOC) + 50×sin(√(2.4×comment_density))` |
| `code_quality_index` | `0.30×MI + 0.25×testability + 0.20×coupling + 0.15×doc_coverage + 0.10×(1−duplicate_ratio)` |
| `bug_hotspot_score` | `v(G) × CBO × state_mutation_count × (1 / max(test_indicators, 1))` |
| `refactoring_roi` | `(bug_hotspot × Ca) / (v(G) + LOC)` |

---

*Last updated: 2026-03-25*
