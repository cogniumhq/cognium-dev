# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.23.1] - 2026-05-28

### Fixed

- **Sink misclassifications removed** (closes #3) — 20 sink entries had wrong `type` / `cwe` values from an earlier "Auto-mined from CVE analysis" pass and have been deleted in favor of the canonical entries in the correct files:
  - `configs/sinks/sql.yaml` — removed 6 non-SQL entries (`File`, `FileInputStream`, `getResource`, `URL.openConnection`, `URL.openStream`, `Class.forName`)
  - `configs/sinks/path.yaml` — removed 10 non-path entries (`XPath.compile`, `PrintWriter.println`, `Class.forName`, `newInstance`, `ObjectInputStream.readObject`, `Statement.execute`/`executeQuery`/`executeUpdate`, `ProcessBuilder.start`, `PrintWriter.print`)
  - `configs/sinks/code_injection.yaml` — removed 4 non-code-injection entries (`newInstance`, `ObjectInputStream.readObject`, `XPath.compile`, `PrintWriter.println`)
  - Net: 217 lines deleted across the three files. Canonical entries verified present in `ssrf.yaml`, `code_injection.yaml`, `deserialization.yaml`, `command.yaml`, `xpath.yaml`, and the proper sections of `sql.yaml` / `path.yaml`. Improves CWE-mapping accuracy with no loss of detection.

[3.23.1]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.23.0...circle-ir-v3.23.1

## [3.23.0] - 2026-05-28

### Added

- **MyBatis ORM SQL injection sinks** — 12 new sink patterns for MyBatis mapper methods vulnerable to SQL injection when using `${}` interpolation syntax: `insert`, `insertSelective`, `update`, `updateByPrimaryKey`, `updateByPrimaryKeySelective`, `delete`, `deleteByPrimaryKey`, `selectOne`, `selectList`, `selectByPrimaryKey`, `selectByExample`. Pattern matches the `*Mapper` class convention used by MyBatis Generator.

### Changed

- **Node engine** raised to `>=20.19.0` (was `>=20.0.0`) to align with modern toolchain requirements.
- **Parser** (`src/core/parser.ts`) — documented the `new Function` dynamic-import pattern used to hide Node built-ins from browser bundlers, including the Vitest VM caveat that requires explicit `wasmPath` / `languagePaths` in test setup.
- **Test setup** (`tests/setup.ts`) — pre-resolves WASM grammar paths so the Tree-sitter parser initializes deterministically under Vitest's VM pool (which doesn't expose a dynamic-import callback).

[3.23.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.22.3...circle-ir-v3.23.0

## [3.22.3] - 2026-05-21

### Fixed

- **Expand defensive-throw suppression (unhandled-exception)**: `isValidationThrow()` now suppresses `throw new Error(...)` (not just TypeError/RangeError) when preceded by a guard condition. Added `switch default:` as a guard context. Expanded guard regex to recognize `Array.isArray`, `instanceof`, `isFinite`, `isNaN`, `Number.isInteger`, `===`, `!==`. Lookback window increased from 3 to 5 lines. Eliminates 6 remaining FPs on Express `/lib`.
- **Fix swallowed-exception callback-forwarding detection**: The catch variable extraction now looks at both `catchLine` and `catchLine - 1` to handle CFG start_line pointing to the first body statement rather than the `catch (...)` declaration. Skips the declaration line during forwarding scan to prevent `catch (err)` from false-matching as a forwarding call. Fixes Express `application.js:629` `try { view.render(opts, cb); } catch (err) { cb(err); }` which was incorrectly flagged.

[3.22.3]: https://github.com/cogniumhq/circle-ir/compare/v3.22.2...v3.22.3

## [3.22.2] - 2026-05-21

### Fixed

- **Fix Rust multi-line Command chain sink detection**: `receiverMightBeClass()` now extracts the type name before `::` early, so multi-line chained receivers like `Command::new("sh")\n.arg("-c")\n.arg(&input)` correctly match `class: "Command"` sinks. Previously the scoped-call regex at line 690 failed because `.` doesn't match `\n`.
- **Strengthen Rust cmdi benchmark tests**: All 3 existing Rust command injection tests now assert both source detection and `command_injection` sink detection (previously source-only).

[3.22.2]: https://github.com/cogniumhq/circle-ir/compare/v3.22.1...v3.22.2

## [3.22.1] - 2026-05-20

### Fixed

- **Reduce false positives in taint analysis** with three targeted precision improvements:
  - **Receiver-type-aware sink filtering**: Expanded `SAFE_RECEIVERS_BY_METHOD` for `query()`, `authenticate()`, and `add()` to suppress false positives from classless sink patterns (e.g., `UriComponentsBuilder.query()` no longer flagged as SQL injection, `auth.authenticate()` no longer flagged as code injection).
  - **Placeholder-aware SQL injection filter**: `isParameterizedQueryCall()` now detects Go (`?`), Python (`%s`), Java (`:name`), and PostgreSQL (`$1`) placeholder patterns in query string literals, suppressing false positives for parameterized queries across all languages.
  - **Sink-type-aware `fromXML`/`unmarshal` filtering**: `fromXML()` and `unmarshal()` calls on XStream/XML receivers are only flagged as deserialization (CWE-502), no longer also flagged as command injection (CWE-78).
- **Tighten `receiverMightBeClass` heuristic**: Short receiver names (e.g., `auth`, `r`) no longer match unrelated classes via overly broad substring matching. Added fraction-based guards, CamelCase word-prefix matching, trailing-digit stripping, and explicit Go-idiom mappings (`r` → `Request`).
- **Remove classless `query` sink patterns**: Classless `{ method: 'query' }` entries that matched any `.query()` call removed from config-loader; class-constrained patterns (`Connection`, `Pool`, `Client`, `JdbcTemplate`, `sqlx`) retained.
- **Fix bash call extraction**: `eval "echo $user"` no longer has the command name duplicated as arg[0]. Fixed tree-sitter node identity check to use `child.id === nameNode.id`.
- **Bash taint flow end-to-end**: `curl`→`eval` and `$1`→`eval` taint flows now correctly propagate through bash variable assignments.

### Added

- 40 new precision tests: receiver-type filtering (23), placeholder SQL filtering (13), bash taint flow diagnostics (4).

[3.22.1]: https://github.com/cogniumhq/circle-ir/compare/v3.22.0...v3.22.1

## [3.22.0] - 2026-05-17

### Added

- **Go language support**: Full Go SAST analysis with parsing, type/call/import extraction, DFG, CFG, taint analysis, and framework detection.
  - **GoPlugin** (`src/languages/plugins/go.ts`): Struct/interface extraction with field types, method-to-type matching via receiver, call extraction with argument tracking, import extraction (single, grouped, aliased, blank `_`, dot `.`).
  - **DFG builder** (`buildGoDFG`): Tracks short var declarations (`:=`), var declarations, assignments, function parameters, method receivers, range clause variables, multiple return values (`x, err := ...`), blank identifier skipping, top-level package vars.
  - **CFG builder** (`buildGoCFG`): Function and method body processing via `buildMethodCFG`, top-level declarations as synthetic block.
  - **Taint sources** (18 patterns): `net/http` (FormValue, PostFormValue, Header.Get, Cookie, ReadAll), Gin (Query, Param, PostForm, GetRawData, BindJSON), Echo (QueryParam, FormValue, Param), stdlib (Getenv, ReadFile, Scanner.Text, fmt.Scan).
  - **Taint sinks** (14 patterns): SQL injection (db.Query/QueryRow/Exec, tx.Query), command injection (exec.Command/CommandContext), path traversal (os.Open/ReadFile/WriteFile), XSS (fmt.Fprintf, ResponseWriter.Write), SSRF (http.Get/Post), deserialization (json.Unmarshal, Decoder.Decode).
  - **Sanitizers** (4 patterns): db.Prepare (SQL), filepath.Clean (path), html.EscapeString (XSS), template.HTMLEscapeString (XSS).
  - **Framework detection**: Gin, Echo, Fiber, Chi, net/http.
  - **67 tests** covering parsing, imports, types, calls, DFG, CFG, taint analysis, framework detection, and edge cases.

### Fixed

- **Go CFG `isJavaScript` flag**: `buildGoCFG` was passing `isJavaScript=true` to `buildMethodCFG`; corrected to `false`.

[3.22.0]: https://github.com/cogniumhq/circle-ir/compare/v3.21.0...v3.22.0

## [3.21.0] - 2026-05-07

### Added

- **Bash taint sources — positional parameters**: `$1`–`$9`, `$@`, `$*` registered as `io_input` taint sources with synthetic DFG defs (`kind: 'param'` at line 0) enabling def-use chains from script arguments to sinks like `eval`.
- **Bash taint sources — command substitution**: `$(curl ...)`, `$(wget ...)`, `$(nc ...)` assignments registered as `network_input` sources; `$(cat ...)`, `$(head ...)`, `$(tail ...)`, etc. as `file_input` sources.
- **Bash taint sources — environment variables**: Known untrusted env var patterns (`$USER_INPUT`, `$HTTP_*`, `$QUERY_STRING`, `$REMOTE_*`, CGI variables) registered as `env_input` sources. Safe vars (`$HOME`, `$PATH`) and locally-assigned vars are excluded.

### Fixed

- **Duplicate DFG uses in Bash**: Removed redundant `extractBashUses()` call that duplicated `$VAR` uses already captured by the main AST walk in `buildBashDFG()`.

[3.21.0]: https://github.com/cogniumhq/circle-ir/compare/v3.20.0...v3.21.0

## [3.20.0] - 2026-05-06

### Added

- **Bash DFG builder**: `buildBashDFG()` tracks variable definitions (`variable_assignment`, `read` builtin, `for` loop variables) and uses (`$VAR`, `${VAR}` expansions) with reaching-definition resolution and def-use chains. Enables taint flow analysis for shell scripts.
- **Bash CFG builder**: `buildBashCFG()` processes `function_definition` bodies and top-level script body with entry/exit blocks. Control flow (`if`, `for`, `while`, `case`) handled via shared `processStatements()`.
- **Bash pattern-based findings** in LanguageSourcesPass:
  - `hardcoded-credential` (CWE-798) — detects `PASSWORD="literal"` patterns
  - `cleartext-transmission` (CWE-319) — detects `curl http://` and `wget http://`
  - `predictable-temp-file` (CWE-377) — detects `/tmp/predictable` without `mktemp`
  - `insecure-file-permission` (CWE-732) — detects `chmod 777` and `chmod 666`
  - `unsafe-archive-extraction` (CWE-22) — detects `tar -xf` without `--strip-components`

[3.20.0]: https://github.com/cogniumhq/circle-ir/compare/v3.19.5...v3.20.0

## [3.19.5] - 2026-04-26

### Added

- **Cross-file CORS inheritance detection**: `analyzeProject()` now resolves CORS misconfigurations inherited through class hierarchy. When a parent servlet writes `Access-Control-Allow-Origin` with a virtual method call and child classes override that method, the child's return value is resolved from source to emit `cors-null-origin`, `cors-wildcard-origin`, `cors-http-origin`, or `cors-reflected-origin` findings on the child file. Fixes 3 false negatives in Firing Range CORS benchmarks (AllowNullOrigin, DynamicAllowOrigin, AllowInsecureScheme).

[3.19.5]: https://github.com/cogniumhq/circle-ir/compare/v3.19.4...v3.19.5

## [3.19.4] - 2026-04-16

### Fixed

- **Template literal taint tracking**: Template strings with interpolations (`` `...${name}...` ``) are no longer treated as safe literals. The interpolated variable is now extracted and tracked through taint analysis, fixing false negatives for XSS via `res.send()` with template literals (NodeTest00018).

[3.19.4]: https://github.com/cogniumhq/circle-ir/compare/v3.19.3...v3.19.4

## [3.19.3] - 2026-04-16

### Fixed

- **TypeHierarchyResolver memoization**: `getAllSubtypes()` and `getAllImplementations()` now cache results, eliminating redundant BFS traversals in `matchesSinkPattern()`. Fixes O(calls × sinks × hierarchy²) blowup that caused timeouts on Servlet-heavy projects (e.g. DSpace 140 files → 300s timeout).
- **jQuery `.text()` false positive**: `.text()`, `.textContent`, `.innerText`, and `.createTextNode` excluded from `external_taint_escape` — these use safe textContent, not innerHTML.
- **Safe DOM/utility methods excluded from `external_taint_escape`**: `addClass`/`removeClass`/`toggleClass`, `parseInt`/`parseFloat`/`Number`/`String`/`Boolean` no longer flagged as external taint sinks.

[3.19.3]: https://github.com/cogniumhq/circle-ir/compare/v3.19.2...v3.19.3

## [3.19.2] - 2026-04-16

### Added

- **`xfo-csp-mismatch` rule** (CWE-1021, warning): Detects when `X-Frame-Options` and CSP `frame-ancestors` disagree in the same handler (e.g. XFO=DENY but CSP allows framing). Modern browsers use CSP, so the XFO header is effectively ignored.
- **Servlet handler detection**: `SecurityHeadersPass` now detects Java servlet handlers (`HttpServlet.doGet/doPost/service`) to enable missing-header rules on servlet-based code.
- **Logging methods excluded from external-taint-escape**: `console.log`, `println`, `printf` and other logging methods are no longer flagged as `external_taint_escape` sinks — reduces false positives in JavaScript and Java code.

### Fixed

- **JavaScript taint flow detection**: Fixed `isFalsePositive` in constant propagation to not suppress taint flows when the constant propagation engine hasn't tracked any symbols (common in JavaScript). Previously all JS taint flows were silently filtered as false positives.
- **JS DOM taint patterns in constant propagation**: Added `location.hash`, `document.cookie`, `window.name` and 11 other browser DOM taint sources to the constant propagation engine's `TAINT_PATTERNS`, ensuring consistency with the language-sources pass.
- **Top-level JS DFG extraction**: `buildJavaScriptDFG` now processes top-level expression statements (e.g. `eval(payload)` outside any function body), enabling taint flow detection for script-level code.

[3.19.2]: https://github.com/cogniumhq/circle-ir/compare/v3.19.1...v3.19.2

## [3.19.1] - 2026-04-16

### Fixed

- **Security headers constant resolution**: `SecurityHeadersPass` now resolves Java/framework constants like `HttpHeaders.X_FRAME_OPTIONS` → `X-Frame-Options` by converting SCREAMING_SNAKE_CASE field names to Header-Case. Fixes false negatives on Google Firing Range `invalidframingconfig` tests where all 7 test files use `HttpHeaders.X_FRAME_OPTIONS` instead of the literal string.

[3.19.1]: https://github.com/cogniumhq/circle-ir/compare/v3.19.0...v3.19.1

## [3.19.0] - 2026-04-16

### Added

- **Pass #89: `security-headers`** (category: `security`) — inspects HTTP response-header writes (`setHeader`/`addHeader`/`set`/`header`/`insert_header`) and handler presence to detect clickjacking (CWE-1021) and CORS misconfiguration (CWE-346 / CWE-942). Table-driven rules defined in `DEFAULT_HEADER_RULES` (`config-loader.ts`), overridable via `passOptions.securityHeaders.rules`.
  - `missing-x-frame-options` (CWE-1021, warning) — HTTP handler does not set `X-Frame-Options`
  - `x-frame-options-allow-from` (CWE-1021, warning) — `ALLOW-FROM` is deprecated and unsupported by modern browsers
  - `missing-csp-frame-ancestors` (CWE-1021, note) — HTTP handler does not set `Content-Security-Policy`
  - `cors-wildcard-origin` (CWE-942, error) — `Access-Control-Allow-Origin: *`
  - `cors-null-origin` (CWE-346, error) — `Access-Control-Allow-Origin: null` (exploitable via sandboxed iframes)
  - `cors-http-origin` (CWE-346, warning) — allowed origin uses insecure `http://` scheme
  - `cors-reflected-origin` (CWE-346, error) — `Access-Control-Allow-Origin` set to a dynamic (non-literal) value
- **New public type `HeaderRule`** in `src/types/config.ts` — declarative rule shape consumed by `SecurityHeadersPass`.
- **`passOptions.securityHeaders`** — override the default rule table at `analyze()` time.

### Architecture

- Security Headers analysis is a call-site literal inspection problem, not a data-flow problem. The pass reads `graph.ir.calls` + `graph.ir.types[].annotations` directly and does NOT participate in the taint source→sink machinery. Handler detection is heuristic and cross-language (Java/Kotlin annotations, Express/Koa routers, Python/Flask decorators, Rust attribute macros).

[3.19.0]: https://github.com/cogniumhq/circle-ir/compare/v3.18.8...v3.19.0

## [3.18.8] - 2026-04-16

### Added

- **Server-side XSS sanitizer aliases**: `encodeURL`, `urlEncode`, `escapeUrl`, `escapeURL` recognized as XSS/SSRF sanitizers (matches OWASP Firing Range `ServersideEscape` pattern)
- **Apache Commons `escapeHtml3`/`escapeHtml4`**: Added as XSS sanitizers
- **OWASP Java Encoder methods**: `Encode.forHtml`, `Encode.forHtmlContent`, `Encode.forHtmlAttribute`, `Encode.forJavaScript` recognized as XSS sanitizers
- **`htmlSpecialChars` wrapper**: Common PHP-style wrapper name added as XSS sanitizer
- **DOM taint-conduit globals**: `window.status`, `document.title`, `history.state`, `localStorage.getItem`, `sessionStorage.getItem` added to `JS_TAINTED_PATTERNS` — fixes DOMPropagation-style taint flows where attacker data is written to and read back from global DOM properties
- **CWE-94 code injection sinks (13 new entries)**:
  - **Apache Commons JEXL**: `JexlEngine.createExpression`, `JexlEngine.createScript`, `JexlExpression.evaluate`, `JexlScript.execute`
  - **Janino expression evaluator** (Calcite/Flink/Drill): `ExpressionEvaluator.createFastEvaluator`/`cook`, `ScriptEvaluator.cook`, `ClassBodyEvaluator.cook`, `SimpleCompiler.cook`
  - **Apache Camel Simple language** (CVE-2018-8041): `SimpleLanguage.createExpression`, `SimpleLanguage.createPredicate`
  - **Thymeleaf StandardExpression** (CVE-2023-38286): `StandardExpressionParser.parseExpression`, `StandardExpression.getValue`
  - **FreeMarker direct template construction** (CVE-2022-26336): `new Template(name, tainted)`, `Configuration.getTemplate`
  - **Jinjava (Java Jinja template engine)**: `Jinjava.render`, `Jinjava.renderForResult`
  - **Spring Cloud Function** (CVE-2022-22963): `RoutingFunction.getRequestedBeanName`
  - **Kotlin reflection**: `KClass.createInstance`, `KFunction.callBy`
  - **Struts 2 deep injection** (CVE-2017-5638): `TextParseUtil.translateVariables`, `StrutsResultSupport.evaluate`

[3.18.8]: https://github.com/cogniumhq/circle-ir/compare/v3.18.7...v3.18.8

## [3.18.7] - 2026-04-15

### Added

- **Rust extractor sources**: Axum/Actix/Rocket parameter types (`Json<T>`, `Form<T>`, `Query<T>`, `Path<T>`, `Body`, `Bytes`, `Multipart`) now recognized as HTTP body sources
- **Rust `stdin.lock().lines()` source**: Added `lines` method for class `stdin` and `lock` to returnTypeMappings for chained stdin access patterns

### Fixed

- **Bash command-name skip scoped to Bash only**: The shell command-name argument skip (`arg.expression === method_name`) now only applies when `language === 'bash'`, fixing false negative where Rust `html(html)` variable was incorrectly treated as a command name
- **`JSON.parse` no longer a deserialization sink**: Removed `JSON.parse` from DEFAULT_SINKS — JavaScript's `JSON.parse` is safe (no code execution), unlike Java's FastJSON `parseObject`
- **`console.log` no longer an information_exposure sink**: Removed overly noisy sink that caused false positives in general-purpose JS analysis
- **`URL`/`URI` constructor no longer SSRF sinks**: Constructing a URL object doesn't make a network request; removed to reduce false positives
- **Validated URL redirect suppression**: Added validation-guard heuristic for `.href`/`location` assignments — suppresses XSS sink when nearby lines contain `if` + `includes`/`startsWith`/`endsWith`/`indexOf`/`test`/`match`
- **`starts_with`/`contains`/`ends_with` sanitize `open_redirect`**: URL validation functions now remove `open_redirect` findings in addition to existing categories

[3.18.7]: https://github.com/cogniumhq/circle-ir/compare/v3.18.6...v3.18.7

## [3.18.6] - 2026-04-15

### Added

- **JS property sources**: `document.referrer`, `document.cookie`, `document.URL`, `document.documentURI`, `window.name`, `location.pathname` added to `JS_TAINTED_PATTERNS` — sources now propagate through variable assignments
- **DOM sinks**: `setAttribute()` registered as XSS sink (CWE-79, arg position 1)
- **Rust sources**: `stdin().read_line()` (class `stdin`) for `io::stdin().read_line()` patterns
- **Rust sinks**: `reply::html()` and `warp::html()` for warp XSS detection
- **JSON.parse sanitizer**: Added to DEFAULT_SANITIZERS (removes xss, code_injection)

### Fixed

- **Bash false positives**: Sink filter now skips the command-name argument (arg[0] in shell calls where `expression === method_name`), so `curl -s "https://literal.url"` is correctly filtered out
- **Rust `io::stdin()` matching**: `receiverMightBeClass()` now checks the function name in `module::func()` scoped calls, matching `io::stdin()` to class `stdin`
- **Benchmark debug tests**: Added `benchmark-debug.test.ts` with 9 integration tests covering all remaining benchmark gaps

[3.18.6]: https://github.com/cogniumhq/circle-ir/compare/v3.18.5...v3.18.6

## [3.18.5] - 2026-04-15

### Fixed

- **Property sink matching**: Added `cssText` and `style.textContent` to `JS_DOM_XSS_SINKS` regex table in `LanguageSourcesPass`, enabling runtime detection of CSS injection and dynamic stylesheet XSS
- **Rust builder pattern matching**: `receiverMightBeClass()` now recognizes `Response::builder().header()` by mapping `builder()` return type and extracting the type before `::` in scoped calls

[3.18.5]: https://github.com/cogniumhq/circle-ir/compare/v3.18.4...v3.18.5

## [3.18.4] - 2026-04-15

### Added

- **JavaScript sinks**: `style.textContent` for dynamic stylesheet injection (CWE-79)
- **JavaScript sanitizers**: `JSON.parse()` breaks string taint chain (removes xss, code_injection)
- **Rust sinks**: `Redirect::to()`, `Redirect::see_other()`, `Redirect::temporary()`, `Redirect::permanent()` (open redirect, CWE-601); `warp::reply::html()` namespace variant (XSS, CWE-79)

### Fixed

- **Config type correctness**: Fixed invalid `css_injection` SinkType in JavaScript DOM XSS config (→ `xss`)

[3.18.4]: https://github.com/cogniumhq/circle-ir/compare/v3.18.3...v3.18.4

## [3.18.3] - 2026-04-15

### Fixed

- **Property source matching**: Auto-normalize `property_tainted` flag in `loadSourceConfigs()` so YAML-defined property-based sources (e.g., `location.hash`, `event.data`) are correctly matched by the taint engine
- **Browser DOM default sources**: Added `document.referrer`, `location.hash/search/href/pathname`, and `event.data` to DEFAULT_SOURCES with correct `property_tainted` flag
- **Config type correctness**: Fixed invalid `SourceType` values in JavaScript configs (`url_param` → `http_header`, `user_input`/`message_input`/`storage_input` → `dom_input`)

[3.18.3]: https://github.com/cogniumhq/circle-ir/compare/v3.18.2...v3.18.3

## [3.18.2] - 2026-04-15

### Added

- **JavaScript sources**: `localStorage.getItem()` and `sessionStorage.getItem()` as storage input sources
- **JavaScript sinks**: `el.style.background` and `el.style.backgroundImage` for CSS url() injection
- **Rust sinks**: `axum::response::Html()` (XSS, CWE-79) and `HeaderValue::from_str()` (open redirect, CWE-601)
- **Rust sanitizers**: `html_escape::encode_text()`, `html_escape::encode_quoted_attribute()`, `ammonia::clean()`, `ammonia::Builder::clean()`
- **Java sanitizers**: OWASP ESAPI `Encoder.encodeForHTML()`, `encodeForHTMLAttribute()`, `encodeForJavaScript()`; `Jsoup.clean()`

[3.18.2]: https://github.com/cogniumhq/circle-ir/compare/v3.18.1...v3.18.2

## [3.18.1] - 2026-04-15

### Added

- **JavaScript setAttribute filtering** (Stage 6): `setAttribute` sink now only flags dangerous attribute names (`on*`, `style`, `srcdoc`). Safe attributes like `title`, `class`, `id` no longer trigger XSS findings.
- **Bash literal detection**: Bash argument extraction now recognizes string literals (quoted and unquoted), enabling the clean-variable filter to suppress findings when sink arguments are hardcoded constants.

### Fixed

- **Bash curl/wget hardcoded URL FP**: `curl "https://static.example.com"` no longer triggers SSRF findings because the URL argument is correctly identified as a string literal.

[3.18.1]: https://github.com/cogniumhq/circle-ir/compare/v3.18.0...v3.18.1

## [3.18.0] - 2026-04-15

### Added

- **JavaScript sources**: `document.referrer` (CWE-79) and `event.data`/postMessage (CWE-79) as taint sources
- **JavaScript sinks**: jQuery `.html()`, `$()`, `jQuery()`, `.append()`, `.prepend()` for XSS; `cssText` for CSS injection
- **JavaScript sanitizers**: `JSON.parse` (removes command_injection, sql_injection, xss, code_injection) and `URL` constructor (removes open_redirect, ssrf)
- **Java sinks**: CORS misconfiguration via `setHeader("Access-Control-Allow-Origin", ...)` (CWE-942)
- **Java sanitizers**: Google Guava `Escaper.escapeHtml`, `HtmlEscapers.escapeHtml`, `HtmlEscapers.htmlEscaper` (removes xss)
- **Rust sources**: `io::stdin()` and Axum `Body` extractors (`into_body`, `to_bytes`, `body`, `into_inner`, `collect`)
- **Rust sinks**: Warp `reply::html()` / `Html::html()` (XSS), `Response::body()` (XSS), `Response::header()` / `HttpResponse::insert_header()` / `append_header()` (open redirect), `Redirect::redirect()` (open redirect)
- **Bash sources**: `curl` and `wget` output as taint sources for supply-chain attack detection

### Fixed

- **JavaScript FP**: Removed `JSON.parse` from deserialization sinks (it does not execute code)

[3.18.0]: https://github.com/cogniumhq/circle-ir/compare/v3.17.3...v3.18.0

## [3.17.3] - 2026-04-14

### Fixed

- **Export `package.json` subpath** (#11 follow-up): Added `"./package.json": "./package.json"` to the `exports` map so that `require.resolve('circle-ir/package.json')` works under strict Node.js module resolution. Required by consumers (cognium, circle-ir-ai) that use `createRequire` to locate the `dist/wasm/` directory.

[3.17.3]: https://github.com/cogniumhq/circle-ir/compare/v3.17.2...v3.17.3

## [3.17.2] - 2026-04-14

### Fixed

- **WASM auto-detection in nested node_modules** (fixes #11): `initAnalyzer()` now checks `dist/wasm/` within the circle-ir package directory first when auto-detecting WASM paths. This resolves failures when circle-ir is installed as a transitive dependency and npm hoists `web-tree-sitter` to a different `node_modules` level. Consumers no longer need to manually resolve WASM paths with `createRequire`.

[3.17.2]: https://github.com/cogniumhq/circle-ir/compare/v3.17.1...v3.17.2

## [3.17.1] - 2026-04-14

### Changed

- Updated all documentation to list HTML as a supported language (README, SPEC, ARCHITECTURE, CLAUDE, CONTRIBUTING, source comments)

[3.17.1]: https://github.com/cogniumhq/circle-ir/compare/v3.17.0...v3.17.1

## [3.17.0] - 2026-04-13

### Added

- **HTML Web Extraction Preprocessor** — HTML is now a supported language. `analyze()` accepts `language: 'html'` and automatically:
  - Extracts `<script>` blocks and analyzes each as JavaScript (with correct line offset mapping)
  - Extracts inline event handlers (`onclick`, `onerror`, etc.) and analyzes as JS
  - Runs 8 attribute-level security checks (H1–H8) directly on the HTML AST:
    - `html-missing-noopener` (CWE-1022), `html-javascript-uri` (CWE-79),
      `html-missing-sandbox` (CWE-1021), `html-mixed-content` (CWE-319),
      `html-missing-sri` (CWE-353), `html-autocomplete-sensitive` (CWE-525),
      `html-inline-event-handler` (CWE-79), `html-form-action-javascript` (CWE-79)
  - Merges all results into a single `CircleIR` with correct HTML line numbers
- `HtmlPlugin` language plugin registered for `.html`, `.htm`, `.xhtml` extensions
- `tree-sitter-html` WASM grammar added to `wasm/`
- 45 new tests (extractor, attribute security, integration)

[3.17.0]: https://github.com/cogniumhq/circle-ir/compare/v3.16.8...v3.17.0

## [3.16.8] - 2026-04-08

### Changed

- **Dependencies refreshed** — no source code or behavior changes:
  - `web-tree-sitter` 0.26.7 → 0.26.8 (runtime, patch)
  - `esbuild` 0.27.4 → 0.28.0 (build tool)
  - `@types/node` 25.5.0 → 25.5.2
  - `@vitest/coverage-v8` 4.1.2 → 4.1.3
  - `vitest` 4.1.2 → 4.1.3

[3.16.8]: https://github.com/cogniumhq/circle-ir/compare/v3.16.7...v3.16.8

## [3.16.7] - 2026-04-07

### Fixed

- Republish of 3.16.6 — same fix, the previous tag was never published to npm.
  Includes the n-plus-one in-memory collection exclusion and the cognium.config
  re-enable of the pass for circle-ir's own dogfood scan.

[3.16.7]: https://github.com/cogniumhq/circle-ir/compare/v3.16.6...v3.16.7

## [3.16.6] - 2026-04-07

### Fixed

- **n-plus-one pass** — No longer flags `Map.get()` / `Map.has()` calls inside
  loops as database queries. Added in-memory collection receiver detection:
  - Receivers matching `*Index`, `*Map`, `*Lookup`, `*Dict`, `*ById`, `*ByName`,
    `*ByKey`, `*ByType`, `*ByPath`, `*ByFile`, `*ByLine` are now excluded
  - Bare-name receivers like `idom`, `seen`, `visited`, `memo`, `cache`,
    `registry`, `index`, `lookup`, `map`, `set`, `dict` are excluded
  - The in-memory exclusion takes precedence over DB prefix/suffix matches so
    ambiguous names (e.g. `dbIndex`) are treated as in-memory collections
  - Removed `Index` from the DB receiver suffix list — it was the main source
    of false positives on graph algorithms (`rpoIndex.get()` in dominator
    computation)

[3.16.6]: https://github.com/cogniumhq/circle-ir/compare/v3.16.5...v3.16.6

## [3.16.5] - 2026-04-06

### Fixed

- **naming-convention pass** — Skip synthetic names like `<module>` and
  `<anonymous>` that are injected by the IR extractors but are not real
  identifiers in source code.
- **redundant-loop-computation pass** — No longer flags `.length` property
  reads in JavaScript/TypeScript loops. Array/string `.length` is an O(1)
  property access, not a function call.
- **unhandled-exception pass** — Added source-level `try`/`catch` detection
  as a fallback when the CFG builder misses exception edges. Reduces false
  positives on throws that are actually wrapped in try/catch blocks.
- **unbounded-collection pass** — Skip bounded loops (`for...of`, `for...in`,
  `forEach`) which iterate over a finite input and cannot grow unboundedly.

[3.16.5]: https://github.com/cogniumhq/circle-ir/compare/v3.16.4...v3.16.5

## [3.16.4] - 2026-03-30

### Fixed

- **Reduced false positives in taint analysis:**
  - Added `path.resolve()` to sanitizer methods (path normalization)
  - Added safe receiver filtering: `RegExp.exec()`, `db.exec()` no longer flagged as command injection
  - Added argument position filtering: only dangerous args checked (e.g., arg 0 of `execSync`, not options)

[3.16.4]: https://github.com/cogniumhq/circle-ir/compare/v3.16.3...v3.16.4

## [3.16.3] - 2026-03-30

### Fixed

- **Project-level passes now respect disabledPasses** — The `orphan-module` and
  `circular-dependency` passes in `analyzeProject` now check the `disabledPasses`
  option before running.

[3.16.3]: https://github.com/cogniumhq/circle-ir/compare/v3.16.2...v3.16.3

## [3.16.2] - 2026-03-29

### Fixed

- **infinite-loop pass** — No longer flags iterator-based loops (`for...of`, `for...in`,
  `for-each`, Python/Rust `for x in`) as infinite. These loops self-terminate when the
  iterator is exhausted.

[3.16.2]: https://github.com/cogniumhq/circle-ir/compare/v3.16.1...v3.16.2

## [3.16.1] - 2026-03-29

### Changed

- **Cleaned up cognium.config.json** — Removed fragile line-specific suppressions and massive
  skipPatterns lists. Now uses 8 disabled passes with clear reasoning and 11 architectural
  suppressions only.

### Fixed

- **stale-doc-ref pass** — Fixed self-detection issue where the pass's own doc comment example
  `{@link ClassName}` was flagged as a stale reference.

[3.16.1]: https://github.com/cogniumhq/circle-ir/compare/v3.16.0...v3.16.1

## [3.16.0] - 2026-03-29

### Added

- **PassOptions support** — Analysis passes can now receive configuration options via the
  `passOptions` parameter in `analyze()`. Pass-specific settings like thresholds are passed
  through to individual passes, enabling runtime customization without code changes.

- **disabledPasses support** — New `disabledPasses` parameter in `analyze()` allows disabling
  specific passes by name at runtime. Useful for CI/CD pipelines that need to skip certain
  checks or for per-project configuration.

- **cognium.config.json** — Added project configuration file with:
  - Pass-specific options (dependency-fan-out threshold, unbounded-collection skipPatterns)
  - Disabled passes (infinite-loop, n-plus-one, missing-public-doc, naming-convention)
  - 27 documented suppressions for false positives

### Changed

- **Code quality improvements** — Fixed all findings from self-analysis:
  - Removed unused variable in imports.ts
  - Fixed string-concat-loop in sink-filter-pass.ts (use array.join)
  - Pre-compiled regex patterns in taint-propagation-pass.ts
  - Hoisted loop-invariant `.length` computations in 10 files

### Release notes

Version 3.16.0 adds runtime configuration support for analysis passes, enabling per-project
customization of thresholds, disabled passes, and suppressions. The codebase now passes its
own analysis with zero findings. Total test count: **1512**.

[3.16.0]: https://github.com/cogniumhq/circle-ir/compare/v3.15.0...v3.16.0

## [3.15.0] - 2026-03-29

### Changed

- **`null-deref` pass (#20) — expanded null guard detection** — Added 6 new guard patterns:
  - Java assertions: `assert x != null`, `assert null != x`
  - Java stdlib: `Objects.requireNonNull(x)`
  - Guava: `Preconditions.checkNotNull(x)`
  - Spring: `Assert.notNull(x, ...)`
  - JUnit/TestNG: `assertNotNull(x)`, `Assertions.assertNotNull(x)`

  These patterns are now recognized as valid null guards, reducing false positives when
  developers use assertion-based or utility-method null checks.

- **`n-plus-one` pass (#45) — improved receiver detection** — Expanded medium-confidence
  method detection with two-tier matching:
  - **Prefix matching**: Added `mongo*`, `redis*`, `pg*`, `mysql*`, `sqlite*`, `dynamo*`,
    `cosmos*`, `elastic*`, `neo4j*`, `cassandra*`, `firestore*`, `supabase*`, `drizzle*`,
    `knex*`, `typeorm*`, `mikro*` prefixes
  - **Suffix matching**: Added `*Repository`, `*Repo`, `*Dao`, `*DataSource`, `*DbContext`,
    `*Client`, `*Service`, `*Store`, `*Cache`, `*Gateway`, `*Adapter`, `*Provider`,
    `*Manager`, `*Handler`, `*Proxy`, `*Facade`, `*Connection`, `*Pool`, `*Session`,
    `*Template`, `*Mapper`, `*Access`, `*Query`, `*Command`, `*Storage`, `*Bucket`,
    `*Table`, `*Collection`, `*Index` suffixes

  This catches `userRepository.find()` and similar custom repository patterns that were
  previously missed.

- **`sink-filter` pass (XSS) — reduced false positives** — Enhanced Stage 6 JavaScript XSS
  filtering:
  - **Sanitizer detection**: Added 15 common XSS sanitizer patterns including `DOMPurify.sanitize()`,
    `sanitizeHtml()`, `escapeHtml()`, `validator.escape()`, `xss()`, `encodeURIComponent()`,
    Angular's `bypassSecurityTrust*()`, and more
  - **String literal suppression**: `.innerHTML = "static string"` assignments with pure
    string literals (double-quoted, single-quoted, or template literals without interpolation)
    are now suppressed
  - **Constant propagation integration**: If the RHS of an innerHTML assignment is a known
    string constant from constant propagation, the sink is suppressed

### Added

- **40 new tests** for the improved passes:
  - 9 tests for null-deref guard patterns
  - 15 tests for N+1 receiver suffix matching
  - 16 tests for XSS sanitizer and string literal filtering

### Release notes

Version 3.15.0 improves the accuracy of three high-impact passes, reducing both false
positives and false negatives. Total test count: **1512**.

[3.15.0]: https://github.com/cogniumhq/circle-ir/compare/v3.14.0...v3.15.0

## [3.14.0] - 2026-03-28

### Changed

- **Removed `missing-guard-dom` (#53) from the default pipeline** — The pass fired with
  high severity (`error`, CWE-285) on any Java codebase using framework-level authorization
  (Spring Security annotations, filter chains, servlet filters). Those guards do not appear
  as intra-method call nodes in the CFG, so every sensitive operation was reported as
  unguarded regardless of actual protection. The pass file is retained at
  `src/analysis/passes/missing-guard-dom-pass.ts` for direct use or for circle-ir-ai, which
  can apply the same dominator analysis on top of LLM-identified auth guards. The raw signals
  are already present in CircleIR: `ir.calls` (all call sites + method names) and `ir.cfg`
  (full CFG from which a DominatorGraph can be rebuilt).

- **Removed `feature-envy` (#87) from the default pipeline** — The call-count heuristic
  (external_max ≥ 4 AND margin > 2 over internal calls) fires trivially on legitimate
  delegation patterns: facades, controllers, and service classes that orchestrate collaborators
  will look "envious" by definition. Confirming true feature envy requires understanding
  design intent — whether the method belongs to the other class conceptually — which is LLM
  territory. The pass file is retained at `src/analysis/passes/feature-envy-pass.ts`. Raw
  signals are already present in CircleIR: `ir.calls` (per-site receiver + receiver_type) and
  `ir.types` (per-method line ranges).

- **`serial-await` fix message is now advisory** — The previous message prescribed
  `Promise.all()` directly. The new message reads: "appear to have no data dependency —
  verify ordering requirements before parallelising", with `Promise.all()` offered as a
  conditional suggestion. This prevents incorrect refactors when the operations have semantic
  ordering constraints (e.g., audit-after-persistence) that static analysis cannot see.

- **`naming-convention` I-prefix rule is now opt-in (off by default)** — Flagging
  `IUserRepository`-style TypeScript/Java interfaces is a style preference, not a language
  standard; many codebases intentionally use the I-prefix. A new `NamingConventionOptions`
  interface with `enforceIPrefix?: boolean` (default `false`) controls the rule. Enable it
  via `AnalyzerOptions.passOptions.namingConvention.enforceIPrefix = true`. The `NamingConventionOptions`
  type is re-exported from the package root.

- Pipeline reduced from 42 to 40 active passes. `AnalyzerOptions` gains a `passOptions`
  field for per-pass configuration.

### Added

- **`NamingConventionOptions`** exported from package root — allows consumers to configure
  the naming-convention pass without importing from deep internal paths.

## [3.13.0] - 2026-03-28

### Added

- **Pass #83 — `blocking-main-thread`** (`src/analysis/passes/blocking-main-thread-pass.ts`,
  JS/TS, performance, CWE-1050) — Detects synchronous crypto/hashing operations (`pbkdf2Sync`,
  `scryptSync`, `createHash`, `generateKeyPairSync`) and blocking `*Sync` calls inside HTTP
  request handlers (NestJS `@Get`/`@Post` decorators, Express `(req, res)` parameters, handler
  method names). Differentiated from `sync-io-async` (#48) by focusing on request-handler context
  rather than generic async functions.

- **Pass #84 — `excessive-allocation`** (`src/analysis/passes/excessive-allocation-pass.ts`,
  all languages, performance, CWE-770) — Flags collection and object allocations inside loop
  bodies that create GC pressure on every iteration (`new Map()`, `new ArrayList<>()`, `list()`,
  `Vec::new()`). Skips lines with reuse signals (`pool`, `cache`, `preallocat`). All languages
  except Bash.

- **Pass #85 — `missing-stream`** (`src/analysis/passes/missing-stream-pass.ts`,
  JS/TS/Java/Python, performance) — Detects whole-file / whole-response reads that load the
  entire payload into memory: `readFileSync` / `response.text()` (JS/TS), `Files.readAllBytes`
  / `BufferedReader` (Java), `f.read()` (Python). Skips JS/TS methods that already use streaming
  (`.pipe()`, `createReadStream`, `for await`).

- **Pass #86 — `god-class`** (`src/analysis/passes/god-class-pass.ts`,
  Java/TS/Python, architecture, CWE-1060) — Detects classes exceeding 2 of 3 CK metric
  thresholds: WMC > 47 (sum of cyclomatic complexity per method), LCOM2 > 0.8 (normalized lack
  of cohesion, 0–1 scale), CBO > 14 (distinct external type references). All metrics computed
  inline from `graph.ir.cfg` / `graph.ir.dfg` / `graph.ir.calls` — the separate MetricRunner
  pipeline is not used.

- **Pass #87 — `feature-envy`** (`src/analysis/passes/feature-envy-pass.ts`,
  Java/TS/Python, architecture, CWE-1060) — Flags methods that call another class's methods
  far more than their own (≥4 external calls AND external > internal + 2). Suggests moving
  the method to the envied class.

- **Pass #88 — `naming-convention`** (`src/analysis/passes/naming-convention-pass.ts`,
  all languages, maintainability) — Enforces language-idiomatic naming rules:
  Java/TS: PascalCase classes, camelCase methods, UPPER_SNAKE_CASE for `static final` fields,
  no `I`-prefix on interfaces. Python: PascalCase classes, snake_case methods (dunder methods
  exempt). Bash/Rust: snake_case functions. Capped at 20 findings per file.

- **6 new test files** covering all new passes:
  - `tests/analysis/passes/blocking-main-thread.test.ts` — 6 tests
  - `tests/analysis/passes/excessive-allocation.test.ts` — 8 tests
  - `tests/analysis/passes/missing-stream.test.ts` — 7 tests
  - `tests/analysis/passes/god-class.test.ts` — 6 tests
  - `tests/analysis/passes/feature-envy.test.ts` — 6 tests
  - `tests/analysis/passes/naming-convention.test.ts` — 11 tests

### Changed

- **`src/analyzer.ts`** — pipeline extended from 36 to 42 passes; comment block updated.
- **`docs/PASSES.md`** — passes #83–#88 registered; Phase 5 summary added.

### Release notes

Version 3.13.0 adds 6 new static analysis passes across performance, architecture, and
maintainability categories, bringing the total to 42 passes in the pipeline.

[3.13.0]: https://github.com/cogniumhq/circle-ir/compare/v3.12.1...v3.13.0

## [3.12.1] - 2026-03-28

### Changed

- **Dependency upgrades** — all packages bumped to latest:
  - `yaml` 2.8.2 → 2.8.3 (runtime)
  - `vitest` + `@vitest/coverage-v8` 4.1.0 → 4.1.2 (dev)
  - `typescript` 5.9.3 → 6.0.2 (dev)
- **`tsconfig.json`** — `moduleResolution: "node"` → `"bundler"` (required for TypeScript 6;
  `"node"` (alias `"node10"`) is deprecated and will be removed in TypeScript 7.0)
- **CLAUDE.md** — updated test count: 788+ → 1423+

[3.12.1]: https://github.com/cogniumhq/circle-ir/compare/v3.12.0...v3.12.1

## [3.12.0] - 2026-03-28

### Added

- **Java receiver-type resolution (`java.ts`)** — `JavaPlugin.getReceiverType()` now resolves
  identifier receivers by walking the parse tree once and caching the result in a `WeakMap<Tree,
  Map<string, string>>`. Generic types are stripped (`List<String>` → `List`). This allows
  `TypeHierarchyResolver.couldBeType()` to perform polymorphic sink matching for declarations
  such as `PreparedStatement ps = …; ps.executeQuery(q)`.

- **Bash plugin edge-case tests** (`tests/languages/bash-coverage.test.ts`) — 12 integration
  tests covering sink detection (`eval`→`code_injection`, `mysql`→`sql_injection`,
  `curl`→`ssrf`, `rm`→`path_traversal`), source detection (`read`→`io_input`), taint flows
  (read→eval, read→mysql, read→rm, read→curl, `$()`→bash), and multi-sink scripts.
  Known gap: `$VAR` substitution across bash statements is not yet tracked by the DFG; tests
  document this with TODO comments and weaker fallback assertions.

- **Python plugin IR fixture tests** (`tests/languages/python-ir.test.ts`) — 25 end-to-end
  tests using `analyze()` with real Python snippets. Covers plugin metadata, source detection
  (Flask `request.args`/`request.form`, Django `request.GET`, `os.environ.get`), sink detection
  (`cursor.execute`, `os.system`, `subprocess.run`, `eval`, `pickle.loads`), complete taint
  flows (Flask SQL injection, Django command injection, subprocess, eval, deserialization),
  metrics structure validation, and a parameterized-query clean-code check.

- **Inter-procedural taint analysis tests** (extended `tests/analysis/interprocedural.test.ts`)
  — 5 new tests across 3 groups:
  - *B3.1*: return-value taint reaching a sink; depth-limit enforcement
  - *B3.2*: field taint across methods; class with no sources produces empty tainted set
  - *B3.3*: three-method taint chain with confidence; summary consistency check

### Release notes

Version 3.12.0 focuses on test coverage and Java type accuracy. Total test count: **1423**.
Coverage: stmts 86.56%, branches 73.09%, functions 91.28%, lines 88.85% — all above thresholds.

[3.12.0]: https://github.com/cogniumhq/circle-ir/compare/v3.11.0...v3.12.0

## [3.11.0] - 2026-03-27

### Added

- **`missing-guard-dom` pass (#53, CWE-285)** — detects sensitive operations (delete, drop, truncate,
  executeUpdate, createUser/Admin, grantRole, elevatePrivilege) that are not dominated by an
  authentication check (authenticate, isAuthenticated, isAuthorized, hasPermission, verifyToken,
  etc.) on all CFG paths. Java only. Level: `error`.

- **`cleanup-verify` pass (#54, CWE-772)** — verifies that resource cleanup (`close()`,
  `disconnect()`, `release()`, etc.) post-dominates acquisition on every path through the CFG.
  Complements `resource-leak` (which checks for missing close entirely); this pass flags cases
  where `close()` exists but is reachable only on some paths. Uses a reversed-CFG post-dominator
  tree. Skips Rust (RAII) and Bash. Level: `warning`.

- **`missing-override` pass (#64)** — flags methods in subclasses that match a parent class method
  signature but lack the `@Override` annotation. Walks the full inheritance chain (up to 10 levels,
  cycle-safe). Skips constructors, private, static, and abstract methods. Java only. Level: `warning`.

- **`unused-interface-method` pass (#66)** — reports interface methods that are never called
  anywhere in the same file. Conservative single-file scope; intended to surface API surface bloat
  and dead interface contracts. Java and TypeScript. Level: `note`.

- **TypeHierarchyResolver wired into TaintMatcherPass** — `analyzeTaint()` now accepts an optional
  `TypeHierarchyResolver`, built via `createWithJdkTypes()` (pre-populates JDBC, IO, Servlet
  hierarchy) and extended with file types from the IR. Enables `PreparedStatement.executeQuery()`
  to match `Statement`-level sink configs, reducing false negatives in polymorphic call chains.

- **DFG-verifier branch coverage tests** — 4 new tests cover previously untested branches:
  - `reachesSink()` call-argument path (no DFG use entry → verified via call arg match)
  - `calculateConfidence()` field-step penalty (`kind: 'field'` lowers confidence below 0.9)
  - `calculateConfidence()` long-path penalty (chain >5 hops lowers confidence below 0.85)
  - `laterDefsOfVar()` BFS exploration (re-definition reached when original def can't match sink)

- **23 new pass tests** across 4 new test files (`missing-guard-dom.test.ts`,
  `cleanup-verify.test.ts`, `missing-override.test.ts`, `unused-interface-method.test.ts`), each
  using the standard minimal-IR fixture pattern.

### Release notes

Version 3.11.0 completes Phase 4 reliability and architecture passes. The pipeline now runs
**36 sequential passes** (up from 32 in v3.10.0). All existing OWASP/Juliet/NodeGoat benchmark
scores are maintained.

[3.11.0]: https://github.com/cogniumhq/circle-ir/compare/v3.10.0...v3.11.0

## [3.10.0] - 2026-03-27

### Added

- **Command injection interprocedural regression tests** — 4 new regression tests guard against
  future regressions in OWASP cmdi taint propagation through interprocedural call chains:
  - `r.exec(bar)` where `bar` is assigned from a same-class method call (e.g. `doSomething(param)`)
  - `r.exec(bar)` where `bar` is assigned from an external class static method call
  - OWASP BenchmarkTest00174 pattern: `getHeader → URLDecoder.decode → thing.doSomething → argsEnv[]
    → r.exec(cmd, argsEnv)`
  - OWASP BenchmarkTest00303 pattern: `getHeaders → nextElement → URLDecoder.decode → Base64
    encode/decode chain → args[] → r.exec(args)`

### Confirmed

- **Interprocedural cmdi taint propagation works via `isTaintedExpression` child walk** —
  Verified through targeted testing that the `isTaintedExpression` function in
  `constant-propagation/propagator.ts` correctly handles all interprocedural taint patterns via
  its recursive child-walk fallback (lines 2043–2047). This mechanism propagates taint through
  arbitrary method call chains (same-class, cross-class, interface delegation, and library
  wrappers like `Base64.encodeBase64/decodeBase64`) without needing explicit method return-value
  analysis.

### Release notes

Version 3.10.0 is the first release in the 3.10.x series, consolidating:
- All 5 reliability passes added in v3.9.9 (`swallowed-exception`, `broad-catch`,
  `unhandled-exception`, `double-close`, `use-after-close`)
- The `Runtime.exec()` 37-FN fix from v3.9.10
- Confirmed 100% OWASP Java benchmark score (1341 tests passing)

[3.10.0]: https://github.com/cogniumhq/circle-ir/compare/v3.9.10...v3.10.0

## [3.9.10] - 2026-03-27

### Fixed

- **`Runtime.exec()` command injection — 37 OWASP FNs fixed** — `filterCleanVariableSinks`
  (Stage 3 of `SinkFilterPass`) iterated over ALL calls at the sink's source line, including
  nested inner calls. When a nested call had only constant/literal arguments (e.g.
  `System.getProperty("user.dir")` inside `r.exec(args, argsEnv, new File(System.getProperty(...)))`),
  the filter incorrectly removed the outer `exec()` sink. Fix: extract the method name from
  `sink.location` and only evaluate the call that matched the sink pattern, skipping nested inner
  calls. This resolves 26 of the 37 OWASP `cmdi` false negatives (all `exec(String[], String[],
  File)` and `exec(String, String[], File)` overloads). Added 6 regression tests.

## [3.9.9] - 2026-03-26

### Added

- **`ExceptionFlowGraph`** — new graph class wrapping CFG exception edges (`type === 'exception'`).
  Maps try-body entry blocks to catch-handler entry blocks. Public API: `hasTryCatch`, `pairs`,
  `isCatchEntry(id)`, `isTryEntry(id)`, `catchBlocksFor(tryEntryId)`, `tryBlockFor(catchEntryId)`.
  Exported from `circle-ir` as `ExceptionFlowGraph` + `TryCatchInfo`.

- **`swallowed-exception` pass (CWE-390, reliability, medium)** — Detects catch blocks that
  silently discard exceptions: no re-throw, no logging call, no error return. Uses `ExceptionFlowGraph`
  to locate catch handler entry lines, then brace-walks the source text to find the catch body bounds.
  Languages: Java, JS/TS, Python.

- **`broad-catch` pass (CWE-396, reliability, low)** — Detects catch clauses that catch base
  exception types (`Exception`, `Throwable`, `RuntimeException`, `Error` in Java; bare `except:` or
  `except Exception:` in Python) rather than specific subtypes. Languages: Java, Python.

- **`unhandled-exception` pass (CWE-390, reliability, medium)** — Detects explicit `throw`/`raise`
  statements not covered by any try/catch in the same function. Uses `ExceptionFlowGraph` to build
  covered line ranges and checks each throw against them. One finding per method to avoid noise.
  Languages: JS/TS, Python (Java skipped — checked exceptions are intentionally propagated).

- **`double-close` pass (CWE-675, reliability, medium)** — Detects I/O resources that are
  `close()`d more than once within the same method. Reuses resource-open/close patterns from
  `resource-leak`. Skips cases where all closes are inside a `finally` block (benign pattern).
  Languages: Java, JS/TS, Python, Rust.

- **`use-after-close` pass (CWE-672, reliability, high)** — Detects method calls on a resource
  variable after it has been `close()`d in the same method. Finds the first close call, then scans
  for any subsequent non-close method calls on the same receiver. Languages: Java, JS/TS, Python, Rust.

[3.9.9]: https://github.com/cogniumhq/circle-ir/compare/v3.9.8...v3.9.9

## [3.9.8] - 2026-03-26

### Added

- **`DominatorGraph`** — Cooper et al. "A Simple, Fast Dominance Algorithm" (2001) implementation.
  Computes the dominator tree for any CFG in O(n²) time. Exported from `circle-ir` as `DominatorGraph`.
  Public API: `dominates(a, b)`, `strictlyDominates(a, b)`, `immediateDominator(blockId)`, `dominated(blockId)`.

- **`infinite-loop` pass (CWE-835, reliability)** — Detects loops with no reachable exit edge.
  Uses CFG back-edges to identify loop bodies, then checks for exit edges or exit keywords
  (`return`, `throw`, `break`) as a text-level fallback.

- **`deep-inheritance` pass (CWE-1086, architecture)** — Flags class inheritance depth > 5.
  Walks `ir.types[*].extends` chains, guards against cycles, emits a low-severity finding at the
  class declaration site.

- **`redundant-loop-computation` pass (CWE-1050, performance)** — Detects loop-invariant
  expressions recomputed every iteration: `.length` / `.size()` / `.count()` on variables not
  modified in the loop body; `Object.keys/values/entries(x)` on invariant `x`; `Math.sqrt/pow/abs(x)`.

- **`unbounded-collection` pass (CWE-770, performance)** — Detects collections that grow
  inside a loop with no size-limit check or clear/remove operation. Covers `add`/`push`/`put`/
  `append`/`insert` in Java, JS/TS, Python, Rust.

- **`serial-await` pass (performance, JS/TS only)** — Detects sequential `await` expressions
  with no data dependency between them, suggesting `Promise.all()` parallelisation.

- **`react-inline-jsx` pass (performance, JS/TS only)** — Detects inline object literals and
  arrow functions in JSX props, which create new references on every render and defeat memoization.
  Skips `style={{` (idiomatic) and `key=` / `ref=`.

[3.9.8]: https://github.com/cogniumhq/circle-ir/compare/v3.9.7...v3.9.8

## [3.9.7] - 2026-03-26

### Fixed

- **`external_taint_escape` false positives eliminated (4 → 0)** — Two root causes fixed:
  - `InterproceduralPass` Scenario B (sources present, no YAML sinks) now excludes **all**
    `interprocedural_param` sources, not only those with `confidence < 0.6`.
    `interprocedural_param` is a speculative "this parameter might be tainted if called with
    tainted data" signal; real cross-file flows from confirmed external inputs are surfaced by
    `CrossFilePass`.
  - `taint-matcher.ts` `matchesSourcePattern()` now returns `false` when a pattern specifies
    a `class` but the call has no receiver.  The previous code skipped the receiver check
    entirely when `call.receiver` was absent, allowing any bare `get()` function call to match
    **all** `Map/HashMap/Properties` source patterns regardless of receiver type.  This caused
    local helper functions such as `const get = (name) => acc.find(...)` to be classified as
    `plugin_param`/`http_param`/`config_param` sources, producing cascading false positives.

- **Cross-file taint false positives eliminated (1,542 → 0)** — Two root causes fixed:
  - `CrossFilePass` now uses `flatMap` with early-return guards: flows where the target IR
    is missing, has no sinks, or has no matched sink at the target line are silently dropped.
    The previous `matchedSink?.type ?? 'sql_injection'` default was labelling every
    speculative cross-file flow as `sql_injection`.
  - `CrossFileResolver.findCrossFileTaintFlows()` now skips `interprocedural_param` sources
    (same rationale as above), requires the target method to exist in the target file's IR,
    and only emits a flow when a known YAML sink falls within the target method's line range.
    `targetLine` is now set to the actual sink line in the target file rather than the call
    site line in the source file.

[3.9.7]: https://github.com/cogniumhq/circle-ir/compare/v3.9.6...v3.9.7

## [3.9.6] - 2026-03-26

### Fixed

- **`variable-shadowing` false positives eliminated** — Three root causes addressed:
  - Added `SKIP_NAMES` set (`let`, `const`, `var`, TypeScript primitives `boolean`, `string`, `number`, etc.) to suppress phantom DFG defs produced when declaration keywords and type annotations are incorrectly extracted as variable names.
  - Added PascalCase filter: identifiers starting with an uppercase letter (e.g. `SinkType`, `SupportedLanguage`) are skipped — these are type annotation phantoms, not real variables.
  - Fixed `isInNestedScope()` brace-balance algorithm: added `hasOpened` flag to correctly detect when an outer block opens and closes before the inner declaration, marking them as sibling scopes (e.g. consecutive `for` loops) rather than nested ones.

- **`leaked-global` false positives eliminated** — Two root causes addressed:
  - `hasDeclaredDef()` in `ScopeGraph` now also checks module-level declarations (`e.methodStart === -1`) so that module-scope `let`/`const`/`var` variables reassigned inside functions are no longer reported as leaks.
  - Added text-search fallback in `LeakedGlobalPass` for `let x;` declarations with no initializer: these create no DFG def, so a regex scan of source lines (`declPattern`) and module-level lines (`moduleDecl`) detects them before flagging a leak.

- **`external_taint_escape` false positives reduced (35 → 4)** — Two root causes addressed:
  - `InterproceduralPass` Scenario B (no sinks found) now filters out `interprocedural_param` sources with confidence < 0.6 in addition to `constructor_field` sources. Low-confidence interprocedural params arise when TypeScript constructor shorthand (`private source: string`) prevents type extraction.
  - `LanguageSourcesPass` narrowed the DOM input pattern from `/\.value\b/` (matched any `.value` property access) to `/\b(?:event|e)\.(?:target\.)?value\b/` (matches only DOM event `.value` access), eliminating spurious `dom_input` sources from evaluator-style code using `.value` on non-DOM objects.

## [3.9.5] - 2026-03-25

### Added

- **Phase 2: Metrics Engine (Core 20 metrics + 4 composite scores)** — `MetricRunner` computes software quality metrics from the fully-assembled `CircleIR` after the analysis pipeline, storing results in `ir.metrics: FileMetrics`.
  - **`MetricRunner`** (`src/analysis/metrics/metric-runner.ts`) — orchestrates 9 metric passes in sequence; each pass receives the `accumulated` results from prior passes so that `CompositeMetricsPass` (always last) can read earlier values.
  - **`SizeMetricsPass`** — `LOC`, `NLOC`, `comment_density`, `function_count` (regex-based line classification).
  - **`ComplexityMetricsPass`** — per-method `cyclomatic_complexity` (`v(G)` via CFG block/edge filtering by line range), `WMC` (sum), `loop_complexity` (back-edges), `condition_complexity` (true/false branch edges).
  - **`HalsteadMetricsPass`** — `halstead_volume`, `halstead_difficulty`, `halstead_effort`, `halstead_bugs` via regex tokenizer on full source (operators = keywords + symbols; operands = identifiers + literals).
  - **`DataFlowMetricsPass`** — `data_flow_complexity` (count of DFG uses with a reaching definition).
  - **`CouplingMetricsPass`** — per-type `CBO` (distinct external receiver types + field types), `RFC` (methods + distinct external method names), plus `CBO_avg`/`RFC_avg` file-level averages.
  - **`InheritanceMetricsPass`** — per-type `DIT` (inheritance depth within the file) and `NOC` (direct child count), plus `DIT_max`/`NOC_total`.
  - **`CohesionMetricsPass`** — per-type `LCOM` (Henderson-Sellers: method pairs sharing no instance field minus pairs sharing at least one), plus `LCOM_avg`.
  - **`DocumentationMetricsPass`** — `doc_coverage` ratio (types+methods with a `/** */` block ending on the line before `start_line`).
  - **`CompositeMetricsPass`** — `maintainability_index` (Microsoft MI normalized 0–100), `code_quality_index`, `bug_hotspot_score`, `refactoring_roi` — all derived from `accumulated` metrics.
- **`analyze()` updated**: metrics are now always computed and returned in `ir.metrics: FileMetrics`.
- **Test count**: 956 → 1013 (+57 new tests across 10 new test files under `tests/analysis/metrics/`)

## [3.9.4] - 2026-03-25

### Added

- **Phase 1 Group 4: four new analysis passes + ImportGraph infrastructure** — completing Phase 1:
  - **`ImportGraph`** (`src/graph/import-graph.ts`) — directed file→file import graph built from per-file `ir.imports`. Resolves relative imports (starting with `.`) against the importer's directory with extension fallback (`.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.java`, `.rs`). Exposes `edgesFrom()`, `edgesTo()`, `findCycles()` (Tarjan's SCC — returns SCCs with size ≥ 2), and `findOrphans()` (files with zero incoming edges that are not recognized entry points). Exported from `src/graph/index.ts`.
  - **`DependencyFanOutPass`** (`dependency-fan-out`, architecture, low/note) — per-file pass; flags any module with ≥ 20 import entries (`ir.imports.length`). High fan-out is a coupling smell that makes modules harder to test and modify independently. Threshold is `FAN_OUT_THRESHOLD = 20`.
  - **`StaleDocRefPass`** (`stale-doc-ref`, maintainability, low/note) — per-file pass; scans all `/** ... */` doc comment blocks for `{@link Symbol}` and `@see Symbol` references. Normalizes qualified references (strips `#method` fragment and class prefix) then checks each against the known-symbol set (`ir.types[].name` + `ir.imports[].imported_name`). Unknown references are flagged.
  - **`CircularDependencyPass`** (`circular-dependency`, CWE-1047, architecture, medium/warning) — project-level pass (like `CrossFilePass`); accepts `ProjectGraph` + `ImportGraph` and runs `importGraph.findCycles()`. Each cycle produces one finding anchored to the alphabetically-first file in the cycle with all cycle members listed in `evidence.cycle`. Findings are attached to per-file `CircleIR.findings`.
  - **`OrphanModulePass`** (`orphan-module`, architecture, low/note) — project-level pass; runs `importGraph.findOrphans()`. Each orphan file gets one finding. Entry points (filename base matching `index|main|app|server|mod`) are excluded. Findings are attached to per-file `CircleIR.findings`.
- **Pipeline updated**: 19 → 21 per-file passes (`DependencyFanOutPass`, `StaleDocRefPass` added after `UnusedVariablePass`). `CircularDependencyPass` and `OrphanModulePass` run as post-steps in `analyzeProject()` after `CrossFilePass`.
- **Test count**: 921 → 956 (+35 new tests across 5 new test files: `import-graph.test.ts`, `dependency-fan-out.test.ts`, `stale-doc-ref.test.ts`, `circular-dependency.test.ts`, `orphan-module.test.ts`)

## [3.9.3] - 2026-03-25

### Added

- **Phase 1 Group 3: three new analysis passes + ScopeGraph infrastructure** — all wired into the 19-pass pipeline:
  - **`ScopeGraph`** (`src/graph/scope-graph.ts`) — thin wrapper over `CodeGraph` that enriches each `DFGDef` with `hasDeclKeyword` (whether the source line contains a declaration keyword such as `let`/`const`/`var` in JS/TS, type keywords in Java, `let` in Rust) and `methodStart`/`methodEnd` bounds. Provides `defsInMethod()` and `hasDeclaredDef()` helpers used by all three Group-3 passes.
  - **`VariableShadowingPass`** (`variable-shadowing`, CWE-1109, reliability, medium/warning) — for each method, groups DFG defs by variable name and detects: (1) **param shadow** — a `kind='param'` def + a later `kind='local'` def with a declaration keyword (or Python, which has no keywords); (2) **outer-local shadow** — two `kind='local'` defs that both have a declaration keyword, flagging the later one.
  - **`LeakedGlobalPass`** (`leaked-global`, CWE-1109, reliability, medium/warning) — JS/TS only; flags bare assignments (`x = 5`) inside function bodies where the variable has no `let`/`const`/`var` declaration anywhere in the enclosing function. Skips `_`-prefixed names and common skip-list names (`err`, `e`, `i`, `j`, etc.).
  - **`UnusedVariablePass`** (`unused-variable`, CWE-561, reliability, low/note) — flags `kind='local'` DFG defs where `graph.usesOfDef(def.id)` is empty, meaning the assigned value is never read. Skips `_`-prefixed names, skip-list names, catch-block variables, and test files.
- **Test count**: 897 → 921 (+24 new pass unit tests across 3 new test files)

## [3.9.2] - 2026-03-25

### Added

- **Phase 1 Group 2: five new analysis passes** — all emit `SastFinding[]` via `PassContext.addFinding()`, wired into the 16-pass pipeline:
  - **`NullDerefPass`** (`null-deref`, CWE-476, reliability, high/error) — finds DFG defs explicitly assigned `null`/`None`/`undefined`, then flags downstream uses (call receivers and field accesses) with no null guard between def and use. Language filter: Java, JS/TS, Python only (Rust/Bash skipped). Guard detection covers `!= null`, `!== null`, `is not None`, `if (x)`, `if x:`, `?.` optional chaining.
  - **`ResourceLeakPass`** (`resource-leak`, CWE-772, reliability, high/error or medium/warning) — detects 24 resource constructor types (`FileInputStream`, `Socket`, `BufferedReader`, …) and 12 factory methods (`open`, `createReadStream`, …). Definite leak (no `close()` at all) → high/error. Close without `finally` block → medium/warning. Recognizes Java try-with-resources (`try (`) and Python context managers (`with open(`) as safe.
  - **`UncheckedReturnPass`** (`unchecked-return`, CWE-252, reliability, medium/warning) — two-tier curated list: HIGH confidence (always flag: `createNewFile`, `mkdir`, `mkdirs`, `delete`, `tryLock`, `tryAcquire`, `compareAndSet`, `find`); MEDIUM confidence (flag only when receiver name matches file patterns: `renameTo`, `setExecutable`, `setReadable`, `setWritable`). Skips lines where result is captured in a DFG def or appears in conditional context (`if (`, `while (`, `assert`, `?`, `||`, `&&`).
  - **`SyncIoAsyncPass`** (`sync-io-async`, CWE-1050, performance, medium/warning) — JS/TS/Python only; flags any call whose name ends in `Sync` (e.g. `readFileSync`, `execSync`, `customOperationSync`) or is in the blocking set (`sleep`) when the call site is inside a method whose `modifiers` includes `async`.
  - **`StringConcatLoopPass`** (`string-concat-loop`, CWE-1046, performance, low/warning) — scans source lines within CFG loop bodies (`graph.loopBodies()`) for `identifier +=` patterns. Filters out numeric variable names (`i`, `count`, `sum`, `total`, …), numeric suffixes (`Count`, `Sum`, `Total`, …), and numeric RHS literals, leaving only likely string concatenation.
- **Test count**: 857 → 897 (+40 new pass unit tests across 5 new test files)

## [3.9.1] - 2026-03-25

### Added

- **`analyzeProject` is now part of the public API** — exported from the top-level package entry point (`src/index.ts`). Previously the function existed in `src/analyzer.ts` but was not re-exported, making it inaccessible to downstream consumers.

## [3.9.0] - 2026-03-25

### Added

- **Phase 1 Group 1: five new analysis passes** — all emit `SastFinding[]` via `PassContext.addFinding()` and are wired into the 11-pass pipeline:
  - **`DeadCodePass`** (`dead-code`, CWE-561, reliability) — BFS reachability on the CFG; unreachable non-entry/exit blocks with `start_line > 0` are reported as `warning` findings
  - **`MissingAwaitPass`** (`missing-await`, CWE-252, reliability) — JS/TS only; 24-method curated set; flagged when call is not awaited, result is not assigned (no DFG def at line), and line is not a `return` statement
  - **`NPlusOnePass`** (`n-plus-one`, CWE-1049, performance) — DB/HTTP calls inside CFG loop bodies (`loopBodies()`); two-tier confidence: HIGH_CONFIDENCE methods flagged regardless of receiver; MEDIUM_CONFIDENCE require a DB-like receiver (`prisma`, `mongoose`, `axios`, `db`, `conn`, `repo`, …)
  - **`MissingPublicDocPass`** (`missing-public-doc`, maintainability) — checks for `/**` doc comment within 10 lines before declaration; language-specific public rules (Java: `public` modifier; JS/TS: not `private`/`protected`; Python: no `_` prefix); Python docstring detection; test files excluded
  - **`TodoInProdPass`** (`todo-in-prod`, maintainability) — line-by-line regex scan for `TODO`/`FIXME`/`HACK`/`XXX` markers in comment context (`//`, `#`, `--`, `*`); `FIXME`/`HACK` → medium, `TODO`/`XXX` → low; test files excluded
- **`analyzeProject()` — multi-file analysis API**: New public function that accepts an array of `{ code, filePath, language }` entries, runs single-file analysis on each, then uses `CrossFileResolver` to find cross-file taint flows. Returns `ProjectAnalysis` with `files`, `type_hierarchy`, `cross_file_calls`, `taint_paths`, and `findings` (empty; LLM enrichment is out of scope).
- **`ProjectGraph`** (`src/graph/project-graph.ts`): Wraps multiple `CodeGraph` instances. Provides lazily-built `SymbolTable`, `TypeHierarchyResolver`, and `CrossFileResolver` — all three rebuilt together on the first access after any `addFile()` call.
- **`CrossFilePass`** (`src/analysis/passes/cross-file-pass.ts`): Project-level pass that maps `CrossFileTaintFlow[]` → `TaintPath[]`, surfaces resolved inter-file calls, and exports the full `TypeHierarchy`.
- **`ProjectGraph` exported** from `src/graph/index.ts`.
- **SAST taxonomy types** (`src/types/index.ts`):
  - `PassCategory` — ISO 25010 aligned: `security | reliability | performance | maintainability | architecture`
  - `SarifLevel` — `error | warning | note | none`
  - `SastFinding` — SARIF 2.1.0 aligned finding interface with CWE mapping, `level` (SarifLevel), `category` (PassCategory), `rule_id`, optional `fix` and `evidence`; no LLM fields
  - `MetricCategory` — `complexity | size | coupling | inheritance | cohesion | documentation | duplication`
  - `MetricValue` — standard metric names (CK suite: WMC/DIT/NOC/CBO/RFC/LCOM; Halstead: V/D/E/B; McCabe: v(G)) with ISO 25010 sub-characteristic alignment
  - `FileMetrics` — per-file metric aggregation
  - `CircleIR.findings?` — optional `SastFinding[]` populated by analysis passes
  - `CircleIR.metrics?` — optional `FileMetrics` reserved for future metric passes
- **`PassContext.addFinding()`** — analysis passes can emit `SastFinding` objects directly into the pipeline
- **`PipelineRunResult`** — `AnalysisPipeline.run()` now returns `{ results: Map, findings: SastFinding[] }` instead of a bare Map; exported from `src/graph/index.ts`
- **`CodeGraph.loopBodies()`** (`src/graph/code-graph.ts`) — returns `{ start_line, end_line }[]` for each loop body detected via CFG back-edges (`edge.type === 'back'`); used by the n-plus-one pass
- **`docs/PASSES.md`** — canonical reference for all planned passes: number, `rule_id`, CWE, SARIF level, required graphs, implementation status; metric registry with 40+ metrics mapped to `MetricCategory` and ISO 25010 sub-characteristics

### Changed

- **`AnalysisPass` interface** — added `category: PassCategory` field; all 6 existing security passes updated with `category = 'security'`
- **`analyze()` pipeline** — extended from 6 to 11 passes; `DeadCodePass`, `MissingAwaitPass`, `NPlusOnePass`, `MissingPublicDocPass`, `TodoInProdPass` added after `InterproceduralPass`
- **`analyzer.ts` decomposed into 6 AnalysisPass modules** (behavior unchanged, zero test regressions):
  - `TaintMatcherPass` — config-based source/sink extraction + plugin merge
  - `ConstantPropagationPass` — dead-code detection, symbol table, field taint
  - `LanguageSourcesPass` — JS/Python language-specific sources and sinks
  - `SinkFilterPass` — four-stage false-positive elimination
  - `TaintPropagationPass` — DFG-based flow verification + array/collection/param supplements
  - `InterproceduralPass` — cross-method taint propagation (both scenarios)
- **`analyzer.ts`** reduced from ~2100 lines to ~630 lines; `analyze()` is now a clean orchestrator
- **`CodeGraph`** (`src/graph/code-graph.ts`): Introduced lazy Map indexes (defById, defsByLine, defsByVar, usesByLine, usesByDefId, chainsByFromDef, callsByLine, callsByMethod, sanitizersByLine, methodsByName, blockById) built once per analysis
- **Test count**: 788 → 857 (69 new pass unit tests across 5 new test files)

## [3.8.4] - 2026-03-24

### Fixed

- **JS/TS false positive reduction**: Added class constraint (`ScriptEngine`) to the classless `evaluate` sink pattern in `config-loader.ts` that was matching any `evaluate()` call as code injection (CWE-94). Discovered via self-analysis (dogfooding). This eliminates ~87% of false positives when analyzing JS/TS codebases that use `evaluate()` as a method name (e.g., AST evaluators, expression engines).

### Changed

- **TODO.md**: Added pending JS/TS precision improvements identified during dogfooding (`.value` dom_input narrowing, `new Function()` literal-arg suppression)

## [3.8.3] - 2026-03-17

### Changed

- **License**: Changed from ISC to MIT for broader compatibility and clearer permissions
- **Dependencies**: Updated to latest versions
  - `web-tree-sitter`: ^0.26.3 → ^0.26.7
  - `@types/node`: ^25.0.10 → ^25.5.0
  - `@vitest/coverage-v8`: ^3.0.0 → ^4.1.0
  - `vitest`: ^3.0.0 → ^4.1.0
  - `esbuild`: ^0.27.2 → ^0.27.4
- **Test coverage**: Adjusted branch coverage threshold to 64% to reflect vitest 4.x branch calculation differences in language plugin conditional logic

### Removed

- **ts-node**: Removed unused devDependency and its 74 transitive dependencies

### Added

- **CI/CD**: GitHub Actions workflows for automated testing and npm publishing
- **Documentation**: Added PUBLISHING.md with comprehensive release guide

## [3.8.2] - 2026-03-12

### Fixed

- **JS/Python: language auto-detection from filename** — requests that omit `language` now auto-detect from the filename extension (`.js`→`javascript`, `.ts`→`typescript`, `.py`→`python`, `.rs`→`rust`, `.sh`→`bash`); previously all fell back to `java`, causing JS/Python patterns to never fire
- **JS: SSRF via `http.get`/`https.get`** — added `{ method: 'get', class: 'http', ... }` and `https` entries to Node.js SSRF sinks in `config-loader.ts`; `http.get(url, callback)` now correctly produces CWE-918 (SSRF)
- **JS: command injection via destructured `exec`/`spawn`** — class-less entries for `spawn`, `spawnSync`, `execFile` added to `config-loader.ts`; combined with existing `exec`/`execSync` entries, all `child_process` forms now detected
- **Python: XSS via Flask route `return` statements** — added `findPythonReturnXSSSinks()` to detect `return '<html>...' + tainted_var` patterns in Flask routes; these are return statements, not call nodes, so they were invisible to the standard `findSinks()` path
- **CWE-668 spurious duplicate eliminated** — `analyzeInterprocedural` in the main flow (when real sinks already exist) no longer adds `external_taint_escape` sinks to `taint.sinks`; they were already skipped for flow generation (line 1216) but still added to the sinks array, causing double-findings when paired with a proper sink (e.g., CWE-918 SSRF + CWE-668 on adjacent lines)
- **JS: spurious XSS alongside command injection / path traversal eliminated** — added `buildJavaScriptTaintedVars()` (forward taint propagation for JS/TS) and a pre-propagation XSS sink filter; `res.send(stdout)` (callback param from `exec()`) and `res.send(data)` (callback param from `fs.readFile()`) are no longer tagged as XSS sinks because `stdout`/`data` are not in the tainted-variables map

## [3.8.1] - 2026-03-12

### Fixed

- **CWE-22 false positive eliminated** — removed `BufferedReader` constructor from path traversal sinks in `config-loader.ts`; `BufferedReader(Reader)` wraps a `Reader` object and never takes a file path, so it cannot be a path traversal sink
- **CWE-668 false positive eliminated (stream wrappers)** — added Java I/O stream wrappers (`InputStreamReader`, `OutputStreamWriter`, `BufferedInputStream`, `BufferedOutputStream`, `DataInputStream`, `DataOutputStream`, `BufferedReader`, `BufferedWriter`, `PrintStream`, `PrintWriter`) to `safeUtilityMethods` in `interprocedural.ts`; these are pure stream decorators and should not trigger `external_taint_escape` findings
- **CWE-668 false positive eliminated (string accumulators)** — added `StringBuilder`/`StringBuffer`/`Writer` accumulator methods (`append`, `insert`, `prepend`, `concat`, `delete`, `deleteCharAt`, `replace`, `reverse`, `write`, `writeln`, `println`) to `collectionMethods` in `interprocedural.ts`; string-building operations are not security sinks
- **CWE-22 false positive eliminated (URL constructor)** — removed `new URL(userInput)` and `URL.openStream()` from path traversal sinks in `config-loader.ts`; these are SSRF vectors (CWE-918), not file-system path traversal; the SSRF section already covers them correctly
- **CWE-668 false positive eliminated (byte array streams)** — added `ByteArrayInputStream`, `ByteArrayOutputStream`, and `ObjectOutputStream` to `safeUtilityMethods` in `interprocedural.ts`; byte array streams wrap in-memory data, not external I/O, and are not taint escape points

## [3.8.0] - 2026-03-11

### Added

- **Python: per-key container taint tracking** — `buildPythonTaintedVars` now tracks taint at per-key granularity for dicts and ConfigParser objects:
  - Subscript assignment: `map['keyB'] = param` seeds `containerTainted['map[\'keyB\']']`; `bar = map['keyB']` propagates correctly while `bar = map['keyA']` (safe key) does not
  - ConfigParser: `conf.set('s','k',param)` seeds per-key entry; `conf.get('s','k')` reads it back; distinguishes between tainted and safe keys in same section
- **Python: augmented assignment taint propagation** — `var += tainted_expr` now correctly preserves or seeds taint; previously `+=` lines were silently skipped
- **Python: for-loop iteration taint seeding** — `for name in request.headers.keys()` now marks `name` as tainted; handles both direct sources and tainted iterables
- **Python: new taint source patterns** — `PYTHON_TAINTED_PATTERNS` extended with `request.query_string`, `request.get_data(`, `get_form_parameter(`, `get_query_parameter(`, `get_header_value(`, `get_cookie_value(` (OWASP-style wrapper helpers)
- **Python: multi-line apostrophe guard detection** — `findPythonQuoteSanitizedVars` extended to look ahead up to 5 lines for the `return`/`raise` statement inside `if "'" in var:` blocks; previously only checked the immediately-next line
- **Python: inline `.replace()` sanitizer detection** — `query = f"...{bar.replace('\'', '&apos;')}..."` now marks `query` as XPath-safe; handles inline quote-escaping patterns that do not reassign the source variable
- **Python: parameterized XPath suppression** — `root.xpath(query, name=bar)` calls where the tainted variable appears only as a keyword argument (not in the query string) are now suppressed; lxml named variable substitution is not injectable
- **Python: sanitization propagation** — if `bar` is apostrophe-sanitized and `query = f"...{bar}..."`, `query` is also marked sanitized; prevents FPs where the sanitized var is used in a derived variable
- **Python benchmark 56.7% → 63.8%** — xpathi FPs reduced 22 → 7 (score 46% → 58%); trustbound improved 45% → 84% (6 → 17 TPs)

## [3.7.0] - 2026-03-11

### Added

- **Python P1 source detection** — three-pronged approach for Flask/Django/FastAPI taint tracking:
  - **`python.json` source patterns fixed** — 8 dotted method names split into correct `method`+`class` pairs (e.g. `"method":"get","class":"args"` instead of `"method":"args.get","class":"request"`) so `matchesSourcePattern` correctly matches `request.args.get()`, `request.form.get()`, `request.GET.get()`, etc.; 5 new patterns added (getlist/args, getlist/form, get_json/request, FILES field, query_params)
  - **`PYTHON_TAINTED_PATTERNS` + Python section in `taint-matcher.ts`** — regex-based source detection for `request.args[...]` subscript accesses passed as call arguments (not call nodes); covers 13 Flask/Django/FastAPI request property patterns
  - **`findPythonAssignmentSources()` in `analyzer.ts`** — line-scan detection for `x = request.args['id']` assignment patterns; handles `language !== 'python'` guard and skips comment lines
- **Python benchmark 25.2% → 56.7%** — sqli/weakrand/hash/securecookie all at 100%; cmdi improved; overall F1 77.5%
- **Import extractor test coverage improvements** — 13 new edge-case tests in `tests/extractors/imports.test.ts`:
  - JS: side-effect import, combined default+named, renamed CommonJS destructuring
  - Python: wildcard from-import, aliased from-import, dotted module import, multi-level relative import, multi-name from-import
  - Rust: `{self}` in use list, aliased item in use list, nested scoped path in use list, aliased nested scoped path with `::`, bare use identifier
- **Test count 730 → 743**

## [3.6.0] - 2026-03-11

### Added

- **Bash/Shell analysis fully functional** — core pipeline wired to extract `command` nodes as calls, detect `read` as taint source (io_input), and match sinks (eval/sh/bash/mysql/psql/sqlite3/cat/rm/cp/mv/curl/wget); 68.2% TPR, 0% FPR on 31 synthetic benchmark cases
- **`extractBashCalls()` in `calls.ts`** — new language branch in `extractCalls()` for Bash; extracts `command` AST nodes using `name` field, collects arguments with variable reference extraction (`$VAR`, `${VAR}`, `"$VAR"`)
- **Bash `nodeTypesToCollect` in `analyzer.ts`** — added `command`, `function_definition`, `variable_assignment`, `declaration_command`, `if_statement`, `for_statement`, `c_style_for_statement`, `while_statement`
- **Plugin source/sink merging in `analyzer.ts`** — language plugin `getBuiltinSources()` and `getBuiltinSinks()` are now merged into `baseConfig` at analysis time; enables pure-plugin languages like Bash to define their patterns without YAML config files
- **`'bash'` added to all three `SupportedLanguage` types** — `core/parser.ts`, `types/index.ts`, `languages/types.ts`; `'c'` and `'cpp'` synced into `languages/types.ts` for consistency
- **Bash synthetic benchmark** — 31 test cases covering CWE-78/94/89/22/918; scores 68.2% TPR (15 TP, 9 TN, 0 FP, 7 FN); 7 FNs are curl/wget command-substitution patterns requiring DFG tracking

### Changed

- **`BashPlugin.getBuiltinSources()`** — removed `curl` and `wget` (they're also sinks; without DFG tracking of `$()` they cause false positives); `read` source type changed from `user_input` to `io_input` to match `SourceType` union

## [3.5.0] - 2026-03-10

### Added

- **`BashPlugin`** (`src/languages/plugins/bash.ts`) — new language plugin with id `'bash'`, extensions `.sh/.bash/.zsh/.ksh`, WASM `tree-sitter-bash.wasm`; node type mappings for `command` → methodCall/functionCall, `function_definition` → functionDeclaration, `variable_assignment` → assignment; sink patterns for eval (CWE-94), sh/bash/zsh/ksh -c (CWE-78), mysql/psql/sqlite3 (CWE-89), cat/rm/cp/mv/chmod/chown (CWE-22), curl/wget (CWE-918)
- **`tree-sitter-bash.wasm`** — added to `wasm/` directory (committed)
- **14 new BashPlugin tests** in `tests/languages/plugins.test.ts`; total test count 730 (up from 716)
- **`'bash'` added to `SupportedLanguage`** in `src/languages/types.ts`

## [3.4.0] - 2026-03-09

### Added

- **Fastify taint sources** (`src/languages/plugins/javascript.ts`) — `request.raw` (http_param) and `request.hostname` (http_header) for Fastify request objects
- **Koa taint sources** — `ctx.header`, `ctx.headers` (http_header), `ctx.host`, `ctx.hostname` (http_header), `ctx.path`, `ctx.url` (http_path), `ctx.querystring` (http_param) for Koa context objects
- **Prisma unsafe raw query sinks** — `$executeRawUnsafe` and `$queryRawUnsafe` (CWE-89, critical); the parameterized `$executeRaw`/`$queryRaw` template literal variants are intentionally excluded as they are safe
- **Test coverage improvements** — imports.ts 61.7% → 77.6%, types.ts 69.7% → 93.2%, dfg.ts 71% → 85.87%, base.ts 30% → 96.66%, constant-propagation/index.ts 77.66% → 100%, constant-propagation/propagator.ts 70.25% → 75.39%; 716 total tests (up from 653)

## [3.3.3] - 2026-03-09

### Fixed

- **`checkSanitized` implemented** (`src/analysis/taint-propagation.ts`) — the function was a stub that always returned `{ sanitized: false }`. It now performs variable-specific sanitizer detection:
  - Checks for a recognised sanitizer call **AT the target definition line** (e.g. `safe = escapeHtml(input)`). This is variable-specific: the DFG chain guarantees the target variable is the return value of that sanitizer call.
  - **Sink-check context** (sinkType is a known CWE type such as `sql_injection`): requires the sanitizer to cover that specific vulnerability type.
  - **Propagation context** (sinkType is a source type such as `http_param`): accepts any recognised sanitizer, since the eventual sink type is not yet known.
  - Intentionally does **not** perform a range scan (from → to lines) which was the cause of the previous over-eager false-negative behaviour.
- **Initial-taint "next-line" heuristic now respects sanitizers**: `propagateTaint` filters variables that were added to the initial taint set via the "next-line" heuristic (e.g. when the source call and the tainted variable definition are on adjacent lines) but are actually the result of a sanitizer call at their definition line.
- **3 new tests** covering: propagation stopped through `escapeHtml`, propagation continues through non-sanitizer `toLowerCase`, and sanitizer on a different variable does not suppress taint on the original.

## [3.3.2] - 2026-03-05

### Fixed

- **Taint Propagation Through String Methods**: Removed `trim` and `replace` from `SANITIZER_METHODS` — these methods do not sanitize any vulnerability type (trim only removes whitespace; replace is not a reliable sanitizer). Method chains like `request.getParameter("x").toLowerCase().trim()` now correctly mark the result as tainted, eliminating false negatives.

## [3.3.1] - 2026-02-22

### Added

- **WebAssembly.Module Support**: Parser and browser initialization now accept pre-compiled `WebAssembly.Module` instances for Cloudflare Workers compatibility
- **WASM Options**: New `wasmModule` and `languageModules` options for pre-compiled WASM to bypass dynamic compilation
- **Custom WASM Instantiation**: Parser accepts `instantiateWasm` callback for custom WASM loading strategies

### Changed

- **Literal Sink Filtering**: `analyzeForAPI` now applies `filterCleanVariableSinks` and `filterSanitizedSinks` to reduce false positives
- **Taint Treatment**: Literal arguments and quoted string expressions are now treated as clean (not tainted) to eliminate false positives on constant values

### Fixed

- Browser initialization now accepts `string | WebAssembly.Module` for `wasmUrl` and `languageUrls` parameters

## [3.3.0] - 2025-02-19

### Added

- **Logger Dependency Injection**: New `setLogger()` function allows consumers to inject custom loggers (pino, winston, etc.)
- **Logger Exports**: `setLogger`, `configureLogger`, `setLogLevel`, `getLogLevel`, `logger` now exported from main index

### Changed

- **Zero-dependency Logger**: Replaced pino with a simple console-based logger (zero dependencies, browser-compatible)
- **Removed Dead Code**: Deleted unused modules (advisory-db, cargo-parser, dependency-scanner) that were not part of taint analysis
- **Cleaned skipMethods**: Removed benchmark-specific method names from interprocedural analysis skip list

### Removed

- `pino` dependency (replaced with zero-dependency console logger + DI)
- `pino-pretty` devDependency
- Unused barrel exports: `isInDangerousPosition`, `formatVerificationResult`
- Dead analysis modules: `advisory-db.ts`, `cargo-parser.ts`, `dependency-scanner.ts`

## [3.1.0] - 2025-02-11

### Changed

- **npm-ready Package**: Added proper exports map, module field, sideEffects flag, and publishConfig
- **WASM Path Resolution**: Fixed path resolution to work when installed as npm package (resolves relative to module location)
- **Browser Compatibility**: Used Function constructor pattern to hide Node.js imports from bundlers

### Fixed

- WASM files now correctly resolve whether circle-ir is run from source or installed via npm
- Browser builds no longer fail due to Node.js module imports

## [3.0.0] - 2025-02-01

### Added

- **Core SAST Library**: Complete taint analysis engine for detecting security vulnerabilities
- **Multi-language Support**: Java, JavaScript/TypeScript, Python, Rust
- **Universal Core**: Environment-agnostic library works in Node.js, browsers, and Cloudflare Workers
- **Vulnerability Detection**: SQL injection, command injection, XSS, path traversal, LDAP injection, XPath injection, deserialization, SSRF, code injection, XXE
- **Configuration-driven Analysis**: YAML-based source/sink definitions
- **Browser Example**: Interactive HTML example for browser-based analysis (`examples/browser-example.html`)

### Benchmark Results

- **OWASP Benchmark**: +100% (TPR: 100%, FPR: 0%, 1415/1415 test cases)
- **Juliet Test Suite**: +100% (156/156 test cases)
- **SecuriBench Micro**: 97.7% TPR, 6.7% FPR (105/108 vulns detected)
- **CWE-Bench-Java**: 42.5% static (51/120 real-world CVEs, vs CodeQL 22.5%, IRIS+GPT-4 45.8%)

### Technical Highlights

- Tree-sitter WASM parsing for accurate AST generation
- Constant propagation for false positive elimination
- Inter-procedural taint analysis
- Sanitizer recognition (PreparedStatement, ESAPI, etc.)
- Per-index collection taint tracking
- Language plugin architecture

[3.9.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.9.0
[3.8.4]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.4
[3.8.3]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.3
[3.8.2]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.2
[3.8.1]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.1
[3.8.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.8.0
[3.7.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.7.0
[3.6.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.6.0
[3.5.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.5.0
[3.4.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.4.0
[3.3.3]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.3
[3.3.2]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.2
[3.3.1]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.1
[3.3.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.3.0
[3.1.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.1.0
[3.0.0]: https://github.com/cogniumhq/circle-ir/releases/tag/v3.0.0
