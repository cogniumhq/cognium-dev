# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.82.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.82.0 — Sprint 29 bundle closing **#113**
  (`external_taint_escape` over-fires on sanitized-input shapes — numeric
  casts, `Math.min`/`Math.max` bounds-clamps, and allow-list/membership
  guards `Array.includes` / `Set.has` / `.contains` / `indexOf` now declare
  `external_taint_escape` in their sanitizer `removes:` set) and the
  remaining 2 of 9 **#86** CWE coverage gaps via two new security passes:
  - **#103 `info-disclosure-stacktrace`** (CWE-209, warning) — exception
    detail returned to a client via an HTTP response handle in Java
    (`e.printStackTrace(response.getWriter())`), JS/TS (`res.send(err.stack)`,
    `res.json(err)`), Python (`return traceback.format_exc()` in a Flask /
    Django / FastAPI handler), Go (`http.Error(w, err.Error())`,
    `fmt.Fprintln(w, err)`). Logger receivers (`console`/`logger`/`log`/
    `slog`/`pino`/`winston`) are suppressed.
  - **#104 `unrestricted-file-upload`** (CWE-434, error) — HTTP-uploaded
    file saved with its untrusted original name (`getOriginalFilename`,
    `originalname`, `.filename`, `header.Filename`) with no extension
    allow-list or canonicalization. Per-function FP-guard suppresses
    findings inside any function whose body contains a `secure_filename`,
    `FilenameUtils.getExtension`, `ALLOWED_EXT`, `fileFilter`,
    `path.extname`, or `filepath.Ext` reference.

## [3.81.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.81.0 — Sprint 28 bundle closing **#110** (xss
  mistyping of every non-XSS `.write()` call across all languages — root
  cause was an unscoped `{ method: "write", type: "xss" }` entry in
  `configs/sinks/xss.yaml` + its mirror in `config-loader.ts`) and the
  remaining CWEs of **#109**: CWE-916 `weak-password-hash`, CWE-256
  `plaintext-password-storage`, CWE-523 `cleartext-credential-transport`,
  CWE-261 `weak-password-encoding`. Four new pattern passes, one shared
  `_credential-helpers.ts` module, 23 new regression tests (full suite
  2607 pass). See `packages/circle-ir/CHANGELOG.md` for the full
  breakdown.

## [3.80.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.80.0 — Sprint 26 bundle closing **#117**
  (CWE-501 Trust Boundary under-fire on OWASP shape), **#118**
  (CWE-614 Insecure Cookie missed FQ `new javax.servlet.http.Cookie(...)`
  constructor), and **#109** (CWE-260/798 Hardcoded Credentials missed
  config-style constants like `DB_PASSWORD = "Pr0d-DB-pass!2024"`).
  See `packages/circle-ir/CHANGELOG.md` for the full breakdown. **#113**
  deferred — probes did not reproduce the issue body's FP set.

## [3.79.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.79.0 — **#116** CWE-327 weak-crypto Java precision
  was 58.3% (130 TP / 93 FP) on OWASP Java benchmark v3.67.0 — 85% of
  all Java FPs. Root cause: `KeyGenerator.getInstance("AES")` (the
  canonical, safe AES key-derivation API) was treated identically to
  `Cipher.getInstance("AES")`, including the "AES with no mode → ECB"
  rule. `KeyGenerator` has no cipher mode — the mode is chosen later by
  `Cipher.getInstance("AES/CBC/...")`. Fix splits the gate into
  `isCipherInstance` (full Cipher logic) and `isKeyGenInstance`
  (weak-base only); `KeyGenerator.getInstance("DES" | "RC4" | "Blowfish")`
  still flags. Cipher detection unchanged. No CLI changes — version
  bump only.

## [3.78.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.78.0 — **#119** CWE-328 weak-hash Java recall
  was 69% (89 TP / 40 FN) on OWASP Java benchmark v3.67.0. Fix adds
  three resolution paths missing from the existing pass:
  Apache Commons getter form (`DigestUtils.getMd5Digest()` /
  `.getSha1Digest()` / `.getShaDigest()`), Apache Commons algorithm
  constants (`MessageDigest.getInstance(MessageDigestAlgorithms.MD5)`),
  and variable / field / final-local algorithm names resolved via
  constant propagation with a regex-bound fallback for
  `String NAME = "MD5";` declarations the const-prop pass does not
  yet track. SHA-256 and dynamic-parameter cases remain unflagged.
  No CLI changes — version bump only.

## [3.77.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.77.0 — **#121** `jwt-verify-disabled` Java branch
  was firing on any `<receiver-containing-"parser">.parse(...)` call
  (20 critical FPs across 12 popular Java OSS repos, zero TPs in the
  same sample, three repos forced to BLOCKED trust score). Fix anchors
  the receiver gate to the explicit `Jwts.parser()` JJWT chain. No CLI
  changes — version bump only.

## [3.76.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.76.0 — **#120** Python sanitizer state dropped
  across intraprocedural alias hop. Fix: `aliasSanitizedFor` now
  propagates through pure `lhs = upstreamIdentifier` copies via a
  fixpoint, gated by latest-origin to preserve re-tainting recall. No
  CLI changes — version bump only.

## [3.75.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.75.0 — Sprint 25 fast wins:
  - **#112** Java `new Random().nextInt(...)` chained-constructor pattern
    now fires `weak-random` (CWE-331). Typed-local form was already
    detected; chained form was missed because the IR emits the method
    call with `receiver_type=null`.
  - **#111** Go `w.Header().Set/Add(k, tainted)` and Python
    `resp.headers.set/add/setdefault/__setitem__/extend(...)` and
    `resp.set_cookie(name, tainted)` now fire `crlf` (CWE-113). Go
    sinks already existed but `receiverMightBeClass` didn't recognise
    the `<expr>.ClassName()` chained-method shape; Python had no CRLF
    sinks at all.
- Known limitation: Python subscript assignment
  `resp.headers['X-A'] = value` is not covered because the IR does not
  emit subscript writes as calls.

## [3.74.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.74.0 which closes the Go portion of cognium-dev #102
  (five Go safe-handler false positives left open after Sprint 23):
  - **FP-19a** parameterised `db.Query`/`db.Exec` no longer triggers
    `external_taint_escape`.
  - **FP-19b** `html/template.Execute` auto-escape recognised via
    import-aware sanitizer emission.
  - **FP-20** map-allowlist host guard
    (`if !allowedHosts[host] { return }`) suppresses downstream `ssrf`
    flow.
  - **FP-25** `exec.Command("ping", "-c", "1", host)` (literal non-shell
    program) no longer fires `command_injection`. Sprint 23 #53
    shell-shape lock preserved.
  - **FP-27** `html.EscapeString` → `fmt.Fprintf` sanitization correctly
    suppresses the synthetic CWE-668 fallback.
- No CLI behaviour change; existing severity mappings cover all affected
  sink types.

## [3.73.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.73.0 which closes the Sprint 23 bundled "S" set:
  - **#53** Go string-concat taint preservation across `+` (right-,
    left-, and middle-concat into `exec.Command`/`os.ReadFile`).
  - **#102** Bash realpath + case prefix-guard FP suppression
    (`resolved=$(realpath); case "$resolved" in "$ROOT"/*) ...; *) exit;;`).
  - **#107** Go `log_injection` sink config for
    `log.{Print,Println,Printf,Fatal,Fatalln,Fatalf,Panic,Panicln,Panicf}`.
  - **#108** Go `code_injection`/SSTI sink config for `text/template`
    and `html/template` `Parse`/`ParseFiles`/`ParseGlob`/`ParseFS`.
- No CLI behaviour change; severity mapping for `code_injection` and
  `log_injection` was already in place from Sprint 22 (#104).

## [3.72.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.72.0 which closes #104 (Sprint 22) — OOP object-flow
  taint FN, sink-agnostic. Sixteen new positive-recall fixtures across
  Python (9) and JavaScript (7) covering path_traversal, open_redirect,
  log_injection, ldap_injection, xpath_injection, nosql_injection, xxe,
  deserialization, and code_injection/SSTI from constructor-injected
  fields (`self.X` / `this.X`) consumed by sibling methods.
- New sink-config coverage:
  - Python `logging.{info,warning,error,debug,critical,log,exception}`
    (CWE-117 log_injection) module-level functions.
  - Python pymongo classless `find_one`/`update_one`/`delete_one`/...
    (CWE-943 nosql_injection) for `db.users.find_one({...})` dynamic
    attribute access.
  - JS ldapjs `ldap.search`/`searchSync` (CWE-90 ldap_injection).
  - JS xpath module `xpath.select`/`select1`/`evaluate`/`parse`
    (CWE-643 xpath_injection).
  - JS libxmljs `parseXml`/`parseXmlString` and xmldom
    `parseFromString` (CWE-611 xxe).
  - JS ejs/handlebars/pug/mustache/nunjucks template render/compile
    (CWE-94 code_injection — SSTI).
- No CLI surface changes; output formats unchanged.

## [3.71.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.71.0 which closes #105 (Sprint 21) — OOP safe-mirror
  sanitizer false positives:
  - **FP-31** — allowlist-guarded getters
    (`if x not in self.ALLOWED: raise; return self.url`) no longer fire
    `ssrf` when called from a sink. Cache-shape lookups and plain getters
    still propagate (regression-locked).
  - **FP-32** — MongoDB value-bound filter dicts
    (`findOne({ user: name })`) no longer fire `nosql_injection`.
    Operator-injection shapes (`findOne(filter)`,
    `findOne({$where: ...})`) still fire.
  - Regression locks for FP-33 (hardened lxml parser), FP-34 (EJS `<%=`
    auto-escape), and FN-INV (direct `self.url` read) — all
    already-correct behavior pinned by `repro-sprint21.test.ts`.
- No CLI surface changes; output formats unchanged.

## [3.70.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.70.0 which ships Sprint 20 — `cache-no-vary` pass
  (#98 in PASSES.md, CWE-524, severity `medium`, level `warning`):
  - **#96 L91** — Python (Flask/Django/FastAPI) and cross-language
    (JS/TS Express, Go net/http, Java Spring) handlers that set
    `Cache-Control: public` (or `max-age>0` / `s-maxage>0`) on a
    response in a handler that also reads authenticated / user-scoped
    state (cookies, `Authorization`, session, `@CookieValue`,
    `Principal`, `Authentication`) but do not set a covering
    `Vary: Cookie` / `Vary: Authorization` are now flagged.
  - Strict auth-qualifier mode — `/health`, `/version`, and static-asset
    endpoints (no auth signal) do **not** fire.
  - Covered by `res.vary('Cookie')` (JS), `@vary_on_cookie` (Python),
    `w.Header().Set("Vary", "Cookie")` (Go), or
    `response.addHeader("Vary", "Cookie")` (Java).

## [3.69.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.69.0 which ships Sprint 19 — `module-side-effect`
  pass (#97 in PASSES.md):
  - **#93** — npm `postinstall` / `preinstall` lifecycle droppers
    (`scripts.{pre,post}install` invoking curl/wget/node -e/sh -c/eval)
    and JS module-top `child_process` / `https.request` /
    `fetch(process.env)` are now flagged. Benign install scripts
    (`node-gyp rebuild`, `prebuild-install`, `husky install`,
    `patch-package`) are allowlisted.
  - **#96 L47** — Python module-import-time credential POST harvest
    (`requests.post(URL, data=dict(os.environ))` at module top) now
    fires `module-side-effect` (CWE-829). Same call inside a function
    body does not.
  - **#98** — Go `func init()` running `exec.Command` / `http.{Post,Get}`
    / `net.LookupTXT` / `os.Setenv` and Rust `build.rs` invoking
    `Command::new` are now flagged. `println!("cargo:...")` directives
    in `build.rs` continue to produce no finding.

## [3.68.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.68.0 which ships Sprint 18 (Python consolidation):
  - **#65 (bug fix)** — Python f-string interpolation
    (`cur.execute(f"... {uid}")`) now propagates taint correctly. The
    `extractPythonLiteral` helper previously treated f-strings as
    compile-time literals and silently dropped the interpolated
    variables; sinks behind f-strings now fire as expected.
  - **#96 (FN, partial)** — `urllib.request.urlretrieve(url, dest)`
    registered as a dual sink: `ssrf`/CWE-918 on arg 0 (URL) and
    `path_traversal`/CWE-22 on arg 1 (destination filename).
  - **#100 (FP, regression locks)** — 7 fixtures lock the Python safe
    corpus (parameterized SQL, `int()` type-cast barrier,
    `realpath()` + `startswith()` guard, sanitizer-wrapper
    interproc recognition) plus two negative locks for wrong-context
    and identity-function sanitizers.

## [3.67.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.67.0 which ships Sprint 17 (JS/TS/JSX consolidation):
  - **#94** — `protobufjs.parse(taint)` / `Root.parse(taint)` now emit
    `code_injection`/CWE-94 (CVE-2026-41242).
  - **#88.2** — `.tsx` files with `dangerouslySetInnerHTML={{__html: taint}}`
    now fire the React XSS sink (typescript → javascript plugin fallback
    in the language registry).
  - **#95** — Per-sink `allow_unresolved_receiver: true` flag detects
    Express runtime-decorated receivers (`req.db.query(taint)`,
    `req.db.execute(taint)`) for `Connection`/`Pool`/`Client` SQL sinks.
  - **#97** — Lock test for TS partial-parse robustness
    (`execSync(\`git diff \${branch}\`)` at L18 with noisy
    `process.env.npm_package_*` access in scope).
  - **#99** — Stage-8 FP filter in `sink-filter-pass.ts` drops JS/TS
    `open_redirect` and `crlf` findings under conditional-allowlist
    guards (`if (allowed.includes(url))`), `encodeURIComponent`
    sanitizers, and constant-literal `setHeader` calls.
  - **#68** — `mass_assignment` / CWE-1321 verification lock for
    `Object.assign({}, req.body)` and `_.merge({}, req.body)`.
- See `packages/circle-ir/CHANGELOG.md` for detail.

## [3.66.0] - 2026-06-18

### Changed

- Tracks circle-ir 3.66.0 which ships Sprint 16:
  - **#78 round 2 (OOP field-sensitivity)** — Java static field stores
    (`Config.dbHost = req.getParameter(...)` flowed to
    `Runtime.exec(dbHost)`), non-bean setter/getter pairs
    (`u.setCred(taint)` → `u.getCred()` in SQL sink), and cross-instance
    aliasing via constructor-stored receivers (`Service` writes
    `this.repo.sql = taint`, `Repo.run()` executes it).
  - **#74 follow-up (cross-file Java taint)** — `CrossFileResolver` now
    consults `call.receiver_type_fqn` first, unlocking SymbolTable FQN
    lookups for direct-instance, `import static`, and Spring `@Autowired`
    cross-file dispatch. Interface dispatch falls through to polymorphic
    candidates when the resolved parent type is an `interface`.
  - **#52** — FreeMarker `Configuration.getTemplate(filename)` SSTI
    fixture locked.
- Cross-file Java taint paths now render in the standard cross-file
  section of text/JSON/SARIF output for the above patterns.
- See `packages/circle-ir/CHANGELOG.md` for detail.

## [3.65.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.65.0 which closes the dedup sub-gap of #49:
  unsanitized Java fixtures no longer emit the same
  `(source_line, sink_line, sink_type)` triple twice from independent
  internal detectors (DFG propagator + four supplementary detectors). A
  final dedup pass in `TaintPropagationPass.run()` retains the
  highest-confidence flow per triple. Real `xxe` and `path_traversal`
  flows still fire on unsanitized code. See
  `packages/circle-ir/CHANGELOG.md` for detail.

## [3.64.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.64.0 which closes Sprint 14 (cognium-dev #101 — Java
  FP corpus regression). Four false-positives from
  `coggiyadmin/java-vuln-demo` are suppressed without regressing the 2402
  pre-existing tests:
  - FP-01 `path_traversal` on `new File(base, filename)` inside a method
    using the canonical-path-startsWith-throw idiom.
  - FP-02 `xxe` inside methods that harden `DocumentBuilderFactory` /
    `SAXParserFactory` via `setFeature("disallow-doctype-decl", true)` /
    `setFeature("external-general-entities", false)` /
    `setFeature("external-parameter-entities", false)` /
    `setFeature("load-external-dtd", false)` or
    `setProperty(SUPPORT_DTD, false)`.
  - FP-03 `command_injection` on the switch→constant pattern
    (`String cmd; switch(type){ case "x": cmd = "/bin/x"; ...} exec(cmd);`).
  - FP-04 `sql_injection` on the bounded-allowlist pattern
    (`if (!ALLOWLIST.contains(col)) col = "name";`) — already suppressed
    in 3.63.0, now locked behind a regression test.

  See `packages/circle-ir/CHANGELOG.md` for the detailed engine-level
  changes (new `isInJavaSanitizedMethod()` helper, `TaintSource.in_method`
  method-scope plumbing across all seven source-emission sites,
  cross-method bleed gate in `detectCollectionFlows`, switch-case
  literal-reassignment pattern in `isReassignedToLiteralBetween`).

## [3.63.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.63.0 which closes Sprint 13 (issues #70, #74):
  taint-flow source lines emitted by `detectCollectionFlows` and
  `detectArrayElementFlows` are now reported correctly per method scope
  (previously every collection/array-element flow in a multi-method file
  pointed at the file's first source). Cross-file Python taint paths
  (source in `controller.py` → sink in `db_helper.py` /
  `shell_helper.py`) are locked in with positive regression fixtures —
  `analyzeProject()` already wires `CrossFilePass` →
  `CrossFileResolver` → `findCrossFileTaintFlows` correctly. See
  `packages/circle-ir/CHANGELOG.md` for detail.

## [3.62.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.62.0 which closes the Python batch (issues #66, #59):
  `zipfile.ZipFile($p).extractall(...)` now produces a `path_traversal`
  flow via new lowercase Python-scoped `extractall` and `ZipFile`
  constructor sinks; Flask `send_from_directory('/dir', $f)` is detected
  as CWE-22; Flask method/property sources `request.get_data()`,
  `request.get_json()`, and `request.stream` are recognised
  (`pickle.loads(request.get_data())` → `deserialization`);
  bare-imported functions like `from urllib.request import urlopen` are
  now matched against class-qualified patterns via
  `call.resolution.target` (recovers SSRF flow); non-ASCII identifiers
  such as `café` propagate taint correctly (Python alias map and the
  word-boundary regex in `taint-propagation-pass` are now Unicode-aware,
  using `[\p{L}\p{N}_]+` with the `u` flag). See
  `packages/circle-ir/CHANGELOG.md` for detail.

## [3.61.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.61.0 which closes the Bash batch (issues #72, #73):
  bash `bash -c "$1"` / `host=$1; bash -c "$host"` now produce
  `command_injection` flows (sink dedup collision repaired + positional-param
  seeding fixed); `source "$URL"` / `. "$URL"` are detected as CWE-98 file
  inclusion sinks; tainted args into unknown shell utilities (`ping`,
  `whois`, `curl`, …) are re-classified from generic `external_taint_escape`
  to CWE-78 `command_injection`; the idiomatic
  `if [[ ! "$var" =~ ^[a-zA-Z0-9_]+$ ]]; then exit; fi` regex-allowlist
  guard is now recognised as a sanitizer. CLI formatters gain
  SINK_SEVERITY / SINK_CWE entries for `redos`, `format_string`, `crlf`,
  and `mass_assignment` (unblocks `tsc --noEmit`). See
  `packages/circle-ir/CHANGELOG.md` for detail.

## [3.60.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.60.0 which closes the JS/TS batch (issues #88, #80, #69,
  #68): HTML `<script>` taint flows now propagate through the HTML merge step,
  `.tsx` / `.jsx` files route to the JSX-aware `tree-sitter-tsx` grammar,
  React's `dangerouslySetInnerHTML` is recognised as an XSS sink, DOM-XSS via
  `el.innerHTML` / `el.outerHTML` property assignment is detected,
  `node-serialize.unserialize` is modelled as a deserialization sink, and
  prototype-pollution patterns (`_.merge`, `Object.assign`, `lodash.merge`,
  etc.) now carry CWE-1321. See `packages/circle-ir/CHANGELOG.md` for detail.

## [3.59.0] - 2026-06-17

### Changed

- Tracks circle-ir 3.59.0 which fixes issue #78: OOP constructor-injected
  field flow now propagates taint to sinks in sibling methods of the same
  class, for both direct `(this|self).<field>` reads and getter / `@property`
  indirection. See `packages/circle-ir/CHANGELOG.md` for detail.

## [3.58.0] - 2026-06-16

### Changed

- Tracks circle-ir 3.58.0 which ships the Sprint 9 FP-precision cluster
  (#48, #50, #51, #55, #56, #57, #58, #79, #85, #92): pure-literal sink
  suppression, Rust safe-path/xss sanitizers, type-cast taint barriers,
  path-canonicalization sanitizers, allowlist + reassign-to-literal
  guards, dead-code-by-const-guard suppression, DBAPI XSS misclassification
  suppression, Java regex-allowlist + switch-const guards, security-headers
  global-middleware verification, and interprocedural sanitizer wrappers.
  See `packages/circle-ir/CHANGELOG.md` for per-issue detail.

### Added

- `packages/cli/src/exclude-tests.test.ts` locks in `--exclude-tests`
  behaviour across Go (`_test.go`), Python (`_test.py`, `test_*.py`),
  JS/TS (`.test.ts`, `.spec.js`), Java (`*Test.java`, `*IT.java`),
  Rust (`_test.rs`), and `test/`, `tests/`, `__tests__/`, `spec/`
  directories.

## [3.57.0] - 2026-06-16

### Fixed

- **Issue #85 — `--exclude-tests` now suppresses Go `_test.go` files.**
  `TEST_PATTERNS` in `src/cli.ts` already covered Java (`Test.java`,
  `Tests.java`, `IT.java`), JS/TS (`.test.ts`, `.spec.js`, etc.),
  Python (`_test.py`, `_tests.py`, `test_*.py`), and Rust (`_test.rs`),
  but Go's `_test.go` convention was missing. Adds `/_test\.go$/` so
  `inj_test.go` fires by default and is suppressed under
  `--exclude-tests`, matching the engine-level `scan-secrets-pass.ts`
  regex.

### Changed

- **circle-ir upgraded 3.56.0 → 3.57.0** — Sprint 8 adds Java for-each and
  container taint propagation, plus Go path sanitizers:
  - **#84** `for (String x : taintedList)` now correctly propagates collection
    taint to the loop variable, so downstream uses at sinks fire.
  - **#62-partial** `m.put(k, tainted)` → `m.get(k)` at a sink fires SQLi;
    `StringBuilder.append(tainted)` → `sb.toString()` at a sink fires SQLi.
  - **#51** Go `filepath.Base` / `filepath.Clean` / `path.Clean` /
    `filepath.EvalSymlinks` are now recognized as `path_traversal`
    sanitizers, mirroring the Java `getCanonicalPath` / `Path.toRealPath`
    treatment and the Rust `file_name` / `canonicalize` entries.
  - **#50** `SecurityHeadersPass` now suppresses `missing-x-frame-options`
    and `missing-csp-frame-ancestors` when a global security middleware
    (Express `helmet()`, Spring `SecurityFilterChain`, Flask `Talisman`)
    is detected in the same file.
  - **#73** (part 1) Bash `findBashTaintSources` now tracks brace depth so
    `$1`/`$2` inside function bodies are not conflated with script-CLI
    positionals. The regex-allowlist guard (`[[ $x =~ ^… ]]`) is deferred
    to Sprint 9.

  Sprint 8 also adds a new regression-fixture file
  (`tests/analysis/repro-sprint8.test.ts`, 19 fixtures) that codifies the
  end-to-end contracts for issues #49, #50, #51, #62, #73, #84, #90, and #91.
  See `packages/circle-ir/CHANGELOG.md` for full detail.

## [3.56.0] - 2026-06-16

### Changed

- **circle-ir upgraded 3.55.0 → 3.56.0** — Sprint 7 finishes the cross-
  language `weak-crypto` family (issue #87). Python and Go now detect the
  same set of insecure-cryptographic-config issues already shipped for
  Java in 3.55.0:
  - Python `modes.ECB()` (cryptography.hazmat) — CWE-327
  - Python `AES.new(b"literal", …)` / `algorithms.AES(b"literal")` — CWE-321
  - Python `rsa.generate_private_key(key_size<2048)` — CWE-326
  - Go `aes.NewCipher([]byte("literal"))` — CWE-321
  - Go `rsa.GenerateKey(rand.Reader, <2048)` — CWE-326

  Both languages additionally support a regex-fallback "literal-binding"
  scan so the common two-line idiom
  `key = b"…"` / `c = AES.new(key, …)` is also flagged. Function
  parameters and runtime values are still excluded.

## [3.55.0] - 2026-06-16

### Changed

- **circle-ir upgraded 3.54.0 → 3.55.0** — Sprint 6 closes out the
  cognium-dev#86 9-category gap analysis with four new categories:
  - **CRLF / HTTP response splitting (CWE-113)** — new `crlf` taint sink.
    Header-writing sinks (`HttpServletResponse.setHeader`/`addHeader`,
    Express `res.setHeader`/`writeHead`/`cookie`/`location`/`redirect`,
    Go `http.Header.Set`/`Add`) are re-routed from `xss` to `crlf`.
    `sendRedirect` retains its primary `ssrf` / open-redirect classification.
  - **Mass-assignment / over-posting (CWE-915)** — new `mass_assignment`
    taint sink for `Object.assign(target, req.body)`, lodash `_.merge`/
    `_.extend`, and jQuery `$.extend`. New `mass-assignment` pattern pass
    (#96) flags Python kwargs-splat `User(**request.form)` and JS object
    spread `{...req.body}`.
  - **CSRF protection disabled (CWE-352)** — new `csrf-protection-disabled`
    pattern pass (#94, `critical`). Flags Spring Security `http.csrf().disable()`,
    lambda DSL `http.csrf(c -> c.disable())`, method-ref
    `csrf(CsrfConfigurer::disable)`, `csrfTokenRepository(null)`, and
    Django `@csrf_exempt`.
  - **XML entity expansion (CWE-776)** — new `xml-entity-expansion` pattern
    pass (#95, `high`). Flags Java XML factory `.newInstance()` without
    `disallow-doctype-decl`/`external-general-entities`/`SUPPORT_DTD`/
    `ACCESS_EXTERNAL_DTD` evidence in file, and Python `lxml.etree.parse`/
    `fromstring`/`XML` and `xml.etree.ElementTree.parse`/`fromstring`
    unless `defusedxml` is imported.

  All findings surface through `scan` and the text / JSON / SARIF formatters
  without CLI changes. See circle-ir 3.55.0 CHANGELOG for per-language
  detection details and the `canSourceReachSink` coverage fix that unblocked
  inline source-as-argument flows for the new sink types.

## [3.54.0] - 2026-06-16

### Changed

- **circle-ir upgraded 3.53.0 → 3.54.0** — Sprint 5 coverage additions for
  cognium-dev#86 (9-category gap analysis):
  - **JWT verification disabled (CWE-347)** — new `jwt-verify-disabled`
    pattern pass (#93, `critical`). Flags PyJWT `jwt.decode` with
    `verify_signature: False` / `verify=False` / `algorithms=["none"]`,
    `jsonwebtoken` `jwt.verify` with `algorithms: ['none']` / null key,
    auth0-java `JWT.require(Algorithm.none())`, and jjwt
    `Jwts.parser()...parse(token)` (unverified parse).
  - **ReDoS (CWE-1333)** — new `redos` taint sink type. Tainted regex
    patterns flowing into `re.{match,search,compile,findall,…}` (Python),
    `Pattern.compile` / `String.matches|replaceAll|replaceFirst|split`
    (Java), `new RegExp(...)` (JS), and `regexp.{Compile,MustCompile,Match,
    MatchString}` (Go) are now flagged.
  - **Format-string injection (CWE-134)** — new `format_string` taint sink
    type. Tainted format strings flowing into `String.format` /
    `Formatter.format` / `System.out.printf` (Java), `ctypes.printf` (Python),
    and `fmt.{Sprintf,Printf,Errorf,Fprintf}` (Go) are flagged. Python
    `userFmt.format(...)` (receiver-taint) is deferred to Sprint 6.

  All findings surface through `scan` and the text / JSON / SARIF formatters
  without CLI changes. See circle-ir 3.54.0 CHANGELOG for per-language
  detection details.

## [3.53.0] - 2026-06-16

### Changed

- **circle-ir upgraded 3.52.0 → 3.53.0** — Sprint 4 Java precision/coverage:
  - **Issue #52** — three previously-missed Java patterns now fire:
    Text4Shell (`StringSubstitutor.replace`, CWE-94), FreeMarker SSTI
    (`new Template(...)`, CWE-94), and Zip-Slip (`ZipEntry.getName()` →
    `new File(...)`, CWE-22). The Zip-Slip rule is also re-modeled
    (source instead of sink), eliminating duplicate findings.
  - **Issue #87 (partial)** — `weak-crypto` extended to flag static/zero
    IVs (CWE-329), hardcoded symmetric keys (CWE-321), and weak RSA key
    sizes < 2048 (CWE-326). Per-issue CWE in the SARIF / JSON output.
  - **Matcher fix** — sink and source matchers now use IR-resolved
    `receiver_type` before the receiver-name heuristic, improving Java/TS
    precision across all class-qualified patterns.

  All findings surface through `scan` and the text / JSON / SARIF
  formatters without CLI changes. Closes cognium-dev#52; partial #87.

## [3.52.0] - 2026-06-16

### Changed

- **circle-ir upgraded 3.51.0 → 3.52.0** — replaces broken
  `weak_random` / `weak_hash` / `weak_crypto` / `insecure_cookie`
  taint-sink registrations with four dedicated pattern passes
  (`weak-hash`, `weak-crypto`, `weak-random`, `tls-verify-disabled`)
  and extends `insecure-cookie` to Java + Python.

  Detection now fires across Java, Python, JS/TS, and Go on the
  hard-coded algorithm string / missing flag / disabled TLS
  verification — no source-to-sink taint flow needed. `scan` and the
  text/JSON/SARIF formatters surface these findings without any CLI
  changes. Closes cognium-dev#60. See circle-ir 3.52.0 CHANGELOG for
  per-language detection details.

## [3.51.0] - 2026-06-16

### Added

- **Recognize `.jsx` and `.cjs` as JavaScript** in the CLI `LANG_MAP`
  (`src/cli.ts`). Previously `cognium-dev scan` silently skipped React
  `.jsx` components and CommonJS `.cjs` modules because no entry mapped
  the extension to a circle-ir language. Both now route to the
  `javascript` plugin. Closes part of cognium-dev#88 (sub-issue #88.1).
  Regression coverage in `tests/glob.test.ts`.

### Fixed

- **circle-ir upgraded 3.50.0 → 3.51.0** — Go `text/template` XSS
  sinks (`Template.Execute` / `Template.ExecuteTemplate`) are now
  reported as `xss` findings (CWE-79). HTTP-derived data passed to
  `text/template` reaches the browser un-escaped; `html/template` is
  unaffected (auto-escaping). See circle-ir 3.51.0 CHANGELOG for
  details.

[3.51.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.50.0...cognium-dev-v3.51.0

## [3.50.0] - 2026-06-16

### Fixed

- **circle-ir upgraded 3.49.0 → 3.50.0** — closes cognium-dev#83
  (subsumes #76). Inline taint sources used as a call/concat
  argument now fire without an intermediate variable: Java
  `exec("echo " + req.getParameter("u"))` / `exec(req.getParameter("u"))`,
  JS `eval(req.query.x)` / `vm.runInThisContext(req.cookies.c)` /
  `child_process.exec(req.body.cmd)`, Python
  `os.system("echo " + request.args.get("u"))` and
  `for p in request.args.getlist("p"): os.system(p)`. CLI text/JSON/SARIF
  output is unchanged; previously-missed flows now appear as normal
  command_injection / code_injection / sql_injection findings.

[3.50.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.49.0...cognium-dev-v3.50.0

## [3.48.0] - 2026-06-12

### Fixed

- **circle-ir upgraded 3.47.0 → 3.48.0** — fixes `RangeError: Maximum call stack size exceeded` raised by `cognium-dev scan` on Java sources with deeply nested AST shapes (e.g. CoreNLP's `DefaultTeXHyphenData.java` with 4500+ segment `"a" + "b" + …` string concatenation chains parsed as left-associative binary expressions), closes cognium-ai#88. All recursive tree walkers in the hot path are now iterative DFS with an explicit stack: `walkTree`, `BaseLanguagePlugin.findNodes`, the Java plugin's internal `walk`, `ConstantPropagator.visit` / `isTaintedExpression` / `collectClassFields` / `findAllMethods`, and the HTML pre-processing walks (`walkNode`, `walkForSecurityChecks`). The wrapper/step pattern preserves pre-order visit semantics for `isTaintedExpression` (step returns `boolean | undefined`). Regression coverage at 6000- and 10000-segment chains in `tests/core/deep-nesting.test.ts`. CLI text/JSON/SARIF formats are unchanged; previously-crashing scans now complete and report findings normally. Full circle-ir suite at 2102 passing tests.

[3.48.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.47.0...cognium-dev-v3.48.0

## [3.47.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.46.0 → 3.47.0** — new pass #91 `spring4shell` detecting Spring4Shell (CVE-2022-22965) implicit form-data binding RCE on Spring MVC controllers, closes cognium-dev#28. Fires (severity `high`, CWE-94, SARIF `error`) when a `@Controller`/`@RestController`/`@ControllerAdvice` class has a route-annotated method (`@RequestMapping`/`@GetMapping`/`@PostMapping`/`@PutMapping`/`@DeleteMapping`/`@PatchMapping`) with a parameter that has no binding annotation (`@RequestBody`, `@RequestParam`, `@PathVariable`, `@ModelAttribute`, `@RequestHeader`, `@CookieValue`, `@MatrixVariable`, `@RequestPart`, `@Valid`, `@Validated`, `@SessionAttribute`, `@RequestAttribute` all suppress), is not a Spring framework-resolved type (`HttpServletRequest`, `Model`, `Principal`, `MultipartFile`, `BindingResult`, `RedirectAttributes`, `WebRequest`, `UriComponentsBuilder`, `HttpEntity`, `ServerWebExchange`, etc.), and is not a scalar (`String`/primitives/`BigDecimal`/`UUID`/`LocalDate`/`List`/`Optional`, etc.). The pass complements the existing `code-injection` (#11) which covers explicit `DataBinder.bind()` / `DataBinder.setPropertyValues()` sinks. CLI text/JSON/SARIF formats are pass-through; the new `spring4shell` rule_id flows through existing rendering. Full circle-ir suite at 2100 passing tests (+71 new in `tests/analysis/passes/spring4shell.test.ts`).

[3.47.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.46.0...cognium-dev-v3.47.0

## [3.46.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.45.0 → 3.46.0** — structured parse-failure signal (`CircleIR.parse_status`), closes cognium-dev#27. Previously, intermittent tree-sitter parse failures on top-100 Java repos silently dropped files: the IR looked normal, the CLI reported "0 vulnerabilities found", and there was no signal to the user that coverage had been lost. Every `analyze()` and `analyzeHtmlFile()` return now carries a `parse_status: { success, has_errors, error_count, error_locations[] }` field, and `logger.warn('Partial parse — IR may be incomplete', ...)` is emitted at default log level on partial parses. The CLI text/JSON/SARIF output formats are pass-through; the new field appears in JSON output verbatim and downstream consumers (cognium-dev CI, circle-ir-ai) can surface dropped files instead of treating them as clean scans. Static-path findings are unchanged. Full circle-ir suite at 2029 passing tests.

[3.46.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.45.0...cognium-dev-v3.46.0

## [3.45.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.44.0 → 3.45.0** — `discoveryMethod` provenance plumbing on `generateFindings()` (cognium-dev#26 precondition). `TaintSource`, `TaintSink`, and `Finding.verification` carry an optional `discoveryMethod` (`'static' | 'llm'`, with `'mixed'` on findings) so circle-ir-ai's `runReport` can replace its N×M LLM cross-product with a single `generateFindings(mergedSources, mergedSinks, dfg, fileName)` call and inherit the DFG-reachability gate. Static-path findings are unchanged byte-for-byte aside from the new `verification.discoveryMethod: 'static'` field; CLI text/JSON/SARIF output formats are pass-through (the new field appears in JSON output verbatim). Full circle-ir suite at 2018 passing tests.

[3.45.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.44.0...cognium-dev-v3.45.0

## [3.44.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.43.0 → 3.44.0** — JSqlParser AST visitor exclusion for SQL-injection sinks (cognium-dev#24, JSqlParser half). `cognium-dev scan` against Java code that uses JSqlParser (`net.sf.jsqlparser.statement.Statement.execute(StatementVisitor)`, `Select.execute(visitor)`, etc.) no longer emits these visitor-pattern AST dispatch calls as `sql_injection` findings. The exclusion is FQN-precise: it only fires when the receiver's resolved type starts with `net.sf.jsqlparser.`. Real JDBC sinks (`java.sql.Statement.execute(sql)`, `executeQuery`, `executeUpdate`, `JdbcTemplate.execute`, …) remain `sql_injection`. Unresolvable receivers and wildcard JSqlParser imports fall back to the simple-name heuristic (recall preserved). CLI output formats unchanged. Full circle-ir suite at 2006 passing tests.

[3.44.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.43.0...cognium-dev-v3.44.0

## [3.43.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.42.0 → 3.43.0** — receiver-type resolution on `CallInfo` for Java (cognium-dev#25). Every Java method invocation and constructor call now carries `receiver_type` (the resolved class/interface name of its receiver) and, when statically derivable, `receiver_type_fqn` (the fully-qualified name). Resolution covers local variables typed at declaration, method/constructor parameters, fields (bare `field.foo()` and `this.field.foo()`), static class receivers, and `new Foo(...)`. FQN sources: explicit imports, same-package inference via the `package` declaration, and implicit `java.lang.*` fallback for the common subset. Wildcard imports keep `receiver_type` populated but conservatively set `receiver_type_fqn` to `null` to avoid mis-disambiguation. Generics are stripped (`List<String>` → `List`). The CLI output format is unchanged — the new fields are passthrough on the IR for downstream consumers (circle-ir-ai dead-code/feature-envy/coupling, cross-file taint stitching). Full circle-ir suite at 1996 passing tests.

[3.43.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.42.0...cognium-dev-v3.43.0

## [3.42.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.41.0 → 3.42.0** — MyBatis mapper-interface call classification (cognium-dev#24, MyBatis half). `cognium-dev scan` against Java code that uses MyBatis mappers (e.g. `userMapper.insert(user)`, `OrderMapper.selectByExample(criteria)`) no longer emits these as raw `sql_injection` findings; they surface as the new `mybatis_mapper_call` sink type (CWE-89, medium severity) so downstream consumers can resolve the mapper's XML/`@Select` binding before reporting. The CLI's SARIF, JSON, and text output formats include the new type via formatter additions (`SINK_SEVERITY`, `SINK_CWE`, `VULNERABILITY_HELP`). Real SQL execution sinks (Statement.execute, JdbcTemplate.query, …) remain `sql_injection`. Full circle-ir suite at 1978 passing tests.

[3.42.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.41.0...cognium-dev-v3.42.0

## [3.41.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.40.0 → 3.41.0** — adds typed-overload-aware deserialization sink classification (cognium-dev#22). `cognium-dev scan` against Java code that uses Jackson `ObjectMapper.readValue(json, User.class)`, Gson `gson.fromJson(json, User.class)`, FastJson `JSON.parseObject(json, User.class)`, or SnakeYAML `yaml.load(stream, User.class)` no longer emits a `deserialization` finding — these typed overloads are safe because the deserialized type is fixed at compile time. The dangerous shapes (`readValue(json)` / `fromJson(json, type)` / `Class.forName(t)` second arg / untyped `yaml.load(stream)`) remain sinks. Output formats unchanged. Also: Python `pickle`/`marshal`/`yaml` deserialization sinks are now language-scoped, eliminating spurious cross-language matches when a Java local is named `yaml`. Full circle-ir suite at 1961 passing tests.

[3.41.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.40.0...cognium-dev-v3.41.0

## [3.40.0] - 2026-06-12

### Changed

- **circle-ir upgraded 3.39.0 → 3.40.0** — adds the `code` field on every emitted `TaintSource` and `TaintSink` (cognium-dev#23). The trimmed source-line text at each entry's recorded `line` is now available in JSON output without re-reading the file, which matters for downstream pipelines that consume `ir.taint.sources` / `ir.taint.sinks` after the tree-sitter AST has been disposed. SARIF and text output formats are unchanged; the JSON `taint` block carries the new optional `code` string per source and per sink. Backward compatible — consumers that don't need the field can ignore it. Full circle-ir suite at 1946 passing tests.

[3.40.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.39.0...cognium-dev-v3.40.0

## [3.39.0] - 2026-06-11

### Changed

- **circle-ir upgraded 3.38.0 → 3.39.0** — adds cross-instance field-binding taint propagation. `cognium-dev scan` against multi-file Java projects now emits `taint_paths` for the canonical CWE-Bench-Java Jenkins shape and adjacent framework-DI patterns where the source is bound onto a field by one class (`@DataBoundConstructor`, `@Autowired` / `@Inject` / `@Resource`, or setter chain) and consumed by another class reading that field on an aliased instance. Both direct field reads (`String p = step.path`) and getter-mediated reads (`String p = step.getPath()`) are now closed, and the sink may live either in the caller's own method body (`Files.newInputStream(Paths.get(p))`) or in a downstream cross-file callee. Output formats (text, JSON, SARIF) are unchanged; previously-hidden field-binding chains now surface with `constructor_field` or `autowired_field` source types and confidence-decayed multi-hop paths. No regressions: full circle-ir suite at 1939 passing tests (1935 baseline + 4 new fixtures).

[3.39.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.38.0...cognium-dev-v3.39.0

## [3.38.0] - 2026-06-11

### Changed

- **circle-ir upgraded 3.37.0 → 3.38.0** — closes the Java cross-file inter-procedural taint gap (#19) that hid CVE-2018-1260 (Spring SpEL injection) and CVE-2011-2732 (Spring open redirect) shapes. `cognium-dev scan` against multi-file Java projects now emits `taint_paths` for the canonical pattern `source-in-callee-A → wrapper-return-in-caller → sink-call-in-caller → sink-in-callee-B`, where neither file in isolation contains both a source and the sink. `cross_file_calls[].args_mapping[].taint_propagates` is now populated from the callee's analyzed `taintedParams` summary (previously hard-coded `false`), giving downstream consumers an at-a-glance view of which arguments carry tainted data across a resolved inter-file call. Output formats (text, JSON, SARIF) are unchanged; previously-hidden multi-hop chains now surface with confidence-decayed paths (0.85 per hop, floor 0.30). The fix also tightens single-hop cross-file flow detection with a variable-connectivity gate that eliminates false positives when a sanitized wrapper sits between the controller-side source and the callee-side sink. Java/JS/Python flows for in-file and pre-existing cross-file shapes are unaffected (verified by full OWASP Benchmark Java + Juliet + SecuriBench Micro suites).

[3.38.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.37.0...cognium-dev-v3.38.0

## [3.37.0] - 2026-06-11

### Changed

- **circle-ir upgraded 3.36.0 → 3.37.0** — closes the remaining Python false-negative tail uncovered after #18 (#20). `cognium-dev scan` against Python projects now emits flows for multi-hop indirection shapes that 3.36.0 still missed: simple alias chains (`bar = uid; sql = "..." + bar; cur.execute(sql)`), configparser round-trips (`conf.set/.get`), and list/dict round-trips via `.append/.add/.extend` then subscript or membership reads. These were the dominant remaining drivers of OWASP BenchmarkPython false negatives. Output formats (text, JSON, SARIF) are unchanged; previously-hidden flows now surface in all three. Java/JS/Bash flows are unaffected — the alias expansion is gated to Python only and verified by an explicit Java sqli non-regression test plus the full 156-case Juliet suite. Cross-module helper indirection (`helpers.db_sqlite.results(cur, sql)`) is not addressed and requires inter-procedural taint summaries, filed as future work.

[3.37.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.36.0...cognium-dev-v3.37.0

## [3.36.0] - 2026-06-11

### Changed

- **circle-ir upgraded 3.35.0 → 3.36.0** — fixes a long-standing structural defect that left `result.taint.flows` empty for every Python sink category (#18). `cognium-dev scan` against Python projects now emits cross-source/sink flows for sql_injection, command_injection (`os.system`, `subprocess.call(..., shell=True)`), path_traversal, code_injection (`eval`, `exec`), deserialization (`pickle.loads`), xxe (`ET.fromstring`), ldap_injection, and open_redirect. Output formats (text, JSON, SARIF) are unchanged; previously-hidden flows now surface in all three. Java/JS/Bash flows are unaffected (verified by 156-case Juliet suite + targeted non-regression test).

[3.36.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.35.0...cognium-dev-v3.36.0

## [3.35.0] - 2026-06-11

### Changed

- **circle-ir upgraded 3.34.0 → 3.35.0** — broadens default `code_injection` sink coverage for the Jenkins Groovy sandbox dispatch surface (#17, CVE-2023-24422). For Java projects, `cognium-dev scan` now flags taint reaching any `org.kohsuke.groovy.sandbox.SandboxInterceptor` / `GroovyInterceptor` dispatch hook (`onMethodCall`, `onStaticCall`, `onGetProperty`, `onSetProperty`, `onGetAttribute`, `onSetAttribute`, `onMethodPointer`, `onSuperCall`, `onSuperConstructor`, plus parent-class entries), `SandboxTransformer.call`, and `GroovySandbox.runInSandbox`. Prior releases only flagged `SandboxInterceptor.onNewInstance`, leaving method/static dispatch (the most common bypass shape) silently uncovered. 16 new sink entries; no CLI flags changed.

[3.35.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.34.0...cognium-dev-v3.35.0

## [3.34.0] - 2026-06-10

### Changed

- **circle-ir upgraded 3.33.0 → 3.34.0** — extends the `runtime_registrations` IR field with Rust trait-dispatch support (#15, Phase 3). For Rust projects, `cognium-dev scan` now records `impl Trait for Type` blocks (one `kind: 'trait_impl'` entry per method, classified as `stdlib` / `actix` / `axum` / `rocket` / `tokio` / `serde` / `unknown` based on the trait path), `inventory::submit! { … }` collector entries (`framework: 'inventory'`), and `#[linkme::distributed_slice(REGISTRY)]` / `#[distributed_slice(REGISTRY)]` attributes (`framework: 'linkme'`). Plumbing only; no new CLI findings. Phase 3 closes the runtime-registration roadmap from #15.

[3.34.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.33.0...cognium-dev-v3.34.0

## [3.33.0] - 2026-06-10

### Changed

- **circle-ir upgraded 3.32.0 → 3.33.0** — extends the `runtime_registrations` IR field with Python decorator support (#15, Phase 2). For Python projects, `cognium-dev scan` now records every `@decorator` on a `def`/`async def`: Flask/FastAPI routes (`@app.route`, `@router.get`, …) as `kind: 'http_route'`; `@app.before_request`/`@app.after_request` as `middleware`; `@app.errorhandler` as `event_listener`; `@pytest.fixture`, `@click.command()`, `@property`, etc. as `decorator` with framework tags (`pytest`, `click`, `stdlib`, `numba`, `celery`, `django`, `unknown`). Plumbing only; no new CLI findings. Phase 3 (Rust trait dispatch) is still pending.

[3.33.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.32.0...cognium-dev-v3.33.0

## [3.32.0] - 2026-06-10

### Changed

- **circle-ir upgraded 3.31.0 → 3.32.0** — adds the `runtime_registrations` IR field (#15, Phase 1). For JS/TS projects, `cognium-dev scan` now records Express-family route registrations (`app.METHOD(path, handler)`), middleware (`app.use`, `router.use`), and event listeners (`server.on`) in the per-file IR. This is plumbing for downstream consumers (e.g. cognium-ai dead-code reachability) that need handler functions treated as virtual entry roots; no new findings are emitted at the CLI layer. Phases 2 (Python decorators) and 3 (Rust trait dispatch) will follow as separate PRs.

[3.32.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.31.0...cognium-dev-v3.32.0

## [3.31.0] - 2026-06-09

### Changed

- **circle-ir upgraded 3.30.0 → 3.31.0** — adds NiFi Expression Language coverage (#11, CVE-2023-36542) and XWiki rendering-pipeline XSS coverage (#10, CVE-2022-24897 / CVE-2023-29201 / CVE-2023-29528 / CVE-2023-36471 / CVE-2023-37908). `cognium-dev scan` now flags `PropertyValue.evaluateAttributeExpressions(...)` as CWE-94 RCE on NiFi processors, and `XWikiRequest.getParameter/get → WikiPrinter.print*/XHTMLWikiPrinter.println/DefaultBlockRenderer.render` as CWE-79 XSS in XWiki rendering. Per-file findings, cross-file taint paths, and SARIF output all surface the new detections.

[3.31.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.30.0...cognium-dev-v3.31.0

## [3.30.0] - 2026-06-09

### Changed

- **circle-ir upgraded 3.29.0 → 3.30.0** — adds Apache Shiro path-traversal coverage (#8, CVE-2023-34478 / CVE-2023-46749). `cognium-dev scan` now flags the `WebUtils.getPathWithinApplication(request) → new File(baseDir, path)` shape used in Shiro-fronted applications, and re-taints values that pass through `WebUtils.decodeRequestString` after auth-time path normalization. Per-file findings, cross-file taint paths, and SARIF output all surface the new CWE-22 detections.

[3.30.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.29.0...cognium-dev-v3.30.0

## [3.29.0] - 2026-06-09

### Changed

- **circle-ir upgraded 3.28.0 → 3.29.0** — fixes two upstream false-negative / false-positive issues that show up in `cognium-dev scan` output:
  - **#14 Java enterprise FPs.** Threadpool dispatch sites like `executor.execute(task)` and `cachedThreadPool.execute(...)` no longer spuriously report `command_injection` / `sql_injection`. The CLI's per-file findings and the cross-file taint-path renderer both drop these on the DBeaver / Dubbo / Ruoyi / JeecgBoot / XXL-JOB corpus (298 → 0 FPs). Legitimate `Runtime.exec` and Apache Commons `DefaultExecutor.execute` detection is preserved.
  - **#12 Apache Camel mail path traversal (CVE-2018-8041).** `new File(safeDir, untrustedHeader)` now triggers a CWE-22 finding, so SARIF / JSON / text output flags the second-argument-controlled traversal the previous release missed.

[3.29.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.28.0...cognium-dev-v3.29.0

## [3.28.0] - 2026-06-09

### Changed

- **circle-ir upgraded 3.27.1 → 3.28.0** — fixes unbounded tree-sitter WASM heap growth across many `analyze()` calls (#16). The CLI no longer leaks WASM memory when scanning large directories (`cognium scan <dir>` runs `analyzeProject()` which calls `analyze()` once per file). On the 120-Java-project corpus the in-process baseline previously regressed by ~20pp versus subprocess-isolated runs; that gap should close with this release.

[3.28.0]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.27.1...cognium-dev-v3.28.0

## [3.27.1] - 2026-06-04

> Versions 3.26.0 and 3.27.0 were prepared locally but never published to npm; their content shipped as part of 3.27.1.

### Changed

- **circle-ir upgraded 3.25.0 → 3.27.1** — adds the `scan-secrets` security pass (Pass #90, CWE-798) detecting hardcoded credentials across all 7 supported languages. Two layers: ~16 high-confidence provider patterns (AWS `AKIA…`, GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, Stripe `sk_live_`/`pk_live_`, OpenAI `sk-…`, Anthropic `sk-ant-…`, Slack `xox[baprs]-…`, Google `AIza…`, JWT, PEM private keys, npm `npm_…`) emitting `hardcoded-credential` (critical/error), and Shannon-entropy scan on base64/hex string literals with UUID/hash/placeholder/base64-JSON denylist emitting `hardcoded-credential-entropy` (high/warning). Test-file paths are skipped. Findings dedupe against the legacy Bash detection so existing users see no double-reporting.

### Notes

- Disable per project via `cognium.config.json`: `{ "disabledPasses": ["scan-secrets"] }`. Filter the entropy branch only by excluding the `hardcoded-credential-entropy` rule_id in your downstream tooling.

[3.27.1]: https://github.com/cogniumhq/cognium-dev/compare/cognium-dev-v3.25.0...cognium-dev-v3.27.1

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
