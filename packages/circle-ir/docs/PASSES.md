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

### Naming convention (Pillar I — no LLM in cognium-dev)

Pass `rule_id`, `name`, finding `evidence` keys, `AnalyzerOptions` fields, and
per-pass option-struct fields MUST NOT contain the tokens `llm`, `ai`,
`verify`, or `adjudicate`. cognium-dev is the deterministic SAST layer;
LLM-aware functionality lives in `circle-ir-ai`. Use generic names:
`confidence`, `speculative`, `includeSpeculative`, `discoveryMethod`. See
ADR-007 (`docs/ARCHITECTURE.md`) and the Pillar I guardrail in `CLAUDE.md`
(root, `packages/circle-ir`, `packages/cli`).

Two legacy identifiers predate this rule and remain for back-compat:
`discoveryMethod: 'static' | 'llm'` provenance value on `generateFindings`
(shipped 3.45.0) and the `LLMVerificationResult` exported type. Both are
deprecation candidates for a future major; no new code should reference
them.

---

## A. Security Passes (all shipped, category = `security`)

All 19 passes operate on the `taint` graph. SARIF level: `error`.

| # | rule_id | CWE | Description |
|---|---------|-----|-------------|
| 1 | `sql-injection` | CWE-89 | User input in SQL without parameterization |
| 2 | `command-injection` | CWE-78 | User input in shell exec/system. Sprint 77a (#216 Pattern X): Java `Runtime.getRuntime().exec(new String[]{...})` / `new ProcessBuilder(new String[]{...})` argv-array forms recognized as `command_injection` + `external_taint_escape` sanitizers (no shell interpretation, tainted argv element cannot smuggle metacharacters; single-string concat form `exec("echo " + arg)` intentionally NOT matched). Sprint 77a: Rust `Command::new("LITERAL").arg(...).arg(...)` argv-form with string-literal program recognized as sanitizer (tainted-program slot `Command::new(prog).arg(...)` NOT matched; shell-via-argv `Command::new("sh"/"bash"/...).arg("-c")` explicitly excluded since `-c` re-enables shell parsing) |
| 3 | `xss` | CWE-79 | User input in HTML output without encoding. Sprint 73 (#216): JS user-defined replace-based wrapper functions (e.g. `function esc(s) { return String(s).replace(/[&<>"']/g, ...) }`) are recognized as sanitizers via two-pass discovery + call-site emission. Sprint 74 (#216 Pattern B): Python var-aware set-membership allow-list guard (`if t not in ALLOWED: abort(...)` → only sanitizes `xss` on lines referencing `t`) covers Jinja `env.from_string` SSTI. Sprint 77a (#216 Pattern X): Python Jinja2 `Environment(..., autoescape=<expr>)` declarations (where `<expr>` is not `False`/`None`/`0`) recognized — `xss` + `external_taint_escape` sanitizer emitted at every `<env>.get_template(...).render(...)` chain line on the same `<env>` identifier; plain `Environment(...)` without `autoescape=` keyword intentionally NOT matched |
| 4 | `path-traversal` | CWE-22 | User input in file path operations. Sprint 76 (#216 Pattern B): Java `Path full = ROOT.resolve(name).normalize()` chain followed by `if (!full.startsWith(ROOT)) throw/return` guard recognized as sanitizer for `path_traversal` + `external_taint_escape` at the resolve line and every subsequent line referencing `full` (`.normalize()` alone is intentionally NOT recognized — absolute-path arguments replace `ROOT`; the `startsWith` guard is load-bearing) |
| 5 | `ssrf` | CWE-918 | User input in outbound HTTP URL. Sprint 75 (#216 Pattern D): JS var-aware allow-list guard (`if (!ALLOWED.has(url.hostname))`, `if (!ALLOWED_HOSTS.includes(host))`, `if (ALLOWED.indexOf(host) < 0)` with `return`/`throw`/`res.status(...).send/end/json(...)` terminator) recognized as sanitizer for both `ssrf` and synthetic `external_taint_escape`; URL/host alias chain (`const url = new URL(src); const h = url.hostname`) tracked |
| 6 | `deserialization` | CWE-502 | Untrusted data passed to deserialization |
| 7 | `xxe` | CWE-611 | External entities enabled in XML parser. Sprint 74 (#216 Pattern B): Python `defusedxml.*` imports (`import defusedxml.ElementTree as ET`, `from defusedxml.ElementTree import fromstring`) recognized — calls through such aliases are treated as xxe-safe |
| 8 | `ldap-injection` | CWE-90 | User input in LDAP query string. Sprint 74 (#216 Pattern B): Python regex-fullmatch tight-allowlist wrapper functions (e.g. `def checked_uid(uid): if not re.fullmatch(r"[A-Za-z0-9_-]+", uid): abort(...); return uid`) recognized as sanitizers via var-aware call-site emission |
| 9 | `xpath-injection` | CWE-643 | User input in XPath expression |
| 10 | `nosql-injection` | CWE-943 | User input in NoSQL query |
| 11 | `code-injection` | CWE-94 | User input in eval/exec/ScriptEngine |
| 12 | `open-redirect` | CWE-601 | User input controls HTTP redirect target |
| 13 | `log-injection` | CWE-117 | User input written to log without sanitization. Sprint 73 (#216): JS user-defined CRLF-redaction wrapper functions (e.g. `function redact(s) { return String(s).replace(/[\r\n\t]/g, '_') }`) are recognized as sanitizers. Sprint 76 (#216 Pattern B): Java inline `log.info("...", user.replaceAll("[\\r\\n\\t]", "_"))` recognized — `log_injection` + `external_taint_escape` sanitizer emitted on the same source line when a recognized slf4j/log4j/JUL log call (`log`/`logger`/`LOG`/`LOGGER`/`slog` receivers; `info`/`warn`/`error`/`debug`/`trace`/`fatal`/`severe`/`fine{,r,st}`/`config`/`warning` methods) contains an inline CRLF-strip `.replaceAll("[...\\r\\n...]", ...)` or `.replace('\\n'\|'\\r'\|'\\t', ...)` argument. A `replaceAll` on a different earlier line is intentionally NOT recognized |
| 14 | `trust-boundary` | CWE-501 | Tainted data crosses trust boundary (e.g. session write) |
| 15 | `external-taint` | CWE-668 | External input reaches sensitive operation (interprocedural). Sprint 73 (#216 Pattern A): recognized terminators no longer fire synthetic ETE flow — Java Jackson `mapper.readValue` / Gson `gson.fromJson`; JS `JSON.parse`, `bcrypt.hash` / `argon2.hash` / `crypto.scrypt` / `crypto.createHash(...).digest(...)`, Excel-formula CSV `'`-prefix (` \`'${x}\` `), and user-defined wrapper functions with threat-char `.replace(...)`. Sprint 74 (#216 Pattern B): Python regex-fullmatch wrapper, var-aware set-membership allow-list guard, and `defusedxml.*` import-alias recognition all suppress synthetic ETE on safe-handler patterns |
| 15a | `redos` | CWE-1333 | Tainted regex pattern reaches `re.match/search/compile/findall/sub`, `Pattern.compile`, `String.matches/replaceAll/replaceFirst/split`, `new RegExp`, `regexp.Compile/Match` (issue #86) |
| 15b | `format-string` | CWE-134 | Tainted format string reaches `String.format` / `Formatter.format` / `System.out.printf` / `fmt.Sprintf|Printf|Fprintf|Errorf` / `ctypes printf` (issue #86) |
| 15c | `crlf` | CWE-113 | Tainted value reaches a response-header / cookie / status-line sink: Java `HttpServletResponse.setHeader/addHeader`, JS Express `res.setHeader/writeHead/cookie/location/redirect`, Go `Header.Set/Add`. Re-routes from `xss` for header-only sinks (issue #86, Sprint 6) |
| 15d | `mass_assignment` | CWE-915 | Untrusted attribute bag splatted into a domain object: JS `Object.assign(user, req.body)`, lodash `_.merge/_.extend(target, req.body)`, jQuery `$.extend(target, req.body)`. Also see pattern pass #96 for Python `User(**request.form)` and JS `{...req.body}` (issue #86, Sprint 6) |
| 16 | `weak-random` | CWE-330 | Math.random / java.util.Random / random.* / math/rand in security context (pattern pass — see §A6) |
| 17 | `weak-hash` | CWE-328 | MD5 or SHA-1 used for security purposes (pattern pass — see §A6) |
| 18 | `weak-crypto` | CWE-327 / CWE-329 / CWE-321 / CWE-326 | Weak ciphers, ECB mode, static/zero IV, hardcoded symmetric key, weak RSA key size (< 2048) (pattern pass — see §A6). Sprint 7 (3.56.0) finished cross-language parity: Python `modes.ECB()` / `AES.new(b"…", …)` / `rsa.generate_private_key(key_size<2048)`; Go `aes.NewCipher([]byte("…"))` / `rsa.GenerateKey(_, <2048)` (issue #87) |
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
| H9 | `vue-template-xss` | CWE-79 | error | shipped | Vue SFC `<template>` `v-html` / `v-bind:innerHTML` / `:innerHTML` / `v-bind:outerHTML` / `:outerHTML` binding whose RHS expression references an identifier tainted in the file's `<script>` blocks (sprint 64, cognium-dev #184) |

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
| 89d | `cors-wildcard-origin` | CWE-942 | error | shipped | `Access-Control-Allow-Origin: *` permits cross-origin from any site (sprint 71: Python `resp.headers['Access-Control-Allow-Origin'] = '*'` subscript-assignment shape) |
| 89e | `cors-null-origin` | CWE-346 | error | shipped | `Access-Control-Allow-Origin: null` exploitable via sandboxed iframes |
| 89f | `cors-http-origin` | CWE-346 | warning | shipped | Allowed origin uses insecure `http://` scheme |
| 89g | `cors-reflected-origin` | CWE-346 | error | shipped | `Access-Control-Allow-Origin` set to a dynamic (non-literal) value |
| 89h | `xfo-csp-mismatch` | CWE-1021 | warning | shipped | `X-Frame-Options` and CSP `frame-ancestors` disagree (e.g. XFO=DENY but CSP allows framing) (sprint 71: Python correlated `resp.headers['X-Frame-Options']` + `resp.headers['Content-Security-Policy']` subscript assignments) |

### A4. Secret Scanner Pass (category = `security`)

Pass #90 `scan-secrets` detects hardcoded credentials across all 7
supported languages via two detection layers, with deduplication
against the legacy Bash `hardcoded-credential` detection in
`LanguageSourcesPass`. Test-file paths are skipped (`__tests__/`,
`*.test.*`, `*Test.java`, etc.).

| # | rule_id | CWE | level | status | Description |
|---|---------|-----|-------|--------|-------------|
| 90a | `hardcoded-credential` | CWE-798 | error | shipped | Provider-specific regex hits (AWS AKIA, GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, Stripe `sk_live_`/`pk_live_`, OpenAI `sk-`, Anthropic `sk-ant-`, Slack `xox[baprs]-`, Google `AIza`, JWT, PEM private key, npm `npm_`). (sprint 78: Rust `pub const <NAME>: &str = "<literal>"` where NAME ~ `/api[_]?key|secret|token|password|passwd|pwd|auth/i` and literal ≥ 8 chars / non-placeholder) |
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
| 17 | `weak-hash` | CWE-328 | warning | shipped | MD2/MD4/MD5/SHA-1 via Java `MessageDigest.getInstance`, Apache Commons `DigestUtils.{md5,sha1}{,Hex}`, Python `hashlib.{md5,sha1,new("md5",…)}`, JS `crypto.createHash`/`createHmac`, Go `crypto/md5` + `crypto/sha1`. Mirrors gosec G401 / Bandit B303. (sprint 71: bash `md5`/`sha1`/`md5sum`/`sha1sum` command in pipeline/standalone) |
| 18 | `weak-crypto` | CWE-327 / CWE-329 / CWE-321 / CWE-326 | error | shipped | Weak symmetric cipher (DES/3DES/RC2/RC4/Blowfish/IDEA/SEED/CAST5) **or** ECB mode (incl. Java AES default = ECB) via Java `Cipher.getInstance`, Python pycryptodome `*.new(...)`/`AES.new(key, MODE_ECB)` and `cryptography.hazmat algorithms.{TripleDES,Blowfish,ARC4,…}`, JS `crypto.createCipher` (deprecated) / `createCipheriv("…-ecb"|"des-…")`, Go `des.NewCipher`/`des.NewTripleDESCipher`/`rc4.NewCipher`. **Java config patterns (issue #87):** static/zero IV (`new IvParameterSpec(new byte[N])`, `"…".getBytes()` → CWE-329), hardcoded symmetric key material (`new SecretKeySpec("…".getBytes(), …)` → CWE-321), weak RSA key size (`KeyPairGenerator.initialize(<2048)` → CWE-326). Mirrors gosec G401/G405 / Bandit B304/B305. (sprint 78: Go raw ECB via `aes.NewCipher` + unwrapped `<v>.Encrypt/Decrypt` — drops vars wrapped by `cipher.NewGCM/CBCEncrypter/CTR/OFB/CFB`; Rust raw ECB via `Aes128/192/256::new` + `.encrypt_block/.decrypt_block`) |
| 19 | `insecure-cookie` | CWE-614 | warning | shipped | Cookie set without Secure / HttpOnly: Express `res.cookie(name, val, opts)` and Fastify `reply.cookie`, Python Flask/Django/Starlette `response.set_cookie(...)`, Java `new javax.servlet.http.Cookie(...)` without `setSecure(true)` + `setHttpOnly(true)` (text-based heuristic — full DFG-based version requires variable-to-call linkage). (sprint 78: Rust actix-web `Cookie::build(...).secure(false).http_only(false)` chain) |
| 92 | `tls-verify-disabled` | CWE-295 | error | shipped | TLS certificate / hostname verification disabled: Go `tls.Config{InsecureSkipVerify: true}` (source-text scan — composite literals are not IR calls), Python `requests/httpx(verify=False)` + `ssl._create_unverified_context` + module-level `ssl._create_default_https_context` override, JS `rejectUnauthorized: false` in any args + `process.env.NODE_TLS_REJECT_UNAUTHORIZED='0'` assignment, Java `setHostnameVerifier((h,s)->true)` / `NoopHostnameVerifier.INSTANCE` / `AllowAllHostnameVerifier`. Mirrors gosec G402 / Bandit B501/B504/B505. (sprint 71: Python `ctx.verify_mode = ssl.CERT_NONE`/`ctx.check_hostname = False` post-create mutation; Rust reqwest `.danger_accept_invalid_certs(true)`/`.danger_accept_invalid_hostnames(true)`) (sprint 78: Java anonymous `X509TrustManager` with empty `checkServerTrusted(...){}` body) |
| 93 | `jwt-verify-disabled` | CWE-347 | error | shipped | JWT signature verification disabled or set to `none`: Python PyJWT `jwt.decode(..., options={"verify_signature": False})` / `verify=False` / `algorithms=["none"]`, JS jsonwebtoken `jwt.verify(t, secret, {algorithms:["none"]})` / `jwt.verify(t, null)` / `verify:false`, Java auth0 `JWT.require(Algorithm.none())`, jjwt `Jwts.parser()…parse(token)` (vs `parseClaimsJws`). Critical severity. Issue #86, Sprint 5. (sprint 78: Java bare `JWT.decode(token)` on auth0 API — decode parses without verifying; Rust jsonwebtoken `.insecure_disable_signature_validation()`) |
| 94 | `csrf-protection-disabled` | CWE-352 | error | shipped | CSRF protection explicitly disabled: Spring Security `http.csrf().disable()` / `http.csrf(c -> c.disable())` / `http.csrf(CsrfConfigurer::disable)` / `csrfTokenRepository(null)`, Django `@csrf_exempt` decorator. Critical severity. Issue #86, Sprint 6 |
| 95 | `xml-entity-expansion` | CWE-776 | error | shipped | XML parser created without entity-expansion safeguards (XML bomb / billion-laughs): Java `SAXParserFactory/DocumentBuilderFactory/XMLInputFactory/SchemaFactory/TransformerFactory.newInstance()` without `disallow-doctype-decl`/`external-general-entities`/`SUPPORT_DTD`/`ACCESS_EXTERNAL_DTD`/`setXIncludeAware(false)`/`setExpandEntityReferences(false)` in file; Python `lxml.etree.parse/fromstring/XML` and `xml.etree.ElementTree.parse/fromstring` without `defusedxml` or `resolve_entities=False`. High severity. Issue #86, Sprint 6. (sprint 78: JS `libxml(js).parseXml(buf, { noent: true })` / `parseXmlString(..., { noent: true })` enables external-entity resolution — XXE / billion-laughs) |
| 96 | `mass-assignment` | CWE-915 | error | shipped | Untrusted attribute bag splatted into a domain object without an allow-list: Python `User(**request.{form,args,values,json,get_json(),files,data})`, JS `{...req.body}` / `{...req.query}` / `{...req.params}` / `{...ctx.request.body}`. Complemented by `mass_assignment` taint sink (#15d) for `Object.assign`/`_.merge`/`_.extend`/`$.extend`. High severity. Issue #86, Sprint 6 |
| 97 | `module-side-effect` | CWE-829 | error | shipped | Dangerous side effects executed at module load / install / build time, where no taint flow is involved (hard-coded supply-chain dropper shape): JS module-top `child_process.{exec,spawn,execSync,spawnSync}` / `https.request` / `http.request` / `fetch(process.env)`; `package.json` `scripts.(pre\|post)?install` invoking `curl`/`wget`/`node -e`/`sh -c`/`eval` (benign `node-gyp rebuild`/`prebuild-install`/`husky install`/`patch-package` allowlisted); Python module-top `requests.{post,put}` / `urllib.request.urlopen` / `socket.create_connection` / `subprocess.run` / `os.system` whose args reference `os.environ` / `pwd.getpw` / `~/.ssh` / `/etc/passwd`; Go `func init()` with `exec.Command` / `http.{Post,Get}` / `net.LookupTXT` / `os.Setenv`; Rust `build.rs` with `Command::new`. High severity. Issues #93, #96 L47, #98 — Sprint 19 |
| 98 | `cache-no-vary` | CWE-524 | warning | shipped | Handler sets a shared-cacheable `Cache-Control` header (`public` or `max-age>0` / `s-maxage>0`, without `private`/`no-store`/`no-cache`) on a response in a handler that also reads authenticated / user-scoped state (cookies, `Authorization`, session, `@CookieValue`, `@RequestHeader("Authorization")`, `Principal`, `Authentication`, `SecurityContextHolder`) but does not set a covering `Vary: Cookie`/`Vary: Authorization`/`Vary: *`. Multi-call handler-scope correlation grouped by `in_method` (+5 line widening for decorators/annotations). JS/TS (Express `res.setHeader`/`res.set`/`res.header`/`res.vary`), Python (Flask/FastAPI/Django `response.headers[...]` subscript, `@cache_control`/`patch_cache_control`, `@vary_on_cookie`/`@vary_on_headers`/`patch_vary_headers`), Go (net/http `w.Header().Set/Add`, gin `c.Header`), Java (Spring/Servlet `setHeader`/`addHeader`/`setCacheControl`/`setVary`). Medium severity. Strict auth-qualifier mode — no fire on `/health`/static-asset/version handlers. Issue #96 L91 — Sprint 20 |
| 99 | `weak-password-hash` | CWE-916 | warning | shipped | Fast/unsalted hash or low-cost KDF applied to a credential-named identifier: Python `hashlib.{md5,sha1,sha224,sha256,sha384,sha512}(password)` / `bcrypt.hashpw(pw, bcrypt.gensalt(rounds<10))` / `PBKDF2HMAC(iterations<100000)`, JS `crypto.createHash("sha256").update(password)` / `bcrypt.hash(pw, <10)` / `crypto.pbkdf2Sync(pw, salt, <100000, …)`, Java `MessageDigest.update(password.getBytes())` / `new PBEKeySpec(pw, salt, <100000, …)`, Go `sha256.Sum256([]byte(password))` / `bcrypt.GenerateFromPassword(pw, <10)`. High severity. Issue #109 — Sprint 28 |
| 100 | `plaintext-password-storage` | CWE-256 | warning | shipped | Credential-named identifier written to persistent store without prior hashing: Python `open(...).write(password)` / `pickle.dump` / `json.dump` / `yaml.dump` / `redis.set(key, password)`, JS `fs.{writeFile,writeFileSync,appendFile,appendFileSync}(path, password)` / `localStorage.setItem` / `sessionStorage.setItem` / `redis.set`, Java `Files.{write,writeString}(path, password)` / `FileWriter.write(password)`, Go `os.WriteFile`/`ioutil.WriteFile`/`f.WriteString(password)`. Intraprocedural prior-hash check suppresses when the same identifier was passed through a known hash/KDF earlier in the function, and inline regex suppresses `f.write(bcrypt.hashpw(pw))`. High severity. Issue #109 — Sprint 28 |
| 101 | `cleartext-credential-transport` | CWE-523 | error | shipped | HTTP request to an `http://` URL whose body / params / headers carry a credential-named identifier: Python `requests.{post,put,patch,request}` / `httpx.*` / `urllib.request.urlopen`, JS `axios.{post,put,patch,request}` / `fetch` / `http.request`, Go `http.Post` / `http.NewRequest("POST", "http://…", body)`. URL allowlist for `localhost` / `127.0.0.1` / `0.0.0.0` (dev environments). High severity. Issue #109 — Sprint 28 |
| 102 | `weak-password-encoding` | CWE-261 | warning | shipped | Encoding (base64 / hex) applied to a credential-named identifier — encoding is **not** encryption: Python `base64.{b64encode,urlsafe_b64encode,standard_b64encode}(password)` / `binascii.hexlify`, JS `Buffer.from(password).toString("base64"\|"hex"\|"base64url")` / `btoa(password)`, Java `Base64.getEncoder().encodeToString(passwordBytes)` / `Hex.encodeHexString`, Go `base64.StdEncoding.EncodeToString` / `hex.EncodeToString`. FP-guard: skip when the surrounding source includes a `"Basic "` literal (HTTP Basic auth header construction). Medium severity. Issue #109 — Sprint 28 |
| 103 | `info-disclosure-stacktrace` | CWE-209 | warning | shipped | Exception detail returned to a client via an HTTP response handle. Java `e.printStackTrace(response.getWriter())` / `response.getWriter().write(e.toString())`, JS/TS `res.send(err.stack)` / `res.json({error: err.stack})` / `res.json(err)` (whole error object), Python `return traceback.format_exc()` / `return str(e)` from a Flask/Django/FastAPI handler, Go `http.Error(w, err.Error()…)` / `fmt.Fprintln(w, err)`. Negative-guard: logger receivers (`console.error`, `logger.error`, `log.Error`, `slog`, `pino`, `winston`) suppressed — logging server-side is not a leak. Medium severity. Issue #86 — Sprint 29 |
| 104 | `unrestricted-file-upload` | CWE-434 | error | shipped | HTTP-uploaded file saved using its untrusted original name with no extension allow-list / canonicalization. Java `MultipartFile.transferTo(new File(dir, file.getOriginalFilename()))` / `Files.copy(part.getInputStream(), Path.of(dir, part.getSubmittedFileName()))`, JS/TS `multer({ dest })` without `fileFilter` / `fs.writeFile(path, req.file.buffer)`, Python `f.save(os.path.join(UPLOAD_DIR, f.filename))` without `secure_filename`, Go `os.Create(header.Filename)` / `ioutil.WriteFile(header.Filename, …)`. Per-function FP-guard: suppress when the enclosing function body contains a safe canonicalizer (`secure_filename`, `FilenameUtils.getExtension`, `ALLOWED_EXT`, `fileFilter`, `path.extname`, `filepath.Ext`). High severity. Issue #86 — Sprint 29 |
| 105 | `unverified-package-install` | CWE-494 | error | shipped | Bash package installer invocation that runs maintainer scripts as root against a path-based artifact without prior signature or checksum verification anywhere in the same script: `dpkg -i/-I/-U/--install`, `rpm -i/-U/--install/--upgrade` (rejects `--verify`/`--checksig`/`--erase`/`--query`), `apt(-get|itude) install <path>.deb`, `yum|dnf|zypper install <path>.rpm`. Whole-script FP-guard: suppress when any line contains `gpg{,v,2} --verify` / `rpm --checksig` / `dpkg --verify` / `sha{1,224,256,384,512}sum -c` / `md5sum -c` / `cksum -c` / `b2sum -c`. Negative-guard for repo-name install (`apt-get install -y curl nginx` — no `.deb`) and `dpkg -l` (list). High severity. Issue #199 — Sprint 69 |
| 106 | `external-secret-exfiltration` | CWE-200 | error | shipped | Composed-flow exfiltration: an environment-read secret variable is transmitted in the BODY of an outbound HTTP request whose destination URL is not internal. SOURCE: Python `os.environ[...]`/`os.environ.get(...)`/`os.getenv(...)`, JS/TS `process.env.X`, Go `os.Getenv(...)`. SINK: Python `requests.{post,put,patch,delete,request}` / `httpx.*`, JS/TS `https.request`/`http.request`/`fetch`/`axios.{post,put,patch,request,delete}` (forward-scanned `req.write(VAR)` / `req.end(VAR)` for carrier-var shape `body = JSON.stringify({...secret...})`), Go `http.PostForm`/`http.Post`/`http.NewRequest`. Internal-host allowlist suppresses `localhost`/`127.0.0.1`/`::1`/RFC1918/`.internal.`/`.local`/`.lan`/`.corp`/single-label hosts. Body-vs-headers gate: suppress when the secret appears only in `headers=`/`headers:` context (typical `Authorization: Bearer <key>` shape). High severity. Issue #151 (FN-TQ-01) — Sprint 70 |
| 107 | `missing-sanitizer-gate` | CWE-79 | note | shipped (speculative) | HTML output sink (`writer.addAttribute`, `print`, `write`, …) reached in a Java helper method without any sanitizer-named call (`isAttributeAllowed`, `escapeHtml`, `encodeForHTMLAttribute`, …) dominating the sink on all CFG paths. Skips Tier 1 entry points (configured `xss` sinks already cover the network trust boundary) and skips methods with no `Map<String,String>` / `Attributes` / attribute-named `String` parameter. Dedup: max one finding per method. Emits `confidence: 'medium'` — suppressed by default via `applyConfidenceFilter`; visible only when `analyze(..., { includeSpeculative: true })` is set (3.94.0 infra). Motivated by CVE-2023-37908 (xwiki-rendering `XHTMLWikiPrinter.cleanAttributes`). Issue #153 — 3.139.0 |
| 108 | `source-semantics` | — (source-tagging, no CWE) | — | shipped | Source-tagging pass (emits no findings). Tags each `TaintSource` in `ir.taint.sources` with three optional booleans consumed by downstream passes: (a) `constant` — source value is a compile-time constant (`String KEY = "abc"`, `static final` initialized from a literal, `SomeEnum.VALUE`) → `findings.ts:sourceSemanticsAllowed` drops the flow for every taint sink; (b) `spi` — source came from `ServiceLoader.{load,loadInstalled,stream}` or `Class.forName` co-located with `META-INF/services/…` within ±30 lines → dropped for every sink EXCEPT `code_injection` (Stage 9f already downgrades that class of finding); (c) `demoPath` — file path contains `/demo/`, `/example/`, `/examples/`, `/samples/`, `/integration-tests/`, or `/integration_tests/` → `scan-secrets-pass` downgrades `hardcoded-credential` findings from `high` → `low` severity and `warning`/`error` → `note` SARIF level. Pipeline slot: after `LanguageSourcesPass`, before `SinkFilterPass` / `TaintPropagationPass`. Regex-only MVP (DFG-based constant propagation, Spring component-scan, custom SPI APIs deferred). Guarded on `disabledPasses: ['source-semantics']`. Issue #138 — 3.143.0 |
| 109 | `sink-semantics` | — (sink-gating, no CWE) | — | shipped | Sink-gating pass (emits no findings). Consults a curated `<ClassName>#<methodName>` → `real_class` + `overrides` registry (`configs/sink-semantics.json`, embedded as `DEFAULT_SINK_SEMANTICS` in `config-loader.ts`) and drops sinks whose emitted `SinkType` label disagrees with the registry's declared real-behavior classification. Seed entries (Tier A, ~8 signatures): `Jedis#executeCommand` / `Connection#executeCommand` / `JedisCluster#executeCommand` → drop `command_injection`,`code_injection` (Redis wire-protocol serialization, not OS exec); `Func1#exec` (RxJava) → drop `command_injection`,`code_injection`; `Action0#call` / `Action1#call` (RxJava) → drop `command_injection`; `Unsafe#defineAnonymousClass` → drop `code_injection` (`sun.misc.Unsafe` JDK-internal bridge); `MethodHandle#invokeExact` → drop `code_injection`. Simple-name receiver match against `TaintSink.class` (fully-qualified receiver types reduced to tail segment at sink-emission time). Unresolved receivers (`sink.class === undefined`) fall through — false-negative-safe. Pipeline slot: after `SinkFilterPass`, before `TaintPropagationPass`. Tier B (speculative verifier) explicitly OUT of scope per Pillar I; belongs in cognium-ai. Guarded on `disabledPasses: ['sink-semantics']`. Issue #139 — 3.144.0 |
| 110 | `cli-main-reflection-suppress` | — (sink-gating, no CWE) | — | shipped | Sink-gating pass (emits no findings). Java-only. Drops reflection `code_injection` sinks in files that declare `main(String[] args)` AND carry NO web-framework Tier-1 signal (no class-level `@RestController`/`@Controller`/`@Service`/`@Component`/`@Path`/`@WebServlet`/`@ServerEndpoint`/`@FeignClient`/`@Repository`; no method-level `@*Mapping`/`@KafkaListener`/`@JmsListener`/`@Scheduled`/JAX-RS verb annotations/`@DataBoundConstructor`/`@DataBoundSetter`; no supertype in `{HttpServlet, GenericServlet, Filter, HandlerInterceptor, CommandLineRunner, SimpleChannelInboundHandler, ChannelInboundHandler, ChannelInboundHandlerAdapter, ChannelDuplexHandler, NettyRequestProcessor, Converter, SingleValueConverter, ConverterMatcher, AbstractReflectionConverter, AbstractSingleValueConverter, AbstractCollectionConverter}`). Rationale: fat-jar developer CLI tools (antlr `TestRig`, `javac`, `java -jar`, `python -m`) are documented to reflectively load user-supplied class names from `args[]` — the OS shell IS the trust boundary. Reflection method set (simple-name match on `sink.method`): `forName`, `newInstance`, `invoke`, `getMethod`, `getDeclaredMethod`, `getConstructor`, `getDeclaredConstructor`, `loadClass`, `defineClass`. Deliberately narrow — ScriptEngine.eval, GroovyShell.evaluate, SpEL `parseExpression`, and Introspector.getBeanInfo remain flagged (executing scripts is a real bug even in a CLI). Any web-framework signal in the file disables the gate → recall preserved for `@RestController` classes / servlets / Netty handlers that happen to also expose a `main`. Pipeline slot: after `SinkSemanticsPass`, before `TaintPropagationPass`. Guarded on `disabledPasses: ['cli-main-reflection-suppress']`. Issue #162 — 3.149.0 |
| 111 | `library-profile-source-gate` | — (source-gating, no CWE) | — | shipped | Source-gating pass (emits no findings). Reads the resolved `ProjectProfile` from `graph.ir.meta.projectProfile` (populated in 3.150.1 via #235) and, when the profile begins with `library/` (`library/production` / `library/dev` / `library/sample` / `library/benchmark` / `library/test`), drops speculative sources — `interprocedural_param` and `constructor_field` — from `graph.ir.taint.sources`. Concrete sources (`http_param`, `env_input`, `db_input`, `file_input`, etc.) are preserved unconditionally. Motivation: `TaintMatcher` emits `interprocedural_param` for every public method parameter under the presumption of an attacker-controlled caller; that presumption is systematically wrong for a library codebase where callers are downstream consumers with their own threat models. Removing the seed source-side also removes every `interprocedural_param → *` flow (Scenario B `external_taint_escape` at CWE-668 in `InterproceduralPass` was 35% of Tier 2 H+C findings in the 22-repo audit). No-op when profile is absent, `'unknown'`, or non-library shape — 3.150.1 output is preserved for callers that skip profile detection. Pipeline slot: after `SourceSemanticsPass` (semantic tags preserved for observability), before `SinkFilterPass` / `TaintPropagationPass` (no dropped seed reaches flow generators). Guarded on `disabledPasses: ['library-profile-source-gate']`. Issue #236 — 3.151.0 |

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
