# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.110.0] - 2026-06-27

Engine bump only — adopts [`circle-ir@3.110.0`](https://www.npmjs.com/package/circle-ir)
which ships the Sprint 53 S-bucket batch:

- **#196 — Java JDK `Logger.getLogger("…").warning(msg)`** now flags
  `log_injection` (CWE-117). Adds a conservative receiver heuristic for
  the `Logger.getLogger(...)` / `LoggerFactory.getLogger(...)` factory
  shape in `taint-matcher.ts`.
- **#193 — Python `logging.Logger.<level>(fmt, *args)`** now flags
  `log_injection` (CWE-117) for tainted positional args. Extends
  `arg_positions` from `[0]` to `[0, 1, 2, 3, 4]` on every level
  method and adds missing `warn`/`fatal`/`exception` aliases.
- **#215 — Python `cursor.execute(f"…{safe_col(name)}… = ?", (value,))`**
  no longer false-positives. New Stage 19 in `sink-filter-pass.ts`
  recognises the regex-allowlist+raise quoter helper shape (Python port
  of Java Stage 15) when combined with bind-placeholder values.
- **#217 — Java fluent-builder fixpoint hang (Keycloak)** verified
  already incidentally fixed by Sprint 36 #141 memoization; a new
  regression guard test ships in the engine package.

No CLI source changes — pure dependency bump.

## [3.109.0] - 2026-06-27

Engine bump only — adopts [`circle-ir@3.109.0`](https://www.npmjs.com/package/circle-ir)
which ships the Sprint 52 sanitizer-wrapped FP cluster (#216 subset):

- **#216 — Python `ldap_injection` FP on `re.sub`-based LDAP metachar
  wrappers** (e.g. `def ldap_safe(s): return re.sub(r"[()=*\\]", "", s)`).
  New Stage 17 in `sink-filter-pass.ts` recognises wrapper functions
  whose body strips at least three of the RFC 4515 LDAP-filter metachars
  `( ) = * \`, plus the built-ins `escape_filter_chars`/`filter_format`.
- **#216 — Python `xxe` FP inside hardened-parser scopes** (e.g.
  `safe_parse(xml_bytes)` whose body constructs `XMLParser(resolve_entities=False)`).
  New Stage 18 adds a scope-aware backward scan halted at the enclosing
  `def` boundary — preserves recall on sibling-function unsafe parsers.
- **#216 — JavaScript `log_injection` FP on CRLF-stripping sanitizers**
  (e.g. `stripCrlf`, `.replace(/[\r\n]/g, '')`). New Stage 16 adds a
  `JS_LOG_INJECTION_SANITIZERS` pattern array with the same inline +
  variable-assignment suppression shape as the existing XSS Stage 7.

Phase 0 empirical reproduction confirmed three additional `/wrapped`
routes (JS XSS, JS deserialization, Python SSTI) were already clean on
v3.108.0; those phases were dropped from the sprint.

## [3.108.0] - 2026-06-26

Engine bump only — adopts [`circle-ir@3.108.0`](https://www.npmjs.com/package/circle-ir)
which ships the Sprint 51 Java FN/FP batch:

- **#214** — Java `sql_injection` Stage 15 inline form FP. New inline
  branch in `sink-filter-pass.ts` extends Sprint 50's regex-allowlist
  quoter suppression to cover `c.prepareStatement("…" + quoteIdent(col)
  + " = ?")` (concat passed inline to the exec method).
- **#197, #196, #117** — confirmed firing under v3.107.0 on canonical
  fixture shapes; residual gaps are narrower inline-fluent-receiver /
  same-line-dedup edge cases queued as follow-ups.

## [3.107.0] - 2026-06-25

Engine bump only — adopts [`circle-ir@3.107.0`](https://www.npmjs.com/package/circle-ir)
which ships the Sprint 50 FP triage batch:

- **#152** — JS `setInterval`/`setTimeout` `code_injection` over-fires
  on function-typed parameter references (`function schedule(cb) {
  setTimeout(cb, 1000); }`). Flow-level filter in
  `taint-propagation-pass.ts` drops the `interprocedural_param ×
  code_injection` cross-product when the sink line is a timer method.
- **#181** — Java `xxe` over-matches CommonMark `Parser.parse()`
  (follow-up to closed #155 — same fixture, different sink-rule). New
  Stage 9f in `sink-filter-pass.ts` reuses the `DATA_PARSER_TYPES`
  set to drop `xxe` sinks when the resolvable receiver type is a
  non-XML parser.
- **#191 / FP-77** — Java `sql_injection` over-fires on
  regex-allowlist-quoter wrappers. New Stage 15 in `sink-filter-pass.ts`
  generalises Stage 13 (#163) — drops the `*Dialect|*SqlBuilder` class
  suffix gate and instead recognises the shape directly: SQL concat
  of literals + in-file method calls, with `?` placeholder for value
  binding and at least one helper whose body contains an inline
  `.matches("strict-anchored")` + `throw` guard.

### Changed
- Bumps `circle-ir` dependency `^3.106.0` → `^3.107.0`.

### Unchanged
- No CLI flag, output-format, or behaviour change.
- `@cognium/project-profile-detect` pinned at `^1.1.0`.
- Pillar I: no LLM identifiers.

## [3.106.2] - 2026-06-24

Detector bump only — adopts
[`@cognium/project-profile-detect@1.1.0`](https://www.npmjs.com/package/@cognium/project-profile-detect)
which adds Maven parent-pom inheritance and an implicit Maven library shape
branch (#192). Targets parent-pom-driven Maven repos (e.g. langchain4j) that
previously fell through to `unknown` because their child poms inherited
`<distributionManagement>` from a parent and carried no Gradle-only
`java-library` plugin, JPMS `module-info.java`, or `META-INF/services` SPI
signal. Those modules now resolve to `library/production`, which lets
ADR-008 fire its severity downgrades.

### Changed
- Bumps `@cognium/project-profile-detect` dependency `^1.0.0` → `^1.1.0`.

### Unchanged
- No CLI flag or output-format change. `circle-ir` pinned at `^3.106.0`.
- Pillar I: no LLM identifiers (verified by grep guard).

## [3.106.1] - 2026-06-24

Internal refactor — detector logic extracted to
[`@cognium/project-profile-detect@1.0.0`](https://www.npmjs.com/package/@cognium/project-profile-detect).
No user-visible behavior change. The CLI now consumes the detector as a
workspace dependency so the same code can be shared with downstream consumers
(e.g. cognium-ai) that need caller-side project-profile detection without
re-implementing the Maven/Gradle walker.

### Changed
- `src/project-profile-detect/` directory removed from this package. The
  9 source files (`index.ts`, `types.ts`, `walk.ts`, `maven-parse.ts`,
  `gradle-parse.ts`, `shape-resolve.ts`, `env-resolve.ts`,
  `publication-detect.ts`, `overrides.ts`) and 8 test files moved to the new
  `@cognium/project-profile-detect` package (git history preserved via
  `git mv`).
- `cli.ts` now imports `detectProjectProfiles` from
  `@cognium/project-profile-detect` instead of the local relative path.
- Adds `@cognium/project-profile-detect@^1.0.0` as a dependency alongside
  `circle-ir@^3.106.0`.

### Unchanged
- Detection contract, three-tier resolution (forcedProfile → overrides → walker),
  Hybrid Approach C library gate, public-registry allowlist, and CLI flags
  (`--profile`, `--profile-override`) are byte-identical to 3.106.0.
- Engine dependency (`circle-ir`) version unchanged at `^3.106.0`.
- Bundle size unchanged (~1.38 MB) — the detector was already bundled in.

Pillar I: no LLM identifiers (verified by grep guard).

## [3.106.0] - 2026-06-24

Tracking release for circle-ir@3.106.0 Sprint 48: the new
**project-profile architecture** (#169). Bumps the `circle-ir`
dependency from `^3.105.0` to `^3.106.0`.

End-user-visible CLI surface changes:

- **Per-project profile auto-detection** — `cognium-dev scan` now walks
  the scan root for build files (`pom.xml`, `build.gradle`,
  `build.gradle.kts`), resolves each module to a `ProjectProfile`
  (`shape/env` — e.g. `library/production`, `server/production`,
  `application/dev`), and forwards the per-file profile map to the
  engine. The engine applies shape-conditional severity bucketing
  (ADR-008 C-Yes-Yes policy): `library/...` modules downgrade
  Tier-D-tagged findings (CRIT→MED, HIGH/MED/LOW→LOW), while
  `application/...` modules restore the original severity for findings
  that Sprint 47 had pre-emptively downgraded.

- **Shape resolver — hybrid Approach C** — a module is `library` only
  when it carries a library-signal (`java-library` plugin / JPMS
  `module-info.java` / SPI `META-INF/services/`) **and** its
  `distributionManagement` URL resolves to a strict public-registry
  allowlist (Maven Central, Sonatype OSSRH, Gradle Plugins Portal,
  legacy jcenter). Internal helper modules with library signals but
  no public publication resolve to `application`, preventing the
  library downgrade from masking real bugs in first-party code.
  Corporate Nexus / Artifactory URLs explicitly do **not** promote a
  module to `library/...`.

- **Signal precedence** — `spring-boot` plugin (→ `server`) >
  `war`/`ear` packaging (→ `server`) > `maven-plugin`/`gradle-plugin`
  (→ `plugin`) > Gradle `application` plugin (→ `cli`) >
  `main(String[])` discovery (→ `application`) > library hybrid gate >
  `unknown`.

- **New flags**:
  - `--project-profile <shape/env>` — force a single profile (skips
    auto-detection). Example: `--project-profile library/production`.
  - `--no-project-profile` — disable auto-detection entirely; every
    file resolves to `unknown` (pre-3.106.0 behaviour).
  - `--project-profile-explain` — print the detected per-module
    profiles and reason chain, then exit. Useful for tuning a
    `cognium.config.json`.

- **`cognium.config.json` extensions**:
  - `"profile": "library/production"` — repo-wide forced profile.
  - `"profileOverrides": { "src/main/java/internal/**": "application/production", "third_party/**": "unknown" }` —
    glob-keyed per-path overrides. First matching glob wins.

- **Per-finding `profile` in JSON/SARIF output** — each emitted
  vulnerability now carries a `profile` field showing which profile
  the engine applied. SARIF places it under `properties.profile`. Text
  output adds a top-of-report project-profile summary block.

- **Pillar I — no LLM-themed identifiers** introduced anywhere.
  Flag names, config keys, and tag strings are fully generic.

Backward-compatibility:
- Running without any profile flag and without a `profile` /
  `profileOverrides` config field invokes auto-detection. On scan
  trees with no build files (e.g. a loose `.java` file), every file
  resolves to `unknown` and the engine emits identical findings to
  3.105.0.
- The new `--no-project-profile` flag is the explicit opt-out for
  callers that depend on pre-3.106.0 behaviour.

## [3.105.0] - 2026-06-24

Tracking release for the circle-ir@3.105.0 Sprint 47 Tier-D six-pack:
six Java FP tickets closed under two orthogonal mechanisms
(library-API-surface tag + downgrade, and three narrow suppression
gates). Bumps the `circle-ir` dependency from `^3.104.0` to `^3.105.0`.

End-user-visible CLI surface changes:

- **`[library-api-surface]` badge in text output** — when a
  vulnerability carries the `library-api-surface:caller-responsibility`
  tag (emitted by circle-ir Stages 9e/9f/9g for JEXL/Handlebars,
  SPI Class.forName, and ClassLoader override sinks), the text
  formatter renders a cyan `[library-api-surface]` badge before the
  severity chip. The badge signals to auditors that the finding lives
  at a library-API boundary where the caller (not the library) bears
  trust responsibility.
- **`properties.tags` in SARIF output** — vulnerability tags pass
  through to SARIF `result.properties.tags`, enabling downstream SARIF
  consumers to apply policy-aware rendering.
- **`tags?: string[]` in JSON output** — same field passes through
  verbatim on each `vulnerabilities[]` entry.
- **Severity downgrade** — findings carrying the
  `library-api-surface:caller-responsibility` tag are downgraded to
  MEDIUM (from HIGH/CRITICAL) by circle-ir's central
  `applyLibraryApiSurfaceDowngrade` hook; the CLI's per-flow
  `SINK_SEVERITY` mapping also respects the tag.

End-user effect (six Java rule fixes):

- **cognium-dev#161 — JEXL/Handlebars/template HIGH downgrade** —
  `JexlEngine.createExpression`, `JexlExpression.evaluate`, and
  template-engine `.compile()` callsites (Handlebars, Mustache,
  Pebble, Velocity, Freemarker, Thymeleaf) now surface at MEDIUM with
  the `[library-api-surface]` badge instead of HIGH.
- **cognium-dev#165 — SPI Class.forName HIGH downgrade** —
  `Class.forName(<var>)` callsites near
  `getResources("META-INF/services/...")` patterns now surface at
  MEDIUM. Arbitrary `Class.forName(<user-input>)` outside the SPI
  pattern continues at HIGH.
- **cognium-dev#168 — ClassLoader override HIGH downgrade** — sinks
  inside `ClassLoader` / `URLClassLoader` / `SecureClassLoader`
  subclass `loadClass(String)` / `findClass(String)` overrides now
  surface at MEDIUM.
- **cognium-dev#164 — polymorphic dispatch over typed parser array
  suppressed** — `parser.parseExpression(tainted)` no longer fires
  when `parser` iterates a `private static final X[] PARSERS = {
  new X(), new X() }`-style fully-enumerated typed array of literal
  constructions.
- **cognium-dev#163 — SQL builder/dialect wrapper suppressed** —
  `sql_injection` no longer fires inside `*Dialect` / `*SqlBuilder` /
  `*Quoter` / `*Wrapper` / `*SqlGenerator` / `*QueryBuilder` classes
  when a `.wrap(` / `.quote(` / `.escape(` / `.identifier(` wrapper
  call appears within ±10 lines of the sink. Business classes with
  raw concat continue to fire.
- **cognium-dev#177 — SQL extraction codegen suppressed** —
  `sql_injection` no longer fires inside methods whose signature
  shape is "builder/AST in, String out" (return type ∈ `{String,
  CharSequence, Optional<String>}`, name matches
  `get*Sql*`/`extract*Sql*`/`to*Sql*`/`*Statement*ToString$`/
  `*Query*String$`, first param NOT `String`/`CharSequence`).
  String-in/string-out helpers continue to fire.

### Changed

- `Vulnerability` interface in `src/formatters.ts` gains optional
  `tags?: string[]`. Passes through verbatim from circle-ir
  `TaintFlowInfo.tags`.
- `formatResults()` (text formatter) renders a cyan
  `[library-api-surface]` badge before the severity chip when the
  tag is present.
- `generateSarifResults()` adds `tags: vuln.tags` to SARIF
  `result.properties` when the field is present.
- `cli.ts`: `SastFinding`→`Vulnerability` conversion passes `tags`
  through; sink-severity computation applies the
  `library-api-surface:caller-responsibility` downgrade to MEDIUM
  before formatting.

## [3.104.0] - 2026-06-24

Tracking release for the circle-ir@3.104.0 Sprint 46 fixes closing the
three remaining standalone Tier-1 zero-FP queue items. No CLI surface
changes; bumps the `circle-ir` dependency from `^3.103.0` to `^3.104.0`.
End-user effect (three Java rule fixes packaged under one shared
helper module `_fp-allowlists.ts`):

- **cognium-dev#176 — `hardcoded-credential` CRIT on PEM delimiter
  constants** — Java scans no longer surface CRIT CWE-798
  `hardcoded-credential` findings on PEM-format delimiter string
  literals (`"-----BEGIN PRIVATE KEY-----"`,
  `"-----BEGIN RSA PRIVATE KEY-----"`, etc.) that lack adjacent
  base64-shape body. The new body-adjacency check requires >=30
  base64-shape characters within 5 lines of the BEGIN delimiter; real
  embedded PEM keys always have this body, while parser constants /
  `String.contains()` arguments / error messages don't. Confirmed FP
  repro: `mock-server` `PEMToFile.java:39-43`, `WebhookServer.java:230,239`,
  `CertificateConfigurationValidator.java:59,178` — 7 CRITs suppressed.
  Real embedded keys continue to fire.
- **cognium-dev#174 — `hardcoded-credential` HIGH on CLI option-key
  constants** — Java scans no longer surface HIGH CWE-798
  `hardcoded-credential` findings on JOptSimple / PicoCLI / argparse4j /
  commons-cli kebab-case option-name constants like
  `HTTPS_KEYSTORE_PASSWORD = "keystore-password"`. The new
  `CLI_OPTION_KEY_RE` negative predicate matches all-lowercase
  alphanumeric values with at least one hyphen (length <=48); JVM
  identifiers cannot contain hyphens, so a hyphen-bearing string value
  is structurally not a JVM string secret. Confirmed FP repro:
  `wiremock` `HttpsSettings`-style constants. Real password values
  with uppercase, underscores, dots, or special characters continue
  to fire.
- **cognium-dev#175 — `weak-crypto` / `weak-password-hash` in
  protocol-mandated legacy auth** — Java scans no longer surface
  CWE-327 / CWE-916 findings in protocol-mandated legacy-auth files
  (NTLM / Kerberos pre-auth / SMB1 signing / SASL CRAM-MD5 / HTTP
  Digest). DES/RC4/MD4/MD5 are hardcoded by the protocol specs
  (MS-NLMP, RFC 3961, RFC 2617, RFC 2195); switching algorithms breaks
  interop with conformant peers. The new
  `isProtocolMandatedCryptoFile` predicate suppresses on three
  signals: path segment (`/ntlm/`, `/kerberos/`, `/krb5/`, `/smb1?/`,
  `/sasl/cram-md5/`, `/digest/`), class name (`NtlmEngine`,
  `Krb5Helper`, `KerberosClient`, `Smb*Signing`, `CramMd5*`,
  `DigestScheme`), or inline RFC / MS-NLMP citation. Confirmed FP
  repro: `AsyncHttpClient` `NtlmEngine.java:499/502/530/603` — 6 FPs
  suppressed. Weak crypto in non-protocol files continues to fire.

## [3.103.0] - 2026-06-24

Tracking release for the circle-ir@3.103.0 Sprint 45 fixes closing two
small standalone Tier-1 zero-FP queue items. No CLI surface changes;
bumps the `circle-ir` dependency from `^3.102.0` to `^3.103.0`.
End-user effect (two Java rule fixes — `sql_injection` line-resolution
and `resource-leak` ownership-transfer suppressions):

- **cognium-dev#157 — `sql_injection` sink on `throw new SQLException(...)`** —
  Java scans no longer surface HIGH CWE-89 `sql_injection` findings
  whose sink line is a `throw new SQLException(...)` statement. A
  `throw new <Anything>(...)` statement is structurally never a
  runtime sink: it constructs the exception object and unwinds the
  stack — no SQL execution, no command exec, no XSS, no path I/O
  happens. The new Stage 12 post-emission filter in `sink-filter-pass`
  is sink-type-agnostic and also suppresses sinks on
  `throw new IOException(...)`, `throw new RuntimeException(...)`,
  etc. Confirmed FP repro: `chinabugotech__hutool`
  `DialectRunner.java:208`. Real sinks elsewhere in the same method
  (e.g. a downstream `stmt.executeQuery(sql)` line) continue to fire.
- **cognium-dev#158 — `resource-leak` factory-return / field-store FPs** —
  Java scans no longer surface HIGH CWE-772 `resource-leak` findings
  for three ownership-transfer patterns that the engine previously
  could not see:
    1. **Return-flow** — `URLConnection conn = openConnection(); return (HttpURLConnection) conn;`
       and similar shapes where the opened handle is returned to the
       caller (typically consumed via try-with-resources).
    2. **Field-store with paired close method** —
       `this.camera = OpenCameraInterface.open(id)` paired with a
       `closeDriver()` method that calls `camera.release()` on the
       same field.
    3. **Factory-method-name heuristic** — methods named with the
       prefix family `open` / `create` / `new` / `get` / `make` /
       `build` followed by a capital letter (e.g. `createSocket(...)`)
       AND a non-`void` return type, which by convention transfer
       resource ownership to the caller.
  Approximately 5/49 of the surveyed HIGH `resource-leak` findings
  (~10%) were of this shape. Each suppression requires two
  independent conditions to fire (conservative-bias preserved): a
  real `FileInputStream` / `Socket` open with no close, no return,
  and no field-store continues to fire as a definite leak; a
  field-store with no paired close method in the class continues to
  fire; a method named `process()` / `run()` / `void foo()` continues
  to fire.

## [3.102.0] - 2026-06-24

Tracking release for the circle-ir@3.102.0 Sprint 44 fixes closing the
remaining new-work items on the #179 sink-shape umbrella and #166. No
CLI surface changes; bumps the `circle-ir` dependency from `^3.101.0`
to `^3.102.0`. End-user effect (two Java rule fixes plus regression
locks for two existing gates):

- **cognium-dev#179 Sink 1 — argv-form `ProcessBuilder` constructor** —
  Java scans of projects calling `new ProcessBuilder(Arrays.asList(...))`,
  `new ProcessBuilder(List.of(...))`,
  `new ProcessBuilder(Collections.singletonList(...))`,
  `new ProcessBuilder(new String[]{...})`, or
  `new ProcessBuilder("git", "log", ref)` (varargs ≥2) no longer
  surface CRITICAL CWE-78 `command_injection` FPs. Argv-form
  constructors pass arguments directly to `fork(2)` — the kernel
  treats each slot as a literal, no shell, no metacharacter
  expansion. Single bare-variable `new ProcessBuilder(userCmd)` and
  `Runtime.getRuntime().exec(userCmd)` continue to fire.
- **cognium-dev#166 — XXE JDK 8u121+ hardening recognition** — Java
  scans of projects that use any of the following hardening patterns
  no longer surface CWE-776 / CWE-611 `xml-entity-expansion` FPs:
    - Apache `load-external-dtd` feature URL with `setFeature(..., false)`
    - JDK 8u121+ entity-limit system properties
      (`jdk.xml.totalEntitySizeLimit`, `entityExpansionLimit`,
      `maxGeneralEntitySizeLimit`, `maxParameterEntitySizeLimit`,
      `elementAttributeLimit`) set to 0
    - `XMLConstants.FEATURE_SECURE_PROCESSING` constant or
      `feature/secure-processing` URL string
  Confirmed FP repros: `languagetool` `PatternRuleLoader.java:70`,
  `FalseFriendRuleLoader.java:78`, `DisambiguationRuleLoader.java:45`,
  `BitextPatternRuleLoader.java:41`. SAX parsers / `DocumentBuilder`s
  without any hardening pattern continue to fire.
- **cognium-dev#179 Sinks 2/3 regression locks** — new regression
  tests verify the existing gates for typed Jackson
  `mapper.readValue(json, ConcreteType.class)` (Sink 2, via
  `safe_if_class_literal_at: 1`) and parameterized JdbcTemplate
  `update("...?", args)` / `queryForObject("...?", mapper, id)`
  (Sink 3, via placeholder-aware SQL filter). No behavior change —
  pure regression locks against future drift.

## [3.101.0] - 2026-06-24

Tracking release for the circle-ir@3.101.0 Tier-1 zero-FP queue
cluster release. No CLI surface changes; bumps the `circle-ir`
dependency from `^3.100.0` to `^3.101.0`. End-user effect (three
Java rule fixes — biggest single sprint CRITICAL-severity reduction
to date):

- **cognium-dev#167 — picocli `new CommandLine(...)` constructor** —
  Java scans of projects using picocli no longer surface CWE-78
  command_injection FPs for the annotation-driven CLI parser
  constructor. Apache Commons Exec `CommandLine` continues to fire.
- **cognium-dev#170 — Redis / MQ protocol-client wire-command
  methods** — Java scans of projects using jedis / lettuce /
  spring-data-redis / spring-data-mongodb / spring-amqp / rabbitmq /
  kafka-clients / paho-mqtt no longer surface CWE-78 FPs for
  `executeCommand` / `execute` / `dispatch` / `send` / `publish` /
  `command` / `run`. Real `Runtime.exec` / `ProcessBuilder` calls
  inside the same files continue to fire. Expected 30-60% reduction
  in CRITICAL-severity finding count on Java corpora dominated by
  Redis / MQ client code.
- **cognium-dev#173 — output-only `TransformerFactory` + empty
  `DocumentBuilder`** — Java scans of projects that only serialize
  XML (`DOMSource → StreamResult`) or only construct empty
  `Document` trees (`builder.newDocument()` with no `.parse(...)`)
  no longer surface CWE-776 / CWE-611 xml-entity-expansion FPs.
  `StreamSource` / `SAXSource` / `InputSource` parsing,
  `DocumentBuilder.parse(...)`, and `SAXParserFactory` continue to
  fire.

## [3.100.0] - 2026-06-23

Tracking release for the circle-ir@3.100.0 Tier-1 zero-FP queue cluster
release. No CLI surface changes; bumps the `circle-ir` dependency from
`^3.99.0` to `^3.100.0`. End-user effect (four Java `code_injection`
CWE-094 rule fixes, ~18 fewer HIGH FPs across the Java HIGH FP corpus):

- **cognium-dev#155 — `parser.parse(...)` over-match** — Java scans
  of projects using commonmark `Parser`, hutool `DateParser`, zxing
  `ResultParser`, `SimpleDateFormat`, `DecimalFormat`, picocli /
  airline / jcommander CLI arg parsers no longer surface CWE-094 FPs
  for `.parse(...)` calls on these non-script data-parser types.
- **cognium-dev#156 — compiled-template render/process** — Java
  scans of projects using Freemarker / Jetbrick / Rythm / Velocity /
  Beetl no longer surface CWE-094 FPs for `.render(...)`,
  `.process(...)`, `.merge(...)`, or `.renderTo(...)` on compiled
  `Template` / `JetTemplate` / `ITemplate` receivers. The compile
  step (`engine.getTemplate(tainted)`) continues to fire.
- **cognium-dev#159 — reflection / SpEL with literal / annotation
  arg** — Java scans no longer surface CWE-094 FPs for
  `Class.forName("literal")`, `Class.forName(ann.value())`,
  `spel.parseExpression("literal")`, `method.invoke(target)`
  (one arg), or `clazz.getMethod("literal")`. Tainted variants
  continue to fire.
- **cognium-dev#160 — no-arg `Constructor#newInstance()`** — Java
  scans no longer surface CWE-094 FPs for `ctor.newInstance()` with
  zero args. `ctor.newInstance(arg)` continues to fire.

## [3.99.0] - 2026-06-23

Tracking release for the circle-ir@3.99.0 combined Tier-1 zero-FP queue
release. No CLI surface changes; bumps the `circle-ir` dependency from
`^3.98.0` to `^3.99.0`. End-user effect (two unrelated rule fixes):

- **cognium-dev#132 — JS/TS CRLF / open_redirect** — JS/TS code using
  `Set/Map.has(...)` allowlist guards for `res.redirect(...)`
  (idiomatic in modern Express/Koa apps) no longer produces false
  `crlf` / `open_redirect` findings. Express/Koa
  `res.cookie(name, value, [opts])` calls (with or without security
  flags) no longer produce false `crlf` findings — the cookie helper
  serialises via `cookie.serialize()` which URL-encodes CR (%0D) /
  LF (%0A). Raw-header `setHeader('Set-Cookie', tainted)` and bare
  unguarded `res.redirect(req.query.url)` continue to fire.
- **cognium-dev#133 — info-disclosure-stacktrace (CWE-209)** —
  Returning `err.message` to the client no longer triggers the
  `info-disclosure-stacktrace` rule. The rule now correctly reflects
  its canonical CWE-209 stack-trace-disclosure scope. Returning
  `err.stack`, `err.toString()`, the full error object, or
  `traceback.format_exc()` continues to fire. Python file-handle writes
  (`f.write(SECRET)` where `f = open(...)`) no longer trigger the rule.

## [3.98.0] - 2026-06-23

Tracking release for the circle-ir@3.98.0 Python Jinja2 safe
render-context FP suppression (cognium-dev#147). No CLI surface
changes; bumps the `circle-ir` dependency from `^3.97.0` to `^3.98.0`.
End-user effect: Python scans no longer report XSS (CWE-79) or
SSTI/code-injection (CWE-94) findings for the three safe Jinja2 render
shapes — `render_template_string("lit", **ctx)`, `Template("lit")`,
and `Template("lit").render(**ctx)` — when the template body is a
single quoted string literal. Tainted-template-source variants (string
concat, identifier reference, function-call result, f-string
interpolation) continue to fire. Cross-file `cf-ip-0-*` taint paths
that previously surfaced the FP at the project level are also
suppressed because the upstream sink no longer exists.

## [3.97.0] - 2026-06-23

Tracking release for the circle-ir@3.97.0 Go `json.Unmarshal` /
`json.Decoder.Decode` typed-destination safe-gate (cognium-dev#148). No
CLI surface changes; bumps the `circle-ir` dependency. End-user effect: Go
scans no longer report a `deserialization` (CWE-502) finding on
`json.Unmarshal(body, &typedStruct)` /
`json.NewDecoder(r).Decode(&typedStruct)` calls. Untyped destinations
(`interface{}`, `any`, `map[string]interface{}`,
`make(map[string]interface{})`) and unresolvable shapes continue to emit.
Side benefit: downstream `sql_injection` sinks that were previously masked
by the upstream Unmarshal FP are now visible (closes FN-IL-19 as noted in
the issue body).

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.97.0`.

## [3.96.0] - 2026-06-23

Tracking release for the circle-ir@3.96.0 `setInterval` / `setTimeout`
CWE-94 sink-shape gate (cognium-dev#152). No CLI surface changes; bumps
the `circle-ir` dependency. End-user effect: JS/TS scans no longer report
a `code_injection` finding on `setInterval` / `setTimeout` calls whose
first argument is a function literal (the common, benign callback shape).
All other CWE-94 sinks (`eval`, `Function`, `new Function(...)`, and
tainted-identifier flows into `setInterval` / `setTimeout`) emit
unchanged.

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.96.0`.

## [3.95.0] - 2026-06-23

Tracking release for the circle-ir@3.95.0 entry-point gate opt-out toggle
(cognium-dev#137) and Pillar I documentation propagation. No CLI surface
changes; bumps the `circle-ir` dependency.

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.95.0`. End-user
  effect: **none**. The new `AnalyzerOptions.enableEntryPointGate` knob is
  library-only API surface and defaults to `true`, preserving the
  unconditional Java entry-point gate behaviour that has shipped since
  3.88.0 (#128) and was extended to Netty handlers in 3.93.0 (#154).
- Repository docs — Pillar I (zero LLM in cognium-dev) is now documented
  in `packages/circle-ir/docs/ARCHITECTURE.md` (ADR-007),
  `packages/circle-ir/docs/SPEC.md`, and `packages/circle-ir/docs/PASSES.md`
  in addition to the existing `CLAUDE.md` guardrails.

### Pillar I boundary note

The CLI deliberately does **not** expose any flag for the entry-point gate
toggle. Disabling the gate is a debugging or recall-tuning operation
intended for library consumers; the deterministic CLI keeps the gate on
unconditionally. Guardrail codified in `packages/cli/CLAUDE.md`.

## [3.94.0] - 2026-06-23

Tracking release for the circle-ir@3.94.0 speculative-finding suppression
infrastructure (cognium-dev#153 pre-req). No CLI surface changes; bumps
the `circle-ir` dependency.

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.94.0`. End-user
  effect: **none**. The new `SastFinding.confidence` field and
  `AnalyzerOptions.includeSpeculative` knob are library-only API surface;
  no pass currently emits speculative findings and the CLI does not expose
  any flag for the toggle. Default deterministic behaviour is byte-
  identical to 3.93.0.

### Pillar I boundary note

The CLI deliberately does **not** expose a `--include-speculative` (or
any `--llm-*`) flag in 3.94.0. cognium-dev is the deterministic SAST entry
point; speculative-finding adjudication is the responsibility of the
downstream consumers that will set the library option directly. Guardrail
codified in `CLAUDE.md`.

## [3.93.0] - 2026-06-23

Tracking release for the circle-ir@3.93.0 Netty entry-point classifier
extension (cognium-dev#154 — closes the recognition gap behind
CVE-2022-26884 dolphinscheduler). No CLI surface changes; bumps the
`circle-ir` dependency.

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.93.0`. End-user
  effect: Java scans now recognise `SimpleChannelInboundHandler<T>`,
  `ChannelInboundHandler`, `ChannelInboundHandlerAdapter`,
  `ChannelDuplexHandler`, and `NettyRequestProcessor` lifecycle methods
  as TIER_1 entry points, preserving their wire-message parameter taint
  sources through verification. Generalises to Cassandra wire protocol,
  Apache Flink workers, gRPC-over-Netty servers, Twitter Finagle, and
  dolphinscheduler logger / master / worker RPC handlers when their
  handler types weren't previously in the recognised set.

## [3.92.0] - 2026-06-23

Tracking release for the circle-ir@3.92.0 Java-bundle (close cognium-dev#143
as unjustified, ship cognium-dev#142 defensive per-file finding cap, status
update on cognium-dev#141). No CLI surface changes; bumps the `circle-ir`
dependency.

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.92.0`. End-user
  effect: any single file producing more than 1000 findings is now
  collapsed to a single `saturated-file` advisory in the report
  (`rule_id: 'saturated-file'`, `severity: 'low'`,
  `category: 'maintainability'`, `level: 'note'`). The advisory carries
  the suppressed count and per-rule / per-severity roll-ups in its
  `evidence` field so triagers can recognise the saturation pattern
  without re-running with the cap disabled. Combined with the 3.89.0
  `crossFileBudgetMs` breaker, this closes the residual worst-case
  hang path on langchain4j-shape inputs. Consumers that need the
  uncapped stream can pass `perFileFindingCap: 0` to `analyze()` /
  `analyzeProject()` programmatically (no CLI flag yet — defer until
  empirical need surfaces).

## [3.91.0] - 2026-06-23

Tracking release for the circle-ir@3.91.0 entry-point classifier update
(cognium-dev#136 — Tier 1 heuristic gaps for `@Service` / `@Repository` /
`@Component` stereotype beans). No CLI surface changes; bumps the
`circle-ir` dependency.

### Changed

- `package.json` — `circle-ir` dependency bumped to `^3.91.0` for the
  Tier 1 stereotype-bean classification fix. End-user effect: Java
  library-jar scans where the calling `@RestController` is not in scope
  will now retain `interprocedural_param` taint sources on `@Service` /
  `@Repository` / `@Component` methods (previously dropped at the
  TIER_3 gate). Expect modest recall increase on stereotype-only
  codebases; no precision regression on the jedis / library-facade
  cluster locked by the precision tests.

### Issues closed

- cognium-dev#136 — Sprint 35 step 3: Tier 1 entry-point gate — Java
  heuristic gaps.

## [3.90.2] - 2026-06-23

Documentation-only patch. Formalises the `--format json` / `--format sarif`
stdout contract that 3.89.1 + 3.89.2 implemented but never documented as a
stability promise. Filed as #149 after a downstream consumer (the
`sast-validation` regression harness) discovered the 3.89.2 stdout cleanup
silently broke a `tail -n +2` parser idiom — the fix direction is correct,
but the contract change deserved an explicit migration note.

### Documentation

- `README.md` — new **Output streams (stdout vs stderr)** subsection under
  Output Format. Tabulates every output channel by stream, calls out the
  stable stdout contract for `--format json` and `--format sarif` (pure
  parseable payload starting at character 1, version inside the JSON
  object), and tells pre-3.89.2 consumers to drop any `tail -n +2` /
  `split("\n",1)[1]` skip-the-first-line idioms.

### Contract (retroactive, descriptive — no behavior change)

- **stdout** for `--format json` / `--format sarif`: pure machine-readable
  payload. No banner, no preamble, no log lines. The `.version` field
  carries the engine version; consumers do not need to parse a stdout
  preamble for it.
- **stderr** for everything else: status lines, spinner, errors, library
  log output (silent by default), findings instrumentation
  (`CIRCLE_IR_INSTRUMENT_FINDINGS=1`).
- This contract was implemented across **3.89.1** (library logger to
  stderr, default level silent) and **3.89.2** (CLI status lines, spinner,
  usage hints to stderr). 3.90.2 ships only the documentation.

### Issues closed

- #149 — `scan -f json: stdout contract changed in 3.89.2 (banner
  removed) — broke downstream JSON parsers`. Behavior was already
  correct; this release adds the documentation the issue requested.

## [3.90.1] - 2026-06-23

Tracking release alongside circle-ir 3.90.1. Picks up the per-file perf fix
for the langchain4j #141 hang — single-file scans on deep
`Stream.builder().add(...).add(...)…build()` chains no longer hang in
constant-propagation.

### Changed

- `circle-ir` dep bumped to `^3.90.1`.

### Measured

A previously-hanging single-file scan
(`EmbeddingStoreWithFilteringIT.java`, 1517 LOC) now completes in ~321 ms
end-to-end. See circle-ir 3.90.1 for the underlying root-cause analysis
and the synthetic chain benchmark table.

## [3.90.0] - 2026-06-23

Tracking release alongside circle-ir 3.90.0. Wires the new opt-in findings
instrumentation hook (PR B of #143 split, scoped per cognium-dev #145) to a
CLI environment variable so scans can produce the per-finding data #143
needs to prototype coalesce rules.

### Added

- `src/cli.ts` — reads `CIRCLE_IR_INSTRUMENT_FINDINGS=1` and calls
  `setFindingsInstrumentation(true)` before any `analyze()` invocation.
  Off by default. When enabled, each scanned file emits two JSON-tagged
  lines on **stderr** (`[finding] …`, `[findings-summary] …`); stdout
  output (text / JSON / SARIF) is unchanged. See circle-ir 3.90.0 for the
  payload contract.

### Changed

- `circle-ir` dep bumped to `^3.90.0`.

### Stability

The JSONL payload schema is stable-additive: future circle-ir releases may
add new fields without a major bump. Consumers consuming the stderr stream
should ignore unknown keys.

### Usage

```bash
CIRCLE_IR_INSTRUMENT_FINDINGS=1 cognium-dev scan ./repo --format json --quiet \
  > findings.json 2> findings-instr.jsonl
```

## [3.89.2] - 2026-06-22

CLI-only patch. Finishes the stdout-cleanliness work started in 3.89.1
(which fixed the library logger) by routing the CLI's own status messages
to stderr, and exposes the circle-ir cross-file budget knob on the command
line. `circle-ir` dep stays at `^3.89.1` (no library changes).

### Fixed

- `src/cli.ts` — pre-existing stdout pollution: `Loaded config: …`,
  `Suppressed N finding(s) via config`, and `Results written to …` now
  write to **stderr** via `console.error` instead of `console.log`. This
  was latent before 3.89.1 (text scans pipe the same payload either way),
  but became a real corruption risk for `--format json` / `--format sarif`
  consumers whenever a `cognium.config.json` is loaded or `--profile` is
  used. The text-format summary block (`Found N security finding(s) …`)
  is unchanged — it was already gated on `format === 'text'` and is part
  of the text payload.
- `src/cli.ts` — error usage hints (`Usage: cognium-dev …`,
  `Run 'cognium-dev --help' …`) now write to stderr alongside their
  accompanying error message instead of stdout. Match standard CLI
  convention (errors + diagnostics on stderr, payload on stdout).
- `src/utils/spinner.ts` — spinner output (animation frames, cursor
  hide/show, line clear, and `succeed`/`fail`/`warn` final status lines)
  now writes to **stderr** instead of stdout. Previously the
  `✔ Scanned N file(s)` and similar terminal lines used `console.log`
  unconditionally, corrupting `--format json`/`--format sarif` stdout
  whenever the spinner ran without `--quiet`. TTY detection now keys off
  `process.stderr.isTTY` to match the new output stream.

### Added

- `src/cli.ts` — new `--cross-file-budget-ms <n>` flag, forwarded to
  `analyzeProject({ crossFileBudgetMs: n })` (circle-ir 3.89.0+). `0`
  means unlimited (legacy pre-3.89.0 behaviour). When the flag is omitted
  the library default (`300_000` ms / 5 min) applies. Invalid input
  (non-integer, negative) warns on stderr and the library default is used.
- `src/utils/args.ts` — help text documents the flag with two examples
  (60 s cap; unlimited).

### Migration

- Any consumer that was scraping `cognium-dev scan` **stdout** for the
  status lines `Loaded config: …`, `Suppressed N finding(s) via config`,
  or `Results written to …` must now read them from **stderr**.
- Users who relied on the implicit unlimited cross-file budget from
  pre-3.89.0 can restore it with `--cross-file-budget-ms 0`.

## [3.89.1] - 2026-06-22

Patch follow-up to 3.89.0. Tracks the circle-ir 3.89.1 stdout-pollution
fix and adds a first-class CLI hook for controlling library log output.

### Fixed

- Tracks circle-ir 3.89.1 — `--format json` / `--format sarif` output is no
  longer corrupted by the new cross-file phase markers. circle-ir now routes
  all log output to stderr and defaults to `silent` level, so JSON/SARIF
  stdout pipelines are safe by default without any flag.

### Added

- `src/cli.ts` — new `--log-level <level>` flag and `COGNIUM_LOG_LEVEL` env
  var to control circle-ir logger verbosity (`silent` | `trace` | `debug` |
  `info` | `warn` | `error` | `fatal`). Precedence: CLI flag > env var >
  default (`silent`). Applied before the first analyzer call so phase
  markers and budget warnings are emitted at the requested level. Invalid
  values are ignored with a stderr warning.
- `src/utils/args.ts` — help text documents the new flag + env var, with
  two examples showing stderr-only verbose output.

### Changed

- Bumps `circle-ir` dep to `^3.89.1`.

## [3.89.0] - 2026-06-22

### Changed

- Tracks circle-ir 3.89.0 — Sprint 36 cross-file phase pre-indexing +
  defensive budget breaker (#141). CLI now relies on the new analyzer
  default `crossFileBudgetMs: 300_000` (5 min) for cross-file taint
  resolution. On clean corpora the cross-file phase completes well under
  the budget; on pathological corpora the breaker returns partial paths
  rather than hanging the scan.

### Added

- `src/formatters.ts` — `CrossFileData.budgetExceeded?: boolean` field
  propagated from `ProjectAnalysis.cross_file_budget_exceeded`.
- Text output: yellow warning lines after the cross-file section when
  `budgetExceeded === true`, advising the user that some cross-file
  taint paths may be missing and pointing at the `crossFileBudgetMs`
  analyzer option.
- JSON output: top-level `cross_file_budget_exceeded` boolean and
  `summary.crossFileBudgetExceeded` mirror of the same flag, so CI
  pipelines and downstream consumers can detect partial results without
  parsing log text.

## [3.88.0] - 2026-06-22

### Changed

- Tracks circle-ir 3.88.0 — Sprint 35 ship of cognium-dev #128
  entry-point-anchored taint sources. The new tier classifier in
  `src/analysis/entry-point-detection.ts` (verbatim port from
  cognium-ai@2.14.0, PR #135) is now wired into
  `interprocedural-pass.ts` Scenario A, dropping speculative
  `interprocedural_param` flows on Java library-facade methods
  (`*Util` / `*Utils` / `*Helper(s)` classes, `*.template.*` /
  `*.engine.*` packages, direct JDK-facade implementers, and all
  non-entry-point Java methods). Suppresses the residual portion of
  the Java OSS top-25 CWE-78 FP cluster that #129's receiver-class
  allowlist did not catch. CLI surface unchanged; bump dep
  `circle-ir@^3.88.0`.

## [3.87.0] - 2026-06-22

### Changed

- Tracks circle-ir 3.87.0 — Sprint 35 prep additive `Finding` schema
  fix (#134). `Finding.source.type` and `Finding.sink.type` now expose
  the engine-internal taint classifications (e.g.
  `'interprocedural_param'`, `'sql_injection'`), and `Finding.line`
  becomes a canonical top-level "go-to-line" coordinate mirroring
  `sink.line`. Unblocks #128 triage by letting downstream consumers
  filter by source kind directly. CLI surface unchanged; bump dep
  `circle-ir@^3.87.0`.

## [3.86.0] - 2026-06-21

### Changed

- Tracks circle-ir 3.86.0 — Sprint 34 Java OSS top-25 FP cluster
  cleanup shipping two independent precision gates:
  - **#129** CWE-78 receiver-class allowlist in `findSinks()`.
    Statically-resolved non-allowlist receivers (e.g.
    `UnifiedJedis.executeCommand`) are suppressed; unresolved
    receivers (JS `child_process.exec`, Python `subprocess.run`)
    fall through to preserve recall. Allowlist covers java.lang,
    Apache Commons Exec, Gradle, Jenkins, Spring, hutool.
    Expected -86% high CWE-78 findings on Java OSS top-25.
  - **#130** hardcoded-credential value-shape gate raising the
    minimum credential value length from 3 to 12 chars and adding
    three negative shape predicates (dotted property keys, plain
    identifier strings, short numeric placeholders). Layer 1
    provider regexes and Layer 2 entropy gate unaffected. Expected
    -100% on cluster-2 highs (11 → 0).
- CLI surface unchanged; bump dep `circle-ir@^3.86.0`.

## [3.85.1] - 2026-06-20

### Changed

- Tracks circle-ir 3.85.1 — Sprint 33 P0 perf hotfix closing **#126**
  (perf regression introduced by 3.85.0's Sprint 32 release). The two new
  Gate 1 / Gate 3 file-level pre-scans (`findAnnotationLineRanges`,
  `findStringArrayLineRanges`) ran unconditionally on every file. On
  string-constant-heavy Java repos (gson 14.5×, Hystrix ≥17.7×,
  openapi-generator ≥7.1×, hutool 2.66×), paren-/brace-walking dominated
  runtime even when the entropy layer could not possibly fire.
- Fast-path **`FAST_CANDIDATE_PROBE_RE`** (cheap regex matching any
  quoted run of ≥32 base64-shape chars,
  `[A-Za-z0-9+/=_-]{32,}`) short-circuits both pre-scans and the entire
  Layer 2 loop when
  the file contains zero ≥32-char base64-shape literals. Conservative
  superset of every shape that would clear the Gate 4 length floor —
  zero recall loss. Provider patterns (Layer 1) and named-credential
  matcher (Layer 1b) are unaffected. Gate 3 walker `lineBudget` also
  tightened 500 → 100 as defense-in-depth.
- +2 regression tests (5000-line annotation-dense Java fixture: fast-path
  & recall locks). Full circle-ir suite **2664 pass | 1 skipped** (was
  2662 / 1). See `packages/circle-ir/CHANGELOG.md` for the full
  implementation breakdown.

## [3.85.0] - 2026-06-20

### Changed

- Tracks circle-ir 3.85.0 — Sprint 32 closing **#125**
  (`hardcoded-credential-entropy` 96.3% FP rate on top-20 Java OSS
  harness). Four context gates added to the pass-#90 entropy layer:
  - **Gate 1** annotation-arg suppression
    (`@Annotation(...)` / `#[...]`)
  - **Gate 2** generated-file wholesale skip (path + filename heuristics
    including `gen/`, `generated/`, `*__c.java`, `*.pb.go`, `*_pb2.py`,
    `*.generated.tsx`)
  - **Gate 3** string-array constant-table suppression (≥3 string
    literals inside `=\s*[{\[]` span)
  - **Gate 4** field-name strengthening — credential-keyword identifier
    on LHS now **required** for entropy emit; literal length floor raised
    8 → 32 chars
  Recall preserved via Layer 1 (16 provider regexes) and Layer 1b
  (named-credential matcher). +10 regression tests; full circle-ir suite
  **2662 pass | 1 skipped** (was 2652 / 1). See
  `packages/circle-ir/CHANGELOG.md` for the full implementation
  breakdown.

## [3.84.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.84.0 — Sprint 31 bundle closing **#114** (Python
  safe-handler FPs) and **#115** (Rust safe-handler FPs). Five new
  shape/guard recognizers across two languages:
  - Python: `findPythonNetlocAllowlistGuardSanitizers` (Flask host
    allow-list `if urlparse(t).netloc not in ALLOWED_HOSTS: return`) and
    `findPythonRangeCheckGuardSanitizers` (numeric range guard
    `if x < N or x > MAX: return`).
  - Rust: `isSafeRustCommandCall` (literal non-shell `Command::new` with
    chained `.arg`/`.args`/`.spawn`/`.output`),
    `findRustCanonicalizeGuardSanitizers` (path guard
    `if !p.canonicalize()?.starts_with(&ROOT) { return Err(...) }`), and
    `findRustSetAllowlistGuardSanitizers` (HashSet/HashMap allow-list
    guards).
  - Closes parent **#102** — Go (3.82.0), Bash (3.82.0), Rust (3.84.0) all
    have parallel safe-handler shape filters.
  See `packages/circle-ir/CHANGELOG.md` for the full implementation
  breakdown.

## [3.83.0] - 2026-06-19

### Changed

- Tracks circle-ir 3.83.0 — Sprint 30 bundle closing **#124** (Java
  sink-type mis-categorization on `Pattern.compile` / `Process.waitFor` /
  `ProcessBuilder.inheritIO` / `redirectOutput` / `redirectInput`). Five
  spurious `JAVA_SINK_RULES` entries removed; the real command-exec sinks
  (`Runtime.exec`, `ProcessBuilder.start`, `ProcessBuilder.command(List)`,
  `new ProcessBuilder(cmd)`) continue to fire on tainted args. See
  `packages/circle-ir/CHANGELOG.md` for the full rule-removal breakdown.

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
