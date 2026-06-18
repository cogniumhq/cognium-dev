# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.70.0] - 2026-06-18

### Added — Sprint 20: `cache-no-vary` pass (#96 L91)

Sprint 20 ships pass #98 detecting cross-language CWE-524 (Use of Cache
Containing Sensitive Information) shared-cache leaks. A handler that sets
`Cache-Control: public` (or `max-age>0`/`s-maxage>0`) on a response while
also reading authenticated / user-scoped state, but does not set a
covering `Vary: Cookie`/`Vary: Authorization`/`Vary: *`, can be served
from a shared cache (CDN, reverse proxy, browser disk cache shared between
profiles) to a different user.

`rule_id: cache-no-vary`, `cwe: CWE-524`, severity `medium`, level
`warning`. Category `security`. Per-file pass; runs after
`module-side-effect` in the optional-pass block.

**Strict auth-qualifier mode.** The pass fires only when **all three**
signals appear in the same handler (`in_method` group, +5 line widening
for decorators/annotations):

1. cache-public signal (call or source-text)
2. auth signal (cookies, `Authorization`, session, `@CookieValue`,
   `@RequestHeader("Authorization")`, `Principal`, `Authentication`,
   `SecurityContextHolder`)
3. **no** covering `Vary` signal

This eliminates the static-asset / `/health` / `/version` FP class.

**Languages covered:**

- **JS/TS** (Express/Fastify/Koa) — `res.setHeader('Cache-Control', V)`,
  `res.set(...)`, `res.header(...)`; covered by `res.vary('Cookie')` or
  `res.setHeader('Vary', ...)`. Auth signals: `req.cookies.*`,
  `req.headers.cookie`, `req.headers.authorization`, `req.session.*`,
  `req.user`, `res.cookie(...)` (Set-Cookie write).
- **Python** (Flask/FastAPI/Django) — `response.headers['Cache-Control'] = V`
  subscript assign (source-text), `@cache_control(public=True, max_age=N)`
  decorator, `patch_cache_control(...)`, `response.cache_control.public = True`;
  covered by `@vary_on_cookie`, `@vary_on_headers(...)`,
  `response.headers['Vary'] = V` (source-text), `patch_vary_headers(...)`.
  Auth signals: `request.cookies.*`, `request.headers['Authorization']`,
  `request.authorization`, `session[...]`, `g.user`, `current_user`,
  `set_cookie(...)`.
- **Go** (net/http, gin) — `w.Header().Set("Cache-Control", V)` /
  `.Add(...)`, `c.Header("Cache-Control", V)`; covered by
  `w.Header().Set("Vary", V)` etc. Auth signals: `r.Cookie(...)`,
  `r.Header.Get("Cookie"|"Authorization")`, `r.BasicAuth()`,
  `http.SetCookie(w, ...)`, gin `c.GetHeader/Cookie/SetCookie`.
- **Java** (Spring, Servlet) — `response.setHeader("Cache-Control", V)` /
  `addHeader(...)`, `headers.setCacheControl(...)`,
  `headers.add("Cache-Control", V)`, `CacheControl.maxAge(...).cachePublic()`;
  covered by `response.setHeader("Vary", V)` / `addHeader("Vary", V)`,
  `headers.setVary(...)`, `headers.add("Vary", V)`. Auth signals:
  `@CookieValue`, `@RequestHeader("Authorization")`,
  `request.getCookies()`, `request.getHeader("Cookie"|"Authorization")`,
  `response.addCookie(...)`, `SecurityContextHolder`, `Principal` /
  `Authentication` params.

**Allowlist guardrails:**

- `Cache-Control` values containing `private`, `no-store`, or `no-cache`
  are skipped — explicitly non-shared-cacheable.
- `max-age=0` (without `public`) is skipped — effectively non-cacheable.
- Test/spec files (`**/test/**`, `**/__tests__/**`, `**/*.test.*`,
  `**/*.spec.*`) are skipped.
- `Vary: *` is treated as covering everything.

**Issue closure:** #96 L91 — Python cache-header CWE-524 sub-finding
shipped (extended cross-language). Other #96 Python residuals
(`urlretrieve` + `subprocess` chains, git traversal) remain open as
separate sprint material.

12 new regression fixtures (`tests/analysis/repro-sprint20.test.ts`),
3 per language (1 positive + 2 negatives covering vary-set and no-auth
static-asset shapes). Total test count: 2467 pass / 1 skip.

## [3.69.0] - 2026-06-18

### Added — Sprint 19: `module-side-effect` pass (#93, #96 L47, #98)

Sprint 19 ships a new analysis pass (#97 in PASSES.md) detecting dangerous
side effects executed at module load / install / build time, where no
taint flow is involved — the canonical delivery vector for supply-chain
droppers (shai-hulud-style TruffleHog harvesters, malicious typosquats,
`build.rs` exfil).

`rule_id: module-side-effect`, `cwe: CWE-829`, severity `high`, level
`error`. Category `security`. Per-file pass; runs after
`tls-verify-disabled` in the optional-pass block.

#### Detection layers per language

- **JavaScript / TypeScript** — module-level (`in_method === null`) call
  to `child_process.{exec,spawn,execSync,spawnSync}`, `https.request`,
  `http.request`, `http.get`, `https.get`, or `fetch` when an arg
  expression references `process.env`/`os.homedir`/`/etc/passwd`/SSH
  private keys.
- **`package.json` source-text scan** — `scripts.(pre|post)?install`
  invoking `curl`/`wget`/`nc`/`node -e`/`sh -c`/`bash -c`/`eval`/`base64
  -d`. Benign install scripts (`node-gyp rebuild`, `prebuild-install`,
  `husky install`, `patch-package`, `npm run build`) are allowlisted.
- **Python** — module-level (`in_method === null`) call to
  `requests.{post,put}`, `urllib.request.urlopen`,
  `socket.{connect,create_connection}`, `subprocess.{run,Popen}`, or
  `os.system` whose arg expressions reference `os.environ`,
  `pwd.getpw*`, `~/.ssh/id_*`, `/etc/passwd`, `Path.home`, or
  `glob.glob` of secret paths.
- **Go** — call inside `func init()` (`in_method === 'init'`) where the
  callee is `exec.Command`, `http.{Post,Get}`, `net.LookupTXT`, or
  `os.Setenv`.
- **Rust** — file gated to `build.rs` (`meta.file` endsWith
  `build.rs`); fires on `Command::new` / `std::process::Command::new`
  and `reqwest::*` calls. `println!("cargo:...")` directives emit no IR
  call so the legitimate build-script API is unaffected.

#### Tests

- New file: `tests/analysis/repro-sprint19.test.ts` with 8 locking
  fixtures (5 positive + 3 negative-control), one per delivery shape.
- Full suite: **2455 pass** (2447 baseline + 8 new), 1 skipped, zero
  regressions across 139 test files.

#### Out of scope (deferred)

- **Caret-trap manifest/lockfile drift** (#93 FN-SC-06/07) — requires
  project-graph access; separate sprint.
- **#96 L91 — `Cache-Control` without `Vary`** (CWE-524) — separate
  cache-timing pass.
- **Cross-file taint into module-side-effect** — current pass is
  single-file; supply-chain analysis across the dep tree is out of
  scope.

#### Files changed

- `src/analysis/passes/module-side-effect-pass.ts` — NEW.
- `src/analyzer.ts` — register pass; import added.
- `tests/analysis/repro-sprint19.test.ts` — NEW.
- `docs/PASSES.md` — pass #97 row.

## [3.68.0] - 2026-06-18

### Added — Sprint 18: Python consolidation (#100, #96, #65)

Sprint 18 ships one f-string taint bug fix, two new Python sinks for
`urllib.request.urlretrieve`, and a 12-fixture regression test file
locking the Python FP/FN inventory tracked in #100, #96, and #65.

#### #100 — Python safe-corpus FP suppression (regression locks)

The Python FP inventory in `fp_corpus.py` and `sanitizer_combos.py`
is already correctly suppressed by existing engine machinery
(parameterized-query detection, type-cast barriers in
`SANITIZER_METHODS`, sanitizer-wrapper recognition via the
interprocedural pass). Sprint 18 adds explicit regression fixtures so
the suppression cannot silently regress:

- `#100.1` — `cursor.execute("... %s", (uid,))` → zero `sql_injection`.
- `#100.2` — `int(request.args.get(...))` → zero `xss`.
- `#100.3` — `os.path.realpath(...).startswith(SAFE)` guard →
  zero `path_traversal`.
- `#100.4` — sqlite3 `?` placeholder + tuple → zero `sql_injection`.
- `#100.5` — `def my_clean(x): return shlex.quote(x); subprocess.run(
  'echo ' + my_clean(taint), shell=True)` → zero `command_injection`
  (interproc wrapper detection of `shlex.quote`).
- `#100.6` / `#100.7` — wrong-context sanitizer (`html.escape` used as
  a SQL value) and fake identity-function sanitizer remain detected
  (negative locks for true positives).

#### #96 — `urllib.request.urlretrieve` ssrf + path_traversal sinks

`getBuiltinSinks()` in `src/languages/plugins/python.ts` adds two new
entries for `urllib.request.urlretrieve(url, dest)`:

- `{ method: 'urlretrieve', class: 'urllib.request', type: 'ssrf',
   cwe: 'CWE-918', argPositions: [0] }` — tainted URL.
- `{ method: 'urlretrieve', class: 'urllib.request', type:
   'path_traversal', cwe: 'CWE-22', argPositions: [1] }` — tainted
   destination filename.

Deferred to Sprint 19: `#96` L47 (import-time credential harvest —
requires a new module-side-effects pass) and L91 (`Cache-Control`
without `Vary` — requires a new cache-timing-attack pass).

`#96.2` (git `format-patch` filename via subject) is also deferred to
Sprint 19: the deliberate `isSafePythonSubprocessCall` safe-shape skip
(cognium-dev #48) correctly suppresses list-form `subprocess.run`
without `shell=True` because Python invokes `execve()` directly with
no shell interpolation. The real vulnerability is `path_traversal` via
git's patch-file naming side effect, which requires modeling subprocess
side-effects.

#### #65 — Python f-string interpolation now propagates taint to sinks

**Bug fix.** `extractPythonLiteral` in `src/core/extractors/calls.ts`
previously stripped the `f` prefix from f-strings and returned the raw
text (with `{var}` braces preserved) as the argument literal. This
made the taint matcher treat f-strings as compile-time literals,
missing sinks like
`cur.execute(f"SELECT * FROM users WHERE id = {uid}")`.

Fix: f-strings with `interpolation` child nodes (tree-sitter-python
production) now return `literal=null`, so the matcher sees the
argument as a non-literal expression and runs taint propagation on
the interpolated variables. Plain f-strings without interpolations
(`f"hello"`) still return a literal value.

`#65.1` parameterized psycopg2 calls (`cur.execute("... %s", (uid,))`)
remain correctly suppressed via the existing parameterized-query
path. `#65.2-neg` f-string interpolation now fires `sql_injection`
as expected.

#### Tests

- `tests/analysis/repro-sprint18.test.ts` — 12 new fixtures covering
  the four #100 FP families, two negative locks, three #96 conventional
  cases, and two #65 controls.
- Full vitest suite: **2447 passed | 1 skipped** across 138 files
  (was 2435 in 3.67.0; +12 Sprint 18 fixtures).

## [3.67.0] - 2026-06-18

### Added — Sprint 17: JS/TS/JSX consolidation (#88.2, #94, #95, #97, #99, #68)

Sprint 17 ships four FN fixes, one FP cleanup, and one verification lock
in a single release.

#### #94 — protobufjs.parse code_injection sink (CVE-2026-41242)

`protobufjs` (and its `Root` class) compile a textual schema into JS at
runtime via `parse(schemaText)`. A tainted schema therefore executes
arbitrary code. `DEFAULT_SINKS` in `src/analysis/config-loader.ts` now
registers three sink entries (`protobuf.parse`, `protobufjs.parse`,
`Root.parse`) typed as `code_injection`/CWE-94/critical with
`arg_positions: [0]` and `languages: ['javascript', 'typescript']`.

Documentation mirror added to `configs/sinks/nodejs.json` for parity with
the static catalog.

#### #88.2 — `.tsx` JSX-attribute sink detection

`.tsx` files routed to the `tsx` parse grammar (analyzer.ts:386-398)
produced no `xss` flows for `dangerouslySetInnerHTML={{__html: taint}}`
attribute calls. Root cause was in `DefaultLanguageRegistry.get()`
(`src/languages/registry.ts`): `get('tsx')` correctly fell back to the
`javascript` plugin, but `get('typescript')` returned `undefined` because
no plugin is registered under that id. Sink-matching for `.tsx` files
(which analyzer keeps at `language='typescript'`) therefore had no plugin
context.

Fix: added a `typescript` → `javascript` fallback inside
`DefaultLanguageRegistry.get()`. The synthetic JSX-attribute call emitted
by `synthesiseJsxAttributeCall` in `src/core/extractors/calls.ts:259-350`
now reaches the XSS sink in both `.jsx` and `.tsx` files.

#### #95 — `allow_unresolved_receiver` flag for runtime-decorated receivers

Express middleware patterns like `app.use((req, _, next) => { req.db = pool; next(); })`
followed by `req.db.query(taint)` previously missed the SQL sink because
`call.receiver_type` is unresolved (the decoration is runtime-only). The
existing `receiverMightBeClass` heuristic extracts the last segment
(`db`) which never matches `Connection`/`Pool`/`Client`.

New per-sink opt-in flag `allow_unresolved_receiver: boolean` added to
the `SinkPattern` interface (`src/types/config.ts`). When set, the
matcher (`matchesSinkPattern` in `src/analysis/taint-matcher.ts:926-944`)
accepts the sink iff:
1. `pattern.allow_unresolved_receiver === true`
2. `call.receiver_type` is empty
3. `call.receiver_type_fqn` is empty
4. `call.receiver` contains a dotted property chain

Applied to SQL sinks in `DEFAULT_SINKS`: `Connection.query`,
`Pool.query`, `Client.query`, plus newly-added `Pool.execute` and
`Connection.execute`. The flag is opt-in per entry to keep the FP
surface narrow.

#### #97 — TS partial-parse robustness lock

Issue #97 reported that a TS file with ambient `declare const TAINT`,
`process.env.npm_package_dependencies_*` access at L37, and
`execSync(\`git diff \${branch}\`)` at L18 dropped all analysis. Direct
investigation found the TS grammar handles these patterns without
ERROR-node fallout (`parse_errors === 0`), and the existing extractor
already reaches the L18 sink. The remaining gap was source extraction
for ambient `declare const` (deferred — out of acceptance scope).

Lock test in `tests/analysis/repro-sprint17.test.ts` (#97 fixture)
uses `process.argv[2]` as the source so the canonical
`command_injection` flow at the `execSync` call site is now regression-locked.

#### #99 — Safe-corpus FP cleanup (xss / open_redirect / crlf)

`src/analysis/passes/sink-filter-pass.ts` gained a Stage 8 filter for
JS/TS `open_redirect` and `crlf` sinks. It runs only when
`language ∈ {javascript, typescript}` and drops a sink finding if any of:
1. **Conditional-allowlist guard** — an `if (...)` clause within the
   preceding 7 lines uses one of `includes`/`startsWith`/`endsWith`/
   `indexOf`/`test`/`match` (recognises
   `if (allowed.includes(url)) res.redirect(url)`).
2. **`encodeURIComponent` / `encodeURI` sanitizer** present on the
   sink line.
3. **`setHeader` literal value** (`res.setHeader('CORS', '*')` etc.).

Stage 7 XSS sanitizer-guard (existing) already covers DOMPurify-style
patterns for `xss` sinks.

#### #68 — mass_assignment / CWE-1321 verification lock

`Object.assign({}, req.body)` and `_.merge({}, req.body)` already emit
`mass_assignment`/CWE-1321 findings via the entries in `config-loader.ts:1922-1943`.
Lock test (#68 fixture) asserts this behaviour to prevent regression.

### Testing

- New: `tests/analysis/repro-sprint17.test.ts` (12 fixtures, 10 plan +
  2 #68 lock variants — all passing).
- Full suite: 137 test files, 2435 passed + 1 skipped. No regressions.
- `npm run typecheck` clean.

## [3.66.0] - 2026-06-18

### Added — Sprint 16: OOP field-sensitivity r2 (#78) + Java cross-file taint (#74)

Sprint 16 ships three workstreams in a single release:

#### D — OOP field-sensitivity round 2 (#78)

Round 1 (v3.39.0+) shipped constructor-injected field flow with direct
field read and getter-chain detection. Round 2 adds three new Java
patterns covered by `tests/analysis/repro-sprint16.test.ts`:

1. **Static field stores (intra-class)** — `findStaticFieldSources` in
   `src/analysis/passes/language-sources-pass.ts` walks static-method
   bodies for `<ClassName>.<staticField> = <rhs>` and `<staticField> = <rhs>`
   assignments. When the RHS matches a known HTTP source pattern, it
   emits synthetic taint sources with `variable: '<field>'` and
   `variable: '<ClassName>.<field>'` so downstream sinks in sibling
   static methods (e.g. `Runtime.exec(dbHost)`) get attributed correctly.
   Gates on `FieldInfo.modifiers` containing `static`. Confidence 0.85.

2. **Non-bean setter/getter pairs** — `findSetterChainSources` in the
   same file builds a `Map<field, {setters, getters}>` by parsing
   single-statement method bodies (joined-line + `{...}` extraction so
   one-line Java methods like `void setX(String x){this.x=x;}` parse
   correctly). When a setter call site receives a tainted argument, a
   subsequent getter call (`u.getCred()`) in a sink expression emits a
   synthetic source on the getter call site with `variable: getter.name`.
   Confidence 0.75 (matches round-1 getter path).

3. **Cross-instance aliasing via constructor-stored receiver** — new
   `findCrossInstanceAliasingPaths` helper in
   `src/analysis/passes/cross-file-pass.ts` walks each Java class for
   `this.<aliasField>.<innerField> = <rhs>` assignments. Strictly gates
   on (a) `aliasField` being a declared field whose type FQN resolves
   inside the project's IRs, (b) `innerField` being a declared field on
   the aliased type, (c) RHS matching a known HTTP source. Then scans
   the aliased class's methods for sinks whose call args reference
   `innerField` and emits a full `InterproceduralTaintPath`
   (source → field_write → field_read → sink). Confidence 0.65.

#### E — Cross-file Java taint (#74 follow-up)

The Java extractor already populates `call.receiver_type_fqn` for
invocations whose receiver type resolves via imports/locals/fields
(`extractors/calls.ts`), and the SymbolTable already indexes Java
methods under their FQN. The missing link was in `CrossFileResolver`:

1. **FQN preflight** — `resolveWithReceiver` in
   `src/resolution/cross-file.ts` now consults `call.receiver_type_fqn`
   first, before falling back to context-derived `inferReceiverType`.
   This unlocks the SymbolTable's FQN index for Java multi-file
   resolution (direct instance, static import, @Autowired).

2. **Interface dispatch** — when the resolved method's parent type is
   an `interface` (looked up via `symbolTable.getSymbol(parentType)`),
   `resolveWithReceiver` now prefers polymorphic candidates from
   `findPolymorphicCandidates(receiverType, methodName)` over the
   interface symbol itself. This routes `userRepo.load(taint)` to the
   `UserRepoJdbc.load` implementor's SQL sink across files.

#### B — FreeMarker SSTI (#52)

No code changes — the `Configuration.getTemplate(filename)` pattern
already fires `code_injection` via existing sink coverage. Added the
fixture to `repro-sprint16.test.ts` to lock the behaviour.

### Tests

- New `tests/analysis/repro-sprint16.test.ts`:
  - B.1 — FreeMarker `Configuration.getTemplate(taint)` → `code_injection`
  - D.1 — static field intra-class (`Config.dbHost`) → `command_injection`
  - D.2 — non-bean setter/getter (`u.setCred`/`u.getCred`) → `sql_injection`
  - D.3 — cross-instance aliasing (`Service` → `Repo`) → `sql_injection`
  - E.1 — direct instance (`Controller` → `DbHelper`) → cross-file SQLi
  - E.2 — `import static` (`runUserQuery`) → cross-file SQLi
  - E.3 — Spring `@Autowired` (`@Autowired DbHelper helper`) → cross-file SQLi
  - E.4 — interface dispatch (`UserRepo` → `UserRepoJdbc`) → cross-file SQLi
  - N.1 — same-file negative control for E.1 (locks single-file path)
- Full suite: 2423 passed, 1 skipped, 0 failed (136 test files).

## [3.65.0] - 2026-06-17

### Fixed — Duplicate taint flow emission (#49 dedup gap)

Sprint 15 closes the duplicate-emission sub-gap of cognium-dev #49:
unsanitized Java fixtures were emitting the same `(source_line, sink_line,
sink_type)` triple two or three times when multiple internal detectors
(the DFG-based propagator + the four supplementary detectors) all reached
the same sink call from different tainted-variable chains.

The merge-time dedup at the supplement seams in `TaintPropagationPass.run()`
keys on `(source_line, sink_line)` only — not `sink_type` — and the DFG
result itself was not deduped at all. As a result an unsanitized
`builder.parse(new ByteArrayInputStream(body.getBytes()))` would emit
`xxe ×2` from the same `(source_line=19, sink_line=22, sink_type='xxe')`
key.

A final dedup pass now runs at the end of `TaintPropagationPass.run()`,
keyed on `(source_line, sink_line, sink_type)`. The highest-confidence
flow per key is retained; ties keep the first occurrence. This does not
affect the per-method Java FP suppression added in 3.64.0 (the dedup runs
after the method-level filter).

### Tests

- New `tests/analysis/repro-sprint15.test.ts` (3 cases) locks the dedup
  behaviour on an unsanitized Java fixture, while asserting that real
  `xxe` and `path_traversal` flows still fire.
- Full suite: 2414 passed, 1 skipped, 0 failed.

## [3.64.0] - 2026-06-17

### Fixed — Java FP corpus regression (cognium-dev #101)

Sprint 14 closes the four false-positives flagged by the upstream Java FP
corpus (`coggiyadmin/java-vuln-demo`) without regressing any of the 2411
existing tests:

1. **FP-01 path_traversal (`SafeService.java`)** — `new File(base, filename)`
   inside a method that follows the canonical-path-startsWith-throw idiom no
   longer fires. A new `isInJavaSanitizedMethod()` helper in
   `src/analysis/passes/taint-propagation-pass.ts` walks the enclosing method
   body and recognises:
   - `.getCanonicalPath()` call
   - `.startsWith(<base>.getCanonicalPath(...)` guard
   - `throw new <Exception>` on the failure branch
2. **FP-02 xxe (`SafeService.java`)** — `DocumentBuilderFactory` /
   `SAXParserFactory` configurations that call
   `setFeature("...disallow-doctype-decl"|"external-general-entities"|
   "external-parameter-entities"|"load-external-dtd", …)` or
   `setProperty(SUPPORT_DTD, false)` are now treated as method-level
   sanitizers and suppress XXE flows inside the same method scope.
3. **FP-03 command_injection (`FalsePositiveCorpus.java`)** — the
   switch→constant pattern (`String cmd; switch(type){ case "x": cmd =
   "/bin/x"; ...} exec(cmd);`) no longer fires. Three coordinated fixes:
   - `taint-propagation.ts` `findInitialTaint()` next-line def-seeding
     heuristic now requires `def.variable === source.variable` when both
     are present, preventing an unrelated declaration on `source.line + 1`
     from inheriting the source's taint.
   - `detectCollectionFlows` in `taint-propagation-pass.ts` adds a
     cross-method bleed gate: when the picked source's binding variable
     differs from the sink arg variable AND lives in a different method
     scope, the match is discarded as a `constProp.tainted` cross-method
     bleed (e.g. `cmd` tainted in `debugExec` reused as a key in
     `runReport`). Same-method cross-variable matches (e.g. `id` loop var
     derived from `input` source) are preserved.
   - `isReassignedToLiteralBetween()` learns a third pattern for
     `case "x": var = "literal"; break;` and `default: var = "literal"; break;`
     forms to recognise the switch-case literal reassignment as a
     sanitizer.
4. **FP-04 sql_injection (`FalsePositiveCorpus.java`)** — the
   `if (!ALLOWLIST.contains(col)) col = "name";` pattern was already
   suppressed by the existing single-line `if` guard branch of
   `isReassignedToLiteralBetween`. Now locked behind a Sprint 14
   regression test in `tests/analysis/repro-sprint14.test.ts`.

### Added — Method-scope plumbing for taint sources

All seven source-emission sites in `src/analysis/taint-matcher.ts` now stamp
`TaintSource.in_method` (new field on the `TaintSource` interface) with the
enclosing method name:

- YAML call-pattern sources
- Annotated parameters
- Method-level annotations
- Rust web framework extractors
- Interprocedural parameter sources
- JS Express regex sweep
- Python regex sweep

`detectExpressionScanFlows` gates on this field to refuse cross-method
variable-name collisions (e.g. two methods both with a `cmd` variable but
only one is tainted). This complements the cross-method bleed gate in
`detectCollectionFlows`.

### Tests

- New `tests/analysis/repro-sprint14.test.ts` (4 cases) locks the four
  FP categories from cognium-dev #101.
- Full suite: 2411 passed, 1 skipped, 0 failed (was 2402 + 1 skipped in
  3.63.0).

## [3.63.0] - 2026-06-17

### Fixed — Source-line attribution in supplementary flow detectors (#70)

`detectCollectionFlows` and `detectArrayElementFlows` in
`src/analysis/passes/taint-propagation-pass.ts` historically anchored every
flow to `sources[0]` — the file's first source — once they decided a sink
was tainted. In multi-method files this misattributed every collection /
array-element flow to the *first* method's source line (e.g. line 8's
`getHeader` showed up as the source for cookie/db flows in methods 2 and 3).

Both detectors now receive `types: CircleIR['types']` and call a shared
`pickScopedSource(sources, sinkLine, methodName, types, taintedVar)` helper
that mirrors the matching strategy used by the already-correct
`detectParameterSinkFlows` / `detectExpressionScanFlows`:

1. **Variable match** — prefer any source whose `variable` equals the
   tainted variable name (closest strict-preceding wins).
2. **Scope match** — restrict to sources whose `line` falls inside the
   sink's enclosing method (via `types[].methods[].start_line/end_line`).
3. **Global closest-preceding** — fallback when neither variable nor scope
   produces a candidate.
4. **Last resort** — `sources[0]` (preserves pre-fix behaviour when no
   source precedes the sink).

`closestPreceding` uses **strict** preceding (`s.line < sinkLine`) so
synthetic same-line sources stamped on the sink itself (e.g. the
`plugin_param` source emitted for `m.get("k")` on the same line as
`Runtime.getRuntime().exec(m.get("k"))`) do not shadow the real upstream
`req.getParameter` source on the line above.

### Locked — Cross-file Python taint already works (#74)

Investigation confirmed `analyzeProject()` already produces the expected
cross-file `TaintPath` entries for the issue #74 scenarios (source in
`controller.py` → sink in `db_helper.py` / `shell_helper.py`). The
end-to-end pipeline (`CrossFilePass` → `CrossFileResolver` → Python
`<module>` synthetic-type wrapping → `findCrossFileTaintFlows`) is wired
correctly. The capability is now locked in with positive regression
fixtures rather than re-engineered.

### Added

- `tests/analysis/repro-sprint13.test.ts` — five fixtures:
  three single-file Java cases for #70 (three-method source distinction,
  two-method header-source repeat, `Map.put`/`Map.get` collection flow)
  and two multi-file Python cases for #74 (cross-file SQL injection,
  cross-file command injection).

### Notes

- Public API unchanged; no `SastFinding` schema change.
- 2407 vitest tests passing (5 new + 2402 baseline), 1 skipped — no
  regressions.

## [3.62.0] - 2026-06-17

### Fixed — cognium-dev Python batch (issues #66, #59)

This release closes the Python sprint covering nine sub-claims from the
FN/FP sweep. Four stale-close claims are locked in with regression
fixtures; five real fixes touch the sink/source catalog, the
class-qualified pattern matcher, and the Python alias-map / taint flow
regex paths for non-ASCII identifiers.

**Phase A — Regression guards for stale-close claims (#66.1b / #66.3b /
#66.4b / #59.2).**
- `tarfile.open(tainted).extractall('/x')` → `path_traversal` flow.
- `pickle.loads(request.data)` → `deserialization` flow.
- `import urllib.request; urllib.request.urlopen(tainted)` → `ssrf` flow.
- Single-line compound `def d(): q=request.args.get(...);os.system('echo '+q)`
  → `command_injection` flow.
- New: `tests/analysis/repro-python-batch.test.ts`.

**Phase B — Python `extractall` (lowercase) + `ZipFile` constructor
sinks (#66.1a).** `DEFAULT_SINKS` in
`src/analysis/config-loader.ts` shipped only `extractAll` (camelCase) for
JS/Java/Go. Python tree-sitter emits the lowercase identifier
`extractall`; the matcher is case-sensitive, so
`zipfile.ZipFile(tainted).extractall(...)` did not fire. A
Python-scoped `extractall` sink (`type: path_traversal`, `cwe: CWE-22`,
`arg_positions: [0]`) is added. A Python-scoped `ZipFile` constructor
sink is also added because `zf.extractall('/constant')` carries the
taint on the receiver — matching the constructor mirrors how
`tarfile.open` already matches the generic Python `open` sink.

**Phase C — Flask `send_from_directory` sink (#66.2).**
`DEFAULT_SINKS` now includes
`{ method: 'send_from_directory', type: 'path_traversal', cwe: 'CWE-22',
  severity: 'high', arg_positions: [1], languages: ['python'] }`.
Untrusted `filename` arguments can escape the base directory via `../`.

**Phase D — Flask method/property sources (#66.3a).**
`DEFAULT_SOURCES` now includes `request.get_data` (method) and
`request.get_json` (method) as `http_body` sources with
`return_tainted: true`, plus `request.stream` as a property source with
`property_tainted: true`. Previously only the canonical
`request.data`/`request.json`/`request.form` properties were registered,
which missed `pickle.loads(request.get_data())`-style flows.

**Phase E — Bare-imported function class-qualified match (#66.4a).**
`matchesSourcePattern` and `matchesSinkPattern` in
`src/analysis/taint-matcher.ts` previously rejected calls with no
receiver when the pattern had a `class:` constraint, even when Python
import resolution had already populated `call.resolution.target` with
the fully qualified name. Both matchers now accept a bare call when
`call.resolution.target === \`${pattern.class}.${pattern.method}\`` or
ends with `.${pattern.class}.${pattern.method}`, recovering flows like
`from urllib.request import urlopen; urlopen(tainted)` → `ssrf` while
leaving locally defined functions of the same name (no import
resolution) untouched.

**Phase F — Non-ASCII identifier propagation (#59.1).**
`buildPythonTaintedVars` in
`src/analysis/passes/language-sources-pass.ts` used ASCII-only `\w+`
and `\b...\b` patterns to extract assignment LHS/RHS variables and check
for taint propagation. JavaScript regex `\w` is `[A-Za-z0-9_]`, so an
identifier like `café` never matched `(\w+)\s*=` and was dropped from
the alias map. The standard taint-flow regex in
`src/analysis/passes/taint-propagation-pass.ts` had the same problem at
the `reCache` construction. All identifier patterns now use
`[\p{L}\p{N}_]+` for the match and
`(?<![\p{L}\p{N}_])${v}(?![\p{L}\p{N}_])` for the boundary check, both
with the `u` flag. The non-ASCII `café` repro now produces the expected
`command_injection` flow.

### Tests

- 2402 vitest cases passing (1 skipped) — up from 2391.

## [3.61.0] - 2026-06-17

### Fixed — cognium-dev Bash batch (issues #72, #73)

This release closes the Bash sprint covering six sub-claims from the FN/FP
sweep. Two stale-close claims are locked in with regression fixtures. The
four real fixes touch the sink dedup model, the DFG positional-parameter
seeding, the BashPlugin sink catalog, the interprocedural escape sink
classification, and the language-sources pass.

**#72.5 / #73.1 — Regression guards for stale-close claims.**
- Cross-line `eval "echo $REQUEST_URI"` continues to fire as
  `code_injection`.
- Function-local `$1` inside a `format_name()` definition continues to be
  suppressed (does not leak as a top-level positional-param source).
- New: `tests/analysis/repro-bash-batch.test.ts` Phase A.

**#72.1, #72.2 — Bash sink `argPositions` collision repaired (Phase B).**
`DEFAULT_SINKS` in `src/analysis/config-loader.ts` shipped `bash`, `sh`,
`shell`, `spawn`, `fork`, `popen`, `system` entries with `arg_positions:
[0]` and NO `languages:` filter. The Bash plugin's `getBuiltinSinks()`
provides per-flag entries with `argPositions: [1]` (the `-c` flag), but the
matcher's first-match-wins dedup key
(`${location}:${line}:${cwe}`) meant the DEFAULT_SINKS entry won. Fix adds
a `languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust']`
filter to those seven entries so they no longer shadow the bash plugin's
correct positions when analyzing bash files. The taint-matcher already
honors `pattern.languages`.

**#72.1, #72.2 — Positional-param source seeding fixed (Phase C).**
`buildBashDFG` synthesizes def entries for `$1..$9, $@, $*` at `line: 0`,
but `findInitialTaint` in `taint-propagation.ts` only consulted
`defsByLine.get(source.line)` — so the seed taint for a source emitted at
the use-line never connected to the synthetic line-0 def. Same bug in
`interprocedural.ts`'s `seedIds` construction. Both now also walk
`defsByLine.get(0)` and seed param-kind defs whose `variable` matches
`source.variable`. The new seeding path is guarded by `def.kind === 'param'`
to keep other languages unaffected.

**#72.6 — `source` / `.` file-inclusion sinks added (Phase D).**
`BashPlugin.getBuiltinSinks()` now emits `source` and `.` as
`path_traversal` sinks with `cwe: 'CWE-98'`, `severity: 'critical'`,
`argPositions: [0]`. Both are RCE primitives equivalent to `eval()` on the
file contents when the path is attacker-controlled. As a supporting fix,
`buildBashDFG` (`src/core/extractors/dfg.ts`) now lazily synthesizes
`param`-kind defs at `line: 0` for any `simple_expansion` /
`expansion` reference (`$VAR` / `${VAR}`) that has no reaching def and is
not a positional parameter. This unifies env-vars with positional params so
Phase C's variable-name seeding handles both uniformly.

**#72.3, #72.4 — Bash external escape re-classified (Phase E).**
`interprocedural.ts` previously emitted a generic
`external_taint_escape` (CWE-668, medium, 0.7) when tainted args flowed
into an unknown external call. For bash, virtually every shell utility
(`ping`, `whois`, `curl`, `nc`, …) is "unknown" and the user-facing
severity was wrong: an unquoted positional like `ping -c 3 $host` is
concretely `command_injection` via word-splitting. When the analyzed
language is `bash`, we now emit `command_injection` (CWE-78, high, 0.6)
instead, except for a small allowlist of side-effect-free builtins
(`echo`, `printf`, `test`, `[`, `[[`, `true`, `false`, `:`, `declare`,
`local`, `export`, `readonly`, `typeset`) which are skipped.

**#73.2 — Bash regex-allowlist sanitizer (Phase F).**
The idiomatic guard
```bash
if [[ ! "$var" =~ ^[a-zA-Z0-9_]+$ ]]; then exit 1; fi
```
was previously ignored, producing false positive `command_injection` /
`path_traversal` findings on subsequent `$var` uses. A new detector in
`language-sources-pass.ts` (`findBashRegexAllowlistSanitizers`) recognizes
the `if [[ ! "$var" =~ <regex> ]]; then exit|return|die` pattern when the
regex is a safe anchored character-class allowlist (no `.*`/`.+`, no
alternation, no backrefs) and emits `TaintSanitizer { type:
'regex_allowlist', method: '=~' }` entries covering downstream sink lines.
`SinkFilterPass` merges these into the sanitizer set alongside the
`TaintMatcherPass` output. Negative control: `.+` and other unsafe regex
bodies do NOT emit a sanitizer.

**Test coverage:** new `tests/analysis/repro-bash-batch.test.ts` (12
cases). Full suite: 2392 tests passing.

---

## [3.60.0] - 2026-06-17

### Fixed — cognium-dev JS/TS batch (issues #88, #80, #69, #68)

This release closes the JS/TS sprint covering five distinct problem areas. The
ground-truth investigation against 3.59.0 revealed three claims that were
already stale (Sprint 6–9 widening had already addressed them); those are
locked in with regression fixtures so they cannot silently regress. The four
real fixes touch the HTML pre-processor, the JSX parser grammar, the JS call
extractor, and the runtime sink catalog.

**#88.1 / #69 — Regression guards for stale-close claims.**
- `.jsx` file recognition: `eval(location.hash)` in a `.jsx` source fires
  `code_injection`. Original failure on the reporter's site was masked by their
  `cognium.config.json include: src/**/*.ts` glob, not a circle-ir bug.
- `exec(req.query.host)`, `exec(req.body.cmd)`, and the local-var copy variant
  all fire `command_injection`. Negative control `exec("ls")` does not fire.
- New: `tests/analysis/repro-jsts-batch.test.ts` Phase A.

**#80 — HTML `<script>` taint flows propagated through merge.**
`mergeHtmlResults()` (`src/analysis/html/html-merge.ts`) was building the
merged `Taint` object as `{ sources, sinks, sanitizers }`, silently dropping
the per-block `taint.flows` array. Downstream consumers (CLI vulnerability
builder, SARIF) read `result.taint.flows` and saw `undefined`, so HTML pages
with `<script>document.write(...)</script>` or `<script>eval(location.hash)</script>`
reported zero vulnerabilities. Fix accumulates each script block's flows,
shifts `source_line` / `sink_line` by the block's HTML offset, and includes
them in the merged result.

**#88.2 — `.tsx` / `.jsx` JSX grammar swap.**
`tree-sitter-typescript.wasm` does not parse JSX. Any code path located after
the first JSX fragment in a `.tsx` / `.jsx` source was silently dropped
because the parser inserted an ERROR node and the call extractor stopped
collecting calls. Fix adds `tree-sitter-tsx.wasm` to `wasm/`, extends the
language-plugin grammar selector to route `.tsx` / `.jsx` extensions to the
JSX-aware grammar, and adjusts the parser cache key. The TSX grammar is a
superset of the TS grammar; non-JSX `.ts` files are unaffected.

**#68.1 — `dangerouslySetInnerHTML` JSX XSS sink.**
React's `<div dangerouslySetInnerHTML={{__html: tainted}}/>` renders raw HTML
and is a first-class XSS sink. New `extractJSXAttributeSink()` helper in
`src/core/extractors/calls.ts` walks `jsx_attribute` nodes, locates the
`__html` field inside the object expression, and emits a synthetic `CallInfo`
so the existing method-call taint matcher catches it. The sink definition
itself already existed in the JavaScript plugin's `getBuiltinSinks()`.

**#68.2 — Prototype-pollution CWE re-tag.**
`_.merge({}, req.body)`, `Object.assign({}, req.body)`, `_.extend`,
`Object.defineProperty`, `lodash.merge`, `lodash.extend`, `_.defaultsDeep`,
and `jQuery.extend` are now stamped with `CWE-1321` (Improperly Controlled
Modification of Object Prototype Attributes) instead of the previous
`CWE-915` (Improperly Controlled Modification of Dynamically-Determined
Object Attributes). The `mass_assignment` `SinkType` union is preserved
intentionally — adding a new `prototype_pollution` type would cascade through
the CWE map, severity map, and every formatter consumer.

**#68.3 — `node-serialize.unserialize` deserialization RCE.**
Three new sink entries added to `DEFAULT_SINKS` in
`src/analysis/config-loader.ts`: class-bound `serialize.unserialize(...)`,
class-bound `node-serialize.unserialize(...)`, and the classless destructured
variant. All three are `deserialization` / `CWE-502` / `critical`.

**#68.4 — DOM-XSS via `innerHTML` / `outerHTML` property assignment.**
`javascript_dom_xss.yaml` declared these as `property` sinks but the runtime
taint matcher only handled method calls. Fix mirrors the JSX-attribute
approach: new `extractDomPropertyAssignmentSink()` walks `assignment_expression`
nodes, matches LHS member expressions whose property is `innerHTML` /
`outerHTML`, and emits a synthetic `CallInfo` so the standard sink-matching
path catches `el.innerHTML = location.hash.slice(1)` and friends.

**Coverage.** 18 new regression cases in
`tests/analysis/repro-jsts-batch.test.ts` (Phase A through Phase D.4). Full
suite: 2379 passed, 1 skipped.

## [3.59.0] - 2026-06-17

### Fixed — Issue #78: OOP constructor-injected field flow (Java + Python)

- **Java + Python** — A class whose constructor assigns a tainted value to
  a `this.<field>` / `self.<field>` slot now propagates that taint to
  sinks in OTHER methods of the same class. Two access patterns covered:
  - Direct field/attribute read: `st.executeQuery("... " + this.name)`,
    `os.system("... " + self.host)`.
  - Getter / `@property` indirection: `st.executeQuery("... " + getName())`,
    `os.system("... " + self.target)` where the accessor body is a single
    `return (this|self).<taintedField>`.
- **Implementation.** New helper `findOopFieldReadSources()` in
  `analysis/passes/language-sources-pass.ts` walks each class, locates its
  constructor (`name === class.name` for Java, `__init__` for Python),
  scans the constructor body for `(this|self).<field> = <expr>` where
  `<expr>` is either a constructor parameter or an HTTP source pattern
  (e.g. `req.getParameter`, `request.args.get`), and emits synthetic
  `TaintSource` entries bound to the field-access expression and to any
  single-return getter / property that returns it. The variable-name scan
  in `TaintPropagationPass` then connects these to sinks via the existing
  pipeline — no changes to downstream propagation logic.
- **Coverage** — Java 5a/5b + Python 5a/5b from issue #78 now report.
  Tests added at `tests/analysis/repro-issue-78.test.ts` (5 cases
  including a negative control).

## [3.58.0] - 2026-06-16

### Fixed — Sprint 9: FP-precision cluster (#48, #50, #51, #55, #56, #57, #58, #79, #85, #92)

- **Issue #92.4, #92.5 — Pure-literal sink suppression.**
  NodeTest00004 (`db.query("SELECT * FROM products WHERE active = 1", cb)`)
  and NodeTest00012 (`fs.readFile('./public/README.md', cb)`) regressed to
  FP after Sprint 6/7 sink widening. Extends `findSinks()` in
  `analysis/taint-matcher.ts` to early-skip SQL/path/command/code/xss
  sinks whose relevant argument is a pure string literal.

- **Issue #92.1, #92.2 — Rust safe-path / safe-xss sanitizers.**
  Adds `Path::file_name`, `Path::canonicalize`, `Path::components`,
  `html_escape::encode_text`, `encode_safe`, and
  `encode_double_quoted_attribute` to `configs/sinks/rust.json` so
  `pathtraver_safe_basename` and `xss_safe_escaped` fixtures no longer
  fire.

- **Issue #57 — Type-cast taint barriers.**
  A numeric/UUID/enum value cannot carry a string injection. Adds
  cross-language sanitizers with `removes: [sql_injection,
  command_injection, path_traversal, code_injection]`:
  Java `Integer.parseInt`/`Long.parseLong`/`UUID.fromString`/`Enum.valueOf`;
  Python `int`/`float`/`bool`/`uuid.UUID`/`decimal.Decimal`;
  JS/TS `Number`/`parseInt`/`parseFloat`/`BigInt`;
  Go `strconv.Atoi`/`ParseInt`/`ParseFloat`/`uuid.Parse`.

- **Issue #48.2, #51.1 — Path-canonicalization sanitizers.**
  Adds Python `os.path.realpath`/`abspath`/`normpath`/`pathlib.Path.resolve`
  and Go `filepath.Clean`/`Base`/`EvalSymlinks`/`path.Clean`/`path.Base`
  to the path-traversal sanitizer set.

- **Issue #56, #58.3 — Allowlist + reassign-to-literal guards.**
  `Propagator` (`analysis/constant-propagation/propagator.ts`) now
  recognises `if (!ALLOWLIST.contains(col)) col = "name";` set-membership
  reassignment, and naked reassignment of a tainted variable to a string
  literal — both drop the variable from `tainted` and re-seed it as a
  constant.

- **Issue #55 — Dead-code-by-const-guard suppression.**
  When `Propagator` folds an `if` / `if_expression` condition to known
  `false`, every line in the then-branch is added to `unreachableLines`;
  symmetric for `if (true) { … } else { dead }`. Sink-filter pass
  (`sink-filter-pass.ts:81`) drops sinks on those lines.

- **Issue #48.1 — Subprocess(list, shell=False) verified.**
  `isSafePythonSubprocessCall` already fires for the `safe_api.py`
  fixture. Locks the behaviour in a regression test.

- **Issue #48.3 — DBAPI XSS misclassification suppressed.**
  Parameterised `cursor.execute(...)` followed by `return jsonify(...)`
  no longer reports XSS — context-sensitive suppression added in
  `sink-filter-pass.ts`.

- **Issue #58.1, #58.2 — Java regex allowlist + switch-const.**
  `Propagator` recognises strict-anchored `Pattern.matcher(x).matches()`
  guards (e.g. `if (!SAFE_NAME.matcher(name).matches()) throw …;`) and
  switch-statements whose every branch assigns a literal — both add the
  affected variable to `sanitizedVars`. `TaintPropagationPass.run()` has
  a final unified filter that drops any flow whose source variable is in
  `sanitizedVars`, ensuring all flow-generator paths credit the guard.

- **Issue #50 — `missing-x-frame-options` precision verified.**
  Flask + `flask_talisman.Talisman()` and Spring `SecurityFilterChain`
  already suppress `missing-x-frame-options`/`missing-csp-frame-ancestors`
  via `SECURITY_MIDDLEWARE_METHODS` and
  `SECURITY_MIDDLEWARE_ANNOTATIONS_RE`. Locks the behaviour in regression
  tests.

- **Issue #79 — Interprocedural sanitizer wrapper.**
  `findSanitizers()` (`analysis/taint-matcher.ts:1314`) now derives
  wrapper sanitizers from methods whose body is exactly
  `return <known_sanitizer>(<param>)` (≤2-line body, single inner call,
  exact parameter ref, source-line `return <call>(…)` shape check).
  Emits `derived_wrapper` `TaintSanitizer` entries at each call site so
  the existing `filterSanitizedSinks` and `checkSanitized` credit the
  wrapper. Rejects unsafe shapes like `return x + shlex.quote(x)`.

- **Issue #85 — Go `_test.go` exclusion verified (CLI).** No engine
  change; handled in `packages/cli` v3.58.0.

## [3.57.0] - 2026-06-16

### Fixed — Sprint 8: Java for-each + container taint propagation + Go path sanitizers + security-headers precision + Bash function-local positionals

- **Issue #73 (part 1) — Bash function-local `$1`/`$2` no longer conflated
  with script-CLI positionals.**
  `findBashTaintSources` in `analysis/passes/language-sources-pass.ts`
  scanned every line of the script for `$1`–`$9`/`$@`/`$*` and emitted a
  `script_arg` source for each, conflating function-local positional
  parameters (`format_name() { local first="$1"; }`) with actual script
  CLI args. Adds brace-depth tracking with POSIX (`name() {`), Bash
  (`function name {`), and hybrid (`function name() {`) header detection;
  positional-parameter scans are now suppressed when `braceDepth > 0`.
  Part 2 of the issue (`[[ $x =~ ^allowlist$ ]]` regex-guard recognition)
  is structural work deferred to Sprint 9.

- **Issue #50 — security-headers global-middleware suppression.**
  The `missing-x-frame-options` and `missing-csp-frame-ancestors` rules
  (file-level `missing` rules in `SecurityHeadersPass`) fired at line 1
  of every handler file regardless of whether a global header middleware
  was installed. Adds a `detectGlobalSecurityMiddleware(graph, calls)`
  helper recognising Express `helmet()` / `app.use(helmet())`, Spring
  `httpSecurity.headers().frameOptions()` chain + `@EnableWebSecurity` /
  `SecurityFilterChain` markers, and Flask `Talisman(app)` /
  `secure.Secure()` / `@app.after_request`. When detected, all
  `requiresHandler=true` `missing-*` rules are suppressed for that file.
  Value-based rules (`cors-wildcard-origin`, `cors-null-origin`,
  `x-frame-options-allow-from`, etc.) are unaffected — they inspect
  actual header values and are not about middleware presence.

- **Issue #51 — Go `filepath` / `path` path-traversal sanitizers.**
  `DEFAULT_SANITIZERS` in `analysis/config-loader.ts` now lists
  `filepath.Base` (strips directory components — full sanitizer),
  `filepath.Clean` / `path.Clean` (normalize `../` segments —
  defense-in-depth, mirrors Java `getCanonicalPath` in this table), and
  `filepath.EvalSymlinks` (Go equivalent of Java `Path.toRealPath`).
  Clears the `pathtraver_safe_basename` synthetic regression introduced
  by 3.53.0–3.56.0 sink widening. The stricter `Clean` + `HasPrefix`
  guard recognition (analogous to Sprint 8's `filterJavaPathCanonicalization`)
  is tracked as a follow-up structural change for Sprint 9.

- **Issue #84 — Java for-each loop element-taint.**
  `for (String id : taintedList) stmt.executeQuery("... " + id + " ...")`
  now correctly propagates collection taint to the loop variable. The
  propagator's `enhanced_for_statement` handler reads the iterated
  collection via `childForFieldName('value')` and checks
  `tainted`/`taintedArrayElements`/`taintedCollections` (scoped and
  unscoped). If the collection (or any of its tracked elements/keys) is
  tainted, the loop variable is seeded into `tainted` so downstream
  uses at sinks fire as expected.

- **Issue #62-partial — Map.put + StringBuilder taint propagation.**
  Two additions to `propagator.checkCollectionTaint`:
  - `m.put(k, tainted)` now seeds `m` into `tainted` (in addition to
    `taintedCollections`), so the existing `detectCollectionFlows`
    matcher in `taint-propagation-pass` finds `m.get(k)` at sinks
    (`query("... " + m.get("k") + " ...")`).
  - `StringBuilder.append(tainted)` and `StringBuffer.insert(off, tainted)`
    seed the builder receiver into `tainted`, so
    `stmt.executeQuery(sb.toString())` fires via the existing
    `toString()` collection pattern matcher.

### Regression coverage

- New file: `tests/analysis/repro-sprint8.test.ts` with 19 fixtures
  documenting the Sprint 8 issue contracts end-to-end:
  - 5 for **#90** (Fastjson typed-overload `parseObject` variants — already
    handled by `safe_if_class_literal_at` + `TYPE_ARG_IDENTIFIERS` shipped
    in earlier sprints; codified here as regression fixtures).
  - 1 for **#91** (`*Template.render(body)` template-receiver suppression
    — already handled by `SAFE_RECEIVER_SUBSTRINGS_BY_METHOD` from 3.55.0).
  - 1 for **#84** (for-each over tainted List → SQLi — newly fixed in
    this release).
  - 3 for **#49** (path canonicalization guard, XXE `setFeature` hardening,
    sink dedupe — already handled by earlier sprints; codified here as
    regression fixtures).
  - 2 for **#62** (Map.put → m.get(k) at sink, StringBuilder.append →
    sb.toString() at sink — newly fixed in this release).
  - 3 for **#51** (Go `filepath.Base` clears `path_traversal`, Go
    `filepath.Clean` clears `path_traversal`, untreated tainted input
    still fires — newly added in this release).
  - 2 for **#50** (Express `helmet()` suppresses `missing-x-frame-options`;
    untreated handler still fires — newly added in this release).
  - 2 for **#73** (Bash function-local `$1` is not a script-CLI source;
    top-level `$1` is still flagged — newly added in this release).
- Total suite: 2317 passed, 1 skipped (was 2298 in 3.56.0).

## [3.56.0] - 2026-06-16

### Added

- **Issue #87 — Sprint 7: cross-language `weak-crypto` parity.** Finishes the
  Python and Go side of the insecure-cryptographic-config family so all four
  supported languages (Java, Python, JS/TS, Go) detect the same set of issues
  (`weak-cipher`, `ecb-mode`, `deprecated-api`, `static-iv`, `hardcoded-key`,
  `weak-rsa-key`).

  Python additions to the `weak-crypto` pattern pass:
  - `modes.ECB()` from `cryptography.hazmat.primitives.ciphers` — CWE-327
  - `AES.new(b"literal", …)` and `algorithms.AES(b"literal")` — CWE-321
    (hardcoded symmetric key)
  - `rsa.generate_private_key(key_size=N)` with `N < 2048` — CWE-326
    (weak RSA key)

  Go additions:
  - `aes.NewCipher([]byte("literal"))` (and the `des`/`rc4` siblings) —
    CWE-321 hardcoded symmetric key
  - `rsa.GenerateKey(rand.Reader, N)` with `N < 2048` — CWE-326 weak RSA

  Both languages additionally support a regex-fallback "literal-binding"
  scan that recognises the very common pattern of binding a literal to a
  variable on one line and passing the variable to the cipher constructor
  on the next:

  ```python
  key = b"1234567890123456"
  c = AES.new(key, AES.MODE_CBC)    # flagged
  ```

  ```go
  key := []byte("1234567890123456")
  c, _ := aes.NewCipher(key)        // flagged
  ```

  Function parameters and runtime values continue to be ignored — no false
  positives are introduced for code that loads keys from KMS/Vault/env.

### Fixed

- The Python plugin emits bytes literals as `b"…"` in `argument.expression`
  but the `argument.literal` field strips the trailing quote, so the
  `weak-crypto` pass now prefers `expression` over `literal` when matching
  the inline `b"…"` regex.

## [3.55.0] - 2026-06-16

### Added

- **Issue #86 — Sprint 6: four more vulnerability categories.** Completes the
  9-category #86 gap analysis. Adds two new `SinkType` values and three new
  pattern passes.

  - **`crlf` SinkType (CWE-113)** — HTTP response splitting / header injection.
    Re-routed from `xss` for header-only sinks. Sinks:
    - Java `HttpServletResponse.setHeader`/`addHeader`
    - JS Express `res.setHeader`/`writeHead`/`cookie`/`location`/`redirect`
    - Go `http.Header.Set`/`Add`
    Severity: medium. `sendRedirect` stays classified as `ssrf` / open-redirect
    (CWE-601) to preserve the multi-hop cross-file chain semantics.

  - **`mass_assignment` SinkType (CWE-915)** — over-posting through
    `Object.assign(target, untrusted)`, lodash `_.merge`/`_.extend`,
    jQuery `$.extend`. Severity: high.

  - **`csrf-protection-disabled` (CWE-352, pass #94)** — pure pattern pass.
    Flags explicit CSRF disablement: Spring Security `http.csrf().disable()`,
    lambda DSL `http.csrf(c -> c.disable())`, method-ref `csrf(CsrfConfigurer::disable)`,
    `csrfTokenRepository(null)`, and Django `@csrf_exempt`. Severity: critical.

  - **`xml-entity-expansion` (CWE-776, pass #95)** — pure pattern pass for
    XML bomb / billion-laughs. Flags Java factory `.newInstance()` for
    `SAXParserFactory`/`DocumentBuilderFactory`/`XMLInputFactory`/
    `SchemaFactory`/`TransformerFactory` unless the file contains
    `disallow-doctype-decl`/`external-general-entities`/`SUPPORT_DTD`/
    `ACCESS_EXTERNAL_DTD`/`setXIncludeAware(false)`/
    `setExpandEntityReferences(false)`. Flags Python `lxml.etree.parse`/
    `fromstring`/`XML` and `xml.etree.ElementTree.parse`/`fromstring`
    unless `defusedxml` is imported or `resolve_entities=False` is passed.
    Severity: high.

  - **`mass-assignment` (CWE-915, pass #96)** — pure pattern pass.
    Flags Python kwargs-splat `User(**request.{form,args,values,json,
    get_json(),files,data})` and JS object spread `{...req.body}`/
    `{...req.query}`/`{...req.params}`/`{...ctx.request.body}`.
    Complements the `mass_assignment` taint sink for `Object.assign` and
    friends. Severity: high.

### Fixed

- **`canSourceReachSink` coverage matrix** — `crlf` and `mass_assignment`
  added to the `http_param`/`http_body`/`http_header`/`http_cookie`/
  `http_query`/`interprocedural_param` source-to-sink mapping in
  `analysis/findings.ts`. Without this, the inline source-as-argument flow
  path in `detectExpressionScanFlows` (and the `generateFindings` matrix)
  silently rejected the new sink types and no flow was emitted for
  `res.setHeader('X-Tag', req.query.t)` or `Object.assign(user, req.body)`.

### Notes

- Total security passes: 24 (21 → 24) and 8 pattern passes (5 → 8).
- 2287 tests passing (+18 net), zero regressions.

## [3.54.0] - 2026-06-16

### Added

- **Issue #86 — Sprint 5: three new vulnerability categories.** Previously
  uncovered patterns now fire. Adds two new `SinkType` values and one new
  pattern pass.

  - **`jwt-verify-disabled` (CWE-347, pass #93)** — pure pattern pass, no taint
    required. Flags JWT signature checks that are explicitly disabled:
    - Python PyJWT: `jwt.decode(t, ..., options={"verify_signature": False})`,
      `verify=False` (legacy), `algorithms=["none"]`
    - JS jsonwebtoken: `jwt.verify(t, secret, {algorithms: ['none']})`,
      `jwt.verify(t, null|''|undefined)`, `verify: false`
    - Java auth0: `JWT.require(Algorithm.none())`
    - Java jjwt 0.x: `Jwts.parser()…parse(token)` (unsigned parse — vs
      `parseClaimsJws` which enforces the signature)
    Severity: critical.

  - **`redos` SinkType (CWE-1333)** — taint flow into regex compile/match
    primitives. Sinks: Python `re.{match,search,compile,findall,fullmatch,
    sub,subn,split,finditer}`, Java `Pattern.compile`/`Pattern.matches` and
    `String.matches`/`replaceAll`/`replaceFirst`/`split`, JS `new RegExp(...)`,
    Go `regexp.{Compile,MustCompile,Match,MatchString}`. Severity: high
    (medium for Go since `regexp` is non-backtracking).

  - **`format_string` SinkType (CWE-134)** — taint flow into format-string
    primitives. Sinks: Java `String.format`, `Formatter.format`,
    `System.out.printf`; Go `fmt.{Sprintf,Printf,Errorf,Fprintf}`; Python
    `ctypes printf/fprintf`. Python `userFmt.format(...)` and
    `userFmt % args` are NOT yet detected — they require receiver-taint /
    operator-LHS-taint tracking and are deferred to Sprint 6.

### Notes

- Total security passes: 21 (19 → 21) and 5 pattern passes (4 → 5).
- 2269 tests passing (+10 net), zero regressions.

## [3.53.0] - 2026-06-16

### Added

- **Issue #52 — Java sink/source patterns previously missed by the matcher.**
  Three high-impact Java patterns now fire:
  - **Text4Shell (CVE-2022-42889, CWE-94)** — Apache Commons Text
    `StringSubstitutor.replace(taint)` is now reported as a `code_injection`
    sink. Both the explicit-ctor form (`new StringSubstitutor()` + `ss.replace(x)`)
    and the chained-variable form (`StringSubstitutor.createInterpolator()` →
    `interp.replace(x)`) flow correctly.
  - **FreeMarker SSTI (CWE-94)** — `new Template(name, new StringReader(taint), cfg)`
    is reported as a `code_injection` sink; `tpl.process(...)` continues to fire.
  - **Zip-Slip (CWE-22)** — `ZipEntry.getName()` (and
    `ZipArchiveEntry` / `TarArchiveEntry` / `ArchiveEntry`) is now modeled as a
    **taint source** (was previously a sink, which produced 3 findings per vuln).
    The correct source → `new File()` / `new FileOutputStream()` flow yields
    exactly one `path_traversal` finding.

- **Issue #87 (partial) — weak-crypto configuration patterns.** Extended the
  `weak-crypto` pass with three constant-pattern detectors for Java:
  - **CWE-329 static / zero IV** — `new IvParameterSpec(new byte[N])`,
    `new IvParameterSpec("literal".getBytes())`, and literal `byte[]{…}`.
  - **CWE-321 hardcoded symmetric key** — `new SecretKeySpec("literal".getBytes(), "AES")`
    and literal byte-array key material.
  - **CWE-326 weak RSA key size** — `KeyPairGenerator.initialize(<2048)`
    (uses the IR-resolved `receiver_type === "KeyPairGenerator"` enabled by the
    matcher fix below).
  - ECB and weak-cipher detection unchanged. The `weak-crypto` rule now emits
    findings with per-issue CWE (327 / 329 / 321 / 326).

### Fixed

- **Taint matcher ignored IR-resolved receiver types.** Both
  `matchesSinkPattern` and `matchesSourcePattern` in `taint-matcher.ts` only
  checked the receiver-name string heuristic — they ignored
  `call.receiver_type` populated by the Java/TypeScript language plugins. This
  caused sinks like `ss.replace(x)` (after `StringSubstitutor ss = new ...`)
  and sources like `entry.getName()` (after `ZipEntry entry = …`) to silently
  miss. Both matchers now check IR-resolved `receiver_type` /
  `receiver_type_fqn` before falling back to the name heuristic. This unblocks
  #52 and improves precision across all class-qualified sink/source patterns.

### Tests

- **+16 regression tests** (6 for #52, 10 for #87). Full suite: **2259 passing**
  (was 2243).

## [3.52.0] - 2026-06-16

### Added

- **Config / absence pattern passes (#60)** — Replaced the broken
  `weak_random` / `weak_hash` / `weak_crypto` / `insecure_cookie`
  taint-sink registrations in `configs/sinks/java.json` and
  `config-loader.ts` with five dedicated `AnalysisPass`
  implementations that detect the bad value as a *constant* — no
  source / sanitizer / sink graph is needed because the vulnerability
  is the hard-coded algorithm string (or the absence of a flag), not a
  data flow.
  - `weak-hash` (#17, CWE-328) — MD2/MD4/MD5/SHA-1 via Java
    `MessageDigest.getInstance` / Apache Commons `DigestUtils`,
    Python `hashlib.{md5,sha1,new("md5",…)}`, JS `crypto.createHash`
    / `createHmac`, Go `crypto/md5` + `crypto/sha1`.
  - `weak-crypto` (#18, CWE-327) — DES/3DES/RC2/RC4/Blowfish/IDEA/
    SEED/CAST5 + ECB mode (incl. Java AES default = ECB) via
    `Cipher.getInstance`, pycryptodome `*.new` / `AES.MODE_ECB`,
    `cryptography.hazmat algorithms.{TripleDES,…}`,
    `crypto.createCipher` (deprecated) / `createCipheriv("…-ecb")`,
    Go `des.NewCipher` / `rc4.NewCipher`.
  - `weak-random` (#16, CWE-330) — non-CSPRNG: Java `new Random()`
    / `Math.random` / `ThreadLocalRandom`, Python `random.*`,
    JS `Math.random`, Go `math/rand` (import-aware: skipped when
    `crypto/rand` aliases the bare `rand` symbol).
  - `tls-verify-disabled` (#92, **new**, CWE-295) — Go
    `tls.Config{InsecureSkipVerify: true}` (source-text scan),
    Python `requests/httpx(verify=False)` +
    `ssl._create_unverified_context` + module override, JS
    `rejectUnauthorized: false` + `NODE_TLS_REJECT_UNAUTHORIZED='0'`,
    Java `setHostnameVerifier((h,s)->true)` /
    `NoopHostnameVerifier.INSTANCE` / `AllowAllHostnameVerifier`.
- **`insecure-cookie` (#19) extended to Java + Python** — was JS/TS
  only. Now also flags Flask/Django/Starlette
  `response.set_cookie(...)` without `secure=True`/`httponly=True`
  and `new javax.servlet.http.Cookie(name, value)` whose enclosing
  file has no `.setSecure(true)` + `.setHttpOnly(true)` (text-based
  heuristic; documented in the pass docstring).

### Changed

- **`config-loader.ts`** — removed the unreachable `weak_random`,
  `weak_hash`, `weak_crypto`, and `insecure_cookie` sink registrations
  (lines 1198–1227). They could never match a "tainted value flowing
  into a sink" because the bad value is a hard-coded constant; the new
  pattern passes detect them directly. `trust_boundary` (CWE-501) is
  retained because it is a genuine taint-flow sink (attacker controls
  the session-attribute *name*).
- **`analyzer.ts`** — registered `WeakHashPass`, `WeakCryptoPass`,
  `WeakRandomPass`, `TlsVerifyDisabledPass`, alongside the existing
  `Spring4ShellPass` and `InsecureCookiePass`. Each is disable-able via
  `disabledPasses: ['weak-hash', 'weak-crypto', 'weak-random',
  'tls-verify-disabled']`.

### Tests

- Added 4 new test files (`weak-hash.test.ts`, `weak-crypto.test.ts`,
  `weak-random.test.ts`, `tls-verify-disabled.test.ts`) plus 6 new Java
  + Python cases in `insecure-cookie.test.ts`. Total: 57 new tests.
  Full circle-ir suite: 2243 passing (was 2186), 1 skipped.

## [3.51.0] - 2026-06-16

### Added

- **Go `text/template` XSS sinks** — `Template.Execute(w, data)` and
  `Template.ExecuteTemplate(w, name, data)` are now recognized as
  `xss` sinks (CWE-79, severity `high`). Unlike `html/template`,
  `text/template` does not HTML-escape interpolated values, so any
  HTTP-derived `data` argument reaches the browser as raw HTML.
  Closes part of #88 (sub-issue #88.3). New patterns in
  `configs/sinks/golang.json` and `src/languages/plugins/go.ts`;
  regression cases in `tests/analysis/repro-issue-88.test.ts`.

### Fixed

- **Receiver-name → class resolution for Go templates**
  (`src/analysis/taint-matcher.ts`). The variable name `tmpl` is the
  canonical Go idiom for `*text/template.Template` but is not a
  substring of `template`, so the existing substring heuristic could
  not match `tmpl.Execute(...)` against the new `class: Template`
  sink pattern. Added `tmpl: ['Template']` to `commonMappings` and
  extended `template` to `['JdbcTemplate', 'Template']` (the joint
  mapping is safe because the sink patterns are language-scoped).
  Also added a chained-call factory regex
  (`.Must(...).New(...).Parse(...).Funcs(...)…`) so that the inline
  shape `template.Must(template.New("p").Parse(...)).Execute(w, x)`
  resolves its receiver type to `Template`.

## [3.50.0] - 2026-06-16

### Fixed

- **Inline-source expression loses taint (cross-language FN)** —
  closes #83 (subsumes #76). A taint **source used inline** as a
  call/concat argument was not tracked; only an intermediate variable
  recovered the flow. This was the dominant recall gap on
  OWASP BenchmarkPython, OWASP Benchmark Java with bare-arg variants,
  and the JS `eval(req.query.x)` shape:

  - Java: `Runtime.getRuntime().exec("echo " + req.getParameter("u"))`
    and `exec(req.getParameter("u"))`
  - JS: `eval(req.query.x)`, `vm.runInThisContext(req.cookies.c)`,
    `child_process.exec(req.body.cmd)`
  - Python: `os.system("echo " + request.args.get("u"))` and
    `for p in request.args.getlist("p"): os.system(p)` (#76)

  Root causes and fixes:

  1. **Inline-source colocation pass** (`taint-propagation-pass.ts`).
     The DFG-based propagator skipped inline sources because
     `arg.variable` was null; the existing variable-name scan
     skipped them because `source.variable` was unset. Added a
     colocation pass that emits a direct flow when (a) the source
     line equals the sink line, (b) the source carries no
     `variable` field (assignment-style sources at the sink line
     still respect the source-precedes-sink rule), and (c)
     `canSourceReachSink(source.type, sink.type)` allows the pair.

  2. **Python for-loop iterable** (`taint-propagation-pass.ts`).
     `buildPythonTaintedVars` already adds the loop variable to its
     derived map when the iterable matches a tainted pattern, but
     the Python alias expansion path only ran when at least one
     real source carried a `variable` field. Synthesize a virtual
     `http_param` anchor at the derivation line when no real source
     is registered, so the variable-name scan picks up
     `os.system(... + p)` on the next line.

  3. **Empty-source early returns dropped synthesized flows**
     (`taint-propagation-pass.ts`, `interprocedural-pass.ts`).
     Both passes returned early on `sources.length === 0`,
     discarding flows produced by the Python alias synthesis. Loosen
     both early-returns to allow Python flows through and to
     propagate `taintProp.flows` to `additionalFlows`.

  4. **`canSourceReachSink` coverage** (`findings.ts`). Added
     `code_injection` as a valid sink for `http_param`,
     `http_query`, `http_header`, `http_cookie` so JS RCE patterns
     such as `eval(req.query.x)`, `Function(req.header('x'))`, and
     `vm.runInThisContext(req.cookies.c)` survive the source-to-sink
     gating step. Exported `canSourceReachSink` so detection passes
     gate emit-time flows on the same matrix that `generateFindings`
     uses.

  Regression coverage: `tests/analysis/repro-issue-83.test.ts`
  (8 cases — Java concat+bare, JS `eval`/`cp.exec`, Python concat
  and for-iterable, plus var-first regression guards). Full
  taint-propagation regression suite (2179 tests) passes; the
  prior "does NOT emit when source line is at or after sink line"
  guard is preserved by restricting colocation to inline-only
  (`source.variable` absent) sources.

## [3.49.0] - 2026-06-16

### Added

- **`insecure-cookie` pattern pass for JavaScript / TypeScript
  (CWE-614)** — closes #43. Previously `insecure_cookie` was only
  modelled as a Java sink for `new Cookie(...)`. Express's
  `res.cookie(name, value, options)` is a shape-based vulnerability
  (the absence of `Secure` / `HttpOnly` flags is not a taint-flow
  problem), so a new dedicated pattern pass scans
  `graph.ir.calls` for `cookie` invocations whose receiver looks
  like an Express/Fastify response (`res`, `response`, `reply`) and
  flags any call where the literal options object is missing or does
  not contain both `secure: true` and `httpOnly: true`. One finding
  per call site, severity `medium`, level `warning`. The pass is
  registered in `src/analyzer.ts` after `spring4shell` and can be
  disabled via `disabledPasses: ['insecure-cookie']`. Regression
  coverage: `tests/analysis/passes/insecure-cookie.test.ts`
  (12 cases — vulnerable JS/TS shapes, partial-flag mixes,
  Fastify `reply.cookie`, clearCookie negative, non-response
  receiver negative, Java-language negative, multi-call dedupe).

- **`log_injection` (CWE-117) sinks for Java and JavaScript/TypeScript** —
  closes #44. Previously only Python `class: 'logger'` and Rust
  `info!`/`warn!`/`error!`/etc. macros emitted `log_injection` findings.
  The default sink registry now includes:
  - Java (scoped to `languages: ['java']`): `Logger.info`/`warn`/`error`/
    `debug`/`trace` (slf4j / logback signatures including format-string
    arguments) and `severe`/`warning`/`config`/`fine`/`finer`/`finest`/
    `log` for `java.util.logging.Logger`.
  - JavaScript/TypeScript (scoped to `languages: ['javascript',
    'typescript']`, `class: 'console'`): `console.log`/`warn`/`error`/
    `info`/`debug`/`trace`.

  All entries are severity `low` (CWE-117 log forging / log forgery
  is informational unless paired with downstream parsers that act on
  log content). Regression coverage in
  `tests/analysis/sink-config-coverage.test.ts`.

- **`nosql_injection` (CWE-943) coverage for mongoose `Model`/`Query`
  fluent chains and classless MongoDB-specific method names** —
  closes #45. The previous `class: 'Collection'`-only entries missed
  `User.findOne({ username })`, `User.findOneAndUpdate(...)`,
  `mongoose.connection.db.collection('x').find({...})`, and similar
  patterns because the call-site receiver type does not resolve to
  `Collection`. Added:
  - `class: 'Model'` entries for `find`, `findOne`, `findById`,
    `findOneAndUpdate`/`Delete`/`Replace`, `updateOne`/`Many`,
    `deleteOne`/`Many`, `countDocuments`, `aggregate`.
  - `class: 'Query'` entries for `where`, `equals`.
  - Classless + `languages: ['javascript', 'typescript']` entries for
    `findOne`, `findOneAndUpdate`/`Delete`/`Replace`, `updateOne`/`Many`,
    `deleteOne`/`Many`, `aggregate`. Bare `find` intentionally stays
    class-scoped to avoid colliding with `Array.prototype.find`.

- **Classless `open_redirect` (CWE-601) entry for Express
  `res.redirect()`** — closes #46. Mirrors Python's classless
  `redirect` entry and removes the dependency on receiver type
  resolution for the Express `res` parameter. Language-scoped to
  `javascript`/`typescript`; method name `redirect` is rare outside
  HTTP frameworks so the FP risk is low.

- **Python `path_traversal` sanitizers for `os.path.realpath` and
  `os.path.abspath`** — closes #48 part 2. `os.path.realpath` (resolves
  symlinks + canonicalizes) and `os.path.abspath` (canonicalizes the
  path string) are the standard Python equivalents of Java's
  `File.getCanonicalPath`. Registered on both `os.path` and the bare
  `path` receiver (covers `import os.path as path`). `os.path.normpath`
  was already registered and is unchanged. Regression coverage in
  `tests/analysis/sink-config-coverage.test.ts` (`#48 Python:` block).

### Fixed

- **Rust actix-web / axum typed extractors now produce taint flows** —
  closes #71. Three fixes in `src/analysis/taint-matcher.ts` and
  `src/analysis/passes/{language-sources-pass,taint-propagation-pass}.ts`:
  1. The typed-extractor regex (`RUST_EXTRACTOR_KIND`) now accepts both
     bare and module-prefixed forms (`Path<…>`, `web::Path<…>`,
     `axum::extract::Path<…>`). Previously the bare anchor
     `^(?:Json|Form|Query|Path|…)(?:<|$)` rejected actix's
     `web::Path<String>` param type, so the typed extractor was never
     recognised as a source.
  2. Source `type` is now selected per extractor kind:
     `Form`/`Query`/`Path` → `http_param` (covers `sql`,
     `command_injection`, `path_traversal`, `xss`, `ssrf`, …);
     `Json`/`Body`/`Bytes`/`Multipart` → `http_body`. Previously the
     type was hard-coded to `http_body`, which `canSourceReachSink`
     does NOT map to `path_traversal` or `ssrf` — so even the cases
     that did produce a source produced no flows. `Extension<T>` is
     explicitly excluded (server-injected state, not user input).
  3. Sources now carry `variable`: typed extractors use `param.name`,
     and the existing method-call-based sources (`match_info().get`,
     `uri().query()`, `headers().get()`, …) get their LHS attached via
     a Rust let-binding scan in `findSources`. The expression-scan flow
     detector requires `source.variable` to be set.

  Plus a new Rust alias expansion in `detectExpressionScanFlows` —
  `buildRustTaintedVars(code, seedVars)` does a fixpoint over Rust
  let-bindings and assignments, mirroring `buildPythonTaintedVars`.
  This propagates taint through multi-level extractor chains such as
  ```
  let form = f.into_inner();
  let path = form.path;
  fs::write(path, …);
  ```
  so the flow still anchors to the original `web::Form<T>` parameter
  source. Regression coverage: `tests/analysis/repro-issue-71.test.ts`
  (8 cases — actix `match_info`/`uri.query`/`Path`/`Query`/`Form`
  extractors, http_param type assertion, axum-style `extract::Path`,
  and an `Extension<T>` negative case).

- **Python `subprocess.*([list], shell=False)` no longer mis-flagged as
  `command_injection`** — closes #48 part 1. The canonical safe-shape
  invocation

  ```python
  subprocess.run(["ping", "-c", "3", "--", host],
                 shell=False, capture_output=True, timeout=10)
  ```

  produces no shell — Python invokes `execve(argv)` directly with each
  list element as a separate argv slot, so a tainted element cannot
  escape into shell metacharacters. The previous matcher emitted a
  `command_injection` sink for every `subprocess.run`/`call`/
  `check_output`/`check_call`/`Popen` call regardless of arg[0] shape
  or the `shell` kwarg, and the flow detector then paired it with any
  tainted variable in scope.

  Fix in `src/analysis/taint-matcher.ts`:
  - Added `isSafePythonSubprocessCall(call, pattern, language)` that
    returns true when `language === 'python'`, the matched pattern is
    `command_injection` + `class: 'subprocess'`, arg[0] is a list
    literal (`[...]`), AND no `shell=True` kwarg is present.
  - `findSinks` skips emission when the helper matches, mirroring the
    existing `isParameterizedQueryCall` skip pattern.

  Preserved behaviour:
  - Single-string form (`subprocess.run("ping " + host)`) still fires —
    a tainted executable name is a real CWE-78 vector even without a
    shell.
  - `shell=True` with a list (`subprocess.run([list], shell=True)`)
    still fires — Python's argv-to-shell mapping is surprising and
    keeping the flag is the conservative choice.
  - `os.system`, `os.popen`, and other non-`subprocess` command sinks
    are unaffected (the skip is gated on `pattern.class === 'subprocess'`).

  Regression coverage in `tests/analysis/repro-issue-48-pt1.test.ts` —
  8 cases covering all 5 subprocess methods × {list/string, shell={absent,
  False, True}}, plus an `os.system` guard.

- **`cur.execute(...)` no longer mis-classified as `xss` (CWE-79)** —
  closes #65 part 1 and #48 part 3. The receiver `cur` (3 chars) was
  loosely matching the XWiki XSS sink class `CurrentTimePlugin` via the
  CamelCase word prefix heuristic in `receiverMightBeClass`
  (`'current'.startsWith('cur')` with ratio 3/7 ≥ 0.4), producing a
  spurious `xss` finding on every Python DB-API parameterized query.
  Fix in `src/analysis/taint-matcher.ts`:
  - Added `cur` to the `ambiguousIdentifiers` denylist so the
    prefix/suffix/includes/CamelCase heuristics short-circuit for this
    receiver and fall through to explicit `commonMappings`.
  - Added `cur` / `cursor` → `['Cursor']` in `commonMappings` so
    legitimate DB cursor matches still resolve.
  - Added a 40% coverage gate to the bare prefix/suffix heuristic
    (mirroring the existing `includes` gate at line 922) as a
    defensive measure against similar short-receiver mismatches.

  Net effect on the existing test suite: 20 more tests pass
  (previously-failing benchmark-debug and downstream cases that were
  blocked by the same over-matching), 0 regressions among passing
  tests. Regression coverage in
  `tests/analysis/sink-config-coverage.test.ts` (`#65 Python:` block)
  including a guard that real string-concatenation SQLi still fires.

- **`shlex.quote(...)` no longer lost through `+`-concat assignment in
  Python** — closes #65 part 2. Code shaped like

  ```python
  host = request.args.get("host", "")
  cmd  = "ping -c 3 " + shlex.quote(host)
  subprocess.run(cmd, shell=True, ...)
  ```

  was being reported as `command_injection` even though
  `taint.sanitizers` correctly listed the `shlex.quote()` call as
  covering `command_injection`. Root cause: the Python alias expansion
  in `detectExpressionScanFlows` (TaintPropagationPass) widens the
  seed source set with every variable produced by
  `buildPythonTaintedVars`, but it had no notion of which aliases
  came from a sanitized RHS. The synthetic source for `cmd` therefore
  appeared in the per-sink expression scan and emitted a flow with
  `sanitized: false`.

  Fix in `src/analysis/passes/taint-propagation-pass.ts`:
  - `detectExpressionScanFlows` now accepts `sanitizers` and builds a
    per-alias `Map<varName, Set<sinkType>>` of the sink types each
    derived alias is sanitized against. The check is gated on the
    sanitizer's method name actually appearing on the assignment
    line's RHS (e.g. `shlex.quote(` in
    `cmd = "ping -c 3 " + shlex.quote(host)`).
  - Flow emission skips entries where
    `aliasSanitizedFor.get(source.variable)?.has(sink.type)` is
    true, so `command_injection` flows are suppressed for aliases
    sanitized by `shlex.quote`, while `sql_injection` flows from the
    same alias remain — coverage is sink-type-aware.

  Bare sanitizer calls without an assignment
  (`_ = shlex.quote(host); subprocess.run(host, shell=True)`) are
  unaffected: the underlying tainted variable is not sanitized and
  the flow still fires. Regression coverage in
  `tests/analysis/repro-issue-65-pt2.test.ts` — 5 cases including
  `+`-concat, f-string interpolation, raw-concat TP guard, the
  type-awareness guard against suppressing SQLi when only the
  command-injection sanitizer applies, and the bare-call TP guard.

- **`InterproceduralPass` now populates `code` on every emitted
  `TaintSink`** — closes epic #21 MED item ("surface `code` on
  TaintSource/TaintSink"). Previously, additional sinks surfaced by
  inter-procedural analysis (both Scenario A propagated callee sinks and
  Scenario B `external_taint_escape` sinks) reached the final merged
  `taint.sinks` array without the trimmed source-line text in `code`.
  Downstream consumers (LLM-enrichment pipelines such as circle-ir-ai,
  SARIF reporters) had to re-read the source file to render the offending
  line. The pass now calls the existing `attachSourceLineCode()` helper
  on `additionalSinks` before returning, matching the pattern already
  used by `LanguageSourcesPass`. Idempotent — pre-populated `code` values
  are preserved. No change to the DFG-reachability gate or sink
  classification.

- **TypeScript decorator annotations now extracted on methods and
  parameters** — closes cognium-dev#67. NestJS controllers
  (`@Controller`, `@Get('search')`, `async search(@Query('q') q: string)`)
  and Angular components were silently producing `method.annotations: []`
  and `parameter.annotations: []`, because the JS/TS type extractor in
  `src/core/extractors/types.ts` hardcoded both arrays to `[]`.

  Effect: the `taint-matcher.ts` annotation-based source path (sources
  declared with `{ annotation: 'Query', type: 'http_param', ... }` in
  `config-loader.ts:436-441`) never matched on TypeScript, so framework
  parameter sources for NestJS / Angular went undetected. `@Query` was
  accidentally caught via the unrelated Axum `{ method: 'Query',
  return_tainted: true }` rule at `config-loader.ts:498` (which treats
  `Query('q')` as a tainting *function call*, not a parameter decorator),
  while `@Param` / `@Body` had no fallback and produced zero sources.

  Fix:
  1. New `extractDecoratorName(node)` helper handles the four
     `decorator` shapes the TS grammar emits: `@Foo` (identifier),
     `@Foo('x')` (call_expression > identifier), `@ns.Foo` and
     `@ns.Foo('x')` (member_expression — uses `.property`).
  2. `extractJSMethods()` now accumulates `decorator` siblings inside
     `class_body` and attaches them to the very next `method_definition`.
     **Pending decorators are reset on ANY non-decorator class member**
     (field, accessor, abstract signature, …) so that a decorated field
     between two methods cannot transfer its decorator to the method
     below it — e.g. `@Inject('USER_REPO') private repo: any;` followed
     by `@Get('search') search() {}` correctly attaches only `Get` to
     `search`, never `Inject`.
  3. `extractJSParameters()` now scans `required_parameter` /
     `optional_parameter` children for nested `decorator` nodes.

  Regression coverage in `tests/analysis/repro-issue-67.test.ts`
  (5 tests: direct assertion on `method.annotations` / `param.annotations`
  for NestJS `Controller`/`Get`/`Post`/`Query`/`Param`/`Body`, ≥2 SQLi
  flows on the controller, explicit `@Inject` field → `@Get` method
  leakage guard, a comment-between-decorator-and-method guard
  (tree-sitter emits `// comment` nodes as anonymous siblings inside
  `class_body`; the reset rule skips them), and all four decorator
  grammar shapes).

- **JS taint analysis no longer silently collapses to zero findings on
  realistic multi-handler Express files** — closes cognium-dev#77.
  Files mixing `await`/`.then`/`fs.readFile`/`setTimeout` callback handlers
  with `res.send` boilerplate and a trailing `module.exports = app` reported
  `flows: []` even though every isolated handler pattern fired on its own.
  Bisection isolated the trigger to any top-level
  `<member_expression> = <expr>` statement (`module.exports = app`,
  `exports.x = 1`, `obj.foo = bar`) — a single such assignment flipped 3
  flows to 0.

  Root cause: `isFalsePositive()` in
  `src/analysis/constant-propagation/index.ts` was using
  `result.symbols.size > 0` as a proxy for "did const-prop track any
  variables". This is brittle for JavaScript, where the engine doesn't
  process `lexical_declaration` inside arrow-function bodies, so
  request-handler locals (`c`, `req.body.code`) never appear in `symbols`.
  A top-level `module.exports = app` assignment goes through the JS
  `assignment_expression` visitor and adds the `module.exports` key to
  `symbols`. That single entry flipped `size > 0` from false to true,
  activating reason 3 (`variable_not_tainted`) for every flow path
  variable — none of which were in `tainted` either (because JS const-prop
  hadn't tracked them), so all flows were rejected at
  `taint-propagation-pass.ts:51`.

  Fix: tighten the gate to `result.symbols.has(taintedVar)` — only
  conclude "clean unknown" when const-prop specifically tracked this
  variable and didn't tag it tainted. Strictly tighter than the previous
  check: never causes a new FP, only stops over-suppressing real flows
  where const-prop never saw the variable. Java/Python paths unaffected
  (their tracked locals do appear in `symbols` so the gate still fires
  on truly-clean variables). Regression coverage in
  `tests/analysis/repro-issue-77.test.ts` (5 cases: N1 await, N4 fs
  callback, Q4 3-route compact, `async_taint.js` 4-handler shape, N2
  `.then` arrow skipped as separate pre-existing bug).

- **Python compound-concat sinks no longer dropped when the argument
  begins and ends with a quote** — closes cognium-dev#63.
  `cur.execute("SELECT … '" + u + "'")` (3+-part `+` concat where the
  outer characters are quotes) was being filtered out by
  `filterCleanVariableSinks` because `isStringLiteralExpression()` only
  checked the first and last characters — so any expression that *looked*
  like it started and ended with a quote was treated as a pure string
  literal. The check now walks the leading quoted segment honoring
  backslash escapes and only returns `true` when the closing quote is
  the last non-whitespace character of the expression. Two-part right-
  operand concats (`"a" + u`) and left-operand concats (`u + "b"`) were
  unaffected because their last character is not a quote — the bug only
  manifested when both ends happened to be quotes (3-part and deeper).
  Regression coverage in `tests/analysis/repro-issue-63.test.ts` (5
  cases: V5/V6, V2-control, LEFT, N-way 4-part).

- **Jinja2 `render_template_string` reclassified from `xss` (CWE-79) to
  `code_injection` (CWE-94), severity `critical`** — closes #54.
  Flask's `render_template_string(template_str)` with an
  attacker-controlled template string is Server-Side Template Injection
  (Jinja2 SSTI → RCE), not reflected XSS. The previous mapping
  understated severity (a `low`/`medium` XSS rating versus the true RCE
  impact) and miscategorized the CWE. The companion sinks
  `jinja2.Template(body).render()` and `Template.from_string(...)` were
  already classified correctly as `code_injection`/`CWE-94`; this change
  brings the Flask helper in line.

### Test coverage

- New `tests/analysis/sink-config-coverage.test.ts` pins the expected
  behaviour for issues #44 (5 tests), #45 (2), #46 (2), #54 (2),
  #48 part 2 (5), and #65 part 1 (4) — 20 tests total.
- New `tests/analysis/repro-issue-63.test.ts` pins LEFT/middle-operand
  Python `+` concat taint propagation through `cur.execute(...)` for
  cognium-dev#63 (5 tests: V5/V6/V2/LEFT/N-way).
- New `tests/analysis/repro-issue-77.test.ts` pins JS multi-handler
  taint-flow stability for cognium-dev#77 (5 tests: N1 await, N2 .then
  skip, N4 fs callback, Q4 3-route compact, async_taint.js 4-handler
  with `res.send` + `module.exports`).
- New `tests/analysis/repro-issue-67.test.ts` pins TypeScript decorator
  extraction for cognium-dev#67 (5 tests: explicit annotation
  assertions on `method.annotations` / `param.annotations`, SQLi flows
  through `@Query`/`@Param`/`@Body`, `@Inject` field → `@Get` method
  leakage guard, comment-between-decorator-and-method guard, and all
  four decorator grammar shapes — `@Foo`, `@Foo(...)`, `@ns.Foo`,
  `@ns.Foo(...)`).
- Updated `tests/analysis/benchmark-debug.test.ts` `xss_eval_safe_json`
  assertion to filter on XSS / code-injection / SQL / command-injection
  sink types rather than total sink count. `console.log` is now a
  modeled `log_injection` sink (issue #44) and `JSON.parse` does not
  sanitize CRLF for log forging, so log_injection findings are
  expected to remain.

## [3.48.0] - 2026-06-12

### Fixed

- **Parser / analyzer stack overflow on deeply nested AST shapes** — closes
  cognium-ai#88. Scanning generated Java sources such as CoreNLP's
  `DefaultTeXHyphenData.java` (which contains 4500+ segment
  `"a" + "b" + "c" + …` string concatenation chains) raised
  `RangeError: Maximum call stack size exceeded` because tree-walk helpers
  were recursive and tree-sitter parses `+` chains as left-associative
  binary AST whose depth equals the number of segments. All recursive
  walkers in the hot path are now iterative DFS with an explicit stack and
  preserve pre-order visit semantics:

  - `walkTree` (`src/core/parser.ts`) — primary tree walker used by
    `findNodes`, `collectAllNodes`, and direct callers in `dfg.ts`.
  - `BaseLanguagePlugin.findNodes` (`src/languages/plugins/base.ts`) —
    replaced the `TreeCursor` recursion that overflowed.
  - Java plugin's internal `walk` (`src/languages/plugins/java.ts`).
  - `ConstantPropagator.visit` and
    `ConstantPropagator.isTaintedExpression`
    (`src/analysis/constant-propagation/propagator.ts`) — refactored to
    iterative wrappers that dispatch to a private step method per node;
    structured handlers (`if`/`switch`/`loop`/method) still manage their
    own descent. `isTaintedExpression` now returns `boolean` from a
    wrapper that drives an internal step returning
    `boolean | undefined` (`undefined` meaning "descend").
  - `ConstantPropagator.collectClassFields` and
    `ConstantPropagator.findAllMethods` — defensive iterative DFS.
  - HTML pre-processing walks (`walkNode` in
    `src/analysis/html/html-extractor.ts` and `walkForSecurityChecks`
    in `src/analysis/html/html-attribute-security-pass.ts`) — defensive
    iterative DFS.

  Regression coverage: `tests/core/deep-nesting.test.ts` parses synthetic
  Java files with 6000 and 10000 segment `+`-concatenation chains and
  asserts `parse_status.success === true` without overflow. Full test
  suite (2102 tests) continues to pass.

## [3.47.0] - 2026-06-12

### Added

- **Pass #91 `spring4shell` — Spring4Shell (CVE-2022-22965) implicit
  form-data binding RCE detection** — closes cognium-dev#28.
  A new Java-only pattern pass (category `security`, CWE-94, SARIF level
  `error`, severity `high`) that detects the vulnerable controller shape:

  ```java
  @Controller
  public class FooController {
      @RequestMapping("/bar")
      public String bar(MyBean bean) { ... }   // implicit form-data binding
  }
  ```

  Spring's `WebDataBinder` walks the parameter's class graph and populates
  setters from request parameters via reflection; CVE-2022-22965 abuses
  this chain (`class.module.classLoader.resources.context…`) for arbitrary
  code execution on Spring < 5.3.18 / 5.2.20. The existing `code-injection`
  pass (#11) covers explicit `DataBinder.bind()` /
  `DataBinder.setPropertyValues()` sink calls; the vulnerable code typically
  does NOT make those calls (Spring does it implicitly), so a taint flow
  alone misses the shape. This pass closes that gap by inspecting the
  controller method signature directly.

  Conservative trigger conditions (all required):
  - Class has `@Controller`, `@RestController`, `@ControllerAdvice`, or
    `@RestControllerAdvice`.
  - Method has a route annotation (`@RequestMapping`, `@GetMapping`,
    `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`).
  - A parameter has NO binding annotation. Any of `@RequestBody`,
    `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`,
    `@MatrixVariable`, `@ModelAttribute`, `@RequestPart`, `@Valid`,
    `@Validated`, `@SessionAttribute`, or `@RequestAttribute` on the
    parameter suppresses the finding.
  - The parameter type is not a Spring framework-resolved type
    (`HttpServletRequest`, `HttpServletResponse`, `HttpSession`, `Model`,
    `ModelMap`, `BindingResult`, `Errors`, `Principal`, `Authentication`,
    `Locale`, `MultipartFile`, `Part`, `RedirectAttributes`, `WebRequest`,
    `NativeWebRequest`, `UriComponentsBuilder`, `HttpEntity`,
    `RequestEntity`, `ResponseEntity`, `HttpHeaders`, `InputStream`,
    `OutputStream`, `Reader`, `Writer`, `Cookie`, `ServerHttpRequest`,
    `ServerHttpResponse`, `ServerWebExchange`, `ServletContext`).
  - The parameter type is not a scalar / boxed primitive / standard
    collection (`String`, `CharSequence`, primitives + boxed forms,
    `BigInteger`, `BigDecimal`, `UUID`, `Date`, `LocalDate`,
    `LocalDateTime`, `Instant`, `Duration`, `Period`, `List`, `Set`,
    `Collection`, `Iterable`, `Optional`, etc.).
  - Generics are stripped (`GenericBean<String, Integer>` → `GenericBean`)
    and POJO arrays (`UserDto[]`) are honored.

  Behavior:
  - Per-parameter findings — a method with two naked POJO params produces
    two findings.
  - Disable via `disabledPasses: ['spring4shell']`.
  - Non-Java languages are a no-op.

  Output:
  - `rule_id: 'spring4shell'`, `cwe: 'CWE-94'`, `severity: 'high'`,
    `level: 'error'`, category `security`.
  - Fix hint: "Annotate the parameter with @RequestBody (JSON) or
    @ModelAttribute + @InitBinder/setAllowedFields whitelisting, upgrade
    Spring to ≥ 5.3.18 / 5.2.20, and ensure JDK is patched."
  - `evidence` carries the controller class name, controller annotations,
    method name, method annotations, and the offending parameter name +
    type.

  Test coverage: 71 new tests in
  `tests/analysis/passes/spring4shell.test.ts` — positive cases for each
  controller stereotype and route annotation, parameter-binding suppression
  for every binding annotation, framework-type and scalar-type allowlists,
  multi-parameter methods, generics + array handling, language gating, and
  4 end-to-end `analyze()` integration tests covering the canonical
  Spring4Shell shape, `@RequestBody` JSON safe shape, scalar
  `@RequestParam` shape, and the legacy `HttpServlet` shape (no Spring
  annotations, must not fire). Full suite at 2100 passing tests.

## [3.46.0] - 2026-06-12

### Added

- **Structured parse-failure signal (`CircleIR.parse_status`)** — closes #27.
  Previously, tree-sitter error-recovery silently inserted `ERROR`/`MISSING`
  nodes when a source file failed to parse cleanly: extractors ran on the
  partial tree and the IR was indistinguishable from a clean parse, so the
  CLI and circle-ir-ai treated dropped files as legitimate 0-finding scans.
  This was traced from top-100 Java repo runs that intermittently lost
  coverage with no user-visible signal.

  New optional field on `CircleIR`:

  ```ts
  interface ParseStatus {
    success: boolean;
    has_errors: boolean;
    error_count: number;
    error_locations: Array<{ line: number; column: number }>;
  }
  ```

  Behavior:
  - Populated by every `analyze()` and `analyzeHtmlFile()` return — both
    success and partial-parse paths.
  - When `has_errors` is true, `logger.warn('Partial parse — IR may be
    incomplete', { filePath, language, errorCount, firstErrorLine })` is
    emitted so CLI users see the message at default log level.
  - `error_locations` is capped at 50 entries (memory bound on adversarial
    inputs); `error_count` reflects the true total.
  - Lines are 1-based to match the rest of the IR.

  Also exported: `extractParseStatus(tree: Tree)` helper from
  `circle-ir/core` for callers that parse manually.

  No findings are added, removed, or moved by this change. It is pure
  observability plumbing — the existing partial-tree extractor behavior is
  preserved (best-effort analysis on whatever the grammar recovered).

## [3.45.0] - 2026-06-12

### Added

- **`discoveryMethod` provenance plumbing on `generateFindings()`.**
  Enables the cognium-ai #26 fix to land — the LLM path of
  `runReport` can now call `generateFindings(mergedSources,
  mergedSinks, dfg, fileName)` instead of cross-producting every
  sink against every source, inheriting the existing DFG-reachability
  gate while keeping the LLM-origin signal on the output.

  New optional fields:
  - `TaintSource.discoveryMethod?: 'static' | 'llm'`
  - `TaintSink.discoveryMethod?: 'static' | 'llm'`
  - `Finding.verification.discoveryMethod?: 'static' | 'llm' | 'mixed'`

  Semantics:
  - Absent on input is treated as `'static'` (backwards compatible —
    existing callers that don't set the field keep their pre-3.45.0
    output verbatim except that `verification.discoveryMethod` is now
    populated with `'static'`).
  - On the finding: `'static'` if both contributing source and sink
    are static (or absent); `'llm'` if both are `'llm'`; `'mixed'`
    otherwise.
  - During dedup: when multiple sources reach the same sink and
    collapse into one finding, the merged `discoveryMethod`
    incorporates every contributing source's label (any disagreement
    collapses to `'mixed'`).
  - The DFG-reachability gate, the `canSourceReachSink` mapping, the
    severity rules, and the confidence math are unchanged. This is
    pure metadata plumbing — no static-path findings move.

### Changed

- `src/types/index.ts` — added documented `discoveryMethod` to
  `TaintSource`, `TaintSink`, and `Finding.verification`.
- `src/analysis/findings.ts` — `generateFindings` now computes
  `Finding.verification.discoveryMethod` from each source/sink pair
  via the new `computeDiscoveryMethod` helper, and the dedup loop
  collapses sources into a merged label via `mergeDiscoveryMethod`
  (preserving provenance across higher-confidence overwrites).

### Tests

- New `tests/analysis/findings-discovery-method.test.ts` — 12 tests
  in three suites: (1) finding-level provenance (six cases: static,
  absent, llm, llm+static, static+llm, llm+absent); (2) dedup merge
  semantics (four cases: two-static, two-llm, mixed, mixed surviving
  a confidence overwrite); (3) DFG gate invariants under
  LLM-tagged inputs (two cases: far-apart drops, incompatible
  source/sink types still gated).
- Full suite: 2018/2018 passing (2006 baseline + 12 new).

## [3.44.0] - 2026-06-12

### Added

- **JSqlParser AST visitor exclusion for SQL-injection sinks (Java).**
  Closes the JSqlParser half of
  [cognium-dev#24](https://github.com/cogniumhq/cognium-dev/issues/24).
  `matchesSinkPattern` now consults `CallInfo.receiver_type_fqn` (added
  in 3.43.0) and skips matches whose receiver type belongs to a known
  library namespace that shares simple class names with real sink
  targets without sharing the dangerous semantics. The first entry of
  the new `SINK_FQN_EXCLUSIONS` table drops `sql_injection` matches
  whose receiver FQN starts with `net.sf.jsqlparser.` — these are
  in-memory AST visitor dispatch calls (`Statement.execute(visitor)`,
  `Select.execute(visitor)`, …), not database execution.

  Behavior:
  - Receiver resolved to `net.sf.jsqlparser.*` → exclusion fires, no
    `sql_injection` sink emitted.
  - Receiver resolved to `java.sql.Statement`, `JdbcTemplate`, etc. →
    unchanged, `sql_injection` still emitted.
  - Receiver FQN null/undefined (wildcard imports, unresolvable
    receivers) → exclusion does not fire, simple-name heuristic
    continues to apply (recall preserved).

### Changed

- `src/analysis/taint-matcher.ts` — added `SinkType` to type imports,
  introduced data-driven `SINK_FQN_EXCLUSIONS: Partial<Record<SinkType,
  string[]>>` table, inserted FQN exclusion check inside
  `matchesSinkPattern` after the method-name match passes and before
  pattern.class checks.

### Tests

- New `tests/analysis/taint-jsqlparser-exclusion.test.ts` — 10 tests in
  three suites: (1) exclusion fires when receiver FQN is JSqlParser
  (4 cases: parameter, JSqlParser Select, field-typed, local-var-typed);
  (2) exclusion does not fire for real JDBC types (4 cases:
  `java.sql.Statement.execute/executeQuery/executeUpdate`,
  `JdbcTemplate.execute`); (3) conservative behavior when FQN
  unresolvable (2 cases: no imports, wildcard import).
- Full suite: 2006/2006 passing (1996 baseline + 10 new).

## [3.43.0] - 2026-06-12

### Added

- **Receiver-type resolution on `CallInfo` (Java).** Closes
  [cognium-dev#25](https://github.com/cogniumhq/cognium-dev/issues/25).
  Every Java method invocation and constructor call now carries the
  resolved class/interface name of its receiver, and (when derivable
  from the file's imports / package) the fully-qualified name. This
  eliminates the need for downstream substring-on-receiver heuristics
  that produced false reachability across classes whose identifiers
  happened to share prefixes (`userService` matching `UserServiceImpl`,
  `MockUserService`, `AbstractUserService` indiscriminately) and false
  dead-code on receivers renamed via parameter (`function f(svc:
  UserService)`).

  New `CallInfo` shape:
  ```ts
  interface CallInfo {
    receiver: string | null;
    receiver_type?: string | null;       // simple class/interface name
    receiver_type_fqn?: string | null;   // FQN if statically derivable
    // ... unchanged fields
  }
  ```

  Resolution scope (Java):
  1. **Local variable typed at declaration** — `UserService svc = ...;
     svc.foo()` → `receiver_type: 'UserService'`.
  2. **Method parameter with declared type** — newly tracked via
     `paramTypes` map populated from `method_declaration` and
     `constructor_declaration` formal parameters.
  3. **Field with declared type** — both bare `field.foo()` and
     `this.field.foo()` forms.
  4. **Static class receiver** — uppercase identifier matched against
     imports (`Collections.emptyList()` →
     `java.util.Collections`).
  5. **Constructor calls** — `new Foo(...)` populates `receiver_type:
     'Foo'` plus the FQN.

  FQN resolution sources:
  - Explicit `import com.foo.Bar;` declarations (per-file imports map).
  - Same-package inference via `package` declaration when the receiver
    type matches a class defined in the current file.
  - Implicit `java.lang.*` for the common subset (`String`, `Object`,
    `Math`, `System`, `Thread`, …).
  - Wildcard imports (`import com.foo.*;`) intentionally do **not**
    populate the FQN — too ambiguous without cross-file resolution.
    The simple `receiver_type` still resolves; only the FQN drops to
    `null` to preserve precision.

  Generics are stripped from declared types (`List<String>` → `List`),
  so the resolved `receiver_type` is always the bare type identifier.
  `super`, chained method-call expressions (`getThing().foo()`), and
  undeclared identifiers all conservatively return `null` for both
  fields — consumers should treat absence as "use the fallback
  heuristic", not "definitely external".

  Internal refactor:
  - `ResolutionContext` for Java now carries `packageName`, `paramTypes:
    Map<string, string>`, an FQN-indexed `imports: Map<string, string>`
    (previously a write-only `Set` of bare simple names), and
    `wildcardImports: string[]`.
  - New `resolveReceiverType(receiver, context)` and `resolveFqn(simple,
    context)` helpers; both pure.
  - JS/Python/Rust/Go/Bash extractors are unchanged — Rust's existing
    `receiver_type` population (scoped-identifier prefix) continues
    to work. Other-language receiver-type resolution will land in a
    follow-up when consumed by circle-ir-ai.

### Tests

- 18 new tests in `tests/extractors/receiver-type-resolution.test.ts`:
  - Local-var, parameter, field, and `this.field` receiver kinds.
  - FQN resolution via imports, `java.lang.*` fallback, same-package
    inference, and the wildcard-import → `null` FQN case.
  - Static class receiver, including dotted prefix stripping.
  - Constructor calls (`new Foo(...)`) populate type fields.
  - Conservative `null` fallback for `getThing().foo()`, `super.foo()`,
    `this.undeclared.foo()`.
  - Local variable shadowing a field of the same name.
- Full suite: **1996/1996** passing (1978 baseline + 18 new, no
  regressions).

## [3.42.0] - 2026-06-12

### Added

- **MyBatis mapper-interface call classification.** Closes the MyBatis half
  of [cognium-dev#24](https://github.com/cogniumhq/cognium-dev/issues/24).
  Mapper-interface method calls on identifiers like `userMapper`,
  `OrderMapper`, or `org.example.userMapper` are now emitted as a distinct
  sink type so downstream consumers (circle-ir-ai, cognium-dev) can route
  them differently from raw SQL execution sinks. The dangerous shape is the
  mapper's XML / `@Select` / `@Update` binding using `${...}` interpolation —
  the call site itself is only a candidate that needs binding resolution.

  Implementation:
  1. **New `mybatis_mapper_call` SinkType** (`types/index.ts`). CWE-89,
     `medium` severity. Wired through `RULE_DEFINITIONS`, `KNOWN_SINK_TYPES`
     (so existing SQL sanitizers like `@Param` and `setParameter` apply),
     and the `canSourceReachSink` HTTP-source mapping.
  2. **Suffix-wildcard receiver matching in `receiverMightBeClass`.** A
     `pattern.class` value beginning with `*` (e.g. `*Mapper`, `*Repository`)
     now matches any identifier whose simple name ends with the suffix,
     case-insensitively. Drops a dotted prefix so
     `org.example.userMapper.insert(...)` still matches `*Mapper`.
  3. **`DEFAULT_SINKS` extended** with 11 MyBatis mapper-interface methods
     (`insert`, `insertSelective`, `update`, `updateByPrimaryKey`,
     `updateByPrimaryKeySelective`, `delete`, `deleteByPrimaryKey`,
     `selectOne`, `selectList`, `selectByPrimaryKey`, `selectByExample`),
     all `class: '*Mapper'`, `type: 'mybatis_mapper_call'`,
     `languages: ['java']` to prevent cross-language collisions. The same
     entries in `configs/sinks/sql.yaml` were also retyped for parity with
     external YAML-config consumers.

### Tests

- New `tests/analysis/taint-mybatis-mapper.test.ts` (17 tests):
  - `userMapper.insert(user)` emits `mybatis_mapper_call`, never
    `sql_injection`.
  - `orderMapper.selectByExample(criteria)` and all 9 other configured
    mapper methods (`insertSelective`, `update`, `updateByPrimaryKey`,
    `updateByPrimaryKeySelective`, `delete`, `deleteByPrimaryKey`,
    `selectOne`, `selectList`, `selectByPrimaryKey`) emit the new type.
  - Wildcard variants: `UserMapper.insert(...)` (static-style) and
    `org.example.userMapper.insert(...)` (dotted receiver) both match.
  - Regressions confirmed: `Statement.execute(sql)` and
    `JdbcTemplate.update(sql)` still emit `sql_injection`;
    `userService.insert(user)` does not match the wildcard;
    `userMapper.findById(id)` (not in the configured method list) emits
    no sink.

- Full circle-ir suite: **1978 tests passing** (was 1961).

[3.42.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.41.0...circle-ir-v3.42.0

## [3.41.0] - 2026-06-12

### Added

- **Typed-overload-aware deserialization sink classification.** Closes
  [cognium-dev#22](https://github.com/cogniumhq/cognium-dev/issues/22). The
  Jackson / Gson / FastJson / SnakeYAML deserialization sinks now distinguish
  the polymorphic (untyped or dynamic-class) calls from the safe typed
  overloads where the target type is a compile-time `Foo.class` literal:

  ```java
  mapper.readValue(json)                       // UNSAFE — sink emitted
  mapper.readValue(json, User.class)           // SAFE   — no sink
  mapper.readValue(json, Class.forName(t))     // UNSAFE — sink emitted
  gson.fromJson(json, User.class)              // SAFE   — no sink
  gson.fromJson(json, type)                    // UNSAFE — sink emitted
  JSON.parseObject(json, User.class)           // SAFE   — no sink (FastJson)
  yaml.load(stream, User.class)                // SAFE   — no sink (SnakeYAML)
  yaml.load(stream)                            // UNSAFE — sink emitted
  ```

  Implementation:
  1. **New `SinkPattern.safe_if_class_literal_at?: number`** field in
     `types/config.ts`. Declares the 0-indexed argument position where a
     compile-time class literal makes the call safe. Optional and backward
     compatible — patterns without it are unchanged.
  2. **Class-literal gate in `findSinks`** (`taint-matcher.ts`). Uses the
     regex `^(?:[A-Za-z_]\w*\.)*[A-Z]\w*(?:\[\])*\.class$` against the
     argument's `literal ?? expression`, which matches `User.class`,
     `com.example.User.class`, and `String[].class` but **never** matches
     `Class.forName(...)`, `getClass()`, `type`, or any non-literal — those
     remain dangerous and still match.
  3. **`DEFAULT_SINKS` annotated** for `ObjectMapper.readValue`,
     `JSON.parseObject`, `JSONObject.parseObject`, `Gson.fromJson`,
     `Yaml.load`, and `Yaml.loadAs` with `safe_if_class_literal_at: 1`.

- **Language scoping for Python deserialization sinks.** While auditing the
  collision space for #22, found that the Python `pickle.load*`,
  `marshal.loads`, and `yaml.load*` patterns had no `languages` guard, so
  the lowercase `yaml` class name was matching Java locals named `yaml` (the
  conventional SnakeYAML variable name) and emitting spurious Python-flavoured
  deserialization sinks on Java code. Added `languages: ['python']` to all
  five entries in `config-loader.ts:1445-1449`.

### Tests

- 15 new tests in `tests/analysis/taint-typed-deserialization.test.ts`
  covering Jackson, Gson, FastJson, SnakeYAML typed/untyped/dynamic overloads,
  fully-qualified and array class-literal shapes, and a regression that
  `ObjectInputStream.readObject()` (no safe overload) is still a sink.
- Full suite: **1961 / 1961 passing** (101 files).

### Downstream

`circle-ir-ai` can now delete the 3 regex entries in
`security-scan/sink-filters.ts:NON_SINK_PATTERNS`
(`readValue` / `fromJson` / `parseObject`) — the AST is doing the AST's job.

## [3.40.0] - 2026-06-12

### Added

- **`code` field on `TaintSource` and `TaintSink`.** Closes
  [cognium-dev#23](https://github.com/cogniumhq/cognium-dev/issues/23). Every
  emitted `TaintSource` / `TaintSink` now carries the trimmed source-line text
  at its recorded `line`, so downstream consumers (LLM enrichment pipelines,
  SARIF reporters, the circle-ir-ai boundary harness) can render the offending
  line without re-parsing the file. This matters because the tree-sitter tree
  is disposed after analysis (3.x source-disposal contract) — by the time
  enrichment runs the AST is gone and the consumer's only options were
  reading the file again or guessing from `location`/`method`. Two paths:
  1. **`analyzeTaint(calls, types, config, hierarchy, language, code?)`** — new
     optional `code` arg. When supplied, `findSources` / `findSinks` populate
     `code` on every emitted entry after dedup using
     `code.split('\n')[line - 1].trim()`.
  2. **Exported `attachSourceLineCode(sources, sinks, code)`** helper for
     passes that emit sources/sinks outside `analyzeTaint` (currently
     `LanguageSourcesPass` for Python/JS assignment sources, Bash patterns,
     and Java getter sources). Idempotent — only fills missing `code` values
     so callers can pre-seed if they have a richer rendering.
  Backward compatible: `code` is optional everywhere, and `analyzeTaint`
  without the new arg leaves the field unset (verified by regression test).
  Threaded through `analyzer.ts:626` and `TaintMatcherPass` via the existing
  `PassContext.code` channel, and re-exported from `analysis/index.ts`,
  `core-lib.ts`, and the top-level `index.ts`.

## [3.39.0] - 2026-06-11

### Added

- **Cross-instance field-binding taint propagation.** Closes the canonical
  CWE-Bench-Java Jenkins shape and adjacent framework-DI patterns that
  3.38.0 still could not surface, where the source is bound onto a field by
  one class (`@DataBoundConstructor`, `@Autowired`, setter chain) and
  consumed by another class reading that field on an aliased instance.
  Two surgical changes in `CrossFileResolver` + the project-level pass:
  1. **`findInterproceduralTaintPaths` — caller-body sink emission (step 2c).**
     After marking caller-side locals tainted via a wrapper return, also
     check whether any sink in the *caller's own* method body consumes a
     tainted variable. Closes shapes where the final sink (`Paths.get(p)`,
     `Runtime.exec(cmd)`) lives in the caller's file rather than in a
     cross-file callee — previously only callee-side sinks were emitted.
  2. **New `FieldTaintInfo` summary + `findFieldBindingTaintPaths()`.**
     `analyzeFieldTaint(ir)` runs per file, recording:
     - Constructor-bound fields (via existing `constructor_field` sources).
     - Setter writers (`set<Field>(<param>)` with one param).
     - `@Autowired` / `@Inject` / `@Resource`-annotated fields.
     `findFieldBindingTaintPaths()` per caller method scans local DFG defs
     and co-located uses to detect `local = receiver.field` field-reads
     (handles both expression-bearing defs and the DFG-only case where the
     `expression` field is absent — falls back to co-located use-pair
     matching `(receiver, field)` against the receiver's declared type's
     field list). When the receiver's declared type owns a tainted field,
     the local is marked tainted with origin anchored to the writer, and
     paths are emitted via both caller-body-sink and cross-file-callee
     forwarding paths. Hop kind union extended to include `field_write`
     and `field_read`.
  3. **`CrossFilePass` integration.** Field-binding paths are merged into
     the existing `ipPaths` flow and converted with the same TaintPath
     conversion logic (dedup against direct cross-file flows + IP paths).
- **Verification fixtures (4)** in `tests/analysis/project-graph.test.ts`:
  - Jenkins ReadTrustedStep — ctor-bound field + direct `step.path` read +
    `Paths.get` sink in caller body. Emits 4-hop `constructor_field` →
    `path_traversal` (CWE-22) path with source on `ReadTrustedStep`.
  - Jenkins ReadTrustedStep — ctor-bound field + `step.getPath()` getter
    + `Paths.get` sink in caller body. Closed by the caller-body-sink
    emission in step 2c.
  - `@Autowired` — Spring `@Autowired` field on a service read by an
    aliased instance reaching `Paths.get`. Emits `autowired_field` source.
  - Ctor + setter mix — class with both `@DataBoundConstructor` and a
    setter for the same field still surfaces the ctor-bound path; setter
    presence does not regress ctor detection.
- **Why this is not a redesign** — Both changes reuse every existing
  primitive: `methodTaintInfo`, `resolveCall`, `taint.sources/sinks`,
  `ir.dfg.defs`/`uses`, and the existing `matchTaintedArg` heuristic. The
  walk is two linear passes per caller method, with the second activated
  only when `fieldTaintInfo` is non-empty.
- Total suite size: **1939 passing tests** (1935 baseline from 3.38.0 + 4
  new fixtures).

## [3.38.0] - 2026-06-11

### Fixed

- **Cross-file inter-procedural taint chains now resolve through wrapper return values and sink-param summaries (#19).** Closes the Java Spring-shape gap reported for CVE-2011-2732 (`sendRedirect` open redirect via `UrlHandler.determineTargetUrl` wrapper) — and by virtue of the same fix, the Jenkins #1 shape (`@DataBoundConstructor` field bound to user input flowing through `BuildStep` → `CommandRunner.run` → `Runtime.exec`). After diagnostic review the issue was reframed: it is not Spring-specific. The engine already had *every* intermediate signal — sources per file, sinks per file, the intra-file `interprocedural_param → sink` flow in the sink wrapper, and cross-file call resolution with `args_mapping`. Only the *chaining* between them was missing.
- **Root cause** — three independent gaps in `CrossFileResolver`:
  1. **`isMethodTaintSource` treated `interprocedural_param` sources as "real"**, so every internal helper with typed parameters was marked `returnsSource = true`. Cross-file `wrapper(...)` calls would then ghost-taint their callers.
  2. **`findTaintedParams` only looked at annotations (`@RequestParam` / `@RequestBody` / `@PathVariable`)** — so a sink-wrapper like `RedirectStrategy.sendRedirect(req, res, String url) { res.sendRedirect(url); }` carried `taintedParams = []`, and the `args_mapping[].taint_propagates` summary on every cross-file call was permanently stuck at `false`.
  3. **No chaining method existed**. `findCrossFileTaintFlows()` only emits `source-in-caller → sink-in-callee` flows; it cannot see the canonical 2-wrapper chain `source-in-callee-A → wrapper-return-in-caller → sink-call-in-caller → sink-in-callee-B`, even though `callee-A.returnsSource=true` + `callee-B.taintedParams=[2]` is the exact summary needed to link them.
  4. **`findCrossFileTaintFlows()` overapproximated** when the caller had its own real source: it emitted a path to any downstream cross-file sink regardless of whether the call's *arguments* actually carried the source. A `String safe = sanitizer.sanitizeUrl(raw); sendRedirect(req, res, safe)` shape FP'd because `raw` (the source variable) was never threaded through.
- **Fix — four minimal changes in `CrossFileResolver` + chained-emit in `CrossFilePass`:**
  1. `isMethodTaintSource` + `getSourceType` now skip `interprocedural_param` sources entirely.
  2. `findTaintedParams` adds a sink-arg-matching heuristic: for every known sink inside the method body, scan the corresponding call expression's argument variables and whole-word-match them against the method's parameter names. Hits are added to `taintedParams`.
  3. New `findInterproceduralTaintPaths()` walks each caller method in line order, seeds a per-method tainted-var map from real sources, marks every `local` DFG def at a call site as tainted when the resolved callee has `returnsSource = true` and is not a sanitizer, and emits a multi-hop `InterproceduralTaintPath` whenever a tainted variable is passed to a callee param in `taintedParams`. Confidence decays by 0.85 per hop, floor 0.30.
  4. `findCrossFileTaintFlows()` now derives the source's owning local-def variable (when DFG has one) and requires the cross-file call's arguments to reference it (whole-word). Eliminates the sanitized-wrapper FP without disabling the simpler 2-file shape.
  5. `CrossFilePass` appends `findInterproceduralTaintPaths()` paths to `taintPaths` (deduped against direct flows at the same source/sink coordinates) and populates `args_mapping[].taint_propagates` from the callee's `taintedParams` summary.
- **Verification fixtures (4)** in `tests/analysis/project-graph.test.ts`:
  - CVE-2011-2732 shape: `LoginController.handle → UrlHandler.determineTargetUrl → RedirectStrategy.sendRedirect → res.sendRedirect`. Emits a 4-hop `cf-ip-…` TaintPath, `http_param@UrlHandler:6 → ssrf/CWE-601@RedirectStrategy:7`, with `taint_propagates=true` on param 2 of the sendRedirect cross-file call.
  - Negative control: same shape with `UrlSanitizer.sanitizeUrl` between source and sink — no path emitted (sanitizer name heuristic + variable-connectivity gate).
  - CVE-2018-1260 shape: SpEL parser + `getValue()` in a helper called from a controller — verified the helper file still surfaces an `http_param`-rooted intra-file flow.
  - Jenkins #1 shape: `@DataBoundConstructor` → field getter → `CommandRunner.run(cmd)` → `Runtime.exec(cmd)`. Verified `run`'s param 0 is now flagged `taint_propagates=true`.
- **Why this is not a redesign of cross-file analysis** — The new method reuses every existing primitive: `resolveCall`, `methodTaintInfo`, per-file `taint.sources/sinks`, `ir.dfg.defs`, and `args_mapping`. The walk is a single per-method linear pass over calls. No new IR types, no new pipeline pass, no project-level fix-point.
- **Why Java suites do not regress** — The variable-connectivity gate in `findCrossFileTaintFlows` only fires when DFG has a local def at the source line; sources without a known variable retain the prior behavior. The new chain method only fires when both `returnsSource` (post-`interprocedural_param` exclusion) and `taintedParams` (now sink-arg-derived) are populated. The sanitizer guard short-circuits both directions. Full suite remains at 1935 passing tests (1931 baseline from 3.37.0 + 4 fixtures).

## [3.37.0] - 2026-06-11

### Fixed

- **Python taint flows now propagate through assignment chains, container round-trips, and list-append patterns (#20).** After #18 unblocked *one-hop direct* Python flows (`uid = request.form.get(...); execute("..." + uid)`), every *indirect* shape still produced `taint.flows = []` — the dominant remaining driver of OWASP BenchmarkPython false-negatives and the blocker for circle-ir-ai#75. Probe-confirmed shapes:
  - **Shape A — configparser round-trip:** `conf.set('s','k', tainted); bar = conf.get('s','k'); cur.execute(f'... {bar}')`.
  - **Shape B — list/dict round-trip:** `lst.append(tainted); bar = lst[0]; argList = ['sh','-c', f'echo {bar}']; subprocess.run(argList)`.
  - **Shape C — simple alias chain (NOT in the original bug report, found during analysis):** `bar = uid; sql = "..." + bar; cur.execute(sql)`. Even one rename of a tainted variable broke the flow.
- **Root cause** — single defect with two contributing parts, both downstream of #18:
  1. **`detectExpressionScanFlows` only scanned for source.variable names**, never for derived/aliased variables. The supplement word-boundary-matches sink-argument expressions against the `source.variable` field set by `findPythonAssignmentSources`, but `findPythonAssignmentSources` only emits a source for the *original* `var = request.form.get(...)` assignment. Subsequent aliases (`bar = uid`), container reads (`bar = conf.get(...)`), or compound expressions (`sql = "..." + bar`) were never added to the scan set.
  2. **`buildPythonTaintedVars` already propagated taint through aliases, configparser, dict-subscript and aug-assign**, but its result was only consumed by `analyzer.ts` for sanitizer-detection / session-write checks — never threaded back into the expression-scan flow detector. It also had no rule for receiver-mutating container methods (`lst.append`, `set.add`, `deque.put`, …), so list-append-then-subscript-read (Shape B) was the one inherent gap in its propagation rules.
- **Fix — two minimal, surgical changes:**
  1. `detectExpressionScanFlows` now accepts `code` + `language` and, when `language === 'python'`, calls `buildPythonTaintedVars(code)` to expand `sourcesWithVar` with synthetic source records for every derived/aliased Python variable. Synthetic records inherit the earliest real source's `line`/`type`/`confidence` so emitted flows still anchor at the original `request.form.get(...)` site, not at the alias. Word-boundary scan and `argPositions` filter logic unchanged.
  2. `buildPythonTaintedVars` gained one new rule: `(\w+)\.(append|extend|insert|add|push|put|appendleft)\(taintedExpr)` taints the receiver. This composes naturally with the existing dict-access propagation so `lst.append(x); bar = lst[0]` round-trips correctly without a separate Shape-B handler.
- **Why this is not "build a Python DFG"** — A proper `buildPythonDFG` is still future work (~990 LOC mirroring `buildJavaDFG`, plus AST-walk pass for compound-expression arg decomposition). The supplement+rule are ~50 LOC total, deterministic, regex-based, and unblock the entire BenchmarkPython false-negative tail today.
- **Why Java does not regress** — The Python alias expansion is gated on `language === 'python'`. Java sources rarely set `.variable` (matched on annotations/types), so `sourcesWithVar` is empty for Java and the supplement is a no-op. Verified by an explicit end-to-end Java sqli non-regression test plus the full 156-case Juliet suite.
- **6 end-to-end regression tests** in `tests/analysis/taint-propagation.test.ts` covering: Shape A (configparser → sqli), Shape B (list append → subprocess cmdi), Shape B variant (set.add → list cast → cmdi), Shape C (simple alias → sqli), the #18 one-hop direct positive control, and Java sqli non-regression.
- Total suite size: **1931 passing tests** (1925 baseline from 3.36.0 + 6 new).

### Notes

- The original bug report enumerated shapes A, B, and a third "helper module" cross-module shape (#3). Probe revealed a fourth shape — **simple variable aliasing** (`bar = uid`) — that the reporter did not flag and that fails for the same root cause. The fix addresses it as a free corollary because `buildPythonTaintedVars` already tracked aliases.
- Cross-module / cross-file Python helper indirection (`helpers.db_sqlite.results(cur, sql)`) is **not** addressed by this release. It requires inter-procedural / cross-file taint summaries (the reporter's option #3), which is a substantially larger architectural change. Filed as future work alongside `buildPythonDFG`.
- The supplement is now powered by a deterministic regex-based receiver-taint map, intentionally distinct from the AST-walking propagator used for Java in `ConstantPropagationPass`. Long-term, both should converge on a single Python-aware DFG-based design; in the interim the regex approach matches the Python-specific patterns the BenchmarkPython suite exercises and has no observed false-positive trigger across the full 1931-test suite.

[3.37.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.36.0...circle-ir-v3.37.0

## [3.36.0] - 2026-06-11

### Fixed

- **Python taint flows emit for every sink category — systematic fix (#18).** `result.taint.flows` was empty for *every* non-trivial Python case (sqli, command_injection, path_traversal, code_injection, deserialization, xxe, ldap_injection, open_redirect, …) — including the XSS case the reporter believed was working. Investigation found two structural defects affecting all categories simultaneously, not a per-category sink/source modelling gap:
  1. **No per-language DFG builder for Python.** `core/extractors/dfg.ts:buildDFG()` dispatches on `language` with explicit branches for JS, Rust, Bash, and Go. Python falls through to `buildJavaDFG()`, which scans for `method_declaration` AST nodes; Python's tree-sitter grammar emits `function_definition`. Result: every Python file produced `dfg = { defs: [], uses: [], chains: [] }`, so the DFG-based propagator in `taint-propagation.ts:propagateTaint()` never had a chain to walk.
  2. **Python compound-expression args lose `arg.variable`.** `core/extractors/calls.ts:extractPythonArguments` only sets `arg.variable` when the AST child node is a bare `identifier`. Calls like `cur.execute("SELECT … " + uid)` (binary_operator), `redirect(url)` wrapped in compound expressions, or `conn.search_s('dc=x', SCOPE, '(uid=' + u + ')')` leave `arg.variable = undefined` with only `arg.expression` populated, defeating the `arg.variable === use.variable` matching the DFG propagator relies on.
- **Fix: language-agnostic expression-scan flow supplement** in `TaintPropagationPass`. After the DFG propagator and the three existing supplements (array, collection, parameter) run, `detectExpressionScanFlows()` iterates each sink × each call at that sink's line × each argument expression and word-boundary-matches every source's explicit `.variable` field against the expression text. Reuses the existing FP filters (`isCorrelatedPredicateFP`, `isFalsePositive`, `unreachableLines`) and respects `sink.argPositions`. Source line must strictly precede sink line.
  - **Why this fixes every category at once** — Python's `LanguageSourcesPass.findPythonAssignmentSources` already sets `source.variable` for assignment-style sources (`uid = request.form.get(...)` → `{ type: 'http_body', variable: 'uid', … }`), so a single variable-tracking primitive covers every sink type the SinkFilterPass produces. Not a category-by-category patch.
  - **Why Java does not regress** — Java HTTP-source extractors do not populate `source.variable` (sources are matched on annotations/types, not LHS names), so `sourcesWithVar` is typically empty for Java; the supplement is a no-op. Verified by the existing 156-case Juliet suite + a dedicated `does NOT emit when source has no variable field` unit test + an end-to-end Java sqli test.
  - **Why this is not "just build a Python DFG"** — A proper Python DFG builder would be ~990 LOC mirroring `buildJavaDFG`, plus it would still not address gap #2 (compound-expression arg decomposition would need a separate AST-walk pass). The supplement is ~40 LOC and unblocks circle-ir-ai#75 (OWASP BenchmarkPython false-negative rate) immediately. A full Python DFG remains future work and would naturally subsume this supplement.
- **10 unit tests** in `tests/analysis/passes/taint-propagation-pass.test.ts` covering: positive cases for sqli/cmdi/pathtraver, two distinct sinks at same line emitting two flows (dedup keys on `sink_type`), `argPositions` filter (parameterised-query position 1 does not match position-0 sink), word-boundary requirement (source `id` does not match identifier `fid`), dead-code suppression, no-variable Java source non-emission, source-after-sink rejection, and DFG/expression-scan dedup.
- **11 end-to-end tests** in `tests/analysis/taint-propagation.test.ts` running the full `analyze()` pipeline across every previously-broken Python category (sql_injection, command_injection ×2, path_traversal, code_injection, deserialization, xxe, ldap_injection, open_redirect), the XSS positive control, and a Java sqli non-regression case.
- Total suite size: **1925 passing tests** (1904 baseline + 21 new).

### Notes

- Reporter's premise that "XSS works, others don't" was falsified by direct probe — XSS flows were also 0 prior to this fix; the existing XSS test fixtures happen to hit the array/collection supplement code paths rather than the DFG path. The reporter's perception likely came from CLI-level findings emitted by `XssReflectivePass`, which inspects calls directly without consulting `taint.flows`.
- The Python DFG fall-through (gap #1) is a latent bug that affects other consumers of `ir.dfg` for Python files (e.g. `DFGVerifier`, `PathFinder`, circle-ir-ai). A proper `buildPythonDFG` is filed as future work; until then `ir.dfg` remains structurally empty for Python and downstream consumers should rely on `ir.calls` + `ir.taint.flows` instead.
- The XPath injection probe shows `sinks=0` for `tree.xpath()` — that is a Python sink-config gap (separate from #18) and is not addressed here.

[3.36.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.35.0...circle-ir-v3.36.0

## [3.35.0] - 2026-06-11

### Added

- **Jenkins Groovy sandbox dispatch surface — systematic sink coverage (#17, CVE-2023-24422).** The default `code_injection` sink registry now covers the full `org.kohsuke.groovy.sandbox` and `org.jenkinsci.plugins.scriptsecurity.sandbox.groovy` dispatch surface, not just `SandboxInterceptor.onNewInstance`. The CVE-2023-24422 sandbox-bypass class of vulnerabilities reaches Jenkins through any of these dispatch hooks; modelling only `onNewInstance` left realistic attack shapes (method-call and static-call dispatch) silently undetected even though the YAML sink file already listed them. The gap existed because `getDefaultConfig()` reads the embedded `DEFAULT_SINKS` array, not the YAML files.
  - **`SandboxInterceptor`** (9 methods, all `code_injection` / CWE-94 / critical): `onMethodCall`, `onStaticCall`, `onGetProperty`, `onSetProperty`, `onGetAttribute`, `onSetAttribute`, `onMethodPointer`, `onSuperCall`, `onSuperConstructor`. `onNewInstance` remains as before (kept for regression).
  - **`GroovyInterceptor`** (parent class — 5 methods): `onMethodCall`, `onNewInstance`, `onStaticCall`, `onGetProperty`, `onSetProperty`. Plugins extending `GroovyInterceptor` directly were previously uncovered.
  - **`SandboxTransformer.call`** — AST transformer (CVE bypass typically targets the transformer's pre-execution rewriting step).
  - **`GroovySandbox.runInSandbox`** — Jenkins outer wrapper used by script-security plugin consumers (replaces the fictional `GroovySandbox.sandbox` entry the previous YAML referenced).
  - All 16 entries are mirrored in both `src/analysis/config-loader.ts` (`DEFAULT_SINKS`, the registry actually consumed by `getDefaultConfig()`) and `configs/sinks/code_injection.yaml` (the registry consumed by CLI projects with custom configs). The existing `SandboxInterceptor.onNewInstance` entry in `DEFAULT_SINKS` (classified as `command_injection` / CWE-78 since pre-3.x) is left untouched to avoid breaking downstream consumers that filter on `type === 'command_injection'`; the regression-guard test accepts either type so future normalisation is a separate, deliberate change.
- **9 regression tests** in `tests/analysis/taint.test.ts` covering: each new dispatch hook (positive), the existing `onNewInstance` (regression guard), parent-class `GroovyInterceptor.onMethodCall`, `SandboxTransformer.call`, `GroovySandbox.runInSandbox`, batched property/attribute interception entries, a negative control proving an unrelated `ApplicationLogger.onMethodCall` does NOT match (receiver-class heuristic correctly discriminates), and an end-to-end CVE-2023-24422 shape with `http_param` + `http_header` sources reaching `SandboxInterceptor.onMethodCall`.
- Total suite size: **1904 passing tests** (1895 baseline + 9 new).

### Notes

- Reporter's original premise — that the SandboxInterceptor methods were modelled as *sanitizers* — was incorrect after verification. `SANITIZER_METHODS` contains zero interceptor entries, and the YAML already classified `onMethodCall`/`onStaticCall`/`onNewInstance` as critical sinks. The real defect was the YAML-vs-`DEFAULT_SINKS` registry split: `getDefaultConfig()` only ever reads `DEFAULT_SINKS`, so the YAML entries were dead-letter for any consumer (including circle-ir's own tests) that didn't explicitly load the YAML. This release closes that split for the Jenkins Groovy surface and broadens coverage to the full dispatch API rather than landing a one-off CVE patch.

[3.35.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.34.0...circle-ir-v3.35.0

## [3.34.0] - 2026-06-10

### Added

- **Runtime registration extractor — Phase 3: Rust trait dispatch (#15).** `ir.runtime_registrations` now records Rust dispatch-table wiring that is invisible to plain call extraction. The same `RuntimeRegistration` shape used for JS/TS Phase 1 and Python Phase 2 is reused; a new `kind: 'trait_impl'` value covers both real trait impls and inventory/linkme collector entries.
  - **`impl Trait for Type` blocks** emit one `trait_impl` registration per method in the body. `registrar.method` and `handler.name` are the method name, `registrar.receiver` is the Self type text, and `path` is the last segment of the trait path. Inherent impls (`impl Type { … }`, no `trait` field) are skipped.
  - **Trait classification cascade:**
    1. Last-segment match against the stdlib trait set (`Display`, `Debug`, `Drop`, `Clone`, `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`, `Default`, `From`, `Into`, `TryFrom`, `TryInto`, `AsRef`, `AsMut`, `Borrow`, `BorrowMut`, `Deref`, `DerefMut`, `Iterator`, `IntoIterator`, `FromIterator`, `Future`, `Send`, `Sync`, `Sized`, `Unpin`, `Error`, `FromStr`, `ToString`) → `framework: 'stdlib'`. Covers both bare (`Display`) and fully scoped (`std::fmt::Display`) names.
    2. Prefix regex against the full trait path: `actix_web::*` / `actix::*` → `actix`, `axum::*` → `axum`, `rocket::*` → `rocket`, `tokio::*` → `tokio`, `serde::*` → `serde`, `std::*` / `core::*` / `alloc::*` → `stdlib`.
    3. Fallthrough → `framework: 'unknown'`.
  - **`inventory::submit! { Plugin::new("ping") }` macros** are emitted as `kind: 'trait_impl'`, `framework: 'inventory'`, `registrar.method: 'inventory::submit'`, `handler.name` = the first identifier in the macro token tree.
  - **`#[linkme::distributed_slice(REGISTRY)]` / `#[distributed_slice(REGISTRY)]` attributes** walk parent siblings to find the next decorated `static_item` or `function_item`, emitting `kind: 'trait_impl'`, `framework: 'linkme'`, `registrar.method: 'linkme::distributed_slice'`, `handler.name` = the static/function name.
  - The Rust node cache is extended with `attribute_item` and `static_item` so the new attribute walker stays O(N).
- **11 Rust regression tests** in `tests/extractors/runtime-registrations.test.ts` cover: per-method emission for `impl Handler for PingHandler`, inherent-impl skipping, stdlib traits (`Display`, `Debug`, `Iterator`) classified by last-segment match, scoped `std::fmt::Display` resolving to stdlib, `actix_web::FromRequest` → `actix`, `serde::Serialize` → `serde`, `inventory::submit!` handler extraction, `#[linkme::distributed_slice]` on `static`, bare `#[distributed_slice]` on `fn` (after `use linkme::distributed_slice;`), unrelated attributes/macros (`#[derive]`, `#[cfg(test)]`, `println!`, `vec!`) emitting nothing, and a mixed-file integration case combining trait impls + inventory + linkme.
- Total suite size: **1895 passing tests** (1884 baseline + 11 new).

### Notes

- Phase 3 completes the runtime-registration roadmap from issue #15 (JS/TS Express → Python decorators → Rust trait dispatch). Downstream consumers (e.g. cognium-ai dead-code reachability) can now treat any `kind === 'trait_impl'` handler as a virtual entry root, eliminating "unreachable" false positives for Rust trait-dispatch handlers and inventory/linkme registry entries.

[3.34.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.33.0...circle-ir-v3.34.0

## [3.33.0] - 2026-06-10

### Added

- **Runtime registration extractor — Phase 2: Python decorators (#15).** `ir.runtime_registrations` now records every `@decorator` attached to a Python `function_definition`. The same `RuntimeRegistration` shape used for JS/TS Phase 1 is reused so downstream consumers can treat JS routes and Python routes uniformly.
  - **Decorator shapes:** bare identifier (`@my_dec`), attribute (`@app.route`, `@pytest.fixture`), and call (`@app.route('/x', methods=['GET'])`, `@click.command()`). Path is extracted from the first string literal argument when present.
  - **Classification cascade:**
    1. Stdlib decorators (`property`, `staticmethod`, `classmethod`, `abstractmethod`, `cached_property`, `dataclass`, `cache`, `lru_cache`, `singledispatch`, `singledispatchmethod`, `contextmanager`, `asynccontextmanager`, `final`, `override`, `wraps`) → `kind: 'decorator'`, `framework: 'stdlib'`.
    2. Framework-prefixed (`pytest.*`, `click.*`, `numba.*`, `celery.*`) → `kind: 'decorator'`, `framework: <name>`.
    3. HTTP-route methods (`route`, `get`, `post`, `put`, `patch`, `delete`, `head`, `options`) on router-shaped receivers (`app`, `router`, `blueprint`, `bp`, `api`, `application`, plus `*_router` / `*_bp` / `*_app` suffix) → `kind: 'http_route'`, `framework: 'flask'` (FastAPI/Flask share the call shape so downstream consumers should also consult `imports`).
    4. Middleware methods (`before_request`, `after_request`, `teardown_request`, `before_first_request`, `teardown_appcontext`, `middleware`) → `kind: 'middleware'`.
    5. Event methods (`errorhandler`, `on_event`, `exception_handler`) → `kind: 'event_listener'`.
    6. `.task` with celery import, Django bare decorators (`login_required`, `permission_required`, `csrf_exempt`, `require_http_methods`, `require_GET`, `require_POST`, `require_safe`) → framework tags.
    7. Fallthrough → `kind: 'decorator'`, `framework: 'unknown'`.
  - **Chained decorators emit one registration each**, all pointing at the same decorated handler — `@app.route('/x') / @auth_required / def get_user()` produces two entries (`http_route flask` + `decorator unknown`) sharing `handler.name = 'get_user'`.
- **10 Python regression tests** in `tests/extractors/runtime-registrations.test.ts` cover: Flask `@app.route` with path extraction, chained `@app.route + @auth_required`, FastAPI `@router.get`, `@app.before_request` middleware, `@app.errorhandler(404)` event-listener, `@pytest.fixture` and `@click.command()` framework tagging, `@property` stdlib tagging, bare unknown decorators, async function decorators, and the negative case of a plain undecorated function emitting nothing.
- Total suite size: **1884 passing tests** (1874 baseline + 10 new).

### Notes

- Phase 3 (Rust trait dispatch — `impl Trait for Type`, `Box<dyn Trait>`, `inventory::submit!`, `linkme::distributed_slice`) remains scheduled for a separate PR. The JS Phase 1 extractor and Python Phase 2 extractor share the same `RuntimeRegistration` shape, so adding Rust will only widen the framework union.

[3.33.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.32.0...circle-ir-v3.33.0

## [3.32.0] - 2026-06-10

### Added

- **Runtime registration extractor — Phase 1 (#15).** New optional IR field `runtime_registrations: RuntimeRegistration[]` records framework dispatch-table wiring that is invisible to plain call extraction. Phase 1 covers JS/TS Express-family patterns: HTTP routes (`app.METHOD(path?, ...handlers)` for METHOD ∈ `{get, post, put, patch, delete, head, options, all}`), middleware (`app.use`, `router.use`), and event listeners (`server.on`, `emitter.once`, `socket.ws`). Each entry resolves the handler — named identifier → declaration-site location, inline arrow / function expression → `name: null` at the lambda site, member-expression → textual reference — and records `kind`, `framework`, `path`, and the registrar call site. Receiver filtering keeps noise out: only express-shaped receivers (`app`, `router`, `server`, `*Router`, `*App`, `*Server`) match, or any receiver when a framework module (`express`, `fastify`, `koa`, `@nestjs/*`, etc.) is imported. Phases 2 (Python decorators) and 3 (Rust trait dispatch) will follow as separate PRs. Downstream consumers (e.g. cognium-ai dead-code reachability) can now treat handler targets as virtual entry roots, eliminating "unreachable" false positives for framework-registered handlers.
- **10 regression tests** in `tests/extractors/runtime-registrations.test.ts` cover: named handler resolution, inline-arrow `name=null`, variadic middleware chains (one registration per handler-position arg), `router.use` middleware, `server.on` event listener, negative-control for unrelated receivers, non-JS language returns `[]`, TypeScript with `import express from 'express'`, plain template-string paths, and template-with-substitution path treated as no-path.
- Total suite size: **1874 passing tests** (1864 baseline + 10 new).

[3.32.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.31.0...circle-ir-v3.32.0

## [3.31.0] - 2026-06-09

### Fixed

- **NiFi Expression Language injection sink missing (#11, CVE-2023-36542).** `PropertyValue.evaluateAttributeExpressions(...)` runs NiFi EL against user-controlled property values; this is the exact RCE shape used by CVE-2023-36542. The method is now registered as a `code_injection` / CWE-94 / critical sink in `DEFAULT_SINKS` (both class-qualified on `PropertyValue` and as a classless variant for receiver-typed call resolution).
- **XWiki rendering pipeline XSS sources + sinks missing (#10, CVE-2022-24897 / CVE-2023-29201 / CVE-2023-29528 / CVE-2023-36471 / CVE-2023-37908).** Five XSS CVEs in `xwiki-commons` / `xwiki-rendering` shared an unmodeled-pattern root cause. Added:
  - **Sources:** `XWikiRequest.get` / `getParameter` / `getParameterValues` / `getParameterMap` / `getHeader` (URL/form/header data).
  - **Sinks:** `WikiPrinter.print/println`, `DefaultWikiPrinter.print/println`, `XHTMLWikiPrinter.print/println/printXML/printXMLComment`, `AnnotatedXHTMLWikiPrinter.print/println/printXMLElement/printXMLStartElement`, and the block-render entry points `BlockRenderer.render` / `AbstractBlockRenderer.render` / `DefaultBlockRenderer.render`.

### Added

- **Regression suite for #11 / #10** — `tests/analysis/taint.test.ts` gains four cases:
  - `describe('NiFi Expression Language injection (issue #11, CVE-2023-36542)')` — pins `PropertyValue.evaluateAttributeExpressions` as `code_injection` / CWE-94.
  - `describe('XWiki rendering pipeline XSS (issue #10, …)')` — three cases pinning the XWikiRequest → DefaultWikiPrinter.print XSS flow, XHTMLWikiPrinter.println sink wiring, and DefaultBlockRenderer.render sink wiring.
- Total suite size: **1864 passing tests** (1860 baseline + 4 new).

### Notes

- **#11 deferred sub-cases:** CVE-2018-1260 (Spring OAuth `SpelExpressionParser.parseExpression` + `Expression.getValue`) and CVE-2011-2732 (Spring Security `HttpServletResponse.sendRedirect`) have their sinks already modeled in `DEFAULT_SINKS`. Failure to detect those in the CWE-Bench-Java run is therefore not a sink gap — likely an indirect / cross-file data-flow issue best investigated against a concrete reproducer (tracked on the cognium-ai benchmark side).

[3.31.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.30.0...circle-ir-v3.31.0

## [3.30.0] - 2026-06-09

### Fixed

- **Apache Shiro path-traversal via URI re-decoding (#8, CVE-2023-34478 / CVE-2023-46749).** Shiro's `WebUtils.getPathWithinApplication(request)`, `WebUtils.getRequestUri(request)`, and `WebUtils.decodeRequestString(request, str)` helpers internally call `URLDecoder.decode`, so a value that passed an auth-time normalization filter (e.g. `Paths.normalize`) becomes path-traversal-tainted again after Shiro re-decodes `%2e%2e` → `..`. The taint analyzer previously did not know about these helpers, so the standard `new File(baseDir, pathFromShiro)` shape used in real-world bypasses was missed. Three-part fix in `src/analysis/constant-propagation/patterns.ts` and `src/analysis/config-loader.ts`:
  1. **Shiro WebUtils HTTP source registration.** `getPathWithinApplication`, `getRequestUri`, and `decodeRequestString` are now first-class `http_path`/`high` taint sources in `DEFAULT_SOURCES` (and mirrored in `configs/sources/http_sources.yaml` for downstream consumers).
  2. **Anti-sanitizer entries.** The same three methods are added to `ANTI_SANITIZER_METHODS` so a previously-sanitized string (`Paths.normalize(...)`) passed back through Shiro re-taints the return value.
  3. **Propagator entries.** Added to `PROPAGATOR_METHODS` so taint flows from string args back to return values for the explicit-arg overloads (`WebUtils.decodeRequestString(req, tainted)`).

### Added

- **Regression suite for #8** — `tests/analysis/taint.test.ts` gains three cases under `describe('Shiro URI normalization bypass (issue #8, CVE-2023-34478/46749)')`:
  - `WebUtils.getPathWithinApplication(request) → new File(baseDir, path)` must fire as `path_traversal` (CVE-2023-34478/46749 shape).
  - `Paths.get(raw).normalize() → WebUtils.decodeRequestString(req, normalized) → new File(decoded)` must fire (anti-sanitizer re-taint).
  - Positive control: `WebUtils.getPathWithinApplication` must be recognized as `type: 'http_path'`, `severity: 'high'`.
- Total suite size: **1860 passing tests** (1857 baseline + 3 new).

[3.30.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.29.0...circle-ir-v3.30.0

## [3.29.0] - 2026-06-09

### Fixed

- **Java enterprise false-positives from cross-language sink leak + over-eager receiver heuristic (#14).** The classless Python/Rust `execute(...)` sink patterns (cursor.execute → SQL, exec/popen → cmdi) were matching Java `j.u.c.Executor.execute(Runnable)` and `cachedThreadPool.execute(...)` callsites because the matcher had no language filter and `receiverMightBeClass` accepted any receiver whose lowercased name was a substring/prefix/suffix/CamelCase-word of a sink class name. On the DBeaver / Dubbo / Ruoyi / JeecgBoot / XXL-JOB corpus this produced 298/298 false `command_injection` and `sql_injection` findings on every threadpool dispatch. Two-part fix:
  1. **Language-scoped sink patterns.** `SinkPattern` gains an optional `languages?: SupportedLanguage[]` filter. `analyzeTaint` / `findSinks` / `matchesSinkPattern` / `matchesMethod` now take a `language` argument and skip any pattern whose `languages` list excludes the file's language. Node-specific sinks (`execSync`, `spawn`, `spawnSync`, `execFile`) and Python/Rust `cursor.execute`/`subprocess.run`/`os.system`/`std::process::Command` are tagged. The classless `exec` pattern is intentionally **not** scoped — it remains the catch-all that detects Java `Runtime.exec` via short receivers like `r.exec()` where the receiver-→-class heuristic can't resolve.
  2. **Ambiguous-identifier denylist in `receiverMightBeClass`.** Identifiers whose lowercased form is a generic JDK concept name (`executor`, `pool`, `connection`, `manager`, `handler`, `controller`, `task`, `thread`, `job`) now skip the loose substring/short-prefix/short-suffix/CamelCase heuristics. Explicit `commonMappings` (e.g. `request → HttpServletRequest`, `session → HttpSession`, `stmt → Statement`) still resolve normally, so legitimate framework sinks are unaffected.
- **Apache Camel mail path-traversal coverage of the `File(parent, child)` overload (#12, CVE-2018-8041).** The `java.io.File` constructor sink only marked argument 0 as dangerous, so attacker-controlled child names passed through `new File(safeDir, untrustedHeader)` (the exact shape used by Camel's mail component before the patch) escaped. `arg_positions` now lists `[0, 1]` for both the `java.io.File` and the auto-mined entry; flow detection now follows the second argument through the constructor and reports a single CWE-22 finding instead of letting the chain die at the parent directory.

### Added

- **`SinkPattern.languages?: SupportedLanguage[]`** — optional allow-list restricting a sink pattern to specific source languages. Existing patterns without `languages` continue to match every language, so this change is additive and backwards-compatible for downstream YAML configs.
- **Regression suite for #14** — `tests/analysis/taint.test.ts` gains four cases under `describe('Java enterprise FP suppression (issue #14)')`:
  - `j.u.c.Executor.execute(Runnable)` and `cachedThreadPool.execute(...)` must not produce `command_injection` or `sql_injection` (the upstream FP).
  - Apache Commons `DefaultExecutor.execute(CommandLine)` must still fire as `command_injection` (positive control — class name is unambiguous, so the denylist doesn't apply).
  - `Runtime.getRuntime().exec(...)` via short receiver `r.exec(...)` must still fire (positive control for the classless `exec` catch-all).
- Total suite size: **1857 passing tests** (1853 baseline + 4 new).

### Changed

- `analyzeTaint(calls, types, config, hierarchy?, language?)`, `findSinks(...)`, `matchesSinkPattern(...)`, and `matchesMethod(...)` now propagate the source language end-to-end. The argument is optional and defaults to "unscoped" (existing behaviour) so external callers that don't pass `language` still get every pattern matched — but the in-tree analyzer (`analyzer.ts`, `analyzeForAPI`, `TaintMatcherPass`) all pass the real language now.

[3.29.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.28.0...circle-ir-v3.29.0

## [3.28.0] - 2026-06-09

### Fixed

- **Bounded tree-sitter WASM heap across many `analyze()` calls (#16).** Previously every `analyze()` allocated a fresh `Parser` and leaked the returned `Tree` in the WASM heap, causing a ~20pp benchmark regression when 120 Java projects shared one `initAnalyzer()` call (50.8% in-process vs 70.8% subprocess). Fix: cache one `Parser` per language and dispose `Tree` objects in a `try { … } finally { disposeTree(tree); }` wrapper around the three entry points (`analyze`, `analyzeForAPI`, `analyzeHtmlFile`). Repeated-`analyze()` IR stability is now covered by `tests/core/parser-lifecycle.test.ts`.

### Added

- `disposeTree(tree)` (re-exported from `core/index.ts`) — null-safe, idempotent helper to free a `Tree`'s WASM memory. Use this if you call `parse()` directly.
- `createFreshParser(language)` — escape hatch returning a non-cached `Parser`; caller owns `.delete()`.

### Changed

- `resetParser()` now also disposes cached `Parser` instances and clears `loadingLanguages` / `configuredLanguageModules`, so a reset returns a clean WASM heap.

[3.28.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.27.1...circle-ir-v3.28.0

## [3.27.1] - 2026-06-04

> Versions 3.26.0 and 3.27.0 were prepared locally but never published to npm; their content shipped as part of 3.27.1.

### Added

- **New `scan-secrets` security pass (Pass #90, CWE-798)** — detects hardcoded credentials across all 7 supported languages (Java, JS/TS, Python, Go, Rust, Bash, HTML). Two detection layers:
  1. **~16 high-confidence provider patterns** — AWS access keys (`AKIA…`), GitHub tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`), Stripe (`sk_live_`, `pk_live_`), OpenAI (`sk-…`), Anthropic (`sk-ant-…`), Slack (`xox[baprs]-…`), Google (`AIza…`), JWTs, PEM private keys, npm tokens (`npm_…`). Emits `rule_id=hardcoded-credential`, severity=`critical`, level=`error` (Stripe publishable downgraded to `high`/`warning` because it's leakage, not a credential).
  2. **Shannon-entropy scan on string literals** — base64/hex shapes 20–200 chars with thresholds 4.3 / 3.5 bits/char (lowered 0.2 when the assignment target name matches `key|secret|token|password|credential|api`). Denylist suppresses UUID v4, bare MD5/SHA1/SHA256 hashes, base64-encoded JSON, placeholder words (`changeme`, `example`, `your-key-here`, …), all-same-character strings, and lines inside test/example/expect contexts. Emits `rule_id=hardcoded-credential-entropy`, severity=`high`, level=`warning`.
- **Test-file path skip** — pass early-returns on paths matching `/test/`, `/tests/`, `/__tests__/`, `/spec/`, `/fixtures/`, `/testdata/`, `*.test.ts/js`, `*.spec.ts/js`, `_test.go`, `_test.py`, and Java's `Test*.java` / `*Test.java` conventions, so fixtures and unit tests don't trip the scanner.
- **Dedup against the legacy Bash `hardcoded-credential` detection** in `LanguageSourcesPass` — keyed on `(file, line, rule_id)` via the new additive `PassContext.getFindings?()` accessor. The pass is registered immediately after `LanguageSourcesPass` so existing Bash findings sit in the buffer when dedup runs; users see no double-reporting.
- **`PassContext.getFindings?()`** (additive, optional) — read-only view of the running findings buffer for passes that need to dedup against earlier emissions.
- **39 regression tests** in `tests/analysis/passes/scan-secrets.test.ts` covering provider patterns across languages, an explicit all-7-languages parity matrix (Java, JS, TS, Python, Go, Rust, Bash, HTML) for AWS AKIA, Rust let-binding + raw-string-literal cases, FP guards (test files, env-var refs, comments), entropy positives/negatives (UUID, SHA-256, placeholder, base64-JSON), dedup behavior, and severity mapping.

### Changed

- `analyzer.ts` registers `ScanSecretsPass` after `InterproceduralPass`; pass list in the header comment now goes up to #41. Disable per project via `disabledPasses: ['scan-secrets']`.

[3.27.1]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.25.0...circle-ir-v3.27.1

## [3.25.0] - 2026-06-02

### Changes

- (no commits since last release)

## [3.24.0] - 2026-06-02

### Changes

- docs: pre-write 3.24.0 CHANGELOG entries
- fix(circle-ir): ship tree-sitter-typescript grammar (#5)

## [3.23.5] - 2026-05-30

### Changes

- docs: pre-write 3.23.5 CHANGELOG entries
- fix(circle-ir): yaml.safe_load is not a CWE-502 sink (#4)

## [Unreleased]

## [3.24.0] - 2026-05-30

### Fixed

- **TypeScript files are now parsed with the real tree-sitter-typescript grammar** (closes #5). The library previously hardcoded a `typescript → javascript` redirect in `core/parser.ts` (in both `loadLanguage` and `getDefaultLanguagePath`), so every `.ts` input was parsed with the JavaScript grammar. That worked for ES-compatible subsets of TypeScript but broke as soon as a function had TS-only syntax in its parameter list. The most visible failure was inline object-literal type parameters: `export function describe(p: { name: string }): string { ... }` produced a `labeled_statement [HAS_ERROR]` wrapping an `ERROR` node and a free-standing `statement_block`, with **no `function_declaration` anywhere in the tree** — so the function vanished from `ir.types[].methods[]` entirely. After the fix, that same input parses cleanly to `function_declaration` with `required_parameter` + `type_annotation` children, and the function is extracted with `name`, `parameters[0].name === 'p'`, and `parameters[0].type === '{ name: string }'`.

### Added

- **`tree-sitter-typescript.wasm` (v0.23.2)** shipped in `wasm/` (1.4 MB) and auto-copied to `dist/wasm/` by the existing `build:browser` glob step. Pure-TypeScript grammar only — `.tsx`/JSX is out of scope for this release and is tracked as a follow-up.
- **`required_parameter` / `optional_parameter` handling in `extractJSParameters`** (`src/core/extractors/types.ts`). These are TS-grammar-specific parameter node types that don't appear under the JS grammar. The new branch resolves the parameter's `pattern` field (identifier, rest pattern, object/array destructure, or assignment with default) and its `type` field (`type_annotation` minus the leading `:`). As a side effect, `ParameterInfo.type` is now populated for TS code where it was previously always `null`.
- **6 regression unit tests** in `tests/extractors/types-typescript.test.ts` covering the Issue #5 repro matrix: inline-object solo, inline-object + plain follower, inline-object-array + follower, primitive-typed param, named-interface-typed param, and optional parameter.

### Changed

- **Removed both `typescript → javascript` grammar redirects** from `src/core/parser.ts` (formerly at lines 178 and 354). Requests for the `typescript` grammar now load `tree-sitter-typescript.wasm` directly.
- **`tests/setup.ts`** updated to map `typescript` to `tree-sitter-typescript.wasm` in its explicit `languagePaths` table (was `tree-sitter-javascript.wasm` with a "shares JS grammar" comment).

### Known issues / out of scope

- **TSX/JSX is not supported.** This release ships pure-TS only. A follow-up will dispatch `.tsx` to `tree-sitter-tsx.wasm`. Existing tests do not exercise `.tsx`.
- **Interface extraction is not enriched.** The parser now produces `interface_declaration` nodes, but `extractJavaScriptTypes` still only walks `class_declaration` / `function_declaration` / named arrow funcs. Adding interface extraction (with `kind: 'interface'`) is a clean follow-up but not required to close #5.
- **Generic / union / intersection types are not surfaced into IR.** The corresponding nodes are now present in the tree.
- **Behavior change for TS consumers:** scans of TypeScript code that previously parsed to ERROR-bearing trees may now produce additional findings, because regions that the JS grammar had silently dropped are now visible to the analysis pipeline. This is correctness, not a regression, but is called out here for diff-readers.

### Verification

- Full test suite: **1810 passing, 0 failing** (1804 → 1810; the 6 new tests are the only delta).
- Issue #5 repro matrix (`/tmp/ts-fp/repro.mjs`): all 5 cases now match the expected method-name list.
- AST dump (`/tmp/ts-fp/ast.mjs`): `function_declaration` counts go from 0/1/1/1/1 (broken) to 1/2/2/1/1 (fixed).
- CLI smoke (`bun run dev scan packages/circle-ir/src/core/extractors --format text`): runs cleanly on real TS code, produces sane findings.

[3.24.0]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.23.5...circle-ir-v3.24.0

## [3.23.5] - 2026-05-30

### Fixed

- **`yaml.safe_load` no longer reported as a CWE-502 deserialization sink** (closes #4 source-side). `safe_load` constructs only standard scalar/list/dict types and cannot instantiate arbitrary Python objects, so it must not be a sink. The previous entry in `PythonPlugin.getBuiltinSinks()` carried a dead `sanitizes: ['yaml_unsafe']` annotation (only consumed on sanitizer objects, never on sink patterns), which was insufficient to suppress the finding when source/sink co-occurrence was the harness gate. Verified on OWASP BenchmarkPython (1230 cases): deserialization FP **24 → 7**, overall FPR **14.8% → 12.6%**, accuracy **58.3% → 61.7%**, F1 **78.6% → 80.0%** (TPR unchanged at 81.2%).

### Added

- **`yaml.unsafe_load` and `yaml.full_load` registered as CWE-502 sinks** — genuinely-unsafe APIs that were missing from the previous sink set. Both are `critical` severity, `arg_positions: [0]`.
- Four regression unit tests in `tests/languages/python-plugin.test.ts` locking in: `safe_load` not in sinks, `unsafe_load` is, `full_load` is, and the dead sanitize annotation is gone.

### Known issues

- Even with this fix, OWASP BenchmarkPython FPR is **12.6%** vs the ≤2% target. 91 FPs remain across codeinj (18), xpathi (17), pathtraver (14), redirect (12), xxe (10), xss (9), ldapi (7), trustbound (2), cmdi (2) — likely the same safe-variant-over-matching pattern in other Python plugin sink methods. Tracked as a follow-up to #4.

[3.23.5]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.23.4...circle-ir-v3.23.5

## [3.23.4] - 2026-05-30

### Documentation

- **`PUBLISHING.md` rewritten** as a thin pointer to the monorepo root `release.sh`. Dropped the stale "Phase 3 / Phase 4 / `v*`-tag-triggered `publish.yml`" workflow content. The library is **not published independently** — it ships in lock-step with `cognium-dev` via `./release.sh` from the repo root. Added an "emergency manual publish" section that preserves the lib-first ordering.
- **`TODO.md` refreshed** — Phase 4 marked complete; Java section updated with MyBatis (v3.22.x), `SCMFileSystem.child` (v3.23.2), and `@DataBoundConstructor` (v3.23.3) ticks; cross-instance field-binding propagation added as the remaining engine gap.

No code, taint-config, or pass-pipeline changes. CLI consumer behavior is identical to 3.23.3.

[3.23.4]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.23.3...circle-ir-v3.23.4

## [3.23.3] - 2026-05-28

### Added

- **Method-level annotation taint sources** — extends `SourcePattern` with a new `method_annotation` field (distinct from the param-level `annotation`). When the configured annotation appears on a method or constructor, **all of its parameters** are emitted as taint sources at confidence `1.0`. Used for framework patterns where a single annotation indicates user-controlled binding of every parameter.
- **Jenkins `@DataBoundConstructor` source pattern** (closes the source-side gap of #1) — adds `@DataBoundConstructor` as a `method_annotation` source (`http_param`, severity `high`). Jenkins binds every parameter of a `@DataBoundConstructor` from user-supplied form/JSON data at object construction time, so all such params are now treated as taint origins. Upgrades the previous fallback (`interprocedural_param` at confidence 0.7) to a precise high-confidence source for this case. Field-binding propagation (`this.path = path` → another method reads `step.path` on a different instance) still requires cross-instance flow analysis and remains open as a separate effort.
- New unit test `taint.test.ts > should detect Jenkins @DataBoundConstructor params as taint sources`.

[3.23.3]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.23.2...circle-ir-v3.23.3

## [3.23.2] - 2026-05-28

### Added

- **Jenkins `SCMFileSystem.child(String)` path-traversal sink** (partial fix for #1) — adds `jenkins.scm.api.SCMFileSystem.child(...)` to the path-traversal sink list (CWE-22, severity `high`). Closes the sink side of CWE-Bench-Java miss `jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706.vd43c65dec013`. Detection from real Jenkins code (where the receiver is typed `SCMFileSystem` but named `fs`) requires project-level `TypeHierarchyResolver`; unit test uses a heuristic-matchable receiver name. The source-side gap — tracking `@DataBoundConstructor` field-binding as a taint origin — is not addressed in this patch and remains open in #1.

[3.23.2]: https://github.com/cogniumhq/cognium-dev/compare/circle-ir-v3.23.1...circle-ir-v3.23.2

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
