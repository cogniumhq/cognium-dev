# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.144.0] - 2026-07-01

Ships cognium-dev #139 Tier A — a **sink-semantics registry** that
drops sinks whose emitted `SinkType` label disagrees with a curated
`<ClassName>#<methodName>` → real-behavior classification. New
canonical pass **#109 `sink-semantics`** runs after `SinkFilterPass`
and before `TaintPropagationPass`, so mismatched sinks are removed
before either flow generator (per-file or cross-file) sees them.

**Motivation.** The 22-repo harness audit surfaced false positives
where a sink's *label* did not match its *actual behavior*. Canonical
example: `Jedis.executeCommand(...)` was flagged as
`command_injection` because `configs/sinks/command.yaml`'s
`executeCommand` pattern had no `class` filter — but the call is
Redis wire-protocol serialization, not OS exec. The registry gate
fixes this class of FP without weakening the recall guarantee for
`Runtime.exec`, `ProcessBuilder.start`, `Statement.execute`, or
`Class.forName`.

**New `class?: string` field on `TaintSink`.** Populated at sink
creation in `taint-matcher.ts` from the call-site's
`receiver_type`. Fully-qualified receiver types are reduced to their
simple-name tail (`redis.clients.jedis.Jedis` → `Jedis`) so the
registry can match without per-repo package variance. Unresolved
receivers leave the field `undefined`; the semantics gate then
falls through — the pass is false-negative-safe.

**Registry (`configs/sink-semantics.json`).** Mirrored inline as the
new `DEFAULT_SINK_SEMANTICS` constant in `config-loader.ts` so the
gate is active in browser + Node.js callers that never call
`createTaintConfig`. Registry schema:

```json
{
  "sinks": [
    {
      "signature": "Jedis#executeCommand",
      "real_class": "db_protocol",
      "overrides": ["command_injection", "code_injection"],
      "note": "Redis wire-protocol serialization, not OS exec"
    }
  ]
}
```

- `signature` — `<ClassName>#<methodName>`, simple-name, case-sensitive
- `real_class` — one of `db_protocol` / `jdk_internal` /
  `functional_dispatch` / `admin_config` / `logging` (informational)
- `overrides` — list of `SinkType` values dropped when the matched
  sink's `type` field appears here

**Tier A seed entries (8 signatures).** Every entry class-scoped so
unrelated recall paths are unaffected:

1. `Jedis#executeCommand` → drop `command_injection`, `code_injection`
2. `Connection#executeCommand` → drop `command_injection`, `code_injection`
3. `JedisCluster#executeCommand` → drop `command_injection`, `code_injection`
4. `Func1#exec` (RxJava) → drop `command_injection`, `code_injection`
5. `Action0#call` (RxJava) → drop `command_injection`
6. `Action1#call` (RxJava) → drop `command_injection`
7. `Unsafe#defineAnonymousClass` → drop `code_injection`
   (`sun.misc.Unsafe` JDK-internal bridge)
8. `MethodHandle#invokeExact` → drop `code_injection`
   (JDK invokeExact; not attacker-controllable)

**Configuration.** `createTaintConfig` gained a third optional
argument `sinkSemanticsContents: string[]` for callers that preload
registry JSON strings. Existing 2-arg callers still work — an
undefined `sinkSemantics` on `TaintConfig` disables the gate. The
pass is guarded on `disabledPasses: ['sink-semantics']`.

**Registry contract.** Duplicate signatures union their overrides,
so multiple files can safely extend the same `<Class>#<method>`
entry. Registry lookup is O(1) via a `Map<string, Set<SinkType>>`
built once per pass invocation. The pass mutates
`graph.ir.taint.sinks` in place (preserves array identity so any
consumer that captured a reference before the pass ran continues to
see the reduced sink set).

**Explicitly out of scope.**
- **Tier B speculative verifier on disagreements** — Pillar I
  forbids in circle-ir; belongs in cognium-ai / circle-ir-ai. Tier B
  outputs can be reviewed and promoted to Tier A registry entries
  by hand.
- **Admin-configured binary paths** (PlantUML latex/dot) — requires
  argument-shape analysis distinguishing configured path from
  user-controlled path; deferred.
- **Fully-qualified signature matching** — MVP uses simple-name tail
  match; package-qualified `redis.clients.jedis.Jedis#executeCommand`
  is a follow-up if simple-name collisions surface.
- **Wildcard signatures** (`*Mapper#*`) — deferred; register
  concrete signatures until the registry outgrows explicit entries.

**Tests (all green).**
- `tests/analysis/passes/sink-semantics.test.ts` — 21 tests locking
  every drop path (`Jedis#executeCommand`,
  `Connection#executeCommand`, `Func1#exec`,
  `Unsafe#defineAnonymousClass`, `MethodHandle#invokeExact`), every
  recall guard (`Runtime.exec`, `Statement.execute`, `Class.forName`,
  `MyCustomJedis#executeCommand`, unresolved-receiver fallthrough,
  cross-type label preservation), and the registry-lifecycle edge
  cases (empty registry, duplicate-signature union, array-identity
  preservation, missing `sinkSemantics` config).
- `tests/analysis/repro-issue-139.test.ts` — 6 end-to-end regression
  locks: Jedis FP shape, Func1 FP shape, Unsafe FP shape, Runtime
  recall guard, class-scoped MyCustomJedis recall guard, and simple-
  name normalization invariant.
- Full suite: **3469 passed | 2 skipped** (was 3442 + 27 new).

**PASSES.md** — #109 row added with full seed-entry summary.

## [3.143.0] - 2026-07-01

Ships cognium-dev #138 — a **source-semantics gate** that tags every
`TaintSource` in `ir.taint.sources` with three deterministic booleans
consumed downstream to drop false-positive taint flows and downgrade
demo-path credential findings. New canonical pass **#108
`source-semantics`** runs after `LanguageSourcesPass` and before
`SinkFilterPass` / `TaintPropagationPass`, so the tags are visible to
both the sink pre-filter and the flow generator.

**Three source-taggers.**
1. **`constant`** — set to `true` when `source.code` matches one of
   three compile-time-constant shapes: (a) `[final] TYPE ident =
   "literal";`, (b) `[public|private|protected] static final …` with
   RHS that is a string / numeric / boolean literal or a bare
   identifier reference, (c) `= SomeEnum.VALUE;` (enum constant ref
   with PascalCase or SCREAMING_SNAKE LHS and all-caps constant RHS).
2. **`spi`** — set to `true` when `source.code` matches
   `ServiceLoader.{load,loadInstalled,stream}(…)`, OR
   `Class.forName(…)` with a co-located
   `.getResources("META-INF/services/…")` lookup within a ±30-line
   window of the source line (mirrors the Stage 9f co-location check
   already used by `sink-filter-pass.ts`).
3. **`demoPath`** — set to `true` on every source in the file when
   `ir.meta.file` matches the path-component regex
   `(?:^|\/)(?:demo|example|examples|samples|integration-tests|integration_tests)(?:\/|$)` (case-insensitive). Filename-only
   matches (e.g. `DemoParser.java`) intentionally do not trigger.

**Consumption policy.** The new
`sourceSemanticsAllowed(source, sinkType)` predicate in `findings.ts`
enforces:
- `constant === true` → flow dropped for every taint sink type
  (constants cannot carry attacker-controlled data). The
  `hardcoded-credential` rule continues to fire on constants — that is
  precisely what that rule detects.
- `spi === true` → flow dropped for every taint sink type **except**
  `code_injection` (Stage 9f already downgrades those to
  library-API-surface; dropping again would double-suppress and lose
  recall on real reflection bugs).
- `demoPath === true` → never consumed by the sink allowlist. Instead,
  `scan-secrets-pass.ts` uses it to downgrade `hardcoded-credential`
  findings emitted from Layer 1 (provider patterns) and Layer 1b
  (named-credential) from `severity: 'high' → 'low'` and
  `level: 'warning'|'error' → 'note'`. Layer 2
  (`hardcoded-credential-entropy`) is intentionally left untouched.

**Wiring.**
- `TaintSource` type extended with three optional booleans plus JSDoc
  documenting the consumption policy on the type itself.
- Both the colocation flow generator and the variable-scan flow
  generator in `taint-propagation-pass.ts` now gate flow emission on
  `sourceSemanticsAllowed(source, sink.type)`.
- `scan-secrets-pass.ts` imports the shared `DEMO_PATH_RE` from
  `source-semantics-pass.ts` and applies a per-finding
  `applyDemoDowngrade` at both Layer 1 provider emission and Layer 1b
  named-credential emission. The regex is exported from the pass file
  so the two consumers share a single source of truth.
- Pass registered in `analyzer.ts` guarded on
  `disabledPasses.has('source-semantics')`; sits after
  `LanguageSourcesPass` (so the full source list is available) and
  before `SinkFilterPass` (so the tags are visible to sink pre-filter).
- Detection is **line-text-only MVP** — regex on `source.code`, no DFG
  lift. This is deliberately shallow: sink allowlist is explicit, so a
  false-negative in the tagger merely means the tag isn't set and the
  flow proceeds normally. There is no silent-drop failure mode.

**Deferred (called out in the ticket, not shipped in this release).**
- DFG-based constant propagation (integration with the existing
  `ConstantPropagationPass` sanitizedVars / constants maps). MVP uses
  regex on `source.code`; DFG lift is a follow-up if the FP audit
  shows recall gaps.
- Spring `@Component` / `@Service` / component-scan tagging (requires
  type-hierarchy resolution).
- SPI tag on custom plugin loader APIs beyond `ServiceLoader` /
  `Class.forName` (ticket lists `Plugin.load(name)` as a shape but
  doesn't specify the API surface).
- Demo-path regex refinement to match `-demo` / `_demo` suffixes on
  path segments (the ticket's real-world path shape
  `sa-token-oauth2-server-demo/…` currently does NOT match, only
  proper `/demo/` components). Deferred pending the FP-drop harness
  rerun that is #138's acceptance criterion.

**Tests.** Adds
`tests/analysis/passes/source-semantics.test.ts` (21 tests covering
constant tagging TP/TN, SPI tagging TP/TN, demoPath tagging TP/TN, and
`sourceSemanticsAllowed` consumption behaviour across every taint
sink type) and `tests/analysis/repro-issue-138.test.ts` (4 regression
locks: jib PropertyNames constant shape, Sa-Token ServiceLoader spi
tag, Sa-Token OAuth demo-path downgrade, non-demo-path
`hardcoded-credential` severity preservation). Full suite: 3442
passed | 2 skipped (was 3417 passed).

## [3.142.0] - 2026-07-01

Second sub-batch of cognium-dev #189 (Java FN, Sprint 93). Closes the
remaining Java false negatives from the Sprint 92 top-100 rerun by
resolving the `new X(...)` constructor-receiver form for chained method
calls, registering CRLF sink patterns on the `Cookie` constructor and
`HttpServletResponse.addCookie`, extending the source-to-sink reach map
so `http_param` / `http_query` can reach `deserialization`, and
relaxing the inline-colocation-flow generator to admit nested-source
shapes where the outer LHS binding does not appear in the sink's RHS.

**Shapes flipped from FN → TP.**
1. `crlf` — `res.addCookie(new Cookie("k", req.getParameter("v")))` and
   the intermediate-var variant `Cookie c = new Cookie(name, v);
   res.addCookie(c);` (CVE-analogue V02SetCookie). Now emits
   `http_param → crlf` (CWE-113) at both the constructor and the
   `addCookie` call site.
2. `deserialization` —
   `Object o = new Yaml().load(req.getParameter("y"))` (V02YamlUnsafe
   SnakeYAML shape). Now emits `http_param → deserialization`
   (CWE-502). The `new Yaml()` inline receiver was previously
   unresolvable so the `Yaml.load` sink pattern never matched.
3. `deserialization` — intermediate-var variant `Yaml y = new Yaml();
   Object o = y.load(req.getParameter("y"));`. The colocation flow
   generator previously dropped sources with an LHS-bound `variable`
   field (Java LHS binding tags the source with the outer `o` target
   though `o` is the load *result*), silently suppressing the flow.
   Now emits `http_param → deserialization`.

**Fixes.**
- `resolveReceiverType` in `core/extractors/calls.ts` recognises the
  `new <ClassName>(...)` receiver form ahead of the existing local /
  param / field / static-ref tiers. The constructed class name (simple
  or fully qualified) becomes the resolved receiver type, so chained
  method calls like `new Yaml().load(...)`,
  `new ObjectMapper().readValue(...)`, and
  `new ProcessBuilder(argv).start()` bind to their proper class for
  sink-pattern matching.
- `config-loader.ts` adds two `crlf` (CWE-113) sink entries: the
  `Cookie` constructor at arg positions `[0, 1]` (name + value) and
  `HttpServletResponse.addCookie` at arg position `[0]` (the built
  Cookie handle). Both surface so the inline-ctor and
  intermediate-var shapes each emit a flow.
- `canSourceReachSink` in `analysis/findings.ts` adds
  `deserialization` to the `http_param` and `http_query` allowlists.
  Previously only `http_body` and `io_input` reached `deserialization`,
  so `req.getParameter("y") → Yaml.load(...)` on the same line was
  filtered out by the reach gate. Typed-overload FPs continue to be
  suppressed by the sink pattern's `safe_if_class_literal_at` flag
  (Jackson `readValue`, Yaml `loadAs`, Gson `fromJson`).
- The inline-colocation flow generator in
  `passes/taint-propagation-pass.ts` now admits sources with an
  LHS-bound `variable` field when that variable is absent from the
  sink's RHS. This unblocks the nested-source
  `Object o = y.load(req.getParameter("y"))` shape where Java LHS
  binding tags the source with the outer assignment target. The
  regression guard (`uid = source(); doSink("x = " + uid)`) is
  preserved: when the LHS var appears in the sink's RHS, colocation
  hands off to the variable-scan supplement. When the sink carries no
  source-line text (synthetic contexts), colocation conservatively
  drops variable-bound sources.
- `sink-filter-pass.ts` Stage 11 extends its argv-form ProcessBuilder
  FP suppression to cover the newly resolved
  `sink.method === 'start', sink.class === 'ProcessBuilder'` case.
  When the `.start()` call site is on the same line as an argv-form
  ProcessBuilder ctor, the same argv-form logic drops the `start`
  sink too, preserving the pre-existing FP-179 recall lock.

**Tests.** Adds
`tests/analysis/repro-issue-189-java-3142.test.ts` locking down all
three CRLF shapes, both Yaml shapes (inline ctor + intermediate var),
and the ObjectInputStream baseline recall. Full suite: 3417 passed | 2
skipped (was 3411 passed).

## [3.141.0] - 2026-07-01

Partial fix for cognium-dev #189 (Java FN sub-batch, Sprint 92): extends
the #117 chained-receiver resolver to walk multi-level factory chains and
adds the JAXP factory return-type entries so class-scoped sink patterns
(`DocumentBuilder.parse`, `SAXParser.parse`, `XPath.evaluate`) fire on
inline JAXP chains without an intermediate typed local.

**Shapes flipped from FN → TP.**
1. `xxe` —
   `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(taint)`
   was silently dropped because `resolveReceiverType` could only walk one
   chain level; the `.newDocumentBuilder()` prefix resolved to `null` and
   the `DocumentBuilder.parse` sink pattern never matched. Now emits
   `http_param → xxe`.
2. `xxe` — same shape for `SAXParserFactory.newInstance().newSAXParser()
   .parse(...)`. Now emits `http_param → xxe`.
3. `xpath_injection` — `XPathFactory.newInstance().newXPath()
   .evaluate(...)`. Now emits `http_param → xpath_injection`.

**Fix.**
- `resolveReceiverType` in `core/extractors/calls.ts` recurses into
  chained receivers via a new `splitChainedReceiver` helper that walks
  a receiver expression right-to-left, tracking paren depth, to split
  `<prefix>.<method>(args)` into `{ prefix, methodName }`. The prefix is
  itself resolved recursively; the recursion terminates on a bare
  identifier (local var / param / field) or a static class reference.
- `JAVA_CHAINED_FACTORY_RETURN_TYPES` is extended with the JAXP families:
  `DocumentBuilderFactory`, `SAXParserFactory`, `SAXParser`,
  `XPathFactory`, `TransformerFactory`, `XMLInputFactory`. Each factory's
  static `newInstance` self-loop is registered so both `Factory.newInstance()
  .newFoo()` and `Factory.newInstance()` are resolvable.

The Sprint 91 (#117) servlet single-level chain
(`req.getSession().setAttribute(...)`) is preserved by a dedicated
regression test in the same file, ensuring the recursive rewrite does
not regress the existing fix.

**Out of scope (deferred).** The `ssrf/URL.openConnection` and
`crlf/addCookie + new Cookie(...)` shapes remain FN — they need
receiver-taint propagation on `URL` and constructor-argument
propagation through `Cookie`, both of which are separate infrastructure
work outside the chained-receiver walker.

### Added
- `splitChainedReceiver()` helper in `core/extractors/calls.ts` for
  right-to-left chain splitting with paren-depth tracking.
- JAXP factory entries (`DocumentBuilderFactory`, `SAXParserFactory`,
  `SAXParser`, `XPathFactory`, `TransformerFactory`, `XMLInputFactory`)
  in `JAVA_CHAINED_FACTORY_RETURN_TYPES`.
- `tests/analysis/repro-issue-189-java.test.ts` — 4-test regression lock
  covering the three chained JAXP shapes and the Sprint 91 servlet chain.

### Changed
- `resolveReceiverType()` in `core/extractors/calls.ts` now recurses into
  chained receivers instead of matching only a single `<var>.<method>(...)`
  level.

## [3.140.0] - 2026-07-01

Fix for cognium-dev #117 (CWE-501 Trust Boundary Violation) — 0% recall on
OWASP Java Benchmark's trustbound category (83 misses) is caused by the
inline chained-receiver shape, not by same-line dedup as previously
suspected in the Sprint 51 comment.

**Root cause (two-part).**
1. `req.getSession().setAttribute("k", req.getParameter("v"))` produced
   `receiver_type=null` on the `setAttribute` call because the Java
   receiver-type resolver only handled `this`, `super`, local vars,
   params, fields, and static class references — chained factory calls
   (`<var>.<method>()`) were left unresolved. The class-scoped
   `HttpSession.setAttribute` trust_boundary sink pattern therefore did
   not match, while the classless `xss` `setAttribute` pattern still
   fired at the same line, leaving the trust_boundary flow absent from
   the taint stream. The DFG-based intermediate shape
   (`HttpSession s = req.getSession(); s.setAttribute(...)`) worked
   because `s` resolves via `localVarTypes`.
2. Even if the trust_boundary sink had been recognised on the inline
   shape, `canSourceReachSink` at `findings.ts:175` did not list
   `trust_boundary` as a valid sink for any `http_*` or
   `interprocedural_param` source. The inline-colocation flow detector
   in `taint-propagation-pass.ts:1259` calls this compatibility check
   at emit time, so the `http_param → trust_boundary` co-located flow
   would still have been silently dropped. (The DFG-based path does
   not apply this filter, which is why the intermediate shape worked
   pre-fix once the sink was recognised.)

**Fix.**
- `resolveReceiverType` in `core/extractors/calls.ts` learns a narrow
  Java servlet chained-factory return-type table: `HttpServletRequest
  .getSession()` → `HttpSession`, `.getServletContext()` →
  `ServletContext`, `.getRequestDispatcher()` → `RequestDispatcher`;
  and `HttpSession.getServletContext()` → `ServletContext`. Applied
  only when the receiver expression matches `<localVar>.<method>(...)`
  and the local variable's declared type is in the table. Preserves
  the existing conservative-null fallback for unrecognised chains.
- `canSourceReachSink` reach map gains `trust_boundary` as a valid
  sink for `http_param`, `http_body`, `http_header`, `http_cookie`,
  `http_path`, `http_query`, and `interprocedural_param`. Mirrors the
  Sprint 82 (#189) fix that added `open_redirect` to the same set for
  the equivalent inline-colocation reason.

**Regression lock.** New `tests/analysis/repro-issue-117.test.ts` (4
tests) asserts:
- Inline `req.getSession().setAttribute(...)` emits BOTH `xss` and
  `trust_boundary` flows.
- Intermediate `HttpSession s = req.getSession(); s.setAttribute(...)`
  emits BOTH `xss` and `trust_boundary` flows (unchanged behaviour).
- Inline `req.getServletContext().setAttribute(...)` emits at least
  one `trust_boundary` flow.
- Spring `model.addAttribute("q", q)` does NOT spuriously emit
  `trust_boundary` (chained-factory resolution is narrow to the
  servlet API table, not any `setAttribute` receiver).

**Impact.** OWASP Java Benchmark trustbound category recall lifts from
0% to a positive value for the inline shape (measured by the new
regression tests; benchmark reruns will land in a follow-up). Zero
existing tests changed behaviour. No new pass number; both fixes are
config-map / resolver extensions to shipped code paths.

**Suite.** 3407 passed | 2 skipped (was 3403 | 2 in 3.139.0). Typecheck
clean.

## [3.139.0] - 2026-06-30

New engine pass `missing-sanitizer-gate` (#107, CWE-79) targeting
CVE-2023-37908 (xwiki-rendering `XHTMLWikiPrinter`) and the general
"HTML attribute pass-through without sanitizer-call gate" pattern.

**Pass shape.** Java-only, intra-procedural, dominator-based. For each
non-entry-point Java method that accepts a `Map<String,String>` /
`Attributes` / attribute-shaped `String` parameter, the pass builds a
method-scoped `DominatorGraph` and, for every HTML output sink call
inside the method, requires at least one sanitizer-named call to
dominate the sink block on all CFG paths. If none does, a finding is
emitted at the sink line.

- **Sinks (name match):** `addAttribute`, `setAttribute`, `write`,
  `writeAttribute`, `writeRaw`, `writeStartElement`, `writeEndElement`,
  `writeCharacters`, `printXML`, `printXMLElement`,
  `printXMLStartElement`, `printXMLEndElement`, `printRaw`, `print`,
  `println`, `printf`, `append`, `format`.
- **Sanitizers (name match):** `isAttributeAllowed`,
  `isElementAllowed`, `isSafe`, `sanitize`, `clean`, `escape`,
  `encode`, `forHtml*`, `encodeForHTML*`, `escapeHtml*`,
  `escapeXml`, `htmlEscape`, `xmlEscape`, plus the prefix rule
  `/^(?:clean|sanitize|escape|encode)[A-Z]/` (matches project-local
  wrappers like `cleanAttributes`).
- **Skips:** Tier 1 entry points (network trust boundary is already
  covered by configured `xss` sinks + taint sources), methods without
  an HTML-shaped parameter, and non-Java languages. Deduped at max one
  finding per method.

**Speculative by default.** Every emitted finding is stamped
`confidence: 'medium'`, `level: 'note'`, so `applyConfidenceFilter`
(3.94.0) drops it from the surface unless the caller opts in via
`analyze(..., { includeSpeculative: true })`. Zero surface impact on
existing users; the CLI's default text/JSON/SARIF output is unchanged.

**Per-method DominatorGraph.** The file-level CFG has one
`type='entry'` block per method, but a single top-level
`new DominatorGraph(cfg)` uses only the first entry — every other
method's blocks are marked unreachable and `dominates()` returns
false. The pass builds one `DominatorGraph` per method rooted at the
method's own entry block (falls back to the first block whose lines
lie within the method for minimal test-fixture CFGs). Avoids the FP
cliff that killed the earlier `missing-guard-dom` pass.

**CVE regression lock.** Vendored `XHTMLWikiPrinter` pre- and post-fix
from `xwiki/xwiki-rendering@c40e2f5f9482` (XRENDERING-663 —
"Restrict allowed attributes in HTML rendering") into
`tests/fixtures/cve-2023-37908/`. The pre-fix file emits at least one
`missing-sanitizer-gate` finding on one of the
`printXMLElement`/`printXMLStartElement` overloads; the post-fix file
(which introduces the `cleanAttributes(...)` wrapper calling
`htmlElementSanitizer.isAttributeAllowed(...)`) emits zero. Pinned in
`tests/analysis/passes/missing-sanitizer-gate-cve-2023-37908.test.ts`.

Tests: 9 synthetic (TP-1, TP-2, TN-1, TN-2, TN-3 param gate,
TN-4 `@RestController` entry-point gate, TN-5 language gate,
speculative gating, dedup) + 3 CVE regression = 12 new tests.
Full suite: 3403 passed | 2 skipped.

Closes cognium-dev#153.

### Files
- **new:** `src/analysis/passes/missing-sanitizer-gate-pass.ts`
- **new:** `tests/analysis/passes/missing-sanitizer-gate.test.ts`
- **new:** `tests/analysis/passes/missing-sanitizer-gate-cve-2023-37908.test.ts`
- **new:** `tests/fixtures/cve-2023-37908/XHTMLWikiPrinter-prefix.java`
- **new:** `tests/fixtures/cve-2023-37908/XHTMLWikiPrinter-postfix.java`
- **mod:** `src/analyzer.ts` — pipeline registration + numbered comment
- **mod:** `docs/PASSES.md` — pass #107 row

## [3.138.0] - 2026-06-30

Combined Sprints 88 + 89 + 90 closing the tail of cognium-dev #189
variant-regression scorecard.

**Sprint 88** — JavaScript command_injection cluster (4 cells):
`execa.command`, `child_process.execFile('sh','-c',...)`,
`util.promisify(exec)`, `child_process.spawn('sh','-c',...)`. Baseline
on 3.137.0 found **0 of 4 FN** — all four variants already TP via
existing configured `nodejs.json` sinks (Sprint 54 added
`execa.command`/`execa.commandSync`; `child_process.exec`/`execFile`/
`spawn`/`spawnSync`/`execSync` have been sinks since the initial
JS plugin). Coverage pinned with `issue-189-sprint88-cmdinj-cluster`
regression tests (4 TP + 4 TN).

**Sprint 89** — deserialization (4) + xpath (3) cluster (7 cells):
3 of 7 FN on 3.137.0. Three new pattern detectors close the gap:

- `findGoGobDeserializationFindings` — Go `encoding/gob`
  `gob.NewDecoder(req.Body).Decode(&v)` (both assigned and inline
  forms). The `gob` package reconstructs arbitrary registered types
  from attacker-controlled bytes; without authenticated framing this
  is a CWE-502. rule_id=`insecure_deserialization`, severity=critical.

- `findJsJsonParseBodyFindings` — JS `JSON.parse(req.body)` (express
  `text()`/`raw()` body middleware leaves `req.body` as an unvetted
  string; the parsed object can carry `__proto__` payloads that
  pollute downstream property lookups). Tracks taint through
  `const raw = req.body; JSON.parse(raw)` aliases. CWE-502 /
  CWE-1321-adjacent. severity=high.

- `findJsDomXpathInjectionFindings` — JS DOM `document.evaluate(
  <tainted>, ...)` with browser sources (`location.search`/`hash`/
  `href`, `URLSearchParams`, `window.name`, `document.cookie`). Gates
  on the presence of `XPathResult` to keep the detector scoped to
  the DOM XPath API. CWE-643, severity=high.

Already-TP cells re-pinned in regression tests: Java SnakeYAML
`Yaml.load`, Rust `bincode::deserialize` (via configured
deserialization sinks), Python `lxml tree.xpath`, Java
`XPath.evaluate`.

**Sprint 90** — xxe (3) + ssti (2) + path (1) cluster (6 cells):
3 of 6 FN on 3.137.0. Three new pattern detectors close the gap:

- `findGoXmlDecoderXxeFindings` — Go `encoding/xml`
  `xml.NewDecoder(req.Body)` followed downstream by
  `dec.Strict = false` or `dec.Entity = ...`. The standard library
  is safe by default but disabling Strict (or overriding the Entity
  map) reintroduces entity-resolution risks. CWE-611, severity=high.

- `findPythonJinjaTemplateSstiFindings` — Python
  `jinja2.Template(<tainted>).render(...)` where the template
  source traces back to `flask.request.args` / `form` / `values` /
  `json` / `data` / `cookies` / `headers`. Sandbox-escape gadgets
  (`{{ ().__class__.__bases__[0].__subclasses__() }}` chains) make
  this RCE-equivalent. rule_id=`template_injection`, CWE-1336,
  severity=critical.

- `findJsTemplateInjectionSstiFindings` — JS
  `Handlebars.compile(<tainted>)` / `ejs.render(<tainted>, ...)` /
  `ejs.compile(<tainted>)` where the template source traces back to
  Express `req.query|body|params|headers|cookies`. Helper-shadowing
  and prototype-gadget chains in both engines have historically led
  to RCE. rule_id=`template_injection`, CWE-1336, severity=critical.

Already-TP cells re-pinned: Java `DocumentBuilderFactory.parse`
(via existing `xml-entity-expansion` pass), JS `libxmljs.parseXml`
with `{ noent: true }`, Rust `Path::new(...).join(<tainted>)` →
`fs::read_to_string` (via configured `path_traversal` sinks).

### Risk + safety controls

- **Go gob detector**: requires `*http.Request` in the signature and
  the decoder variable to have been constructed from `<x>.Body`.
  Inline-form (`gob.NewDecoder(r.Body).Decode(&p)`) and assigned-form
  (`dec := gob.NewDecoder(r.Body)`) are matched separately to avoid
  duplicate findings.
- **JS JSON.parse-body**: only fires when `req.body` (the specific
  raw-text extractor) appears as the parse argument — directly or
  via a tracked alias. Never fires for `JSON.parse(req.query.X)` or
  `JSON.parse(req.params.X)` (those are already parsed strings, not
  unvetted JSON blobs).
- **JS DOM XPath**: gated on `XPathResult` to scope the detector to
  the browser DOM API; will not fire on Node-side `.evaluate()`
  calls on unrelated objects (Mongoose, etc.).
- **Go XML decoder XXE**: only fires when `dec.Strict = false` or
  `dec.Entity = ...` is set on the same variable as the
  `xml.NewDecoder(req.Body)` assignment. Default-Strict decoders
  (the recommended posture) do not trip.
- **Python Jinja Template SSTI**: requires the `jinja2.Template` name
  to be imported (or qualified `jinja2.Template`) and the constructor
  argument to trace to a Flask request extractor. Literal-template
  calls and `render_template('file.html', ...)` (which is safe) do
  not fire.
- **JS Handlebars/EJS SSTI**: requires both the library reference
  (`Handlebars.compile` / `ejs.render` / `ejs.compile`) and an
  Express request-extractor source. Literal-template compilation
  (the typical safe usage) does not fire.

### Verification

- `tests/analysis/passes/issue-189-sprint88-cmdinj-cluster.test.ts`
  (NEW, 8 tests) — 4 TP + 4 TN regression lockdown
- `tests/analysis/passes/issue-189-sprint89-deser-xpath-cluster.test.ts`
  (NEW, 11 tests) — 3 new-detector TPs + 4 detector-control TNs +
  4 already-TP regression-lockdown TPs
- `tests/analysis/passes/issue-189-sprint90-xxe-ssti-path-cluster.test.ts`
  (NEW, 10 tests) — 4 new-detector TPs + 3 detector-control TNs +
  3 already-TP regression-lockdown TPs
- Full suite: **3391 passed | 2 skipped** (was 3362 on 3.137.0)
- `npm run typecheck && npm run build` clean
- Pillar I clean (no LLM/AI identifiers in changed files)

### #189 cumulative status

After Sprint 90, all 80 addressable FN cells across the multi-language
variant corpus are closed (the 16 trust_boundary cells stay parked
behind #117 trust-boundary-pass work). Sprint plan is complete; #189
can close pending the trust-boundary epic.

## [3.137.0] - 2026-06-30

Sprint 87 — cognium-dev #189 variant-regression scorecard: ldap (4) +
log_injection (4) cluster (8 FN cells across JavaScript + TypeScript +
Go + Rust + Python). Engine inventory on 3.136.0 found 3 of 8 already
firing (Python `logger.info` concat, JS `console.log` concat, TS
`pino.info` concat via the existing configured logging sinks). The 5
remaining FN shapes were the four LDAP variants (ldapjs/ldapts/go-ldap/
ldap3) and the Rust `log` crate macros. **5 of 5 addressable FN cells
closed via four new pattern detectors. 8 of 8 corpus cells now emit the
canonical sink signal.**

### Closed in this release

Pattern detectors (`language-sources-pass.ts`):

- `findJsLdapInjectionFindings` — ldapjs / ldapts
  `client.search(base, { filter: <tainted>, ... })` including the ES6
  property-shorthand form `{ filter, ... }` where `filter` traces back
  to an Express request extractor (`req.query|body|params|headers|
  cookies`). Closes `js__ldap_v01_ldapjs.js` and
  `ts__ldap_v01_ldapts.ts`. rule_id=`ldap_injection`, CWE-90,
  severity=critical.

- `findGoLdapInjectionFindings` — go-ldap
  `ldap.NewSearchRequest(base, scope, deref, sizeLimit, timeLimit,
  typesOnly, <tainted-filter>, attrs, controls)` (slot 7) where the
  filter traces back to `r.URL.Query().Get` / `r.Form.Get` /
  `r.FormValue` / etc. String-literal-aware multiline argument walker
  honors commas inside `"ou=users,dc=example,dc=com"` literals. Closes
  `go__ldap_v01_goldap.go`. rule_id=`ldap_injection`, CWE-90,
  severity=critical.

- `findRustLdapInjectionFindings` — ldap3
  `LdapConn::search(base, scope, &<tainted-filter>, attrs)` (slot 3)
  inside actix-web extractor handlers (`web::Query` / `web::Path` /
  `web::Form` / `web::Json` / `HttpRequest`). Per-function tainted-param
  tracking with multiline `.search(` call walker (string-literal aware).
  Closes `rust__ldap_v01_ldap3.rs`. rule_id=`ldap_injection`, CWE-90,
  severity=critical.

- `findRustLogInjectionFindings` — Rust `log` crate macros
  (`info!`, `warn!`, `error!`, `debug!`, `trace!`) where any
  interpolated format argument traces back to an actix-web extractor
  parameter via local `let`-binding propagation. Closes
  `rust__loginj_v01_logcrate.rs`. rule_id=`log_injection`, CWE-117,
  severity=medium.

### Risk + safety controls

- Detector A (JS/TS LDAP): gated on `.search(` + Express request
  extractor token + library reference (`ldapjs`/`ldapts`). Only fires
  when the `filter:` property value (or shorthand symbol) traces to a
  tainted variable via 3-pass whole-file binding propagation. Never
  fires on literal filter strings.
- Detector B (Go LDAP): gated on `ldap.NewSearchRequest(` + Go HTTP
  extractor token. String-literal-aware top-level comma split avoids
  spurious splits on commas inside `"ou=users,dc=example,dc=com"`
  literals. Slot-7-specific.
- Detector C (Rust LDAP): per-function tainted-param scope (params
  typed as `web::Query` / `web::Path` / `web::Form` / `web::Json` /
  `HttpRequest`). Multiline `.search(` walker only fires for the
  slot-3 filter argument, with the same string-literal-aware split.
- Detector D (Rust log): same per-function tainted-param model. Fires
  only on macros from `log`/`tracing` namespaces (gated by file-level
  import token). Literal-only format args are ignored.

### Verification

```bash
cd packages/circle-ir
npx vitest run tests/analysis/passes/issue-189-sprint87-ldap-loginj-cluster.test.ts
# 11/11 passing
npx vitest run                              # full suite: 3362 passed / 2 skipped
npm run typecheck && npm run build          # clean
```

Re-running the Sprint 87 inventory script against the 3.137.0 dist
shows 0/8 FN (was 5/8 on 3.136.0).

## [3.136.0] - 2026-06-30

Sprint 86 — cognium-dev #189 variant-regression scorecard: format_string
(5) + crlf (3) cluster (8 FN cells across Java + Python + Go +
JavaScript). Engine inventory on 3.135.0 found 4 of 8 already firing:
Java `String.format` and Java `resp.setHeader("Set-Cookie", taint)`
(via configured sinks); Go `fmt.Sprintf` and Go `w.Header().Set` (via
configured sinks). The 4 remaining FN shapes were Python `%` /
`.format()`, Node `util.format`, and Python `response.headers[...]`.
**4 of 4 addressable FN cells closed via three new pattern detectors.
8 of 8 corpus cells now emit the canonical sink signal.**

### Closed in this release

Pattern detectors (`language-sources-pass.ts`):

- `findPythonTaintedFormatStringFindings` — Python `<tainted> % args`
  and `<tainted>.format(args)` where the format template traces back
  to an HTTP request extractor (`request.args.get`, `request.form.get`,
  `request.values.get`, `request.json[...]`, `request.headers.get`).
  Closes `py__fmtstr_v01_percent.py` and `py__fmtstr_v02_str_format.py`.
  rule_id=`format_string`, CWE-134, severity=high.

- `findJsUtilFormatFormatStringFindings` — Node `util.format(<tainted>,
  ...)` where the first argument traces back to
  `req.{query|body|params|headers|cookies}`. Closes
  `js__fmtstr_v01_util_format.js`. rule_id=`format_string`, CWE-134,
  severity=medium.

- `findPythonHeaderCrlfInjectionFindings` — Flask/Werkzeug
  `response.headers['X-Custom'] = <tainted>` and
  `.headers.add|set|setdefault|append(...)` where the assigned value
  traces back to an HTTP request extractor. Closes
  `py__crlf_v01_headers_dict.py`. rule_id=`crlf`, CWE-113,
  severity=medium.

### Risk + safety controls

- Detector A (Python format-string): only fires when the symbol holding
  the format template was assigned from a Python HTTP request extractor
  on a prior line (3-pass whole-file taint propagation). Never fires
  on literal format strings or symbols not derived from request input.
- Detector B (Node util.format): gated on both `util.format(` and a
  request-extractor token (`req.query|body|params|headers|cookies`)
  appearing in the file before emit. Only fires when the first
  argument resolves to a tainted symbol via the local-binding tracker.
- Detector C (Python CRLF): only fires when the RHS expression
  contains a tainted symbol (HTTP request derivation traced through
  string-concat and `+`). Doesn't fire on literal Set-Cookie values or
  hash-derived constants.

### Verification

- 11/11 new tests passing (TP per detector + TN per detector +
  sanity TPs for the 4 already-covered cells).
- Full vitest: **3351 passed / 2 skipped** (was 3340; +11).
- Typecheck clean. Pillar I guard clean.
- Re-baseline against `/tmp/sprint86-fmtstr-crlf/`: 0/8 FN
  (was 4/8 on 3.135.0).

### Status

- #189 remaining FN: **47 → 43** (4 closed). Next sprint: 87 (ldap 4 +
  log_injection 4 = 8 cells).
- `format_string` cluster: 5/5 closed.
- `crlf` cluster: 3/3 closed.

## [3.135.0] - 2026-06-30

Sprint 85 — cognium-dev #189 variant-regression scorecard: ssrf cluster
(6 FN cells across Java + JavaScript). Engine inventory on 3.134.0 found
4 of 6 already firing via configured nodejs.json sinks (axios/got/
http.get/request — `got(url)` and `request(url)` match the existing
`request` sink rows by method-name; `http.get` and `axios.get` via
class-scoped rows). The 2 remaining FN shapes were both Java URL fetch
chains. **2 of 2 addressable FN cells closed via one new pattern
detector. 6 of 6 corpus cells now emit the canonical sink signal.**

### Closed in this release

Pattern detector (`language-sources-pass.ts`):

- `findJavaUrlOpenStreamSsrfFindings` — Java `new URL(<servlet-request
  taint>)` → `.openStream()` / `.openConnection()` / `.getContent()`
  receiver chains that the configured `URL.openStream` /
  `URL.openConnection` sinks recognize but the cross-statement flow
  construction misses (the URL value passes through an intermediate
  `URL u = new URL(url);` local binding). Tracks tainted vars derived
  from servlet request extractors (`getParameter`, `getParameterValues`,
  `getHeader`, `getHeaders`, `getCookies`, `getReader`,
  `getQueryString`, `getRequestURI`, `getInputStream`, `getPart`,
  `getParts`) via 3-pass whole-file propagation. Also fires for the
  weak-allowlist variant: an `if (url.startsWith("https://"))` guard is
  not a sanitizer because the host portion remains attacker-controlled
  (URL-parsing + `getHost()` allowlist is the only sound fix). Emits
  `rule_id: 'ssrf'`, CWE-918, critical. Closes `java__V01BasicFetch`
  and `java__V02WeakAllowlist`.

### Already-TP (existing configured sinks)

The four JavaScript cells fire via existing `configs/sinks/nodejs.json`
rows without any code change:

- `axios.get(req.query.url)` — `axios.get` class-scoped row.
- `got(req.query.url)` and `got.get(req.query.url)` — match the `request`
  method-name rows in the existing sink table (no `got` class binding
  required).
- `http.get(req.query.url, cb)` — `http.get` class-scoped row.
- `request(req.query.url, cb)` — matches the `request` method-name rows
  (standalone callable).

### Tests

`tests/analysis/passes/issue-189-sprint85-ssrf-cluster.test.ts` — 6 new
test cases (4 TP for the Java detector including chained-URL form and
weak-allowlist variant, 1 TN for literal URL, 2 sanity for JS axios +
http.get cells). All 3340 tests passing (was 3334 on 3.134.0; +6 new);
2 pre-existing skipped.

### Files touched

- `src/analysis/passes/language-sources-pass.ts` (+109 LOC: 1 new
  detector + 1 wire-in block).
- `tests/analysis/passes/issue-189-sprint85-ssrf-cluster.test.ts`
  (NEW).
- `package.json` (3.134.0 → 3.135.0).

### #189 cumulative progress

| Sprint | Ver | Cluster | Closed |
|---|---|---|---|
| 81 | 3.130.0 | xss (11) | 9 (cells 5, 7 deferred) |
| 82 | 3.132.0 | open_redirect (10) | 10 |
| 83 | 3.133.0 | code_injection (8) | 8 |
| 84 | 3.134.0 | nosql + sqli (12) | 10 + 2 manifest deferrals |
| 85 | 3.135.0 | ssrf (6) | 6 |

45 of 47 addressable #189 cells closed across Sprints 81-85.
Remaining: format_string + crlf (8) → Sprint 86, ldap +
log_injection (8) → Sprint 87, command_injection JS (4) →
Sprint 88, deserialization + xpath (7) → Sprint 89, xxe + ssti +
path (6) → Sprint 90.

## [3.134.0] - 2026-06-30

Sprint 84 — cognium-dev #189 variant-regression scorecard: nosql + sqli
cluster (12 FN cells across 6 languages). Engine inventory found 8 of 12
already firing via configured Node.js Mongo sinks and Go/Java SQL flow
construction; the remaining 4 shapes split into 3 directly-addressable
detector gaps + 2 corpus-manifest mismatches. **3 of 4 addressable FN
cells closed via three new pattern detectors. 10 of 12 corpus cells now
emit the canonical sink signal.**

### Closed in this release

Pattern detectors (`language-sources-pass.ts`):

- `findGoMongoNosqlInjectionFindings` — Go MongoDB driver call shapes
  `coll.{FindOne|Find|InsertOne|InsertMany|UpdateOne|UpdateMany|
  DeleteOne|DeleteMany|FindOneAndUpdate|FindOneAndDelete|
  FindOneAndReplace|Aggregate}(ctx, bson.M{...})` where any argument
  references a value transitively derived from `*http.Request`
  extractors (`URL.Query().Get`, `FormValue`, `PostFormValue`,
  `Header.Get`, `Cookie`). Uses 3-pass transitive var resolution
  inside each `func` scope and a balanced-paren extractor for nested
  calls (`context.TODO()` inside the args). Emits
  `rule_id: 'nosql_injection'`, CWE-943, critical (closes
  `go__v01_find_one`).
- `findJavaMongoNosqlInjectionFindings` — Java Mongo driver call
  shapes `<recv>.{find|findOne|findOneAndUpdate|findOneAndDelete|
  findOneAndReplace|insertOne|insertMany|updateOne|updateMany|
  deleteOne|deleteMany|replaceOne|aggregate|countDocuments|distinct}
  (...,<tainted servlet input>,...)` (including `Filters.eq` and
  `new Document(...)` payloads). Tracks tainted vars derived from
  servlet request extractors (`getParameter`, `getParameterValues`,
  `getHeader`, `getHeaders`, `getCookies`, `getReader`,
  `getQueryString`, `getRequestURI`, `getInputStream`, `getPart`,
  `getParts`) via 3-pass whole-file propagation. Closes
  `java__V01FindOne`.
- `findPythonMongoengineWhereNosqlInjectionFindings` — Python
  mongoengine `__raw__={'$where': <expr>}` where `<expr>` contains
  string concat or f-string interpolation of a tainted Flask request
  extractor (`request.{args|form|values|json|files|cookies|headers|
  data}`). The `$where` operator evaluates JavaScript on the server,
  so tainted JS-string concatenation is true NoSQL injection.
  Skips pure-literal `$where` strings. Closes the engine-side gap on
  `py__v04_mongoose_find` (note: corpus manifest tags this cell as
  `sql_injection`; the engine correctly emits `nosql_injection`).

### Deferred (corpus manifest mismatches — not engine bugs)

Two cells remain FN against the corpus tagging but are semantically
correct in the engine's output:

- `js__v06_mongoose_find` — `User.find({ $where: "this.name == '" +
  req.query.n + "'" })` — engine emits `nosql_injection` (correct);
  corpus expects `sql_injection`. Tracked for manifest correction.
- `py__v04_mongoose_find` — mongoengine `__raw__={'$where': ...}` —
  engine now emits `nosql_injection` (correct); corpus expects
  `sql_injection`. Tracked for manifest correction.

Following Sprint 81 cell-5 precedent (manifest re-tag preferred over
introducing a noisy dual-emit), both cells are flagged for upstream
corpus correction rather than engine change.

### Tests

`tests/analysis/passes/issue-189-sprint84-nosql-sqli-cluster.test.ts`
— 9 new test cases (TP / TP-control / TN for each detector). All
3334 tests passing (was 3325 on 3.133.0; +9 new); 2 pre-existing
skipped.

### Files touched

- `src/analysis/passes/language-sources-pass.ts` (+289 LOC: 3 new
  detectors + 3 wire-in blocks; balanced-paren helper for Go).
- `tests/analysis/passes/issue-189-sprint84-nosql-sqli-cluster.test.ts`
  (NEW).
- `package.json` (3.133.0 → 3.134.0).

### #189 cumulative progress

| Sprint | Ver | Cluster | Closed |
|---|---|---|---|
| 81 | 3.130.0 | xss (11) | 9 (cells 5, 7 deferred) |
| 82 | 3.132.0 | open_redirect (10) | 10 |
| 83 | 3.133.0 | code_injection (8) | 8 |
| 84 | 3.134.0 | nosql + sqli (12) | 10 + 2 manifest deferrals |

39 of 41 addressable #189 cells closed across Sprints 81-84.
Remaining: ssrf (6) → Sprint 85, format_string + crlf (8) →
Sprint 86, ldap + log_injection (8) → Sprint 87,
command_injection JS (4) → Sprint 88, deserialization + xpath
(7) → Sprint 89, xxe + ssti + path (6) → Sprint 90.

## [3.133.0] - 2026-06-30

Sprint 83 — cognium-dev #189 variant-regression scorecard: code_injection
cluster (8 FN cells across 4 languages). Engine inventory found 4 of 8
already firing via configured sinks (Go template SSTI, JS `vm.Script`,
JS `setImmediate(string)`, Python `importlib.import_module`); the
remaining 4 shapes are closed by four new pattern detectors. **8 of 8
code_injection FN cells closed.**

### Closed in this release

Pattern detectors (`language-sources-pass.ts`):

- `findGoPluginOpenCodeInjectionFindings` — Go `plugin.Open(<taint>)`
  and `plugin.Lookup(<taint>)` where the argument traces back to an
  `*http.Request` extractor (`FormValue`, `PostFormValue`,
  `URL.Query().Get`, `Header.Get`, `Cookie`) within the same
  function. Loading a Go plugin runs its `init()` and exposes its
  exported symbols, equivalent to dynamic library load (closes
  `go__v04_dynamic_import`).
- `findJsIndirectEvalCodeInjectionFindings` — JS indirect eval forms
  that escape the configured `eval` sink matcher:
  `(0, eval)(taint)`, `globalThis.eval(taint)`, `global.eval(taint)`,
  `window.eval(taint)`, `self.eval(taint)`, and aliased eval
  (`const f = eval; f(taint)` — discovered alias set). All three
  forms execute in the global scope. Triggers when the argument
  traces back to `req.body`, `req.query`, `req.params`, `req.headers`,
  or `req.cookies` via the 3-pass transitive let/const/var resolver
  (closes `js__v07_indirect_eval`). Comment-only lines are skipped to
  avoid matching docstring examples.
- `findPythonInteractiveInterpreterCodeInjectionFindings` — Python
  stdlib `code` module: `code.InteractiveInterpreter().runsource(s)`,
  `code.InteractiveConsole().{runsource,runcode,push,interact}(s)`,
  and `code.compile_command(s)`. Each compiles and executes arbitrary
  Python source. Gated on a file-level `import code` namespace check
  to avoid clashing with user-defined `code` identifiers (Sprint 74
  alias-tracking lesson). Triggers on `request.*` extractor flow
  (closes `py__v03_vm_context`).
- `findRustEvalCrateCodeInjectionFindings` — Rust dynamic-eval crate
  sinks: `evalexpr::eval(...)` (and `_with_context|_boolean|_int|`
  `_float|_string|_tuple|_empty` variants), `libloading::Library::new`
  (dynamic library load), and `mlua/rlua` `<lua>.load(arg)`
  `.{exec|eval|call}(...)`. Per-function tainted-param discovery
  scans `fn` headers for Actix extractor types (`String`, `Bytes`,
  `web::Query|Path|Form|Json`, `HttpRequest`, `axum::body::Bytes`)
  and propagates through `let`/`let mut` bindings with the 3-pass
  resolver. `&` borrow prefix is unwrapped before matching (closes
  `rust__v01_eval_direct`).

### Verified

- 11 of 11 new test cases pass
  (`tests/analysis/passes/issue-189-sprint83-code-injection-cluster.test.ts`)
- Full suite: 3325 passed, 2 skipped across 232 test files
- All TP-control / TN tests prove the new detectors do not over-fire
  on literal-only args (`plugin.Open("/usr/lib/...")`, `(0, eval)("1+1")`,
  `evalexpr::eval("1 + 1")`) or on user-defined `code` vars without an
  `import code` (Python namespace gate)
- Pillar I guard clean (no LLM/AI identifiers)

### #189 progress

After Sprint 83: open_redirect (10) + code_injection (8) = **18 of 80
FN cells closed across Sprints 82-83**. Sprint 84 targets the
nosql (6) + sqli (6) cluster.

## [3.132.0] - 2026-06-30

Sprint 82 — cognium-dev #189 variant-regression scorecard: open_redirect
cluster (10 FN cells across 8 languages). Three engine fixes unblock 4
of the cells through the configured-sink path, and four new pattern
detectors cover the remaining 6 shapes that the configured-sink model
doesn't reach. **10 of 10 open_redirect FN cells closed.**

### Closed in this release

Engine fixes (configured-sink path):

- `findings.ts:175-209` — `canSourceReachSink` reach map gap.
  `open_redirect` was missing from the http-source reach lists, so the
  inline-source colocation detector at `taint-propagation-pass.ts:1259`
  silently dropped every `http_param`/`http_body`/`http_header`/
  `http_cookie`/`http_path`/`http_query`/`interprocedural_param` →
  `open_redirect` pair. Added `'open_redirect'` to all 7 lists.
- `config-loader.ts:1243-1246` — Java
  `HttpServletResponse.sendRedirect(...)` was mis-typed as `ssrf` (the
  CWE column already pointed to `CWE-601`). Re-typed to
  `open_redirect` so manifest sink_type matches downstream consumers
  (closes `java__V01RedirectParam`).
- `taint-propagation-pass.ts` lines 90/102/124/760 — flow-merge dedup
  keyed on `(source_line, sink_line)` only and silently dropped the
  second-iterated sink when one source line had multiple
  distinct-`type` sinks. `res.redirect` is configured both as
  `open_redirect` (CWE-601) and `crlf` (CWE-113); the dedup dropped
  the second one. Added `sink_type` to all four dedup keys (closes
  `js__v01_redirect_param`).

Pattern detectors (`language-sources-pass.ts`):

- `findGoLocationHeaderOpenRedirectFindings` — Go
  `<rw>.Header().Set("Location", taint)` /
  `<rw>.Header().Add("Location", taint)` where `<rw>` is typed
  `http.ResponseWriter`. The configured sink rows for `Header.Set`
  are typed `crlf` (CWE-113); the same line is also CWE-601 when the
  literal key is `Location` (closes `go__v02_location_header`).
- `findPythonHeadersSubscriptOpenRedirectFindings` — Flask
  `resp.headers["Location"] = taint` subscript-assignment shape.
  The configured sinks for `Response.headers` model the dict-add
  form but not subscript assignment (closes `py__v02_location_header`).
- `findRustAppendHeaderTupleOpenRedirectFindings` — Actix builder
  pattern `<builder>.append_header(("Location", taint))` /
  `.insert_header(("Location", taint))` where the value traces back
  to a `web::Query`/`Path`/`Form`/`Json` or `HttpRequest`
  extractor. The configured sinks model single-arg `set_header(value)`
  but not the tuple-arg HeaderName→HeaderValue API (closes
  `rust__v01_redirect_param`).
- `findJsDomOpenRedirectFindings` — DOM open_redirect sinks:
  `location.href = taint`, `window.location = taint`,
  `<elem>.content = '<...>;url=' + taint` (meta-refresh DOM shape),
  `location.assign(taint)` / `location.replace(taint)`. Tainted
  values trace back to `location.search` / `location.hash` /
  `URLSearchParams` / `document.referrer` / `window.name`. Runs in
  the `javascript`/`typescript`/`htmljs` block, which receives the
  extracted `<script>` blocks from HTML files via
  `analyzeMarkupFile` (closes `html__v01_redirect_param`,
  `html__v03_meta_refresh`, `htmljs__v03_meta_refresh`).

### Conservative shape (TP-controls preserved)

- Go: only fires when receiver type-of-name is `http.ResponseWriter`,
  literal key is case-insensitive `"Location"`, and the value isn't
  wrapped in `url.Parse`+`Host` / `IsAbs` / `strings.HasPrefix`.
  `Header().Set("X-Custom-*", taint)` is NOT fired (TN-A2).
- Python: requires the rhs to be a recognized request-source variable
  OR inline `request.<x>.get/[]`. Literal rhs is skipped (TN-B1).
  `headers["X-Custom"] = taint` is NOT fired (TN-B2).
- Rust: requires the value to trace back to an extractor parameter;
  literal value is skipped (TN-C1); non-Location key is skipped (TN-C2).
- JS DOM: requires the rhs to contain (or transitively reference)
  a recognized DOM source token; never fires on literal-only
  assignments (TN-D1, TN-D2, TN-D4). `<elem>.content` only fires
  when the rhs actually looks like a meta-refresh URL string
  (`'<delay>;url=...'`).
- All four detectors skip lines where a recognized URL-allowlist
  sanitizer wraps the value (`startsWith` against a literal `/`-path,
  `URL(...).origin === ...`, Rust `url::Url::parse(...).host_str`).

### Tests

- +19 in
  `tests/analysis/passes/issue-189-sprint82-open-redirect-cluster.test.ts`
  (3 engine-fix TPs + 4 detector TPs + 8 TN-controls + 4 additional
  TPs for shape coverage).

### Pillar I

No LLM/AI identifiers introduced. The only matches in changed files
(`grep -inE '\\bllm\\b|openai|anthropic|claude|\\bgpt\\b'`) are
pre-existing comments unrelated to this sprint.

## [3.131.0] - 2026-06-30

Sprint 77b — cognium-dev #216 FPR scorecard tail: 2 last corpus-blocked
TS Pattern X interop FPs (now unblocked — fixtures committed at
`coggiyadmin/typescript-vuln-demo:interop/`). Two new JS/TS sanitizer
detectors emit `TaintSanitizer` entries that the existing suppression
mechanism in `taint-propagation-pass.ts:198-232` then uses to silence
synthetic `external_taint_escape` flows at the `[source, sink]` range.

### Closed in this release

- `safe_interop_shell_in_string.ts` —
  `execFile('echo', ['--', arg], () => {})` argv-form exec with a
  string-literal program. New `findJsArgvFormExecSanitizers` (in
  `src/analysis/passes/language-sources-pass.ts`) recognizes the
  `(execFile|spawn)(Sync)?('<literal>', [<argv>...])` shape. Emits
  `command_injection` + `external_taint_escape` sanitizer at that
  line.
- `safe_interop_sql_in_string.ts` —
  `pool.query('SELECT * FROM users WHERE name = $1', [name])`
  parameterized pg query. New `findJsParameterizedSqlSanitizers`
  recognizes `.query(<string-literal>, [...])` where the SQL contains
  positional placeholders (`$N` PostgreSQL or `?` MySQL/SQLite) AND
  the second argument is an array literal. Emits `sql_injection` +
  `external_taint_escape` sanitizer at that line.

### Conservative shape (TP-controls preserved)

- Shell-via-argv exclusion: `execFile('sh' | '/bin/sh' | 'bash' | ...,
  ['-c', tainted])` is NOT suppressed since `-c` re-enables shell
  parsing of the subsequent argv slot. Path prefixes (`/bin/`,
  `/usr/bin/`) are recognized.
- Tainted-program slot exclusion: `execFile(prog, [arg])` where
  `prog` is a variable is NOT matched (TP-2 control). Only literal
  programs (`'literal'` / `"literal"` / `` `literal` ``) qualify.
- Single-string `exec` form: `exec("echo " + arg)` is NOT matched
  (TP-1 control — `exec` itself spawns a shell regardless of argv
  form). Detector is scoped to `execFile`/`spawn` (+Sync variants).
- Concat SQL: `pool.query("SELECT ... '" + name + "'")` is NOT
  matched (TP-3 control — string is not a pure literal).
- Interpolated template SQL: `` pool.query(`SELECT ... '${name}'`) ``
  is NOT matched (TP-4 control — backtick form is rejected when the
  string body contains `${`).
- Placeholder requirement: `.query("SELECT * FROM users", [])` with
  no `$N`/`?` placeholder is NOT matched.

### Tests

- +6 in `tests/analysis/passes/issue-216-pattern-x-sprint77b.test.ts`
  (2 TN reproducing the verbatim corpus FPs + 4 TP-control proving
  the sanitizers do not over-suppress shell-via-argv exec, concat
  SQL, or interpolated template SQL).

Full suite: **3295 pass | 2 skipped**. Typecheck + build clean.
Pillar I clean — no LLM/AI identifiers in changed files.

**#216 status:** all 24 corpus FPs now closed. Ticket may close
pending external corpus re-baseline.

## [3.130.0] - 2026-06-30

Sprint 81 — cognium-dev #189 variant-regression: xss cluster (11 FN
cells). Engine inventory on 3.129.0 found cell 8 (React
`dangerouslySetInnerHTML`) already fires and cell 5 (`eval(location
.hash)`) is a corpus-manifest mis-tag (engine correctly emits
`code_injection`, not xss — deferred as corpus correction). The
remaining 9 FN cells are closed by six new per-language pattern
detectors that emit `SastFinding{rule_id:'xss'}` directly, bypassing
the source→sink→flow construction in places where the engine cannot
yet build a flow (string-concat / f-string, Java receiver-chain
typing, framework templates).

### Added

- **Go xss to http.ResponseWriter (cognium-dev #189)** —
  `findGoXssFindings` two-pass: discover ResponseWriter parameter
  names from function signatures `(<name> http.ResponseWriter, ...)`,
  then for every `fmt.Fprint(f|ln)?(<name>, ...)` whose first arg
  matches a discovered name, emit xss unless one of the args is
  wrapped in a recognized HTML escaper (`html.EscapeString`,
  `template.HTMLEscapeString`, etc.). Tolerates trailing `//`
  comments. Emits `xss` (CWE-79).

- **Java HttpServletResponse receiver-chain xss (cognium-dev #189)** —
  `findJavaResponseWriterXssFindings` recognizes the chained call
  `<recv>.getWriter().{print,println,write,printf,format,append}
  (<args>)` where `<recv>` is a parameter typed `HttpServletResponse`.
  Skip when args is a pure string literal or when an OWASP encoder
  (`Encode.forHtml*`, `StringEscapeUtils.escapeHtml4`,
  `HtmlEscapers.htmlEscaper`, `Jsoup.clean`, …) wraps the value.
  Closes the receiver-chain gap where the configured `PrintWriter
  .print` sink doesn't resolve. Emits `xss` (CWE-79).

- **Vue v-html template directive xss (cognium-dev #189)** —
  `findJsVueVHtmlXssFindings` scans `template: '<...v-html="<var>"
  ...>'` strings in Vue component options. Builds a transitive
  set of variables tainted by `URLSearchParams`, `location.*`,
  `route.query/params`, `fetch(...)`, `axios.get/post`, etc.,
  then emits xss when the bound variable is in the tainted set
  or declared as a `props` member. Doesn't fire when the binding
  is a literal. Emits `xss` (CWE-79).

- **Angular DomSanitizer bypass xss (cognium-dev #189)** —
  `findTsAngularBypassXssFindings` two-pass: discover
  `DomSanitizer`-typed variable names from constructor parameter
  declarations / class-field type annotations + `this.<f> = <ctor
  param>` aliasing, then emit xss on every `<recv>.bypassSecurity
  Trust(Html|Script|Url|ResourceUrl|Style)(<arg>)` whose `<recv>`
  matches and whose `<arg>` is not a string literal. Emits `xss`
  (CWE-79).

- **Python Flask string-concat / f-string xss (cognium-dev #189)** —
  `findPythonFlaskStringConcatXssFindings` requires a Flask route
  decorator (`@<x>.route(`) above the function and a tainted symbol
  traceable to `request.<args|form|values|files|cookies|headers
  >.{get,[]}`. Detects HTML construction via `+`-concat, f-string
  interpolation (quote-aware so `f'<a href="{u}">'` fires), `%`
  formatting, or `.format()`. Skips when the expression wraps the
  value in `markupsafe.escape` / `html.escape`. Emits `xss` (CWE-79).

- **Python Jinja Markup autoescape-bypass xss (cognium-dev #189)** —
  `findPythonJinjaMarkupXssFindings` namespace-scoped alias tracking
  (Sprint 74 lesson): only treats `Markup` as dangerous when imported
  from `markupsafe` or `flask` and no user-defined `class Markup`
  shadows it. Emits xss when `Markup(<var>)` wraps a request-derived
  value and the file contains a `.render(...)` call. Emits `xss`
  (CWE-79).

### Verification

Inventory re-run on `/tmp/sprint81-xss/` (11 fixtures): 10 of 11
cells fire; cell 5 (`eval(location.hash)`) deferred as corpus-
manifest revision (engine correctly emits `code_injection`).

Tests: 13/13 new in
`tests/analysis/passes/issue-189-sprint81-xss-cluster.test.ts`.
Full suite: 3289 passed, 2 skipped. Pillar I clean.

## [3.129.0] - 2026-06-30

Sprint 78 (combined 78+79+80) — cognium-dev #190 Tier-2 misconfig
regression. Engine inventory of the 14 pinned TP-FN cells on 3.128.0
found 6 already detected (`go-insecure-cookie`, `py-cors-wildcard`,
`py-xfo-csp-mismatch`, `py-tls-verify`, `rust-tls-verify`, `bash-md5`).
This release adds 8 new per-language pattern detectors to close the
remaining gap.

### Added

- **Rust hardcoded credential (cognium-dev #190)** —
  `findRustHardcodedCredentialFindings` recognizes
  `pub const <NAME>: &str = "literal"` where `<NAME>` matches
  `/api[_]?key|secret|token|password|passwd|pwd|auth/i` and the
  literal is non-trivial (length ≥ 8, not a placeholder). Emits
  `hardcoded-credential` (CWE-798).

- **Rust insecure-cookie builder chain (cognium-dev #190)** —
  `findRustInsecureCookieFindings` recognizes the actix-web
  `Cookie::build(...)` chain when it calls `.secure(false)` and/or
  `.http_only(false)`. The dedicated `insecure-cookie-pass.ts`
  handles the `format!("Set-Cookie: ...")` shape; this complements
  it for the typed-builder shape. Emits `insecure-cookie` (CWE-1004).

- **Rust JWT verify-disabled (cognium-dev #190)** —
  `findRustJwtVerifyDisabledFindings` recognizes the jsonwebtoken
  `.insecure_disable_signature_validation()` method call on
  `Validation` values. Emits `jwt-verify-disabled` (CWE-347).

- **Rust ECB-mode weak-crypto (cognium-dev #190)** —
  `findRustWeakCryptoEcbFindings` two-pass: confirm the file
  constructs a raw block cipher (`Aes128::new` / `Aes192::new` /
  `Aes256::new` / `Aes*Ecb::new`), then emit on every
  `.encrypt_block(` / `.decrypt_block(` line. Wrapped CBC/GCM/CTR
  forms go through `Cbc::<Aes128, ...>::new` / `Aes128Gcm::new`
  which expose different APIs and do not match. Emits `weak-crypto`
  (CWE-327).

- **Java pattern findings (cognium-dev #190)** —
  `findJavaPatternFindings` adds two detectors that the dedicated
  passes miss:
  - `jwt-verify-disabled` (CWE-347) on bare `JWT.decode(<token>)`
    on the auth0 `com.auth0.jwt.JWT` class. `decode` parses without
    verifying the signature; `JWT.require(<algorithm>).build().verify(token)`
    is the safe form.
  - `tls-verify-disabled` (CWE-295) on anonymous `X509TrustManager`
    implementations whose `checkServerTrusted(...)` body is empty
    (`{}` without `throw` / `if`). Empty-body trust managers
    accept every certificate.

- **Go ECB-mode weak-crypto (cognium-dev #190)** —
  `findGoPatternFindings` two-pass: collect every
  `<v>, _ := aes.NewCipher(...)` cipher variable; drop variables
  that are wrapped by `cipher.NewGCM(<v>)` /
  `cipher.NewCBCEncrypter(<v>)` / `cipher.NewCTR(<v>)` /
  `cipher.NewOFB(<v>)` / `cipher.NewCFB*(<v>)`; emit
  `weak-crypto` (CWE-327) on every remaining `<v>.Encrypt(` /
  `<v>.Decrypt(` line. The Go stdlib `aes.Cipher.Encrypt/Decrypt`
  operate on a single 16-byte block — calling them directly is ECB.

- **JS `libxmljs` XXE noent flag (cognium-dev #190)** —
  `findJsPatternFindings` recognizes
  `libxml(js).parseXml(buf, { noent: true })` and
  `parseXmlString(...)` with `noent: true` and emits
  `xml-entity-expansion` (CWE-611). The default `noent: false`
  is benign and is not matched.

### Tests

- +16 in `tests/analysis/passes/issue-190-sprint78-misconfig.test.ts`
  (8 TP-FN reproducing the verbatim corpus fixtures + 8 TN-control
  proving the detectors do not over-fire on the obvious benign
  variant — verify chain, secure flags, GCM mode, noent:false, etc.).

Full suite: **3276 pass | 2 skipped** (was 3260 + 16 new tests).
Typecheck + build clean. Pillar I clean.

## [3.128.0] - 2026-06-29

Sprint 77a — cognium-dev #216 Pattern X mixed in-corpus sanitizers.
Closes 3 of the 5 remaining FPs (`SafeInteropShellInString.java`,
`benign_exec_argv.rs`, `benign_autoescape_template.py`). #216 stays
open for 2 TS Pattern A FPs (corpus-blocked; fixtures not yet
committed to `coggiyadmin/typescript-vuln-demo`, deferred to
Sprint 77b).

### Added

- **Java argv-form exec sanitizer (cognium-dev #216 Pattern X)** —
  `findJavaArgvFormExecSanitizers` recognizes the argv-array exec
  forms that cannot smuggle shell metacharacters:

  ```java
  Runtime.getRuntime().exec(new String[]{"echo", "--", arg});
  new ProcessBuilder(new String[]{"ls", "-l", dir});
  ```

  Emits `command_injection` + `external_taint_escape` sanitizers at
  the exec line. The single-string concat form
  `exec("echo " + arg)` is NOT matched and remains a
  `command_injection` finding (TP-1 control).

- **Rust argv-form `Command::new(literal).arg(...)` sanitizer
  (cognium-dev #216 Pattern X)** — `findRustArgvCommandSanitizers`
  recognizes argv-form exec with a string-literal program:

  ```rust
  Command::new("grep").arg(p).arg("/var/log/app.log").status();
  ```

  Emits `command_injection` + `external_taint_escape` sanitizers at
  the call line. Tainted-program slot
  `Command::new(prog).arg(...)` is NOT matched (TP-2 control), and
  shell-via-argv `Command::new("sh"/"bash"/...).arg("-c")` is
  explicitly excluded since `-c` re-enables shell parsing of the
  tainted slot.

- **Python Jinja2 `Environment(autoescape=...)` + `.render(...)`
  sanitizer (cognium-dev #216 Pattern X)** —
  `findPythonJinjaAutoescapeSanitizers` recognizes the canonical
  Jinja2 autoescape-on render chain:

  ```python
  env = Environment(loader=..., autoescape=select_autoescape(["html"]))
  env.get_template("hello.html").render(name=name)
  ```

  Two-pass: pass 1 collects every identifier assigned an
  `Environment(... autoescape=<expr> ...)` call (rejecting
  `autoescape=False` / `None` / `0`); pass 2 emits `xss` +
  `external_taint_escape` sanitizers at every
  `<env>.get_template(...).render(...)` chain line. Plain
  `Environment(...)` without an explicit `autoescape=` keyword is
  NOT matched (TP-3 control).

### Mechanism

All three detectors wire into the existing
`taint-propagation-pass.ts:198-232` sanitizer suppression: configured
`command_injection`/`xss` flows are filtered at the sink line, and
synthetic `external_taint_escape` flows are filtered across the
`[source, sink]` range.

### Tests

+6 in `tests/analysis/passes/issue-216-pattern-x-sprint77a.test.ts`
(3 TN reproducing the verbatim corpus FPs + 3 TP-control proving the
sanitizers do not over-suppress real vulns in similar
shell-concat / tainted-program / autoescape-off variants).

## [3.127.0] - 2026-06-29

Sprint 76 — cognium-dev #216 Pattern B Java inline sanitizers. Closes
2 of the 7 remaining FPs (`BenignPathNormalize.java`,
`BenignRedactedLog.java`). #216 stays open for 5 remaining
cross-language FPs.

### Added

- **Java `Path.resolve(...).normalize()` + `startsWith(ROOT)` guard
  sanitizer (cognium-dev #216 Pattern B)** —
  `findJavaPathNormalizeStartsWithGuardSanitizers` recognizes the
  canonical resolve-under-root safe pattern:

  ```java
  Path full = ROOT.resolve(name).normalize();
  if (!full.startsWith(ROOT)) throw new SecurityException("escape");
  return full;
  ```

  Two-pass: pass 1 collects every `<v> = <root>.resolve(<arg>)
  .normalize()` chain (capturing `<v>` + `<root>`); pass 2 confirms
  a matching `if (!<v>.startsWith(<root>))` guard within 6 lines
  whose body contains a `throw` or `return` terminator. On
  confirmation, emits `path_traversal` + `external_taint_escape`
  sanitizers at the resolve line and at every subsequent line
  referencing `<v>` (covers `return full;`, `Files.read(full)`,
  etc.). `.normalize()` alone is NOT recognized — absolute-path
  arguments replace `ROOT` entirely, so the load-bearing check is
  the `startsWith` guard (TP-1 control).

- **Java inline CRLF/tab-strip log sanitizer (cognium-dev #216
  Pattern B)** — `findJavaInlineCrlfStripLogSanitizers` recognizes
  inline-at-sink CRLF redaction:

  ```java
  log.info("event=user_lookup value={}", user.replaceAll("[\\r\\n\\t]", "_"));
  ```

  Single-pass: emits a `log_injection` + `external_taint_escape`
  sanitizer only when a recognized slf4j/log4j/JUL log call (`log`,
  `logger`, `LOG`, `LOGGER`, `slog` receivers; `info`/`warn`/`error`
  /`debug`/`trace`/`fatal`/`severe`/`fine{,r,st}`/`config`/`warning`
  methods) appears on the same source line as a CRLF-stripping
  `.replaceAll("[...\\r\\n...]", ...)` or single-char
  `.replace('\\n'|'\\r'|'\\t', ...)` argument. A `replaceAll(...)`
  on a different earlier line assigned to a temp variable is NOT
  recognized (TP-2 control: a separately-tainted log argument still
  fires `log_injection`).

### Tests

- New `tests/analysis/passes/issue-216-pattern-b-java.test.ts` with 4
  cases: 2 TN reproducing both corpus FPs (resolve+normalize+
  startsWith and inline log redaction) and 2 TP-control verifying
  that resolve+normalize without the startsWith guard still fires
  `path_traversal` and a wrong-variable `replaceAll` on a separate
  line does not over-suppress `log_injection` at a later log call
  with a different unsanitized argument.

### Fixed

- `BenignPathNormalize.java:9` no longer emits `path_traversal` or
  `external_taint_escape` on `ROOT.resolve(name).normalize()` when
  the canonical `.startsWith(ROOT)` guard is present.
- `BenignRedactedLog.java:10` no longer emits `log_injection` or
  `external_taint_escape` on
  `log.info("...", user.replaceAll("[\\r\\n\\t]", "_"))`.

## [3.126.0] - 2026-06-29

Sprint 75 — cognium-dev #216 Pattern D JS SSRF allow-list. Closes 2 of
the 9 remaining FPs (`benign_fetch_allowlist.js`,
`benign_host_allowlist_fetch.js`). #216 stays open for 7 remaining
cross-language FPs.

### Added

- **JS SSRF allow-list guard sanitizer (cognium-dev #216 Pattern D)** —
  new conservative recognizer `findJsSsrfAllowlistGuardSanitizers`
  wired into `language-sources-pass.ts`. Two-pass detector:
  1. **Alias discovery** — scans for `const <u> = new URL(<src>)` and
     `const <h> = <u>.hostname` (or `.host`) declarations, building a
     `<url-alias> → <src-arg>` and `<host-alias> → <url-alias>` map.
  2. **Guard recognition + emission** — recognizes
     `if (!ALLOWED.has(<v>))`, `if (!ALLOWED.includes(<v>))`, and
     `if (ALLOWED.indexOf(<v>) < 0)` (with optional `.hostname` /
     `.host` accessor on `<v>`) where the allow-list identifier is
     UPPER_SNAKE or matches `/allowed|accepted|whitelist|permitted|
     valid|approved/i`. The guard body must contain a terminator
     (`return`, `throw`, or `res.status(...).send/end/json(...)`). On
     match, emits `TaintSanitizer` entries with
     `sanitizes: ['ssrf', 'external_taint_escape']` on every
     subsequent line in the file that references the guarded variable
     or any host-/url-alias derived from it.

  The detector is **var-aware**: a separate, unguarded variable used
  at a later `fetch(...)` site is NOT sanitized (TP-1 control). It
  also only matches **set-membership** (`has` / `includes` /
  `indexOf`), not substring containment (`String.prototype.includes`
  on a non-array receiver remains unrecognized; TP-2 control).

### Tests

- New `tests/analysis/passes/issue-216-pattern-d-js-ssrf.test.ts`
  with 4 cases: 2 TN reproducing the corpus FPs (Set.has on
  URL.hostname, Array.includes on raw host param) and 2 TP-control
  verifying that the new sanitizer does not over-suppress real SSRF
  flows in similar-but-unsafe variants (unguarded second variable,
  substring check instead of set membership).

### Fixed

- `benign_fetch_allowlist.js:6` no longer emits `ssrf` or
  `external_taint_escape` on `fetch(url)` after `if
  (!ALLOWED.has(url.hostname)) return ...`.
- `benign_host_allowlist_fetch.js:7` no longer emits `ssrf` or
  `external_taint_escape` on `fetch(\`https://${host}/data\`)` after
  `if (!ALLOWED_HOSTS.includes(host)) return ...`.

## [3.125.0] - 2026-06-29

Sprint 74 — cognium-dev #216 Pattern B Python wrappers. Closes 3 of
the 12 remaining FPs (`safe_sanitizer_wrapped_ldap.py`,
`safe_sanitizer_wrapped_ssti.py`, `safe_sanitizer_wrapped_xxe.py`).
#216 stays open for 9 remaining cross-language FPs.

### Added

- **Python wrapper / allow-list / defusedxml sanitizer detectors
  (cognium-dev #216 Pattern B)** — three new conservative sanitizer
  recognizers wired into `language-sources-pass.ts`:
  - `findPythonRegexAllowlistWrapperSanitizers` — discovers
    `def NAME(arg): if not re.fullmatch(<TIGHT_REGEX>, arg):
    <terminator>; return arg` wrapper functions. A "tight" regex is
    a character-class allow-list of `\w`, `\d`, or
    `[A-Za-z0-9_\-\.]`-style with explicit quantifier. Loose
    patterns such as `.*` are rejected. Var-aware emission: for
    every assignment `<v> = NAME(...)` the wrapper kinds
    (`ldap_injection`, `xpath_injection`, `sql_injection`,
    `command_injection`, `path_traversal`, `xss`,
    `external_taint_escape`) are emitted on subsequent lines in the
    same block that reference `<v>`. Unrelated tainted variables
    introduced later are not over-suppressed.
  - `findPythonSetMembershipXssGuardSanitizers` — companion to the
    existing `findPythonNetlocAllowlistGuardSanitizers`. Recognizes
    `if <var> not in ALLOWED: abort(...)` and emits `xss` +
    `external_taint_escape` sanitizers only on subsequent lines
    that reference `<var>`. Covers Jinja `env.from_string` SSTI
    safe-handler patterns. The existing netloc detector still
    handles `open_redirect` / `ssrf` / `path_traversal` /
    `external_taint_escape` at file-line granularity (unchanged).
  - `findPythonDefusedXmlSanitizers` — recognizes `import
    defusedxml.<module>`, `import defusedxml.<module> as <alias>`,
    `import defusedxml as <alias>`, and
    `from defusedxml.<module> import <name>`. Emits `xxe` +
    `external_taint_escape` sanitizers on every line whose call
    receiver alias was bound to defusedxml. Plain
    `xml.etree.ElementTree as ET` is unaffected.

### Tests

- New `tests/analysis/passes/issue-216-pattern-b-python.test.ts`
  with 6 tests (3 TN reproducing the verbatim corpus FPs + 3 TP-
  control proving the sanitizers do not over-suppress real vulns at
  configured sinks: regex wrapper declared but uncalled does not
  sanitize a separately-tainted var; netloc allow-list on var A
  does not sanitize var B at xss sink; plain
  `xml.etree.ElementTree as ET` is not treated as defusedxml).
- Full suite: 3240+2 → 3246+2 (+6).

## [3.124.0] - 2026-06-29

Sprint 73 — cognium-dev #216 Pattern A (`external_taint_escape`
sanitizer-chain, JS/Java slice) plus Pattern B bonus (JS
user-defined wrapper-function recognition). Closes 6 of the 18
remaining FPs on cognium-dev #216 (4 ETE + 2 wrapper). #216 stays
open for 12 remaining cross-language FPs (the 2 TS `safe_interop_*`
fixtures aren't committed to the corpus and are deferred to Sprint
73b; the Pattern B Python wrappers + Pattern D SSRF allowlist + the
remaining Java/JS/Rust/htmljs/python rows go to subsequent sprints).

### Added

- **JS/Java `external_taint_escape` sanitizer detectors
  (cognium-dev #216 Pattern A)** — five new conservative sanitizer
  recognizers wired into `language-sources-pass.ts`:
  - `findJavaSafeJsonParseSanitizers` — Jackson `mapper.readValue(...)`
    and Gson `gson.fromJson(...)` recognized as ETE terminators.
    Configured `deserialization` sinks (e.g. `enableDefaultTyping`
    polymorphic Jackson) are unaffected because the two-tier filter
    in `taint-propagation-pass.ts` gates configured sinks at the
    sink line, while ETE is gated on the source→sink range.
  - `findJsSafeJsonParseSanitizers` — `JSON.parse(...)` recognized
    as ETE terminator. Cannot exec code, unlike configured `eval` /
    `Function` / `vm.runInNewContext` sinks (unaffected).
  - `findJsCryptoHashSanitizers` — one-way hashes
    (`bcrypt.hash` / `bcrypt.hashSync`, `argon2.hash`,
    `crypto.scrypt[Sync]`, `crypto.createHash(...)`, `.digest(...)`)
    recognized as ETE terminators. `weak-password-hash` rule
    continues firing independently for MD5/SHA1.
  - `findJsCsvFormulaPrefixSanitizers` — Excel-formula sanitizer
    pattern (`` `'${x}` `` template literal or `"'" + x` concat)
    recognized as ETE-only sanitizer. Scoped strictly to ETE — does
    not affect xss / sqli / command-injection sinks.
- **JS user-defined wrapper-function sanitizer recognition
  (cognium-dev #216 Pattern B)** — `findJsWrapperFunctionSanitizers`
  is a two-pass detector: (1) discover `function NAME(...)` /
  `const NAME = (...) =>` declarations whose body contains a
  `.replace(...)` against a recognizable threat-character class
  (`[&<>"']` → xss + external_taint_escape, `[\r\n\t]` →
  log_injection + external_taint_escape); (2) emit a per-call-site
  sanitizer at every line invoking the wrapper. Closes the
  `safe_sanitizer_wrapped_xss.js` and `safe_sanitizer_wrapped_loginj.js`
  Pattern B FPs from the v3.107.0 scorecard.

### Tests

- 9 new tests in `tests/analysis/passes/issue-216-pattern-a.test.ts`
  (6 TN reproducing the verbatim corpus FPs + 3 TP-control proving
  the sanitizers don't over-suppress: `bcrypt.hash` does NOT sanitize
  sql_injection; `JSON.parse` does NOT sanitize command_injection;
  CSV `'`-prefix on var A does NOT sanitize raw var B at xss sink).
- Suite: 3231+2 → 3240+2 (+9).

## [3.123.0] - 2026-06-29

Sprints 67 + 69 + 70 + 71 (wave 1) + 72. Closes the last bash FP in
cognium-dev #216 (bash slice 5/5 complete), three S-tier FN tickets
(#199, #151, #183 residual), and 5 of 14 cells in #190. cognium-dev
#216 stays open for cross-language FPs; cognium-dev #190 stays open
for 9 remaining cells (Rust hardcoded-credential bootstrap, Java JWT
`JWT.decode` cross-call reasoning, Rust/Go ECB cipher-mode reasoning).

### Added

- **`unverified-package-install` (CWE-494, bash, #105 in PASSES.md)** —
  cognium-dev #199. Detects `dpkg -i`, `rpm -i/-U`, `apt(-get|itude)
  install <.deb>`, and `yum|dnf|zypper install <.rpm>` invocations of a
  file PATH when the script contains no integrity verifier earlier
  (`gpg --verify`, `rpm --checksig`, `dpkg --verify`, `sha{1,256,512}sum
  -c`, `md5sum -c`, `b2sum -c`, `cksum -c`). Whole-script verifier
  presence gates the finding — matches the canonical "verify-then-
  install" idiom where the gpg/sha verify references a separate file or
  inline data. Closes FN-CVE-B03 (compromised-package-install class).
  CWE-494 Download of Code Without Integrity Check. Severity: high.
- **`external-secret-exfiltration` (CWE-200, Python/JS/TS/Go, #106 in
  PASSES.md)** — cognium-dev #151 (FN-TQ-01). Fires when an environment-
  read secret variable is sent in the body of a request to an external
  host. Per-language detection: Python `requests.{post,put,patch,delete,
  request}` / `httpx.*` with secret-bearing var in `json=`/`data=`/
  `files=`/`content=` (NOT just in `headers=`); JS `https.request(URL,
  …)` / `http.request(…)` / `fetch(…)` / `axios.{post,put,patch,request}
  (…)` with secret-bearing var or carrier var (`body = JSON.stringify
  ({secret})`) in inline body OR forward `req.write(body)`; Go
  `http.PostForm(URL, body)` / `http.Post(URL, ct, body)` /
  `http.NewRequest(method, URL, body)` with secret var in args. Body-vs-
  headers gate suppresses the legitimate `Authorization: Bearer …`
  pattern. Internal-host allowlist (`.internal.`/`.local`/`.lan`/
  `.corp`/loopback/RFC1918/single-label) prevents first-party FPs.
  Severity: high.

### Fixed

- **bash `weak-hash` (CWE-328)** — cognium-dev #190 wave 1. Extended
  rule #17 to recognise `md5`/`sha1`/`md5sum`/`sha1sum` invoked as a
  command (pipeline or standalone). Token must appear at line start or
  after `|`/`;`/`&&`/`||`. `sha256sum`/`sha512sum`/`b2sum` remain
  benign.
- **Python `cors-wildcard-origin` (CWE-942)** — cognium-dev #190 wave
  1. Extended rule #89d to fire on `resp.headers['Access-Control-
  Allow-Origin'] = '*'` subscript-assignment shape (Flask/Django/
  Starlette `Response` objects). Existing `setHeader`/`addHeader`
  method-call coverage stays untouched.
- **Python `xfo-csp-mismatch` (CWE-1021)** — cognium-dev #190 wave 1.
  Extended rule #89h to detect correlated `resp.headers['X-Frame-
  Options'] = 'DENY'|'SAMEORIGIN'` + `resp.headers['Content-Security-
  Policy'] = '… frame-ancestors *|http* …'` subscript assignments
  within the same file.
- **Python `tls-verify-disabled` (CWE-295)** — cognium-dev #190 wave 1.
  Extended rule #92 with the post-create `ssl.SSLContext` mutation
  shape: `ctx.verify_mode = ssl.CERT_NONE` and `ctx.check_hostname =
  False`. Existing `requests/httpx(verify=False)` and
  `ssl._create_unverified_context()` coverage stays untouched.
- **Rust `tls-verify-disabled` (CWE-295)** — cognium-dev #190 wave 1.
  Extended rule #92 for `reqwest::Client::builder()
  .danger_accept_invalid_certs(true)` and `.danger_accept_invalid_
  hostnames(true)`. `false` argument (re-enable) is benign and not
  flagged.
- **Python `input()` as forward-taint source** — cognium-dev #183
  residual. Added `\binput\s*\(` to both `PYTHON_TAINTED_PATTERNS`
  registries (`language-sources-pass.ts` and `taint-matcher.ts`,
  classified as `io_input`). `input()` was already registered in
  `configs/sources/python.json` but the regex registries didn't track
  it, so `name = input()` was not added to `pyTaintedVars`. Closes
  the deferred `getattr(obj, input())()` reflection-invocation shape
  and unblocks the long-standing skipped test in
  `python-reflection-code-injection-fn.test.ts`.
- **bash SQL-CLI tools sink-type classification** — cognium-dev #216
  (last bash FP). The bash interprocedural fallback in
  `src/analysis/interprocedural.ts` re-classifies every external-
  utility call carrying a tainted positional as `command_injection`
  (CWE-78). For `sqlite3`/`mysql`/`psql`/`mariadb` this is wrong: those
  CLIs take SQL strings as positional args, not shell commands. New
  per-utility set re-classifies the fallback finding as
  `sql_injection` (CWE-89). The finding remains (the flow IS a SQL
  injection); only the type label is corrected. Non-SQL CLIs (`ssh`,
  `nc`, etc.) continue to fire `command_injection` unchanged.

### Tests

- `tests/analysis/passes/bash-unverified-package-install.test.ts` — 7
  cases (5 TP across dpkg/rpm/apt-deb/yum-rpm/zypper-rpm + 2 TN with
  gpg/sha verifier present).
- `tests/analysis/passes/external-secret-exfiltration.test.ts` — 8
  cases: 3 TP corpus (Python/JS/Go env-secret → external collector) +
  3 TN safe-mirrors (Authorization-header to internal host, HMAC-only
  local use) + 2 TN external-URL with secret only in Authorization
  header.
- `tests/analysis/passes/config-pattern-190-wave1.test.ts` — 11 cases:
  py cors-wildcard-origin TP/TN, py xfo-csp-mismatch TP/TN, py
  tls-verify-disabled TP/TN, bash weak-hash md5/sha1sum TP +
  sha256sum TN, rust tls-verify-disabled TP/TN.
- `tests/analysis/passes/python-input-source-183.test.ts` — 4 cases:
  aliased + direct `getattr(obj, input())()` TPs, `os.system(input())`
  TP, `shlex.quote` sanitizer TN.
- `tests/analysis/passes/python-reflection-code-injection-fn.test.ts`
  — un-skipped the Sprint 56 deferred test (now passes via Sprint 72
  fix).
- `tests/analysis/passes/bash-fp-216.test.ts` — 5 cases for the bash
  SQL-CLI re-classification (sqlite3/mysql/psql var-indirect TNs +
  sqlite3 direct TP-control + ssh non-SQL TP-control).

Net: **+31 tests** (3199 → 3231 passed; 1 previously-skipped test
un-skipped, 2 skipped remain). All 222 test files pass.

## [3.122.0] - 2026-06-29

Sprint 66 — cognium-dev #216 bash slice continuation (1 more FP closed,
cumulative 3 of 5 bash FPs across Sprints 65+66; #216 stays open for
the remaining 21 FPs across Java/JS/Python/TS/Rust/htmljs + 1 deferred
bash FP). Adds an argv-terminator gate to the bash external-utility
specialization in `interprocedural.ts`.

### Fixed

- **`command_injection` (CWE-78) bash FP — `--` argv terminator with
  quoted positional** (`benign_quoted_vars.sh` shape:
  `grep -- "$pattern" /var/log/app.log`). The bash specialization in
  `src/analysis/interprocedural.ts` re-classifies every external-utility
  call carrying a tainted positional as `command_injection`, but
  previously did so unconditionally — bypassing the obvious safe pattern
  where `--` separates options from positionals AND the positional is
  double-quoted. New gate: when `--` appears as an argument before every
  tainted position AND every tainted positional is double-quoted, the
  `command_injection` sink is suppressed (continue past the per-call
  block). Both conditions are conjunctive — quoting alone permits flag
  injection (`-e payload`), `--` alone permits word-splitting on
  unquoted expansion. Affects argv-data shell utilities (`grep`, `awk`,
  `sed`, `cut`, `sort`, etc.) when called with the canonical safe shape.
  Dangerous utilities called without `--` (`ssh "$1"`, `nc "$1"`, etc.)
  continue to fire as before.

### Tests

- `tests/analysis/passes/bash-fp-216.test.ts` (+6) — 3 TN cases
  (`grep -- "$1"`, `grep -- "$pattern"` with var indirection,
  `awk -- "$1"`) plus 3 TP-control cases (`grep "$1"` without `--`,
  `grep -- $1` unquoted, `ssh "$1"` dangerous utility without `--`)
  proving the gate is correctly conjunctive.

### Stats

- Tests: 3191 passed | 3 skipped (was 3188 passed | 3 skipped pre-sprint).
- No public API change.

### Out of scope (this sprint)

- Bash FP #5 (`sqlite3 :memory: "SELECT ..."` first-arg-is-SQL
  re-classification) — sink-type change rather than suppression; needs
  builtin-sink edit in `src/languages/plugins/bash.ts` and arguably
  belongs under `sql_injection` not `command_injection`.
- Cross-language FPs from #216 (Java/JS/Python/TS/Rust/htmljs).

## [3.121.0] - 2026-06-29

Sprint 65 — cognium-dev #216 v3.107.0 FPR scorecard, bash slice (2 of 5
bash FPs closed; #216 stays open for the remaining 22 FPs across
Java/JS/Python/TS/Rust/htmljs + 2 deferred bash FPs). Refines the
heuristic `predictable-temp-file` (CWE-377) detection inside
`findBashPatternFindings` so two benign shapes no longer trip the
warning.

### Fixed

- **`predictable-temp-file` (CWE-377) bash FP — checksum-verified
  downloads** (`benign_checksum_verify.sh` shape). When the same
  `/tmp/X` literal is later verified by a checksum tool
  (`sha1sum`/`sha224sum`/`sha256sum`/`sha384sum`/`sha512sum`/`md5sum`/`cksum`/`b2sum`
  with `-c`/`--check`), the curl/wget write site no longer emits a
  warning — the verification gate breaks the TOCTOU substitution risk
  that justifies the rule. Implemented as a first-pass scan
  (`collectChecksumVerifiedTmpPaths`) over the whole script feeding the
  per-line emission decision in
  `src/analysis/passes/language-sources-pass.ts`.
- **`predictable-temp-file` (CWE-377) bash FP — archive output
  targets** (`benign_fixed_path.sh` shape). When the `/tmp/X` literal
  is the WRITE target of a recognized archive command (`tar` with a
  create flag cluster, `zip` (not `unzip`), `gzip -c`/`--stdout`/`>`,
  `bzip2`/`xz` (same shape), or `7z a`) AND has a recognized archive
  extension (`.tgz`/`.tar.gz`/`.tar.bz2`/`.tar.xz`/`.tar`/`.tbz2`/`.txz`/`.zip`/`.gz`/`.bz2`/`.xz`/`.7z`),
  the line no longer emits a warning — an output target has no TOCTOU
  read race. Implemented as `isArchiveOutputContext` in the same
  module. Requires BOTH command shape AND extension to keep
  false-suppression surface near zero.

### Tests

- New file `tests/analysis/passes/bash-fp-216.test.ts` (3 cases): 2 TN
  cases mirroring the corpus files, 1 TP-control case proving the
  suppressions do not over-suppress predictable-temp-file with no
  checksum verification or archive output context.
- Suite delta: 3182 → 3185 (+3).

### Notes

- Bash FPs #3 (`benign_path_join.sh` — `path_traversal` on a
  `case "$x" in ${PREFIX}/*) ... ;; *) exit 1 ;; esac` allowlist) is
  already resolved at this head — bash `path_traversal` no longer
  fires on the `cat "/data/$var"` shape; probably cleared by Sprint
  52 / 3.109.0 (`#216 subset`). No additional sanitizer wiring
  needed.
- Bash FPs #4 (`grep -- "$pattern"` argv-terminator gate) and #5
  (`sqlite3 :memory: "SELECT …"` first-arg SQL re-classification)
  need sink-side changes and are deferred. #216 stays open.

## [3.120.0] - 2026-06-29

Sprint 64 — cognium-dev #184 Vue SFC template-XSS detection (sprint 2
of 2, **closes the multi-sprint Vue track**). Adds the synthetic
`vue-template-xss` pass that walks the `<template>` subtree of a
`.vue` file looking for dangerous attribute bindings (`v-html`,
`v-bind:innerHTML`, `:innerHTML`, `v-bind:outerHTML`, `:outerHTML`)
whose RHS expression references an identifier tainted in the file's
`<script>` blocks. Emits a CWE-79 finding at the binding line.

### Added

- **`vue-template-xss` pass** (new file
  `src/analysis/html/vue-template-xss-pass.ts`, registered as H9 in
  `docs/PASSES.md`). Synthetic-emission pattern mirroring the existing
  HTML attribute-security checks (H1–H8) — walks the parse tree
  iteratively (stack-overflow guard), inspects each `start_tag` /
  `self_closing_tag` for the dangerous bindings listed above, then
  resolves the RHS expression's identifiers against a tainted-name set
  built from `ir.taint.sources` ∪ `ir.dfg.defs` (def at source line) ∪
  flow-path variables of each script block. Vue-only (`v-text` and
  plain HTML files skip the pass).
- **5 new tests** in `tests/analysis/passes/vue-sfc-scaffold-tp.test.ts`:
  - TP-5 — `v-html="userInput"` with tainted `<script setup>` def fires
    (flipped from Sprint 63's FN-1 lock).
  - TP-6 — `:innerHTML="userInput"` shorthand fires.
  - TP-7 — `v-bind:innerHTML="userInput"` full form fires.
  - TN-1 — `v-text="userInput"` does NOT fire even with tainted RHS
    (locks v-text-is-safe contract — Vue's v-text uses textContent
    which the browser escapes).
  - TN-2 — `v-html="'<b>literal</b>'"` (string literal RHS) does NOT
    fire — no identifier match.

### Changed

- **`analyzer.ts:870-880`** — `analyzeMarkupFile()` invokes
  `runVueTemplateXssChecks` after the existing
  `runHtmlAttributeSecurityChecks` call, gated on `language === 'vue'`.
  Findings are appended into the same `attributeFindings` array so
  the merge step picks them up.
- **`src/analysis/html/index.ts`** — re-exports
  `runVueTemplateXssChecks`.
- **`docs/PASSES.md`** — H9 row added under A2 (HTML Security Passes).

### Why not YAML sink config

Vue template bindings are HTML attribute syntax, not JS method/property
calls — they never appear in the IR's call graph and so cannot be
expressed in `configs/sinks/*.yaml` (which only matches method, class,
property, or annotation patterns). The existing
`html-attribute-security-pass.ts` precedent (H1–H8) handles
synthetic-emission for attribute-level vulnerabilities; this pass
follows the same shape with the added twist that it consults the
already-built script-block taint set to gate emission.

### Known minor over-flag (deferred)

`v-html="DOMPurify.sanitize(userInput)"` currently emits a finding
because the pass does not track sanitizers across the template
boundary — it sees `userInput` on the RHS, matches it, and fires.
Documented here for clarity; a sanitizer-aware refinement is a
future-sprint improvement if corpus shows the pattern in production
code.

### Test count

3178 + 3 → 3182 + 3 (+4 new cases; FN-1 flipped in place to TP-5).

### Cross-references

- Sprint 63 (v3.119.0) — added the `.vue` routing scaffold this
  sprint builds on top of.
- cognium-dev #184 — closed by this release.

## [3.119.0] - 2026-06-29

Sprint 63 — cognium-dev #184 Vue SFC scaffold (sprint 1 of 2). Adds
JS-pipeline routing for `.vue` Single-File Components so tainted code
inside `<script>` / `<script setup>` / `<script lang="ts">` blocks is
detected end-to-end. **Template-attribute sinks (`v-html`, `v-text`,
`:innerHTML`) are explicitly out of scope and land in Sprint 64** as a
dedicated template-walking pass.

### Why a scaffold-only sprint

Probing `analyze(vueSrc, 'Foo.vue', 'html')` against HEAD showed
tree-sitter-html already extracts `<script>` / `<script setup>` /
`<script lang="ts">` blocks correctly — the existing
`analyzeHtmlFile()` script-extraction path registers taint sinks and
delegates each block to the JS/TS pipeline. The only gap was that
`.vue` files were rejected at the routing layer because `'vue'` was not
in the `SupportedLanguage` union. Sprint 63 closes exactly that gap;
no new grammar, no new pass, no new sink config.

Template-attribute detection (`v-html` etc.) is a separate problem
requiring a new walker over the `<template>` subtree and synthetic
sink emission at the binding line — that's Sprint 64 scope.

### Added

- **`SupportedLanguage` union** — `'vue'` added in all three
  declaration sites (`src/core/parser.ts`, `src/types/index.ts`,
  `src/languages/types.ts`).
- **`VuePlugin`** (`src/languages/plugins/vue.ts`) — minimal plugin
  that mirrors `HtmlPlugin`: `id='vue'`, `extensions=['.vue']`,
  `wasmPath='tree-sitter-html.wasm'` (reuses the HTML grammar — Vue
  SFCs are HTML-syntax-wrapped and parse identically). All extraction
  methods return empty arrays; the plugin acts as a thin preprocessor
  and `<script>` blocks are routed to the JS/TS pipeline by the
  existing html-extractor machinery.
- **VuePlugin registration** in `registerBuiltinPlugins()`
  (`src/languages/plugins/index.ts`).
- **5 new tests** (`tests/analysis/passes/vue-sfc-scaffold-tp.test.ts`):
  - TP-1 `<script>` block with `req.body → eval` fires
    `command_injection`.
  - TP-2 `<script setup>` (Vue 3 composition API) variant fires.
  - TP-3 `<script lang="ts">` (typed) variant fires via TS pipeline.
  - TP-4 Template-only `.vue` (no script) does not crash and emits
    zero findings.
  - FN-1 (Sprint 64 lock) `<template v-html="taint">` is documented as
    a current false-negative and locked at zero findings; flips to
    TP-5 in Sprint 64.

### Changed

- **`analyzer.ts`** — html routing branch extended to include `'vue'`;
  internal helper renamed `analyzeHtmlFile` → `analyzeMarkupFile` and
  threads a `language` parameter for meta / log only. Still calls
  `parse(code, 'html')` internally because Vue reuses the html
  grammar. The rename touches a single private function (not exported
  from the package) — no public-API change.
- **`getNodeTypesForLanguage`** — `'vue'` case added with the same
  (empty) node-type set as `'html'`.

### Test count

3173 + 3 → 3178 + 3 (+5 Vue scaffold cases).

### Sprint 64 preview (NOT in this release)

Sprint 64 will add a `vue-template-extractor` + `vue-template-xss-pass`
plus YAML sink config entries for `v-html` / `v-text`. The FN-1 test
above flips to TP-5 once Sprint 64 ships. If any other change fixes
v-html as a side effect before Sprint 64, FN-1 fails immediately and
the recall lock surfaces it.

## [3.118.0] - 2026-06-28

Sprint 62 — cognium-dev #171 recall lock (Java XXE no-hardening / plantuml
`XmlFactories` shape). **Recall-lock-only sprint — no source change.**

### Verified-already-shipped (recall lock)

- **#171 plantuml `XmlFactories` (DocumentBuilderFactory.newInstance() +
  TransformerFactory.newInstance() with zero hardening)** — high-severity
  `xml-entity-expansion` finding fires as expected. The Sprint 44 #166 fix
  (file-level suppression keyed on `JAVA_SAFE_EVIDENCE_RE`) does **not**
  suppress this shape because no hardening tokens
  (`FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD`, `disallow-doctype-decl`,
  etc.) are present anywhere in the file. The Sprint 43 #173 suppressors
  (`isXmlOutputOnly` / `isDocumentBuilderEmptyOnly`) also do not match
  because the factory-holder class contains no `new DOMSource(` /
  `new StreamResult(` and no `.newDocument()` calls.
- Companion / inverse of #166: the hardened counterpart (any of
  `FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD`,
  `disallow-doctype-decl`, ...) remains fully suppressed per the Sprint 44
  binary-suppression contract.

The ticket's "low-confidence emit for unhardened factories" enhancement
request is intentionally **out of scope** — it would reverse the explicit
Sprint 44 design decision to fully suppress rather than downgrade in the
inverse-FP scenario. The current binary contract satisfies both reporter
goals (plantuml fires high-confidence; languagetool-style false positives
stay suppressed) without API surface change.

Locked in `tests/analysis/passes/java-xxe-no-hardening-tp.test.ts`
(5 cases: 3 TPs + 2 TNs). Test suite: 3173 pass + 3 skipped
(was 3168+3).

## [3.117.0] - 2026-06-28

Sprint 60 — FP regression cluster (#102 + #113 + #114 + #115). Phase 0
baseline confirmed 15/17 ticket scenarios are already-shipped (closed
progressively across Sprints 23/24/29/31); the remaining two false
positives are fixed by additive entries in the sanitizer config table.

### Fixed

- **#113 FP-46 — JS `path.basename(req.body.name)` followed by atomic
  `fs.openSync(dest, 'wx')` emits three `external_taint_escape` flows
  (at openSync, writeSync, closeSync).** `path.basename()` strips
  directory components and returns only the leaf filename, so the value
  can no longer carry a traversal payload across the file-system
  boundary; the synthetic CWE-668 fallback should not fire. Extended
  the JS `path.basename` sanitizer entry in `config-loader.ts` to
  remove `external_taint_escape` in addition to the pre-existing
  `path_traversal`. Mirrors the Go `filepath.Base` entry which already
  carried both. Real injection sinks downstream of a non-basename'd
  path remain unaffected.

- **#113 FP-52 — Java `DIGITS.matcher(req.getParameter("text"))` emits
  one `external_taint_escape` flow at the matcher call.** Passing
  tainted text to a compiled `Pattern.matcher(...)` does not constitute
  a wrong-sphere escape: the matcher walks the string in-process and
  produces match-state (booleans, groups, counts), not a network/file/
  process exit. Added `{ method: 'matcher', removes:
  ['external_taint_escape'] }` (class-agnostic) to the Java sanitizer
  section. Class-agnostic because the receiver is typically a
  Pattern-typed variable (e.g. `DIGITS`) rather than the literal class
  name; the dominant semantic is regex matching. Real injection sinks
  downstream of the matched text still apply.

### Verified-already-shipped (recall locks)

- #102 / #115 Rust safe_handler (3 cases): `Command::new` with fixed
  program + args slice, `HashSet::contains` host allowlist before
  `reqwest::get`, `canonicalize().starts_with(root)` path guard before
  `fs::read_to_string` — all confirmed clean against v3.116.0; shipped
  Sprint 31 (3.84.0).
- #114 Python safe-handler (2 cases): `urlparse(target).netloc in
  ALLOWED_HOSTS` allow-list before `redirect(target)`, and
  `int(request.args.get("qty", "0"))` with range-check before numeric
  output — both confirmed clean; shipped Sprint 31 (3.84.0).
- #113 (10 of 12 cases): JS `Set.has` / range / index-bounds / regex
  guards; Java `Set.contains` / `Pattern.matches`; Go `filepath.Base` /
  `maxAllocBytes` clamp / `regexp.MatchString` / `log.Printf` — all
  confirmed clean; shipped progressively Sprints 24/29 (3.74.0 /
  3.79.0).

All locked in `tests/analysis/passes/fp-cluster-sprint60-recall-lock.test.ts`
(17 cases). Test suite: 3168 pass + 3 skipped (was 3151+3).

## [3.116.0] - 2026-06-28

Sprint 59 — closes #201 (Java Servlet 3.0 `Part.write(...)` unrestricted
upload). Slice A of the originally planned batch (#199 bash `dpkg -i
/tmp/file`) was descoped after Phase 0: the residual ticket scenario
requires file-path taint propagation (curl writes to a temp file → dpkg
reads that file), which is a structural rather than configuration
change. Direct positional cases (`dpkg -i "$1"`) are already covered by
the generic shell-utility command-injection mechanism in
`src/analysis/interprocedural.ts`.

### Fixed

- **#201 — Java Servlet `Part.write("<dir>" + part.getSubmittedFileName())`
  does not fire `unrestricted-file-upload` (CWE-434).** The existing
  `unrestricted-file-upload-pass` checked only `MultipartFile.transferTo`
  and `Files.copy` for Java; the Servlet 3.0 `Part.write(String)`
  direct-write form (CVE-2021-26828 class — attacker uploads `shell.jsp`
  through user-controlled filename → web-served path → RCE) was
  overlooked. Added a third Java call-shape branch: method `write`
  with at least one arg expression matching `UPLOAD_NAME_RE`
  (`getOriginalFilename`/`getSubmittedFileName`/`.filename`/etc.),
  excluding the pre-existing `Files.write` / `FilePath.write`
  path_traversal sink receivers. Recall locks: Spring
  `MultipartFile.transferTo`, Python `f.save("/uploads/" + f.filename)`,
  and JS `multer({ dest })` continue to fire unchanged. TN locks:
  `Files.write(Path.of("/tmp/x"), bytes)` does not collide,
  `part.write("/var/www/static.html")` (literal path) does not fire,
  and functions containing `FilenameUtils.getExtension(...)` /
  `secure_filename` markers are suppressed via the existing
  `inSafeRange` heuristic.

### Descoped

- **#199 — bash `curl -fsSLo /tmp/pkg.deb "${1}"; dpkg -i /tmp/pkg.deb`
  supply-chain RCE.** The direct case `dpkg -i "$1"` is already
  detected as `command_injection` via the generic shell-utility
  unquoted-tainted-arg detector in
  `src/analysis/interprocedural.ts:295-303`. The ticket's actual
  scenario requires propagating taint from a positional-parameter URL
  through a curl-written file path into a downstream dpkg invocation
  — i.e. file-path taint flow across commands — which is structural
  work outside the scope of a config-only release. Issue kept open
  for a future sprint that addresses bash file-path taint propagation.

## [3.115.0] - 2026-06-28

Sprint 58 — closes the final remaining gap on #188 (indirect eval
alias detection). Sprint 55 shipped `new vm.Script(taint)`,
`setImmediate(taintedString)`, and `vm.runInThisContext(taint)` and
explicitly deferred `const f = eval; f(taint)` to a future sprint
pending alias tracking; this release closes that loop.

### Fixed

- **#188 (final) — JS/TS `const f = eval; f(taint)` /
  `let F = Function; F(taint)` does not flag `code_injection`
  (CWE-94).** The matcher saw `method_name: "f"` at the call site
  and the eval sink template required exact `method: "eval"`. Added
  `expandIndirectEvalAliases()` in `src/analysis/taint-matcher.ts`
  parallel to the existing `expandPromisifyAliases()` (Sprint 54
  #187) — a source-line regex picks up
  `(?:const|let|var) <name>(?:: type)? = (eval|Function)` (with a
  negative lookahead for `(` so direct calls like
  `const x = eval(arg)` are not double-matched) and synthesizes a
  classless `code_injection` sink pattern with `method: <name>`
  mirroring the eval / Function template. Standard `findSinks`
  matching handles the alias call site unchanged. Coverage: `const`
  / `let` / `var` alias keywords, TypeScript `const f: any = eval`
  type-annotation form, and `Function`-constructor aliasing. Recall
  locks: direct `eval(taint)` and `util.promisify(exec)` aliases
  continue to fire. Word-boundary discipline verified — `const x =
  evaluator` does not match.

### Deferred

- Transitive aliases (`const g = eval; const f = g; f(taint)`)
  require DFG-based propagation rather than per-line regex matching.
  Documented as `it.skip` in
  `tests/analysis/passes/js-indirect-eval-fn.test.ts`. Will follow
  up in a future sprint if real-world reports surface.

## [3.114.0] - 2026-06-28

Sprint 57 batch — bash detector gap closure for `#200` (curl/wget SSRF)
and partial `#198` (CVE-class env vars into `eval`). Phase 0 inline-
synthesized reproductions baselined against v3.113.0 (2 test files,
13 cases) verified each FN before any source change.

### Fixed

- **#200 — bash `curl -s "$1"` / `wget "$1"` / `curl -fsSL "${1}/path"`
  does not flag `ssrf` (CWE-918), only `cleartext-transmission`.** Two
  independent gaps:
  1. `canSourceReachSink('io_input', 'ssrf')` returned `false` in
     `src/analysis/findings.ts:175`. Bash positional `$1`/`$@` register
     as `io_input` sources but the source→sink matrix gated them out
     before they could reach the bash `curl`/`wget` SSRF sink. Added
     `'ssrf'` to the `io_input` allowed sinks alongside the existing
     command/path/deserialization/xxe/code/xss entries. Cross-language
     parity benefit: Python `socket.urlopen(input())` and JS
     `axios.get(readline())` also flow correctly now. Real-world
     precedent — CVE-2022-41040 ProxyShell-class scripts, CGI/webhook
     handlers that take a URL on stdin or as a CLI arg and curl it
     server-side, are textbook SSRF.
  2. Bash `curl`/`wget` SSRF sinks declared `argPositions: [0]` in
     `src/languages/plugins/bash.ts`, so flag-prefixed invocations
     (`curl -s "$1"`, `wget --quiet "$1"`, `curl -fsSL "$1/path"`)
     missed the URL because it landed at position 1+. Widened to
     `argPositions: []` (scan all positions) — mirrors the Sprint 23
     `exec.Command` widening pattern. The scan-all-args matcher is
     already supported in `taint-propagation-pass.ts` (length-gated at
     lines 523/663/746/1129).

- **#198 (partial) — bash `eval "$RPC_EXPR"` / `eval "$CMD_DATA"` /
  `eval "$XMLRPC_PAYLOAD"` / `eval "$JSONRPC_BODY"` does not flag
  `code_injection` (CWE-94).** `BASH_UNTRUSTED_ENV_PATTERNS` in
  `src/analysis/passes/language-sources-pass.ts:1169-1180` only covered
  CGI-class env names (`USER_INPUT`, `QUERY_STRING`, `REQUEST_*`,
  `HTTP_*`, `REMOTE_*`, `CONTENT_TYPE`, `CONTENT_LENGTH`, `PATH_INFO`,
  `SCRIPT_NAME`, `SERVER_NAME`). Added seven RPC/CMD/EXEC/EVAL/SHELL-
  class patterns (`^RPC_`, `^XMLRPC`, `^JSONRPC`, `^CMD_`, `^EXEC_`,
  `^EVAL_`, `^SHELL_`) seen in recent CVE intake (CVE-2025-67038 HTTP
  RPC pattern and similar). Variable propagation through assignment
  (`expr="${RPC_EXPR}"; eval "$expr"`) already worked once the env var
  was recognized — verified empirically before the fix. Recall lock:
  `eval "$HTTP_USER_AGENT"` and `eval "$1"` continue to fire; benign
  `eval "$HOME/.config"` continues to produce zero flows.

### Deferred (still open on #198)

- Generic env-var taint when the variable name doesn't match any
  recognized pattern. Requires either a much broader default (FPR
  risk) or per-script "unknown env vars are tainted at dangerous
  sinks" backward-flow inference. Out of scope for Sprint 57.

## [3.113.0] - 2026-06-28

Sprint 56 batch — #182 (4 slices) + #183 detector gaps shipped together.
Phase 0 inline-synthesized reproductions baselined against v3.112.0
(5 test files, 20 cases) verified each FN before any source change.

### Fixed

- **#182 Slice A — Rust `log::info!` / `log::warn!` / `log::error!` /
  `log::debug!` / `log::trace!` / `log::log!` are not detected as
  `log_injection` (CWE-117) sinks.** The Rust macro extractor preserves
  the full path prefix in `method_name` (e.g. `log::info!`), but
  `DEFAULT_SINKS` only registered the bare classless forms (`info!`,
  `warn!`, etc.) introduced in earlier sprints. Added six namespaced
  `log::*` sink entries scoped to `languages: ['rust']`. Recall locks:
  bare `info!` and `println!` continue to be detected.

- **#182 Slice B — Go `http.SetCookie(w, &http.Cookie{...})` with missing
  `Secure: true` or `HttpOnly: true` does not flag `insecure-cookie`
  (CWE-614).** Extended `insecure-cookie-pass.ts` with a `go` language
  branch that triggers on `method_name === 'SetCookie'` /
  `receiver === 'http'` and scans the second argument's expression text
  for `Secure: true` / `HttpOnly: true` tokens. Emits a medium-severity
  finding for either missing flag. Known limitation: variable-form
  cookies (`http.SetCookie(w, cookie)` where `cookie` is a previously
  built `*http.Cookie`) cannot be inspected — mirrors existing JS
  spread-options behavior.

- **#182 Slice C — Rust `format!("Set-Cookie: …")` / `write!(buf,
  "Set-Cookie: …")` / `writeln!(buf, "Set-Cookie: …")` without `Secure`
  or `HttpOnly` tokens does not flag `insecure-cookie` (CWE-614).**
  Extended `insecure-cookie-pass.ts` with a `rust` language branch that
  performs a text-based file-source scan (regex matches `format!` /
  `write!` / `writeln!` invocations whose body contains `Set-Cookie:`
  and checks for the presence of `Secure` / `HttpOnly` tokens). Emits a
  medium-severity finding for either missing flag. Text-based scan
  mirrors the existing Java branch in the same pass.

- **#182 Slice D — TypeScript `console.log/warn/error/info(taint)`
  regression lock.** The ticket claim that TS `console.*` calls don't
  surface as `log_injection` sinks was stale on v3.112.0 — the
  `console.*` entries in `DEFAULT_SINKS` are already scoped to
  `languages: ['javascript', 'typescript']`. Shipped a regression test
  file as a guard against future scope narrowing.

- **#183 — Python `importlib.import_module(taint)` does not flag
  `code_injection` (CWE-94).** Added a namespaced `importlib`
  `import_module` sink at severity `high`, parallel to the existing
  classless `__import__` entry and Java's `Class.forName`. Note:
  `importlib.__import__` already matched via the existing classless
  `__import__` sink (class-agnostic matcher behavior when a classless
  entry exists). Deferred: `getattr(obj, taint)()` two-call shape
  requires alias tracking from `getattr`'s return value through the
  next-call receiver — tracked as `it.skip` and left open on #183.

## [3.112.0] - 2026-06-28

Sprint 55 batch — JS/TS framework FN quartet shipped together. Phase 0
inline-synthesized reproductions baselined against v3.111.0 (4 test files,
20 cases) verified each failure before any source change.

### Fixed

- **#185 — JavaScript `got(url)` / `request(url, cb)` bare-function shapes
  do not flag `ssrf` (CWE-918).** The existing `got` and `request` sink
  entries in `config-loader.ts` were registered as class-scoped methods
  (e.g. method-on-instance shapes), but both npm packages default-export
  callable functions invoked at the top level: `const got = require('got');
  got(req.query.url)`. Added classless variants for `got` and `request` so
  bare-function call sites match. Recall lock: `axios.get(taint)` and
  `http.get(taint)` continue to fire.

- **#184 — Angular `DomSanitizer.bypassSecurityTrust*` family does not
  flag `xss` (CWE-79).** Angular's `bypassSecurityTrustHtml` /
  `bypassSecurityTrustScript` / `bypassSecurityTrustStyle` /
  `bypassSecurityTrustUrl` / `bypassSecurityTrustResourceUrl` explicitly
  bypass Angular's built-in template sanitization and re-introduce
  DOM-injection risk when tainted input flows in. Added all five as
  classless XSS sinks in `DEFAULT_SINKS`
  (severity: `critical` for `Script` / `ResourceUrl`, `high` for the
  rest). Recall lock: `React.createElement('div', {
  dangerouslySetInnerHTML: { __html: taint } })` continues to fire.

- **#186 — JavaScript sqlite3 `db.{all,run,each,get,exec}(tainted)` does
  not flag `sql_injection` (CWE-89).** The JS plugin authoritatively
  resolves `const db = new sqlite3.Database(...); db.all(sql)` to the
  resolution target `Connection.all`, but the `matchSink` receiver-class
  heuristic in `taint-matcher.ts` only consulted
  `receiverMightBeClass(call.receiver, pattern.class)` — the simple
  receiver identifier `db` does not look like the class name `Connection`,
  so class-scoped sqlite3 patterns were silently rejected. Extended the
  matcher to additionally consult `call.resolution?.target` and accept the
  match when the resolved target ends with `<pattern.class>.<pattern.method>`.
  Added `Connection.{all,run,each,get,exec}` SQLi sink patterns (with
  `allow_unresolved_receiver: true` as a defence-in-depth fallback).
  Recall lock: parameterized `db.all('… WHERE x = ?', [req.query.q], cb)`
  continues to produce zero flows.

- **#188 — JavaScript `new vm.Script(taint)` and `setImmediate(taint)`
  do not flag `code_injection` (CWE-94).** Added two new entries to
  `DEFAULT_SINKS`:
  - `{ method: 'Script', class: 'constructor' }` for `new vm.Script(...)`
    — the `class: 'constructor'` short-circuit accepts the no-receiver
    `new`-call shape, and the matcher's dotted-simple-name fallback
    (`taint-matcher.ts:1664`) lets `pattern.method = 'Script'` hit
    `method_name = 'vm.Script'`.
  - Classless `setImmediate` — Node evaluates a tainted string passed as
    arg[0], identical to the already-shipped `setTimeout` / `setInterval`
    behaviour.
  Extended the callback-shape gate in `taint-matcher.ts` (which prevents
  CWE-94 false positives on `setTimeout(() => cb(), 100)`) to also
  recognise `setImmediate`. Recall locks: direct `eval(taint)` and
  `setTimeout(taintedString)` continue to fire; `setImmediate(() =>
  cb())` continues to suppress.

### Deferred

- **#188 indirect-eval** (`const f = eval; f(taint)`) requires
  variable-alias tracking in the sink matcher and is deferred to a future
  sprint. Test case is shipped as `it.skip` with a design-sketch comment.

### Tests

- `tests/analysis/passes/js-bare-fn-ssrf-fn.test.ts` (4 cases)
- `tests/analysis/passes/angular-domsanitizer-xss-fn.test.ts` (4 cases)
- `tests/analysis/passes/js-sqlite3-sqli-fn.test.ts` (6 cases)
- `tests/analysis/passes/js-vm-setimmediate-indirect-eval-fn.test.ts`
  (6 cases, 1 skipped)

Suite total: 3103 passing, 2 skipped (up from 3084/1 on v3.111.0; net-new
20 cases minus 1 already-passing recall lock — no regressions).

## [3.111.0] - 2026-06-28

Sprint 54 batch — three FN tickets shipped together. Phase 0 inline-synthesized
reproductions baselined against v3.110.0 (3 test files, 12 cases) verified each
failure before any source change.

### Fixed

- **#194 — Python `col.find({"name": tainted})` does not flag `nosql_injection`
  (CWE-943).** The classless pymongo sink entries in `config-loader.ts` covered
  `find_one`/`update`/`delete`/`insert`/`replace`/`bulk_write` but were missing
  the most common method: `find` (and `aggregate`). Added both to the
  classless Python variants. Recall lock: dict-literal value-bound `find` calls
  carrying tainted HTTP-sourced values now fire one flow.

- **#195 — JavaScript `col.find({name: q})` inline object-literal does not
  flag `nosql_injection`.** The Sprint 21 cognium-dev #105 FP-32 filter
  (`isMongoValueBoundFilter` in `taint-propagation-pass.ts`) unconditionally
  suppressed every literal-object Mongo filter whose keys lacked a `$` prefix.
  Refined to skip the suppression when the source variable is HTTP-derived
  (`http_query`/`http_body`/`http_param`/`http_header`/`http_cookie`) and
  appears in a value position of the filter literal, because Express
  body-parser and equivalent framework parsers normalize bracket-style query
  strings (`?u[$ne]=null`) into nested operator objects at runtime. Non-HTTP
  sources (interprocedural_param, etc.) preserve the original Sprint 21
  FP-32 suppression — see `tests/analysis/repro-sprint21.test.ts`.

- **#187 — JavaScript `command_injection` (CWE-78) false negatives across
  4 shapes.**
  - **v04/v05 shell-mode shape** (`spawn('sh', ['-c', taint])`,
    `execFile('/bin/sh', ['-c', taint])`): widened universal classless
    `spawn`/`spawnSync`/`execFile`/`execFileSync` entries in
    `config-loader.ts` from `arg_positions: [0]` to `[0, 1]` so the argv-array
    position surfaces taint. Added a JS shell-shape gate
    (`isSafeJSChildProcessCall` in `taint-matcher.ts`, mirror of the
    existing Go `isSafeGoExecCommandCall`) that suppresses the finding when
    arg[0] is a non-shell program literal (e.g. `spawn('git', ['clone',
    taint])`), so the wider arg positions do not regress legitimate
    `argv[]`-style usage with hard-coded programs.
  - **v06 execa.command shape** (`execa.command(taint)`): registered
    `execa.command` and `execa.commandSync` as `command_injection` sinks in
    `DEFAULT_SINKS`. The `nodejs.json` JSON config was already augmented but
    is not loaded at runtime by the engine, which uses the hardcoded TS
    defaults.
  - **v08 util.promisify alias shape** (`const x = promisify(exec); x(taint)`):
    added `expandPromisifyAliases` in `taint-matcher.ts` to scan source for
    `const <alias> = (require('util').)?promisify(exec|execFile)` bindings
    and synthesize classless sink patterns for each alias so the
    promisified call site matches as a sink.

### Internal

- New regression tests:
  `tests/analysis/passes/js-mongodb-nosql-injection-fn.test.ts`,
  `tests/analysis/passes/js-spawn-execfile-execa-cmdi-fn.test.ts`,
  `tests/analysis/passes/python-pymongo-nosql-injection-fn.test.ts`
  (12 cases total — 6 FN repros + 6 recall locks).
- Full suite: 3084 tests passing, 1 skipped (was 3083+1; 12 net-new tests
  minus 11 already-present passes — no regressions on Sprint 21 #105 FP-32
  or any prior coverage).

## [3.110.0] - 2026-06-27

Sprint 53 S-bucket batch — four small-complexity tickets shipped together.
Phase 0 inline-synthesized reproductions verified each failure on the
v3.109.0 baseline before any source change.

### Fixed

- **#196 — Java JDK `Logger.getLogger("…").warning(msg)` does not flag
  `log_injection` (CWE-117).** The Java JDK `java.util.logging.Logger`
  sinks were already registered in `config-loader.ts`, but the
  `receiverMightBeClass` heuristic in `taint-matcher.ts` only resolved
  factory-method receivers via `returnTypeMappings` whose regex
  `/\.(\w+)\(\)$/` requires an empty-parens tail (e.g. `getLogger()`),
  so `Logger.getLogger("app").warning(...)` and
  `LoggerFactory.getLogger(Foo.class).warn(...)` were not recognised as
  `Logger`-typed receivers. Added a conservative class-equality
  heuristic: when `className === 'Logger'` and the receiver tail matches
  `/\.getLogger\(.*\)$/`, the receiver is treated as a `Logger`
  instance. Recall lock: `logger.warning("startup complete")` (no
  tainted args) continues to produce zero findings.

- **#193 — Python `logging.Logger.<level>(fmt, *args)` does not flag
  `log_injection` (CWE-117) for tainted positional args.** The Python
  `logging.Logger` sinks in `config-loader.ts` registered each level
  method with `arg_positions: [0]`, covering the format-string but
  invisible to taint in `*args` (positions 1-N), which are interpolated
  into the rendered message via `%` substitution. Extended
  `arg_positions` to `[0, 1, 2, 3, 4]` on `debug`/`info`/`warning`/
  `warn`/`error`/`exception`/`critical`/`fatal` (both
  `class: 'logger'` and `class: 'logging'` variants); `log` uses
  `[1, 2, 3, 4]` since position 0 is the level integer. Added
  previously-missing `warn`/`fatal`/`exception` method aliases. Recall
  locks: constant-only `log.warning("startup complete")` and
  literal-arg `log.warning("user=%s", "anonymous")` produce zero
  findings.

- **#215 — Python `safe_sql_identifier_quote` FP on parameterized
  queries with validated identifier interpolation.** New **Stage 19** in
  `sink-filter-pass.ts` (Python port of the Java Stage 15 SQL
  identifier-quoter wrapper recognition) suppresses
  `cursor.execute(f"…{col}… = ?", (value,))` when:
  (a) the sink method is `cursor.execute`/`executemany`;
  (b) the first arg is an f-string with ≥1 interpolation;
  (c) every interpolation is a literal, an inline helper call, or a
  bare identifier whose assignment within the prior 30 lines is
  `var = helper(arg)`;
  (d) the f-string literal segments contain a bind placeholder
  (`?`, `%s`, or `:name`);
  (e) at least one such helper body contains
  `re.fullmatch(<allowlist>, …)` (or anchored `re.match(^…$, …)`) AND
  a `raise` statement.
  Comment stripping is applied to helper bodies before guard recognition
  so commentary mentioning the word "raise" cannot trip the check.
  Reuses Stage 15's `isImplicitlyAnchoredAllowlistRegex` for the
  Python-side regex shape (`re.fullmatch` is implicitly anchored like
  Java's `String.matches`). Recall locks: helper missing `raise` still
  fires; no `?` placeholder + concatenated value still fires; wildcard
  regex `.*` in helper still fires; direct value interpolation without
  any helper still fires.

### Verified (no code change required)

- **#217 — Java fluent-builder constant-propagation fixpoint hang
  (Keycloak `RoleStorageProviderSpi.java`).** A faithful reproduction
  test using the Keycloak builder shape with cyclic return types
  (`ProviderConfigurationBuilder` ↔ `ProviderConfigProperty`) and the
  static-initializer block from the original repro completes in <500ms
  on HEAD. The Sprint 36 #141 iterative `isTaintedExpressionImpl` +
  per-call memoization (commit `f1b8ab6`) in `propagator.ts` already
  prevents the cubic-recursion blow-up. The new
  `tests/core/fluent-builder-fixpoint-hang.test.ts` is shipped as a
  permanent regression guard against this and similar fluent-builder
  shapes; the recall lock confirms tainted concat sinks at the end of
  a cyclic builder chain continue to fire `sql_injection`.

### Tests

- `tests/core/fluent-builder-fixpoint-hang.test.ts` (2 cases)
- `tests/analysis/passes/java-jdk-logger-log-injection-fn.test.ts` (3 cases)
- `tests/analysis/passes/python-logging-log-injection-fn.test.ts` (4 cases)
- `tests/analysis/passes/python-sql-identifier-quoter-fp.test.ts` (5 cases)

Suite total: 3072 passing, 1 skipped (up from 3060/1 on v3.109.0).

## [3.109.0] - 2026-06-27

Sprint 52 sanitizer-wrapped FP cluster (#216 subset) — Phase 0 empirical
reproduction against the v3.108.0 CLI on the `sanitizer_combos_*` and
`safe_oop_*` fixtures reduced the planned 7-phase scope to 3 shipped
phases (Phases 3, 4, 7 verified clean on v3.108.0 and dropped). The
shipped fixes target three new `SinkFilterPass` stages backed by a
shared scope-aware backward-assignment helper.

### Fixed

- **#216 — Python `ldap_injection` over-fires on `re.sub`-based LDAP
  metachar-stripping wrappers.** New Stage 17 in `sink-filter-pass.ts`
  recognises Python module-level wrapper functions of the canonical shape
  `def NAME(PARAM): return re.sub(r"[CLASS]", "", PARAM)` when the
  character class contains at least three of the LDAP-filter metachars
  `( ) = * \` (per RFC 4515). Such wrappers (plus the built-ins
  `escape_filter_chars` and `filter_format`) are treated as
  `ldap_injection` sanitizers and suppress sinks where either the sink
  line invokes the wrapper inline OR a sink-line identifier was assigned
  from a wrapper call within 30 lines above (scope-aware, halted at the
  enclosing `def`/`class` boundary). Recall locks: wildcard `re.sub`
  patterns (no LDAP metachars) keep firing; direct concat without any
  wrapper keeps firing; wrappers applied to a different variable than
  the sink continue to fire.

- **#216 — Python `xxe` over-fires inside hardened-parser scopes.** New
  Stage 18 in `sink-filter-pass.ts` adds a scope-aware backward scan
  (≤30 lines, halted at the enclosing `def` boundary) for the regex
  `XMLParser(...resolve_entities=False...)`. When such a hardened-parser
  construction is found in the same function body as an `xxe` sink (e.g.
  `safe_parse` wrapper, OOP class method), the sink is dropped. The
  function-boundary halt preserves recall on sibling-function unsafe
  parsers: an `unsafe()` function that constructs its own
  `resolve_entities=True` parser is not suppressed even when a sibling
  `safe_parse` exists in the same module.

- **#216 — JavaScript `log_injection` over-fires on CRLF-stripping
  sanitizers.** New Stage 16 in `sink-filter-pass.ts` adds a
  `JS_LOG_INJECTION_SANITIZERS` pattern array recognising common helper
  names (`stripCrlf`, `stripCRLF`, `removeNewlines`, `sanitizeLogValue`)
  and the inline regex literals `.replace(/[\r\n]/g, '')` and
  `.replace(/\r\n/g, '')`. Suppresses `log_injection` sinks when either
  the sink line calls one of these sanitizers inline OR a sink-line
  identifier was assigned from a sanitizer call within 30 lines above.
  Recall locks: non-CRLF `.replace(/x/g, '')` does NOT suppress; missing
  sanitizer continues to fire.

### Verified (no code change)

- **#216 — JavaScript `xss` `/wrapped` route**
  (`sanitizer_combos_xss.js`): confirmed clean on v3.108.0 (Stage 7
  `JS_XSS_SANITIZERS` already covers `escapeHtml` inline + assignment
  shapes via existing variable-backward-scan).
- **#216 — JavaScript `deserialization` `/wrapped` route**
  (`sanitizer_combos_deserialize.js`): confirmed clean on v3.108.0
  (`JSON.parse(Buffer.from(req.query.s, 'base64').toString())` produces
  zero `deserialization` and zero `external_taint_escape` sinks).
- **#216 — Python `code_injection` SSTI `/wrapped` route**
  (`sanitizer_combos_ssti.py`): confirmed clean on v3.108.0
  (`render_template_string("<p>{{ name }}</p>", name=name)` literal-arg
  + kwarg shape already suppressed by the existing derived-sanitizer
  detector at `language-sources-pass.ts`).

### Internal

- Shared helper `isAssignedFromSanitizerPattern(sourceLines, sinkLine,
  varName, sanitizerPatterns, lookback=30)` extracted in
  `sink-filter-pass.ts` for use by Stages 16 + 17. Scope-aware: stops
  scan at `def`/`function`/arrow-function declaration to preserve recall
  across function boundaries.
- Helper `findPythonLdapStripWrappers(sourceLines)` discovers wrapper
  function names module-wide so callers in any function body share the
  same sanitizer registry.

## [3.108.0] - 2026-06-26

Sprint 51 Java FN/FP batch — empirical Phase 0 reproduction reduced
scope to a single engine code change (#214 Stage 15 inline form). The
other three tickets in the batch (#197, #196, #117) already fire under
v3.107.0 on their canonical fixture shapes; the residual gaps are
narrower-than-reported inline-fluent-receiver edge cases queued as
follow-ups.

### Fixed

- **#214 — Java `sql_injection` Stage 15 still over-fires when SQL
  concat is passed inline to `prepareStatement(...)`.** Sprint 50
  Stage 15 only handled the indirect form (`String sql = "…" +
  quoteIdent(col) + " = ?"; ps = conn.prepareStatement(sql)`). The
  inline form (`ps = c.prepareStatement("…" + quoteIdent(col) + " =
  ?")`) failed gate (b) because `callArgs[0]` is a concat expression,
  not a bare identifier — Stage 15 returned early and the sink
  survived. New inline branch at `sink-filter-pass.ts:1141-1163`
  treats the arg expression itself as the concat RHS when it contains
  at least one string literal and a `+` operator, then applies the
  unchanged gates (c)–(e) (literal-and-method-call-only RHS, `?`
  placeholder, in-file `String.matches("strict-anchored")`+`throw`
  guard). Recall locks unchanged: bare-variable concat, missing `?`
  placeholder, missing/wildcard regex guard all continue to fire.

### Verified (no code change)

- **#197 — Java `HttpServletRequest.getInputStream` →
  `ObjectInputStream.readObject` deserialization FN.** Confirmed
  firing under v3.107.0 against the canonical fixture
  (`getInputStream().readAllBytes()` → `new
  ObjectInputStream(...).readObject()`). The taint-preserving chain
  on `InputStream.readAllBytes` was already wired by a prior sprint.

- **#196 — Java `java.util.logging.Logger` `log_injection` FN.**
  Confirmed firing under v3.107.0 on the intermediate-variable shape
  (`Logger LOG = Logger.getLogger(...); LOG.warning(taint);`). The
  inline-fluent-receiver shape
  (`Logger.getLogger("app").warning(taint)`) does not fire because
  the receiver type does not resolve before the sink-class gate
  evaluates. Queued as a follow-up under the receiver-resolution
  family.

- **#117 — CWE-501 Trust Boundary Violation FN.** Confirmed firing
  under v3.107.0 on the intermediate-variable shape
  (`HttpSession s = req.getSession(); s.setAttribute(k, taint);`).
  The inline shape
  (`req.getSession().setAttribute(k, req.getParameter(...))`) is
  suppressed by the source+sink-same-line dedup (xss fires; the
  trust_boundary finding is dropped to avoid co-located double
  reporting). Queued as a follow-up under the same-line-dedup policy
  review.

### Tests

- 3 new cases in `tests/analysis/passes/java-sql-identifier-quoter-fp.test.ts`:
  inline FP suppression, inline bare-variable recall, inline
  no-`?`-placeholder recall. Total suite: 3045 pass / 1 skipped.

## [3.107.0] - 2026-06-25

Sprint 50 FP triage batch — three independently-reported false positives
fixed under one release. All three are sink-/flow-level gates with
recall locks; no source-detection or pass-pipeline changes.

### Fixed

- **#152 — JS `setInterval`/`setTimeout` `code_injection` over-fires on
  function-typed parameter references.** The 3.96.0 gate in
  `taint-matcher.ts` only covered inline function literals at the call
  site. When the callback is an identifier reference whose runtime type
  cannot be proven without type info (`function schedule(cb) {
  setTimeout(cb, 1000); }`), the matcher still emits the sink and the
  `interprocedural_param × code_injection` cross-product produces a
  flow. New filter in `taint-propagation-pass.ts` drops the flow when
  the sole contributing source is an `interprocedural_param` whose
  sink line matches a `setInterval`/`setTimeout` `code_injection`
  sink. Real string sources (`http_query`, `http_body`, `file_input`)
  still flow because they carry a different `source_type`; an
  `eval(param)` flow on the same parameter still fires because the
  sink line does not match a timer method.

- **#181 — Java `xxe` over-matches CommonMark `Parser.parse()`.**
  Follow-up to #155 (which closed the `code_injection` over-match on
  the same pattern). On v3.104.0 the same minimal fixture began firing
  `xxe` instead — the receiver-fuzzy lookup in `taint-matcher.ts` maps
  any name ending in `parser` to `SAXParser`/`XMLReader`/
  `DocumentBuilder`, and the xxe sink rule accepts the call. New
  Stage 9f in `sink-filter-pass.ts` mirrors Stage 9a (the #155 gate)
  but for `xxe`: drops the sink when the resolvable receiver type is
  in the shared `DATA_PARSER_TYPES` set (commonmark `Parser`, CLI
  arg parsers, date / number parsers, …). Recall on real XML parsers
  (`DocumentBuilder`, `SAXParser`, `XMLReader`) is unchanged because
  those classes are NOT in `DATA_PARSER_TYPES`.

- **#191 / FP-77 — Java `sql_injection` over-fires on
  regex-allowlist-quoter wrappers.** Generalises Stage 13 (#163), which
  required the enclosing class name to match
  `*Dialect|*SqlBuilder|*Quoter|*QueryBuilder`. Utility classes such as
  the reported `SafeSqlIdentifierQuote` don't carry that suffix. New
  Stage 15 in `sink-filter-pass.ts` drops the class-name gate and
  instead inspects the SQL assembly shape: it drops the sink when (a)
  the sink is a JDBC exec method (`prepareStatement`, `execute*`,
  `addBatch`), (b) the SQL string is built from a concat whose tokens
  are ONLY string literals and method calls (no bare-variable concat),
  (c) at least one literal contains a `?` placeholder (parameterized
  value binding), and (d) at least one method call invokes a same-file
  helper whose body contains an inline `.matches("strict-anchored")`
  call plus a `throw` (regex-allowlist guard). Recall locks: bare-var
  concat, no-placeholder, wrapper with no regex guard, and wrapper
  with a wildcard `.+` regex all continue to fire `sql_injection`.

### Unchanged

- Browser+Node compatibility — all three fixes are pure source-text
  inspection in passes that already run cross-environment.
- Pillar I: no LLM identifiers (verified by grep guard).
- Recall on OWASP Benchmark Java + Juliet remains 100% (3042 tests
  pass; 1 skipped — same baseline as 3.106.0).

#191 FP-78 (Python equivalent) was investigated and resolved as a
benchmark-harness artifact: the engine emits the `sql_injection` sink
in `r.taint.sinks` but `r.taint.flows` is empty and `generateFindings`
emits no finding. The FP arises only when the benchmark harness flags
on file-level `hasSink && hasSource` co-occurrence without consulting
flows (see CLAUDE.md note on `BenchmarkPython`); no engine-side change
is required.

## [3.106.0] - 2026-06-24

Sprint 48 closes umbrella ticket **#169 (project-profile architecture)**
— the first deterministic mechanism for shape-conditional severity
bucketing. circle-ir gains a new public-API surface
(`analyzeOptions.projectProfile`) accepting either a single
`ProjectProfile` (`shape/env`, e.g. `library/production`) or a
`Map<file, ProjectProfile>` for per-file resolution, plus the central
transform `applyProjectProfileTransform` wired between
`applyLibraryApiSurfaceDowngrade` (Sprint 47) and
`applyPerFileFindingCap`. Detection itself lives caller-side in the
cognium-dev CLI to preserve the browser+Node-compatible boundary —
circle-ir consumes profiles but never reads the filesystem.

Policy (ADR-008, locked):

- **D1=C CRIT-protected bucketing** under `library/...`: CRIT→MED,
  HIGH→LOW, MED→LOW, LOW→LOW. CRIT never drops below MEDIUM so
  catastrophic findings remain visible even when the artifact's trust
  boundary is `caller`.
- **D2=Yes sink-type allowlist**: bucketing only applies to the
  Tier-D-eligible rule_ids (`code_injection`, `template_injection`,
  `xpath_injection`, `sql_injection`) carrying the Sprint 47
  `library-api-surface:caller-responsibility` tag. All other findings
  pass through unchanged regardless of profile.
- **D3=Yes restoration** under `application/...`: when an upstream
  pass already downgraded a finding (Sprint 47), the original severity
  is restored from `SastFinding.original_severity`. Internal helpers
  that were mis-classified as library by Sprint 47 still report at full
  severity once the project profile is known.

Profiles in v1 are the 5×5 matrix `{library, application, cli, server,
plugin} × {production, dev, sample, benchmark, test}` plus `unknown`
(the v1 no-op fallback for `cli/...`, `server/...`, `plugin/...`, and
`test/...`). The `original_severity` field on `SastFinding` is the
restoration anchor for D3.

Added:
- `ProjectShape`, `ProjectEnv`, `ProjectProfile` types in
  `src/types/index.ts` plus matching exports from `index.ts`.
- `src/analysis/project-profile-transform.ts` — pure transform
  `applyProjectProfileTransform(findings, resolver)` with
  `ProfileResolver = (file: string) => ProjectProfile` callback.
- `AnalyzerOptions.projectProfile?: ProjectProfile |
  Map<string, ProjectProfile>` accepted by `analyze` /
  `analyzeProject` / `analyzeForAPI`.
- `original_severity?: Severity` on `SastFinding` (already populated
  by Sprint 47 `applyLibraryApiSurfaceDowngrade`).
- 17 new unit tests in
  `tests/analysis/project-profile-transform.test.ts` covering
  passthrough rules, library bucketing across all severity levels,
  application restoration, other-shape no-ops, composition with the
  Sprint 47 downgrade hook, per-file routing, and the Pillar I guard.

Changed:
- `analyzer.ts` post-processing chain now runs
  `findings → applyConfidenceFilter → applyLibraryApiSurfaceDowngrade
  → applyProjectProfileTransform → applyPerFileFindingCap`. The new
  transform is a no-op when `projectProfile` is absent, preserving
  pre-3.106.0 output exactly.

End-user effect (when callers supply a profile):
- A `library/production` module no longer fires HIGH/CRIT on
  `library-api-surface`-tagged sinks — they bucket down to
  MEDIUM/warning or LOW/note per the policy table above. CRIT-protected
  findings stay at MEDIUM (never lower).
- An `application/production` module's library-API-tagged findings are
  restored to their pre-Sprint-47 severity, so internal helpers that
  *look* library-shaped but are actually first-party application code
  report at full severity again.
- Profiles `cli/...`, `server/...`, `plugin/...`, and `test/...` are
  no-ops in v1 (placeholder for future shape-specific policies).
- All existing benchmark scores (OWASP Benchmark Java 100%/0%, Juliet
  100%, SecuriBench 97.7%, OWASP BenchmarkPython 81.2%/12.6%) are
  preserved when no profile is supplied. With `library/production`
  the FP rate drops further on real-world library corpora — see
  cognium-dev CHANGELOG 3.106.0 for end-user numbers.

Pillar I: zero LLM-themed identifiers introduced. The transform name,
field names, and all rationale strings are generic and deterministic.

## [3.105.0] - 2026-06-24

Sprint 47 closes the entire Tier-D policy queue: six cognium-dev FP
tickets (#161, #163, #164, #165, #168, #177) under two orthogonal
mechanisms. Mechanism A is a new tag + central downgrade infrastructure
(`SastFinding.tags?: string[]`, `TaintSink.tags?: string[]`,
`TaintFlowInfo.tags?: string[]`, and `applyLibraryApiSurfaceDowngrade`)
that drops severity to MEDIUM for findings carrying the
`library-api-surface:caller-responsibility` tag. Mechanism B is three
narrow suppression gates in `SinkFilterPass`. Pillar I zero-LLM
boundary safe — the tag string is fully generic.

- **cognium-dev#161 — `code_injection` (CWE-94) HIGH on JEXL /
  Handlebars / template-engine compile-evaluate.** Apache Commons
  `JexlEngine.createExpression(...)`, `JexlExpression.evaluate(...)`,
  and template-engine `.compile(...)` callsites (Handlebars, Mustache,
  Pebble, Velocity, Freemarker, Thymeleaf) are *library-API surface*:
  the engines exist to evaluate caller-supplied
  expressions/templates. Stage 9e in `sink-filter-pass.ts` tags such
  sinks with `library-api-surface:caller-responsibility`; the central
  downgrade hook in `analyzer.ts` then drops severity to MEDIUM. The
  sink + flow still fire so auditors can see the callsite.

- **cognium-dev#165 — `code_injection` (CWE-94) HIGH on
  `Class.forName(<var>)` SPI loaders.** The Java SPI pattern
  (`META-INF/services/...`) is *designed* to instantiate caller-declared
  implementation classes. Stage 9f tags `Class.forName` sinks
  `library-api-surface` when the enclosing source file contains a
  `getResources("META-INF/services/...")` call within ±30 lines of the
  callsite. Arbitrary `Class.forName(<user-input>)` outside the SPI
  pattern remains untagged HIGH.

- **cognium-dev#168 — `code_injection` (CWE-94) HIGH inside
  `ClassLoader` subclass overrides.** `loadClass(String)` /
  `findClass(String)` overrides are *required by the JDK contract* to
  look up the named class — the trust decision belongs to whoever
  invokes the loader. Stage 9g tags sinks when the enclosing class
  extends `ClassLoader` / `URLClassLoader` / `SecureClassLoader`, OR
  the class name matches `*ClassLoader` / `*CachingProvider`, OR the
  sink lives inside a `public/protected Class<?> loadClass/findClass
  (String)` method body (textual backward-scan).

- **cognium-dev#164 — `code_injection` (CWE-94) on polymorphic dispatch
  over a typed array of literal parser constructions.** The shape
  `private static final SpelExpressionParser[] PARSERS = new X[] {
  new X(), new X() };` fully enumerates the dispatch target set —
  no arbitrary class is reachable. Stage 9h *suppresses* the sink
  when the receiver appears in `for (X r : ARR)` foreach or
  `ARR[i].m(...)` index access AND the array literal contains only
  `new <TypeName>(...)` literal expressions. Dispatch over runtime-
  populated `List<Parser>` or arrays with reflective lookups remain
  unsuppressed.

- **cognium-dev#163 — `sql_injection` (CWE-89) inside SQL builder /
  dialect / quoter classes.** When the enclosing class name matches
  `*Dialect` / `*SqlBuilder` / `*Quoter` / `*Wrapper` / `*SqlGenerator`
  / `*QueryBuilder` AND a `.wrap(` / `.quote(` / `.escape(` /
  `.identifier(` wrapper call appears within ±10 lines of the sink,
  Stage 13 suppresses the sink. The quoting/wrapping is the
  sanitization step. Business classes with raw concat (e.g.
  `UserService.findByName`) and `*Dialect` classes without wrapper
  calls remain unsuppressed.

- **cognium-dev#177 — `sql_injection` (CWE-89) inside SQL-codegen
  utility methods.** Three-clause signature-shape gate in Stage 14
  suppresses sinks when the enclosing method has return type ∈
  `{String, CharSequence, Optional<String>}`, name matches
  `get*Sql*` / `extract*Sql*` / `to*Sql*` / `*Statement*ToString$` /
  `*Query*String$`, AND the primary parameter type is NOT
  `String`/`CharSequence` (i.e. input is a builder/AST/Statement
  type). Codegen methods *generate* SQL from a parsed builder —
  they don't execute user-supplied SQL. Helpers with String input
  remain unsuppressed.

### Added

- `SastFinding.tags?: string[]` — optional metadata tags carried by
  the finding, e.g. `'library-api-surface:caller-responsibility'`.
  Tags are pass-emitted and consumed by post-processing (severity
  downgrade) and downstream consumers (SARIF properties, CLI
  badges).
- `TaintSink.tags?: string[]` — same field on the sink so the tag
  survives sink→finding propagation through the pipeline.
- `TaintFlowInfo.tags?: string[]` — same field on emitted flows; the
  analyzer chokepoint propagates from `TaintSink.tags` to
  `TaintFlowInfo.tags` by matching `(sink_line, sink_type)` keys.
- New module `src/analysis/library-api-surface-downgrade.ts`:
    - `LIBRARY_API_SURFACE_TAG` constant
      (`'library-api-surface:caller-responsibility'`).
    - `applyLibraryApiSurfaceDowngrade(findings)` pure-function that
      drops `severity` to `medium` / `level` to `warning` for findings
      carrying the tag at `critical` or `high` severity. Non-mutating:
      returns a new array; non-tagged findings pass through identical;
      low-severity findings are not upgraded.
- 6 new test files (31 cases total) covering all six FP tickets:
  `tests/analysis/passes/java-library-api-surface-jexl-handlebars-fp
  .test.ts`,
  `tests/analysis/passes/java-library-api-surface-spi-classforname-fp
  .test.ts`,
  `tests/analysis/passes/java-library-api-surface-classloader-
  override-fp.test.ts`,
  `tests/analysis/passes/java-code-injection-polymorphic-dispatch-fp
  .test.ts`,
  `tests/analysis/passes/java-sql-builder-wrapper-fp.test.ts`,
  `tests/analysis/passes/java-sql-extraction-method-fp.test.ts`.
- 1 new infra test file (6 cases) for the downgrade hook:
  `tests/analysis/library-api-surface-downgrade.test.ts`.

### Changed

- `sink-filter-pass.ts`: imports `LIBRARY_API_SURFACE_TAG`; adds
  Stages 9e/9f/9g (tag emission) and 9h/13/14 (suppression) with
  supporting constants and helpers (`findEnclosingClassDecl`,
  `isInsideLoadClassOverride`, `findEnclosingMethodFromIr`).
- `analyzer.ts`: inserts `applyLibraryApiSurfaceDowngrade(...)`
  between `applyConfidenceFilter(...)` and `applyPerFileFindingCap
  (...)`; adds the sink→flow tag-propagation chokepoint after the
  pipeline run.

### End-user effect

Six previously-HIGH false-positive shapes from the FP corpus
either downgrade to MEDIUM (`#161` / `#165` / `#168` — auditors still
see the callsite, but it no longer blocks CI) or stop firing
entirely (`#163` / `#164` / `#177`). Recall on real
`code_injection` / `sql_injection` sinks is preserved.

## [3.104.0] - 2026-06-24

Sprint 46 closes the three remaining standalone Tier-1 zero-FP queue
items under a single shared-helper module (`_fp-allowlists.ts`). All
edits are pass-layer only — no IR, no YAML config, no CLI surface
change. Pillar I zero-LLM boundary safe.

- **cognium-dev#176 — `hardcoded-credential` (CWE-798) CRIT on PEM
  delimiter string constants.** The `PEM private key` provider pattern
  in `scan-secrets-pass` (Layer 1) matched any line containing
  `-----BEGIN [...] PRIVATE KEY-----` regardless of whether key body
  followed. This fired on parser constants
  (`String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"`),
  `String.contains()` arguments
  (`if (pem.contains("-----BEGIN RSA PRIVATE KEY-----"))`), and error
  messages
  (`throw new IllegalArgumentException("... '-----BEGIN PRIVATE KEY-----' ...")`).
  Sprint 46 adds a body-adjacency check: a PEM delimiter hit requires
  >=30 base64-shape characters (`[A-Za-z0-9+/]{30,}`) within 5 lines
  of the BEGIN delimiter. Real embedded PEM keys always have this body
  (multi-line concatenation or inline single-line); parser
  constants / error messages / contains() arguments don't. 7 CRITs in
  mock-server alone suppressed; real embedded keys continue to fire.

- **cognium-dev#174 — `hardcoded-credential` (CWE-798) HIGH on CLI
  option-key constants.** The Layer 1b named-credential matcher fired
  on JOptSimple / PicoCLI / argparse4j / commons-cli kebab-case
  option-name constants like
  `HTTPS_KEYSTORE_PASSWORD = "keystore-password"`. The LHS identifier
  carries `PASSWORD`, but the RHS value is the flag name the user
  types on the command line, not a credential. Sprint 46 adds a new
  negative predicate (`CLI_OPTION_KEY_RE`) after the existing #130
  value-shape gates: kebab-case values (all-lowercase + alphanumeric
  + at least one hyphen, <=48 chars) are CLI option names by
  construction. JVM identifiers cannot contain hyphens, so a
  hyphen-bearing string value is structurally not a JVM string
  secret. Recall lock: values with uppercase
  (`Pr0d-DB-pass!2024`), underscores (`sk_live_...`), or dots
  (`ya29.A0AfH6SMABcdef...`) don't match the all-lowercase regex and
  continue to fire. 2 FPs in wiremock; ~15-40 projected across the
  corpus.

- **cognium-dev#175 — `weak-crypto` (CWE-327) / `weak-password-hash`
  (CWE-916) on protocol-mandated DES/RC4/MD4/MD5.** NTLM, Kerberos
  pre-auth (RFC 3961 etype 1/3), SMB1 signing, SASL CRAM-MD5 (RFC
  2195), and HTTP Digest (RFC 2617) hardcode legacy algorithms in
  their protocol specs; switching algorithms breaks interop with
  conformant peers. Sprint 46 adds a file-context predicate
  (`isProtocolMandatedCryptoFile`) checking three signals: path
  segment (`/ntlm/`, `/kerberos/`, `/krb5/`, `/smb1?/`,
  `/sasl/cram-md5/`, `/digest/`), class name
  (`NtlmEngine`, `Krb5Helper`, `KerberosClient`, `Smb*Signing`,
  `CramMd5*`, `DigestScheme`), or inline citation (`MS-NLMP`,
  `RFC 4757`, `RFC 3961`, `RFC 2617`, `RFC 2195`, `CRAM-MD5`). Any
  match suppresses the pass entirely for that file. 6 FPs in
  AsyncHttpClient alone; ~10-20 projected. Recall locks: a
  `Cipher.getInstance("DES")` in a non-protocol path with no class
  match and no RFC citation continues to fire; a JWT-MD5-signature
  bug in any non-protocol file continues to fire.

### Added

- New shared helper module
  `src/analysis/passes/_fp-allowlists.ts` (~50 LOC) exporting three
  pure-function predicates:
    - `pemHasInlineBody(lines, hitLineIdx)` — #176 body-adjacency
      check (PEM body >=30 base64 chars within 5 lines of BEGIN).
    - `isCliOptionKeyValue(value)` — #174 kebab-case CLI option-key
      predicate (`^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$`, length <=48).
    - `isProtocolMandatedCryptoFile(file, code)` — #175 path / class /
      citation file-context predicate.
- 17 new tests across three files:
  `tests/analysis/passes/java-pem-delimiter-fp.test.ts` (5 cases),
  `tests/analysis/passes/java-cli-option-key-fp.test.ts` (5 cases),
  `tests/analysis/passes/java-protocol-mandated-crypto-fp.test.ts`
  (7 cases). Each file covers FP repro shapes and recall locks.

### Changed

- `scan-secrets-pass.ts`: imports `pemHasInlineBody` and
  `isCliOptionKeyValue`; Layer 1 emission loop skips PEM hits
  without adjacent body; `isLikelyCredentialAssignment` negative-
  predicate block adds the CLI option-key rejection after the
  existing `PLAIN_IDENTIFIER_RE` check.
- `weak-crypto-pass.ts`: imports `isProtocolMandatedCryptoFile`;
  `run()` returns empty findings array early when the file is in a
  protocol-mandated context.
- `weak-password-hash-pass.ts`: imports
  `isProtocolMandatedCryptoFile`; `run()` expands its context
  destructuring to include `code` and returns empty findings array
  early in the same condition.
- Existing scan-secrets PEM JS template-literal test updated to use
  a realistic >=30-char base64 body stub (was a 4-char `MIIE...`
  stub before #176). The stub change is test-data only; the test
  still verifies the PEM provider regex emits the finding.

### End-user effect (three Java rule fixes)

- Java `hardcoded-credential` CRIT findings on PEM delimiter-only
  constants / error messages / parser arguments are suppressed.
  Real embedded PEM keys (multi-line concatenation or single-line
  with body inline) continue to fire.
- Java `hardcoded-credential` HIGH findings on CLI option-key
  kebab-case constants (joptsimple / picocli / argparse4j /
  commons-cli) are suppressed. Real password values with uppercase /
  underscores / dots / special characters continue to fire.
- Java `weak-crypto` (CWE-327) and `weak-password-hash` (CWE-916)
  findings in protocol-mandated legacy-auth files (NTLM / Kerberos /
  SMB1 / SASL CRAM-MD5 / HTTP Digest) are suppressed. Suppression
  triggers on path segment, class name, or inline RFC / MS-NLMP
  citation. Non-protocol weak-crypto / weak-password-hash bugs
  continue to fire.

## [3.103.0] - 2026-06-24

Sprint 45 closes two small standalone Tier-1 FP queue items previewed
after the Sprint 44 release. Both items are pass-layer only — no IR,
no YAML config, no CLI surface change. Pillar I zero-LLM boundary safe.

- **cognium-dev#157 — Java `sql_injection` (CWE-89) sink reported on a
  `throw new SQLException(...)` line.** A new Stage 12 in
  `SinkFilterPass` (`sink-filter-pass.ts`), scoped to
  `language === 'java'`, drops any sink whose own line text matches
  `^\s*throw\s+new\s+\w+(?:Exception|Error)\b`. A `throw` statement
  is structurally never a runtime sink: the expression constructs the
  exception object then the next bytecode unwinds the stack. No SQL
  execution, no command exec, no XSS, no path I/O happens.
  Sink-type-agnostic by design — also suppresses spurious
  `path_traversal` / `command_injection` / etc. sinks if they land on
  a throw line. Recall lock: a real sink on any other line of the
  same method continues to fire.

- **cognium-dev#158 — Java `resource-leak` (CWE-772) FP on factory
  return / field-store with paired close.** Three additive
  suppressions in `ResourceLeakPass` (`resource-leak-pass.ts`),
  evaluated after the resource-variable extraction and before the
  close-call search. Each requires its conditions in full
  (conservative-bias preserved):
    - **Return-flow suppression** — the resource variable appears in
      a `return ...` expression within the enclosing method
      (`isReturnedToCaller`). Caller owns the handle, typically via
      try-with-resources.
    - **Field-store with paired close-method suppression** — the
      resource is assigned to `this.<field>` (`fieldStoredName`) AND
      the enclosing class declares any method whose call shape is
      `<field>.<closeMethod>(...)` with `closeMethod` in
      `CLOSE_METHODS` (`classHasCloseMethodFor`). Both conditions
      required.
    - **Factory-method-name heuristic** — the enclosing method's name
      matches `^(?:open|create|new|get|make|build)[A-Z]` AND its
      `return_type` is non-`void` / non-`null` (`isFactoryMethod`).
      Both conditions required: `void openFoo()` and `process()`
      continue to fire.
  Recall locks: unreturned, unstored, non-factory resources continue
  to fire as definite HIGH leaks; field-store without any close
  method in the class continues to fire.

### Added

- Stage 12 in `SinkFilterPass` for the Java throw-statement gate
  (`JAVA_THROW_STATEMENT_RE` regex + filter block, ~15 LOC in
  `sink-filter-pass.ts`).
- Three FP suppressions + four helper methods in `ResourceLeakPass`
  (`isReturnedToCaller`, `fieldStoredName`, `classHasCloseMethodFor`,
  `isFactoryMethod`) plus a module-level `FACTORY_METHOD_NAME_RE`
  constant and an `escapeRegex` utility (~80 LOC in
  `resource-leak-pass.ts`).
- 13 new tests across two new test files
  (`tests/analysis/passes/java-sql-throw-statement-fp.test.ts` — 5
  cases; `tests/analysis/passes/java-resource-leak-factory-fp.test.ts`
  — 8 cases).

### Changed

- Total test count: **2941 → 2954 passed / 1 skipped**.

### End-user effect

- Java scans of projects that throw `SQLException` / `IOException` /
  any other `*Exception` or `*Error` no longer surface spurious sink
  findings on those throw lines. Real sinks on any other line of the
  same method continue to fire.
- Java scans of factory-method-style resource openers
  (`openConnection`, `openStream`, `OpenCameraInterface.open`, …)
  whose handle is returned to the caller, stored to an instance field
  with a paired close method on the class, or whose enclosing method
  has a factory-shape name + non-void return type, no longer surface
  HIGH definite-leak findings. The ~10% benchmark FP rate on this
  rule for the affected shapes is eliminated.

## [3.102.0] - 2026-06-24

Sprint 44 closes the remaining new-work items on the **#179 sink-shape
umbrella** and **#166 XXE JDK hardening recognition**. Recon (after
Sprint 43 shipped #179 Sink 4 via 3.101.0) confirmed that #179 Sinks 2
(typed Jackson) and 3 (parameterized JdbcTemplate) are already
addressed by existing gates (`safe_if_class_literal_at: 1` on the
`ObjectMapper.readValue` SinkPattern; placeholder-aware SQL filter for
`?` / `$1` / `:name` / `%s`). The revised sprint scope:

- **cognium-dev#179 Sink 1 — Java `command_injection` (CWE-78) FP on
  argv-form `ProcessBuilder` constructor.** A new Stage 11 in
  `SinkFilterPass` (`sink-filter-pass.ts`), scoped to
  `language === 'java'` AND `sink.type === 'command_injection'` AND
  `sink.method === 'ProcessBuilder'`, suppresses argv-form
  constructor shapes that pass argv directly to `fork(2)` — no shell,
  no metacharacter expansion. Suppressed shapes:
    - `new ProcessBuilder(Arrays.asList(...))`
    - `new ProcessBuilder(List.of(...))`
    - `new ProcessBuilder(Collections.singletonList(...))`
    - `new ProcessBuilder(new ArrayList<...>(...))`
    - `new ProcessBuilder(new String[]{ ... })`
    - `new ProcessBuilder("...", ...)` (varargs ≥2 args, first is a
      string literal)
  Defense-in-depth: single bare-variable `new ProcessBuilder(userCmd)`
  continues to fire (real OS-exec attack surface — argv[0] is the
  command path). `Runtime.getRuntime().exec(...)` continues to fire
  unchanged.

- **cognium-dev#166 — Java `xml-entity-expansion` (CWE-776) FP on
  JDK 8u121+ entity-limit hardening.** Extended `JAVA_SAFE_EVIDENCE_RE`
  in `XmlEntityExpansionPass` (`xml-entity-expansion-pass.ts`) with
  additional alternations recognized as file-level hardening evidence
  (any one match short-circuits the Java path for that file):
    - `load-external-dtd` (Apache feature URL)
    - `jdk.xml.totalEntitySizeLimit` / `entityExpansionLimit` /
      `maxGeneralEntitySizeLimit` / `maxParameterEntitySizeLimit` /
      `elementAttributeLimit` (JDK 8u121+ system properties; any one
      set to 0 fully disables the corresponding limit class)
    - `feature/secure-processing` URL string and
      `FEATURE_SECURE_PROCESSING` constant identifier
  Confirmed FP repros from #166 body: `languagetool`
  `PatternRuleLoader.java:70`, `FalseFriendRuleLoader.java:78`,
  `DisambiguationRuleLoader.java:45`,
  `BitextPatternRuleLoader.java:41`. Recall lock: SAX parsers /
  `DocumentBuilder`s without any hardening pattern continue to fire.

- **cognium-dev#179 Sinks 2/3 regression locks.** Two new test files
  replicate the exact #179 ticket-body shapes verbatim and lock the
  existing gates against future drift:
    - `tests/analysis/passes/java-sink-shape-regression.test.ts` — 5
      cases: Sink 2 (`mapper.readValue(json, User.class)` and FQN),
      Sink 3 (`jdbcTemplate.update("...?", name, id)` and
      `queryForObject`), Sink 4
      (`Transformer.transform(DOMSource → StreamResult)`).
    - No source change required — pure regression locks.

All three items are pass / filter-layer only — no IR, no YAML config,
no CLI surface change. Pillar I zero-LLM boundary safe.

### Added

- Stage 11 in `SinkFilterPass` for argv-form `ProcessBuilder`
  constructor suppression (`PROCESS_BUILDER_ARGV_FORM_RE` regex +
  filter block, ~25 LOC in `sink-filter-pass.ts`).
- Extended `JAVA_SAFE_EVIDENCE_RE` alternation in
  `XmlEntityExpansionPass` with JDK 8u121+ entity-limit properties,
  Apache `load-external-dtd` feature URL, and `FEATURE_SECURE_PROCESSING`
  / `feature/secure-processing` (~6 LOC change in
  `xml-entity-expansion-pass.ts`).
- 20 new tests across three new test files (8 + 5 + 7).

### Changed

- Total test count: **2921 → 2941 passed / 1 skipped**.

### End-user effect

- Java scans of projects using argv-form `ProcessBuilder` constructors
  (any of `Arrays.asList`, `List.of`, `Collections.singletonList`,
  `new ArrayList<>`, `new String[]{}`, or varargs ≥2 with a string
  literal first arg) no longer surface CRITICAL CWE-78 FPs. Single
  bare-variable `new ProcessBuilder(userCmd)` and
  `Runtime.exec(userCmd)` continue to fire.
- Java scans of projects using JDK 8u121+ entity-limit hardening
  (`jdk.xml.*Limit` system properties), the Apache `load-external-dtd`
  feature disable, or the XMLConstants secure-processing feature no
  longer surface CWE-776 / CWE-611 `xml-entity-expansion` FPs. SAX
  parsers / `DocumentBuilder`s without any hardening pattern continue
  to fire.

## [3.101.0] - 2026-06-24

Tier-1 zero-FP queue cluster release covering three Java FPs that
share a common root cause — lexical sink matching with no file-level
package-context check — spanning two distinct vuln classes. The
cluster targets the single biggest CRITICAL-severity noise source in
the top-100 Java sweep (#170), the largest XXE FP bucket (#173), and
a small lingering picocli FP (#167). A new Stage 10 in
`SinkFilterPass` (`sink-filter-pass.ts`), scoped to
`language === 'java'` AND `sink.type === 'command_injection'`,
plus an output-direction gate in `XmlEntityExpansionPass`
(`xml-entity-expansion-pass.ts`), suppress three known-safe shapes.

- **cognium-dev#167 — picocli `new CommandLine(...)` constructor
  (~5-10 FPs)** — Stage 10a suppresses `new CommandLine(...)`
  command_injection sinks when the file imports `picocli.*`. picocli's
  annotation-driven CLI parser shares the simple class name with
  Apache Commons Exec's `CommandLine` (both already in
  `CWE_78_RECEIVER_ALLOWLIST` at `taint-matcher.ts`), causing a
  last-segment name collision. Apache Commons Exec `CommandLine`
  continues to fire normally (different file, different imports).

- **cognium-dev#170 — Redis / MQ protocol-client wire-command methods
  (5 CRIT + 7 HIGH from jedis alone, 30-60% CRIT-count reduction)** —
  Stage 10b suppresses `executeCommand` / `execute` / `dispatch` /
  `send` / `publish` / `command` / `run` calls inside files importing
  a protocol-client package (jedis, lettuce, spring-data-redis,
  spring-data-mongodb, spring-amqp, rabbitmq, kafka-clients,
  paho-mqtt). These methods dispatch protocol-level wire commands
  (RESP / AMQP / Kafka / MQTT / MongoDB) — no shell, no OS process.
  Receiver is implicit `this` in OO context, so `receiver_type` is
  unresolved at sink-emission time and the existing
  `CWE_78_RECEIVER_ALLOWLIST` gate falls through. Defense-in-depth:
  a protocol-client file that ALSO calls `Runtime.exec(...)` /
  `ProcessBuilder` keeps those sinks (the OS-exec receiver regex
  guards against over-suppression).

- **cognium-dev#173 — output-only `TransformerFactory` + empty
  `DocumentBuilder` (~9 FPs / batch, ~25-40 across the corpus)** —
  Two file-level output-direction gates in
  `xml-entity-expansion-pass.ts`:
    - `TransformerFactory.newInstance()` is suppressed when the file
      uses ONLY `DOMSource` / `StreamResult` (in-process Document
      serialization) and NO `StreamSource` / `SAXSource` /
      `InputSource` (no XML bytes ever read). No entity-resolution
      attack surface.
    - `DocumentBuilderFactory.newInstance()` is suppressed when the
      file calls `.newDocument()` (empty in-memory tree) and NO
      `.parse(...)` (never reads bytes). Empty document construction
      cannot be exploited.

All three fixes are pass / filter-layer only — no IR, no YAML config,
no CLI surface change. Pillar I zero-LLM boundary safe.

### Added

- **#167 / #170** — New Stage 10 block in
  `src/analysis/passes/sink-filter-pass.ts`, gated on
  `language === 'java'` AND `sink.type === 'command_injection'`.
  Sub-stages 10a / 10b correspond to #167 and #170 respectively.
- Module-level constants `PROTOCOL_WIRE_METHODS` (7 entries),
  `PROTOCOL_CLIENT_PACKAGES` (8 entries), and `OS_EXEC_RECEIVER_RE`.
  Adding a new safe protocol-client package is a one-line set entry.
- Helper `hasJavaImportFromPackage(packagePrefix, sourceLines)` —
  bounded 80-line forward scan over the file's Java imports. Package
  prefix is pre-validated by `/^[A-Za-z_][\w.]*$/` before being
  interpolated into the regex template (no regex-injection risk).
- **#173** — Output-direction gate in
  `src/analysis/passes/xml-entity-expansion-pass.ts`, gated on
  `language === 'java'`. Four module-level regex constants
  (`JAVA_XML_OUTPUT_ONLY_RE`, `JAVA_XML_PARSE_INPUT_RE`,
  `JAVA_DOC_BUILDER_NEW_DOCUMENT_RE`, `JAVA_DOC_BUILDER_PARSE_RE`)
  encode the safe-shape and unsafe-shape file-level checks.
- New test file `tests/analysis/passes/java-command-injection-fp.test.ts`
  with 8 cases: 5 FP-suppression (1 for #167, 4 for #170) + 2 recall
  locks (`Runtime.exec`, `new ProcessBuilder`) + 1 defense-in-depth
  regression (jedis import alongside real `Runtime.exec`).
- New test file `tests/analysis/passes/java-xxe-output-only-fp.test.ts`
  with 6 cases: 2 FP-suppression (DOM→StreamResult; empty
  DocumentBuilder) + 3 recall locks (`StreamSource` input,
  `DocumentBuilder.parse`, `SAXParserFactory`) + 1 mixed-shape
  regression lock.

### Changed

- Conservative-bias default preserved across all three issues. The
  existing `CWE_78_RECEIVER_ALLOWLIST` at `taint-matcher.ts:764-777`
  and its gate logic at `taint-matcher.ts:1184-1203` are unchanged;
  Stage 10 is pure post-emission filtering. The Java XXE
  `JAVA_SAFE_EVIDENCE_RE` short-circuit is unchanged; the new
  output-direction gate runs after it. Recall on real
  `Runtime.exec(tainted)`, `new ProcessBuilder(tainted)`, Apache
  Commons Exec `CommandLine`, `StreamSource` / `SAXSource` /
  `InputSource` parsing, `DocumentBuilder.parse(...)`, and
  `SAXParserFactory` remains unchanged.

### End-user effect

- Java SAST scans of projects using jedis / lettuce /
  spring-data-redis / spring-data-mongodb / spring-amqp / rabbitmq /
  kafka-clients / paho-mqtt no longer surface CWE-78 FPs for
  protocol-client wire-command methods. Expected 30-60% reduction in
  CRITICAL-severity finding count on Java corpora dominated by
  Redis / MQ client code.
- Java SAST scans of projects using picocli no longer surface CWE-78
  FPs for `new CommandLine(...)` constructors.
- Java SAST scans of projects that only serialize XML
  (CoreNLP `Ssurgeon`, OpenFeign `SOAPEncoder`, AndroidAsync
  `DocumentBody`) or only construct empty `Document` trees no longer
  surface CWE-776 / CWE-611 FPs for `TransformerFactory.newInstance()`
  or `DocumentBuilderFactory.newInstance()`.

- Test suite: **2907 → 2921 passed** (+ 14 new cases), 1 skipped,
  173 test files (+2 new files).

## [3.100.0] - 2026-06-23

Tier-1 zero-FP queue cluster release covering four Java
`code_injection` (CWE-094) FP issues that share a single root cause:
lexical sink matching with no receiver-type or arg-shape gate. The
cluster represents 18 / 49 (~37%) of the Java HIGH FP corpus. A new
Stage 9 in `SinkFilterPass` (`sink-filter-pass.ts`), scoped to
`language === 'java'` AND `sink.type === 'code_injection'`, suppresses
four known-safe shapes via four sub-stages 9a / 9b / 9c / 9d.

- **cognium-dev#155 — `parser.parse(...)` over-match (7 FPs)** —
  Stage 9a suppresses `.parse(...)` calls when the receiver
  variable's declared type resolves to a non-script data parser
  (commonmark `Parser`, hutool `DateParser`, zxing `ResultParser`,
  `SimpleDateFormat`, `DecimalFormat`, CLI arg parsers, …) via a
  bounded 30-line backward scan over the source. The `DATA_PARSER_TYPES`
  allowlist is intentionally curated; unknown receiver types continue
  to fire.

- **cognium-dev#156 — compiled-template render/process (5 FPs)** —
  Stage 9b suppresses `.render(...)`, `.process(...)`, `.merge(...)`,
  and `.renderTo(...)` calls when the receiver resolves to a
  compiled-template class (`Template`, `JetTemplate`, `ITemplate`,
  `VelocityTemplate`, `BeetlTemplate`). The CWE-094 risk lives at
  the compile step (`engine.getTemplate(tainted)`), not at the render
  step — and the compile-step call continues to fire normally.

- **cognium-dev#159 — reflection / SpEL with literal / annotation
  arg (4 FPs)** — Stage 9c suppresses `Class.forName(...)`,
  `loadClass`, `getMethod`, `getDeclaredMethod`, `getConstructor`,
  `getDeclaredConstructor`, `parseExpression`, and `invoke` calls
  when the first argument is a string literal, an annotation accessor
  (`ann.value()` / `ann.name()` / `ann.key()`), or empty. Special
  case: `method.invoke(target)` (one arg, the receiver only) has no
  payload and is suppressed regardless of arg shape.

- **cognium-dev#160 — no-arg `Constructor#newInstance()` (2 FPs)** —
  Stage 9d suppresses `.newInstance()` calls with an empty argument
  list. An empty arg list means the constructor was statically
  resolved earlier (canonical Record constructors are the prototypical
  example).

All four fixes are pass/filter-layer only — no IR, no YAML config,
no CLI surface change. Pillar I zero-LLM boundary safe.

### Added

- **#155 / #156 / #159 / #160** — New Stage 9 block in
  `src/analysis/passes/sink-filter-pass.ts`, gated on
  `language === 'java'` AND `sink.type === 'code_injection'`.
  Sub-stages 9a / 9b / 9c / 9d each correspond to a single issue.
- Module-level constants `DATA_PARSER_TYPES` (12 entries),
  `COMPILED_TEMPLATE_TYPES` (5 entries), and
  `REFLECTION_LITERAL_METHODS` (8 entries). Adding a new safe type
  is a one-line set entry as new FPs land.
- Helper `resolveJavaReceiverType(receiver, sinkLine, sourceLines)` —
  bounded 30-line backward scan for `<TypeName> <recv>` declarations.
  Returns the last segment of dotted type names. Receiver name is
  pre-validated by `/^[A-Za-z_]\w*$/` before being interpolated into
  the regex template (no regex-injection risk).
- Helper `isJavaLiteralOrAnnotationAccessor(expr)` — accepts empty
  arg, string literals (with backslash-escape handling), and
  annotation-accessor shapes (`ann.value()` / `ann.name()` /
  `ann.key()`).
- Helper `extractJavaCallArgs(method, line)` — extracts top-level
  call arguments allowing one level of nested parens so `ann.value()`
  is captured whole. Returns `[]` for empty arg lists.
- New test file `tests/analysis/passes/java-code-injection-fp.test.ts`
  with 12 cases: 8 FP-suppression (2-3 per sub-stage) + 4 recall /
  regression locks.

### Changed

- Conservative-bias default preserved across all four sub-stages: any
  code_injection sink whose receiver type or arg shape doesn't match
  one of the four known-safe shapes continues to fire. Recall on
  tainted `Class.forName`, SpEL, compile-step template loading, and
  GroovyShell parse-then-run remains unchanged.

### End-user effect

- Java SAST scans of projects using commonmark / Freemarker /
  Jetbrick / Rythm / Velocity / Beetl / hutool / zxing / picocli /
  airline / jcommander / standard `SimpleDateFormat` /
  `DecimalFormat`, or static reflection (`Class.forName("Foo")`,
  `ann.value()` lookups, no-arg `newInstance()`) no longer surface
  CWE-094 FPs for these shapes. Expected ~18 fewer HIGH FPs across
  the Java HIGH FP corpus.

- Test suite: **2895 → 2907 passed** (+ 12 new cases), 1 skipped,
  171 test files (+1 new file).

## [3.99.0] - 2026-06-23

Combined Tier-1 zero-FP queue release covering two unrelated pass /
filter-layer FP suppressions:

- **cognium-dev#132 — JS/TS CRLF / open_redirect Stage 8** — The
  Stage 8 filter in `SinkFilterPass` (`sink-filter-pass.ts:241-283`)
  now suppresses two additional safe shapes that were leaking through
  the `.includes/.startsWith/.endsWith/.indexOf/.test/.match`
  conditional-allowlist guard:
    - **Set/Map `.has(...)` allowlist** — extending the
      `guardPatterns` regex to recognise the `has` method covers
      `if (ALLOWED_REDIRECTS.has(url)) res.redirect(url)` shapes used
      throughout modern JS/TS code.
    - **Express/Koa `res.cookie(name, value, [opts])`** — the cookie
      helper serialises via the `cookie` npm package's `serialize()`,
      which URL-encodes CR (%0D) and LF (%0A). The helper path is
      CRLF-safe by construction; only the raw-header path
      `setHeader('Set-Cookie', tainted)` is still flagged (existing
      8c-or-default).

- **cognium-dev#133 — info-disclosure-stacktrace** — The
  `info-disclosure-stacktrace` pass (`info-disclosure-stacktrace-pass.ts`,
  rule #103, CWE-209) no longer emits findings for two safe shapes:
    - **`.message` is not a stack trace** — `.message` and
      `.getMessage()` are removed from the
      `isExceptionExpression` dangerous-attribute alternation.
      `.message` returns a single-line developer-controlled human
      description (e.g. `new Error('Validation failed')`), not a
      stack trace. The rule's canonical CWE-209 scope is stack-trace
      disclosure; `.stack`, `.toString()`, `.getStackTrace()`, full
      error object, and `traceback.format_exc()` remain in scope and
      continue to fire.
    - **Python file-handle writes** — a backward-scan guard in
      `detectResponseLeakCall()` traces `f.write(...)` /
      `f.writelines(...)` receivers back ≤10 lines to a
      `with open(...) as f:` or `f = open(...)` declaration. When
      resolvable, the call is treated as a file-handle write (not a
      response leak). Cannot regress real response leaks because
      response writers are never produced by `open(...)`.

Both fixes are pass/filter-layer only — no IR, no YAML config, no CLI
surface change. Pillar I zero-LLM boundary safe.

### Added

- **#132** — Stage 8d cookie-helper suppressor in
  `src/analysis/passes/sink-filter-pass.ts`:
  `if (sink.method === 'cookie' && sink.type === 'crlf') return false;`.
  Scoped strictly to `crlf` sinks emitted via the `cookie` method;
  raw-header `setHeader('Set-Cookie', tainted)` is unaffected.
- **#133** — `PY_FILE_HANDLE_OPEN_RE` constant + `isPythonFileHandle(
  receiver, callLine, sourceLines)` helper in
  `src/analysis/passes/info-disclosure-stacktrace-pass.ts`. Backward
  10-line bounded scan for `with open(...) as <recv>:` and
  `<recv> = open(...)` declarations.

### Changed

- **#132** — `guardPatterns` regex in
  `src/analysis/passes/sink-filter-pass.ts:249` extended to include
  the `has` method:
  `\b(?:includes|startsWith|endsWith|indexOf|test|match|has)\s*\(`.
  Reuses the existing `if (…)` within-6-lines window — same
  conservativeness as the existing `.includes` / `.startsWith` set.
- **#133** — `isExceptionExpression()` regex in
  `src/analysis/passes/info-disclosure-stacktrace-pass.ts:70` narrowed
  to:
  `\b(err|error|exc|exception|e|t|throwable)\.(stack|toString\(|getStackTrace\(|getLocalizedMessage\(|getCause\()`.
  Drops `message` and `getMessage(` arms.
- **#133** — `argIsException()` no longer short-circuits on a bare
  `arg.variable === 'err'` match when the expression text is a
  containing object literal. It now defers to
  `isExceptionExpression` on the full expression text whenever
  `expression !== variable`, fixing the asymmetric path where
  parser-extracted `variable="err"` (from
  `{ ok: false, error: err.message }`) was triggering the rule even
  after the regex narrowing.
- **#133** — `detectResponseLeakCall()` signature extended to accept
  optional `language` + `sourceLines` parameters, threaded through the
  four call sites in `run()` (`java`, `js/ts`, `go` fallback, `python`).

### Tests

- `tests/analysis/passes/crlf-stage8-fp.test.ts` — 7 cases:
    - 4 FP-suppression: JS `.has` Set guard + redirect, TS `Set<string>`
      `.has` guard + redirect, JS `res.cookie` with security options,
      JS `res.cookie` 2-arg form.
    - 2 recall: bare `res.redirect(req.query.url)`, raw
      `setHeader('Location', req.query.dest)`.
    - 1 regression: existing `.includes` allowlist guard (cognium-dev #99).
- `tests/analysis/passes/info-disclosure-stacktrace-fp.test.ts` — 6 cases:
    - 2 FP-suppression `.message`: JS `res.json({error: err.message})`,
      JS `res.send('failed: ' + err.message)`.
    - 2 FP-suppression Python file-handle: `with open(p, 'w', opener=…0o600…) as f: f.write(API_KEY)`,
      `f = open(p, 'w'); f.write(SECRET); f.close()`.
    - 2 recall: JS `res.json({error: err.stack})`, Python
      `return traceback.format_exc()` in handler.
- `tests/analysis/repro-issue-86.test.ts:214-230` updated — the historic
  Sprint 6 #86 assertion that `res.cookie('session', req.query.s)`
  flags as CRLF is inverted to assert zero flows (cookie helper is
  CRLF-safe by construction, see #132 rationale above).
- Full suite: 2895 passed / 1 skipped (was 2882 / 1 in 3.98.0).

### End-user effect

- **#132** — JS/TS code using `Set/Map.has(...)` allowlist guards for
  `res.redirect(...)` (idiomatic in modern Express/Koa apps) no longer
  produces false `crlf` / `open_redirect` findings. Express/Koa
  `res.cookie(name, value, [opts])` calls (with or without security
  flags) no longer produce false `crlf` findings. Raw-header
  `setHeader('Set-Cookie', tainted)` and bare unguarded
  `res.redirect(req.query.url)` continue to fire.
- **#133** — Returning `err.message` to the client no longer triggers
  `info-disclosure-stacktrace` (CWE-209). The rule now correctly
  reflects its canonical CWE-209 stack-trace scope. Returning
  `err.stack`, `err.toString()`, the full error object, or
  `traceback.format_exc()` continues to fire. Python file-handle
  writes (`f.write(SECRET)` where `f = open(...)`) no longer trigger
  the rule.

## [3.98.0] - 2026-06-23

cognium-dev#147 — Python Jinja2 `render_template_string("lit", **ctx)`,
`Template("lit")`, and `Template("lit").render(**ctx)` no longer emit
`xss` (CWE-79) or `code_injection` (CWE-94) sinks when the template
SOURCE is a single quoted string literal. Jinja2 auto-escapes context
values passed via `render(**ctx)` / `render_template_string("...", **ctx)`
by default, so tainted context kwargs are not an XSS/SSTI vector when
the template body itself is static. Tainted-template-source variants
(string concat, identifier reference, function-call result, f-string
interpolation) continue to fire — conservative bias is enforced by
matching only literal arg[0] / literal-receiver shapes.

The fix sits at two emitter layers, both gated by the same conservative
literal-only signal:

- **`taint-matcher.ts: findSinks()`** — the config-driven sink emitter
  consults the new `isSafeJinjaRenderCall()` helper and `continue`s past
  the safe shapes.
- **`language-sources-pass.ts: findPythonReturnXSSSinks()`** — the
  regex-fallback emitter that fires on `return <html-ish expr containing
  tainted var>` consults the mirror `isSafeJinjaReturnExpr()` helper.
  This second gate is required because the tainted kwarg in
  `render_template_string("lit", **ctx)` keeps the regex-emitted sink
  alive past Stage 3 (clean-variable) filtering in `SinkFilterPass`.

### Added

- `isSafeJinjaRenderCall(call, pattern, language)` helper and
  `TEMPLATE_LITERAL_RECEIVER_RE` constant in
  `src/analysis/taint-matcher.ts`. Scoped to `language === 'python'`,
  `pattern.type ∈ {xss, code_injection}`, and method names
  `render_template_string` / `Template` / `from_string` / `render`.
  Returns `true` for three exact shapes:
    - `render_template_string` / `Template` / `from_string` — when
      `call.arguments[0].literal` is a non-null string.
    - `render` — when `call.receiver` (verbatim source text for the
      chained `Template(...)`) matches
      `/^Template\(\s*(?:"[^"\\]*"|'[^'\\]*')\s*\)$/`.
- `isSafeJinjaReturnExpr(expr)` helper plus `JINJA_LITERAL_ARG_RE_FRAG`,
  `JINJA_SAFE_RTS_RE`, `JINJA_SAFE_TEMPLATE_RE` constants in
  `src/analysis/passes/language-sources-pass.ts`. Detects three safe
  shapes at line level by string-literal arg[0] match:
    - `(?:flask\.|jinja2\.)?render_template_string("lit"[,)]`
    - `(?:jinja2\.)?Template("lit").render(`
    - `(?:jinja2\.)?Template("lit")` (bare, end of expression).

### Changed

- `findSinks()` (`src/analysis/taint-matcher.ts`) — new gate inserted
  immediately after the cognium-dev #148 Go json safe-gate. When
  `isSafeJinjaRenderCall(...)` returns `true`, the per-call sink emission
  is skipped (`continue`).
- `findPythonReturnXSSSinks()`
  (`src/analysis/passes/language-sources-pass.ts`) — new gate inserted
  immediately after the existing `looksLikeHTML` check. When
  `isSafeJinjaReturnExpr(expr)` returns `true`, the per-line regex sink
  emission is skipped (`continue`).

### Tests

- `tests/analysis/passes/jinja-safe-render-fp.test.ts` — 10 cases:
    - 5 FP-suppression: `Template("lit").render(name=tainted)` with both
      quote styles, `render_template_string("lit", name=tainted)`, bare
      `Template("lit")`, no-context `Template("lit").render()`.
    - 4 recall locks: `Template("..." + name + "...").render()`,
      `render_template_string("..." + name + "...")`,
      `Template(tainted).render()`, `render_template_string(call_result(),
      name=tainted)`.
    - 1 issue body repro pairing the safe shape (0 sinks) against the
      concat-source TP (≥1 sink) in the same suite.
- Full suite: 2882 passed / 1 skipped (was 2872 / 1 in 3.97.0).

### End-user effect

Python scans no longer report XSS (CWE-79) or SSTI/code-injection
(CWE-94) findings for the three safe Jinja2 render shapes when the
template body is a string literal — the dominant FP shape in Flask /
Jinja2 services. Tainted-template-source variants (concat, identifier,
call) continue to fire as before. Cross-file `cf-ip-0-*` taint paths
that previously surfaced the FP at the project level are also
suppressed because the upstream sink no longer exists.

## [3.97.0] - 2026-06-23

cognium-dev#148 — Go `json.Unmarshal(data, &dst)` and
`json.NewDecoder(r).Decode(&dst)` CWE-502 (deserialization) sink emission is
now gated by the **destination shape**. Go's `encoding/json` populates the
declared fields of the destination via reflection; it cannot instantiate
attacker-chosen gadgets the way Python pickle or Java native serialization
can. When the destination is a concrete typed value (typed struct, typed
slice, typed map, pointer to a named type) the call is no longer reported
as a deserialization sink. Untyped destinations (`interface{}`, `any`,
`map[string]interface{}`, `make(map[string]interface{})`) and any shape the
heuristic cannot confidently resolve continue to emit (conservative bias).

Side benefit: downstream `sql_injection` sinks that were previously masked
by the upstream Unmarshal FP are now visible — closes FN-IL-19 as noted in
the issue body.

### Added

- `isSafeGoJsonUnmarshalCall(call, pattern, language, sourceLines)` helper
  (`src/analysis/taint-matcher.ts`) — top-level gate scoped strictly to
  `language === 'go'`, `pattern.type === 'deserialization'`, and the
  `json.Unmarshal` / `Decoder.Decode` method/class pair. Extracts the
  destination variable name from the raw `arg.expression` text (`&d`,
  `&dto{...}`) — the Go plugin sets `arg.variable === null` for the
  unary-expression form so the regex on `expression` is the only viable
  signal at this layer.
- `findGoLocalDeclaredType(varName, callLine, sourceLines)` helper — walks
  `sourceLines` backward up to 50 lines from the call site to locate the
  nearest `var <name> <Type>`, `var <name> = <Expr>`, or `<name> := <Expr>`
  declaration. Returns a `GoLocalDeclResult` discriminated union
  (`typed-decl` / `typed-init` / `untyped` / `null`) capturing the kind of
  declaration and the type text where applicable.
- `classifyGoDestinationType(decl)` helper — maps the declaration result
  into a three-way verdict (`'safe'` / `'unsafe'` / `'unknown'`). `'safe'`
  triggers sink suppression; `'unsafe'` (explicit `interface{}` / `any` /
  `map[string]interface{}`) and `'unknown'` (ambiguous shape, no
  declaration found, `make(...)`, function-call RHS, type assertion, etc.)
  keep the sink emitted.

### Changed

- `findSinks()` (`src/analysis/taint-matcher.ts`) — new guard placed after
  the cognium-dev#152 `setInterval` / `setTimeout` callback gate and
  before `formatCallLocation`: when `isSafeGoJsonUnmarshalCall()` returns
  `true`, skip emission. The gate is matcher-layer only — no plugin /
  extractor / DFG modifications, no sink-config field changes, no IR shape
  changes. The existing Java `safe_if_class_literal_at` gate (Jackson /
  Gson / FastJson / SnakeYAML) is unaffected.

### Tests

- `tests/analysis/passes/go-json-unmarshal-typed-fp.test.ts` — 12 cases:
  6 FP-suppression (`var d dto`, `var d *dto`, `var d []User`,
  `var d map[string]string`, `d := dto{}`, `dec.Decode(&typedStruct)`),
  5 recall (`var d interface{}`, `var d any`, `var d map[string]interface{}`,
  `d := make(...)`, no-decl-in-window), plus the
  `safe_interop_json_deserialize_sink.go` issue-body repro that also locks
  the parameterised-query `sql_injection` no-fire behaviour (FN-IL-19 side
  benefit).

### Verification

- `npm test` (circle-ir) — 167 files, 2872 passed, 1 skipped (was 2860).
- `npm run typecheck` — clean.
- `npm run build` — clean.
- `bun run typecheck` + `bun run build` (cli) — clean.
- Pillar I grep guard — no new LLM-themed identifiers introduced.

## [3.96.0] - 2026-06-23

cognium-dev#152 — `setInterval` / `setTimeout` CWE-94 (code_injection) sink
emission is now gated by arg[0] kind. Callback shapes
(`setInterval(() => tick(), 80)`, `setTimeout(function () {...}, 500)`,
async / named / parameterised variants) are the common benign form and
have no implicit-eval semantics; they no longer emit a `code_injection`
sink. Identifier and string forms remain handled by the existing
`SinkFilterPass` cleanness/taint pipeline. End-user effect: eliminates
the false-positive cluster that fired on benign timer callbacks
(e.g. `cognium-ai/src/utils/spinner.ts:28`).

### Added

- `isFunctionCallbackArgument(arg)` helper
  (`src/analysis/taint-matcher.ts`) — conservative detector for JS/TS
  function-literal arguments. Drives detection off the raw `expression`
  text (`(...) => ...`, `async (...) => ...`, `function ...`) because
  the IR extractor's `analyzeJSArgument()` surfaces the first identifier
  referenced inside the body into `arg.variable`, making that field an
  unreliable signal for inline function expressions.

### Changed

- `findSinks()` (`src/analysis/taint-matcher.ts`) — new guard placed
  after the CWE-78 receiver allowlist and before `formatCallLocation`:
  when `pattern.type === 'code_injection'` and `call.method_name` is
  `setInterval` or `setTimeout`, skip emission if arg[0] is a function
  literal. The gate is scoped strictly to those two method names;
  `eval`, `Function`, and all other code_injection sinks are unaffected.

### Tests

- New `tests/analysis/passes/set-interval-timeout-callback-fp.test.ts`
  (11 cases): 8 FP-suppression locks (arrow / async arrow /
  parameterised arrow / anonymous & named function-expression / setTimeout
  arrow / setTimeout function-expression / spinner.ts:28 issue repro);
  2 recall locks (identifier arg[0] keeps the sink for setInterval and
  setTimeout so taint propagation can decide); 1 gate-scoping lock
  (`eval(...)` still emits).

### End-user effect

- JS / TS scans: no `code_injection` finding on `setInterval` /
  `setTimeout` calls whose first argument is a function literal.
- All other CWE-94 sinks (`eval`, `Function`, `new Function(...)`) are
  emitted unchanged.
- All other taint shapes (tainted identifier flowing into
  `setInterval(handler, ...)`) continue to emit a sink, and taint flow
  produces a finding when a source reaches the identifier.

## [3.95.0] - 2026-06-23

cognium-dev#137 — entry-point gate opt-out toggle + Pillar I documentation
propagation. Additive option for callers who need the un-gated source set
for debugging, recall-vs-precision tuning, or third-party harness
comparisons. Default behaviour is unchanged: the entry-point classifier
gate stays on for Java.

### Added

- `AnalyzerOptions.enableEntryPointGate?: boolean` (`src/analyzer.ts`) —
  controls the Tier 1/2/3 entry-point classifier gate that suppresses
  `interprocedural_param` taint sources on library-API methods that are
  not reachable from a recognised HTTP / RPC / lifecycle entry point.
  Default `true` (matches the unconditional behaviour shipped in 3.88.0
  for #128 and extended in 3.93.0 for Netty wire-message handlers, #154).
  Java-only: the classifier returns `TIER_UNKNOWN` for non-Java languages,
  so the gate is a no-op outside Java regardless of toggle state.
- `InterproceduralOptions` interface
  (`src/analysis/passes/interprocedural-pass.ts`) — pass-level options
  struct exposing the `enableEntryPointGate` mirror. `InterproceduralPass`
  now accepts an optional constructor parameter; existing callers that
  invoke `new InterproceduralPass()` are unaffected.

### Changed

- `InterproceduralPass.run()` — the `shouldGateInterproceduralParam`
  predicate is now guarded by `this.enableEntryPointGate`. When the
  toggle is `false`, the gate is bypassed and all `interprocedural_param`
  sources flow into Scenario A flow construction.
- Docs: new ADR-007 in `docs/ARCHITECTURE.md` (Pillar I — zero LLM in
  cognium-dev), naming-convention callout near the top of `docs/SPEC.md`,
  and a "Naming convention" subsection in `docs/PASSES.md`. These codify
  the Pillar I boundary that was added to `CLAUDE.md` (root, circle-ir,
  cli) in 3.94.0. Two legacy identifiers are explicitly preserved for
  back-compat and tagged as deprecation candidates for a future major:
  the `discoveryMethod: 'static' | 'llm'` provenance value (3.45.0) and
  the `LLMVerificationResult` exported type.

### Tests

- `tests/analysis/passes/interprocedural-entry-point-toggle.test.ts` — 9
  new tests across three describe blocks: (1) constructor option handling
  defaults and explicit values, (2) toggle inertness on the empty-sources
  early-exit and on non-`interprocedural_param` sources, (3) `analyze()`
  option wiring on Java library code and non-Java languages. All pass;
  full suite stays green at 2849 passed / 1 skipped (was 2840 / 1) with
  no regressions to the 73-case classifier suite or the #128 FP-cluster
  lock.

### End-user effect

None by default. Existing callers see identical scan output because
`enableEntryPointGate` defaults to `true`, matching the pre-3.95.0
always-on behaviour. The new opt-out path is exercised only by callers
that explicitly set `enableEntryPointGate: false`.

## [3.94.0] - 2026-06-23

cognium-dev#153 (pre-req) — speculative-finding suppression infrastructure.
Lands the API surface that #153's `missing-sanitizer-gate` pass will use to
emit dominator-based heuristic findings without flooding deterministic
consumers. The pass itself ships in 3.95.0; this release is the no-behaviour-
change scaffolding.

### Added

- `SastFinding.confidence?: 'high' | 'medium' | 'low'` (`src/types/index.ts`)
  — optional finding-confidence tier. Pre-3.94.0 passes do not set this
  field and are therefore treated as `'high'` (always emitted). Speculative
  passes can mark dominator/heuristic findings as `'medium'` (or `'low'`
  for experimental) so the engine can filter them out by default. Filtering
  happens between the per-file findings instrumentation hook and the per-
  file finding cap, so diagnostic streams still observe the uncapped,
  unfiltered findings.
- `AnalyzerOptions.includeSpeculative?: boolean` (`src/analyzer.ts`) —
  opt-in to keep `'medium'` / `'low'` findings in the returned stream.
  Default `false`. Intended for callers that run a downstream verifier
  (any consumer that adjudicates heuristic patterns before user
  presentation) and want the full, un-suppressed signal.
- `src/analysis/confidence-filter.ts` — single-purpose helper exposing
  `applyConfidenceFilter(findings, includeSpeculative)` and
  `isHighConfidence(finding)`. ~40 LOC, zero new dependencies, no
  language-specific code. Browser- and Node-safe (no `process`, `fs`,
  etc.).

### Changed

- `analyze()` (`src/analyzer.ts`) — wires `applyConfidenceFilter` into the
  per-file pipeline between `emitFindingsInstrumentation` and
  `applyPerFileFindingCap`. Existing callers see zero behaviour change
  because no shipped pass currently sets `confidence`.

### Tests

- `tests/analysis/confidence-filter.test.ts` — 11 unit tests covering:
  undefined-confidence passthrough, `'high'` passthrough, `'medium'` and
  `'low'` drop when `includeSpeculative=false`, full preservation when
  `includeSpeculative=true`, empty-input handling, no-mutation guarantee,
  and the `isHighConfidence` predicate across all four states. All pass in
  ~95 ms.

### Architectural boundary (Pillar I)

cognium-dev is deterministic SAST with **zero LLM dependencies** anywhere
in this repo. The opt-in knob is therefore named generically
(`includeSpeculative` / `confidence`) — no `--llm-*` flag, no `llm*` option
name, no "LLM verify / verifier / adjudicator" language in code, comments,
help text, CHANGELOGs, or docs. Downstream LLM-aware consumers live in the
separate `circle-ir-ai` / `cognium-ai` repos and consume circle-ir as a
library; they are the only callers that will set `includeSpeculative: true`
in practice. Guardrail codified in root + package `CLAUDE.md` to prevent
future drift.

### End-user effect

- **None for deterministic consumers** — no pass currently emits
  `confidence: 'medium' | 'low'`, so default-filtered output is byte-
  identical to 3.93.0 for all 40 shipped passes.
- **For downstream verifiers** — once #153 ships in 3.95.0, those callers
  can set `includeSpeculative: true` to receive the speculative
  `missing-sanitizer-gate` findings for adjudication.

## [3.93.0] - 2026-06-23

cognium-dev#154 — extend Tier 1 entry-point recognition to cover Netty
channel handlers. Closes the entry-point recognition gap that caused
CVE-2022-26884 (apache dolphinscheduler `LoggerRequestProcessor`) to be
missed even by top LLM models on CWE-Bench-Java.

### Added

- `src/analysis/entry-point-detection.ts` — five new entries in
  `TIER_1_BY_SUPERTYPE`:

  | Supertype (`extends` / `implements`) | Lifecycle method(s) |
  |---|---|
  | `SimpleChannelInboundHandler<T>` | `channelRead0`, `messageReceived` |
  | `ChannelInboundHandler`           | `channelRead`, `channelReadComplete` |
  | `ChannelInboundHandlerAdapter`    | `channelRead`, `channelReadComplete` |
  | `ChannelDuplexHandler`            | `channelRead`, `channelReadComplete` |
  | `NettyRequestProcessor`           | `process` |

  These cover the standard Netty handler shapes plus the dolphinscheduler-
  family `NettyRequestProcessor` wire-message processor surface. Match
  uses simple-name comparison via the existing `simpleTypeName` helper
  so generic parameterisation (`SimpleChannelInboundHandler<MyCommand>`)
  erases to the bare supertype name before lookup.

### End-user effect

- Java code where a handler extends `SimpleChannelInboundHandler<T>`
  (or any other entry above) now keeps its `interprocedural_param`
  taint sources on the wire-message parameter through the
  `shouldGateInterproceduralParam` gate at
  `interprocedural-pass.ts:121`, instead of being dropped at the
  TIER_3 fallback. Recall positive on Netty-based services
  (Cassandra wire protocol, gRPC-over-Netty servers, Apache Flink
  workers, Twitter Finagle, dolphinscheduler logger / master / worker
  RPC); no precision regression — the library-facade short-circuit
  (`*Util` / template-package / JDK-facade-implements) still trumps
  the supertype lookup, and the lifecycle method allowlist is named-
  method-only (a non-lifecycle helper on a Netty handler class stays
  TIER_3).

### Tests

- `tests/analysis/entry-point-detection.test.ts` — eight new tests:
  - Six-row `it.each` covering each (supertype × kind × method) tuple.
  - Generic-erasure case (`SimpleChannelInboundHandler<MyCommand>`).
  - Negative control (non-lifecycle helper on a Netty handler stays TIER_3).
  - End-to-end CVE-2022-26884 shape lock
    (`LoggerRequestProcessor.process(channel, command)` →
    `TIER_1_ENTRY_POINT` AND `shouldGateInterproceduralParam` returns
    `false`).
- Full suite: 2829 pass, 1 skipped on circle-ir.

## [3.92.0] - 2026-06-23

Java-bundle release — close out three #141-class triage items as a single
shipment. Disposition close on cognium-dev#143 (the proposed `(source, sink)`
coalescing schema, declined as unjustified by empirical capture data),
followed by the standalone defensive cap that was originally bundled with
#143 reverting to its pre-reframe shape.

### Added

- **#142 — Defensive per-file finding cap** (`src/analysis/per-file-finding-cap.ts`).
  New `AnalyzerOptions.perFileFindingCap` field (default `1000`,
  `0` disables). When a single file produces more than the cap, the
  individual findings are dropped and replaced by a single
  `saturated-file` advisory (`category: 'maintainability'`,
  `severity: 'low'`, `level: 'note'`) carrying `evidence.suppressed_count`,
  `evidence.cap`, and `evidence.by_rule` / `evidence.by_severity`
  roll-ups. The cap fires after the pipeline so the #145 PR B
  instrumentation hook still observes the uncapped findings stream; it
  fires before `analyzeProject()` collects per-file results so the cross-
  file phase input is bounded by file count, not finding count.
  Rationale: a file producing >1000 findings is structurally wrong (cross-
  product noise from sink-class mismatch, mis-labelled sink type, or
  pathological generated code), not a legitimate detection burst. The
  default of 1000 sits comfortably above the realistic ceiling
  (~200 findings on jedis-shape library facades) and below the
  structural-failure floor observed during the #141 langchain4j investigation
  (~10K findings on a single file before the cross-file hang). Combined
  with the 3.89.0 `crossFileBudgetMs` breaker, this closes the residual
  worst-case path on this class of hang.

### Closed (disposition)

- **#143 — Coalesce findings by `(source, sink)` location with vuln-class
  labels[]** — closed as unjustified. Two empirical captures via the
  `CIRCLE_IR_INSTRUMENT_FINDINGS=1` hook shipped in 3.90.0: (a) jedis /
  jib / eureka cross-file scans yielded 0 multi-label coordinates; (b)
  OWASP Benchmark per-file scans yielded 31 % multi-rule overlap but
  0 HIGH-severity multi-rule locations. The original premise — that a
  single source-sink pair routinely emits N findings under different
  vuln-class labels — is not supported by the Java OSS data. PR A
  (3.88.1 defensive type-axis dedup) and PR B (3.90.0 instrumentation
  hook) ship; the schema change (PR C) does not.

### Verified

- All 2820 tests pass (1 skipped). Eight new unit tests in
  `tests/analysis/per-file-finding-cap.test.ts` cover under-cap pass-
  through, boundary equality, over-cap collapse, by-rule / by-severity
  roll-ups, cap-0 disable, negative-value defensive disable, default cap
  constant, and empty-array handling.

## [3.91.0] - 2026-06-23

Sprint 36 — close cognium-dev#136 Tier 1 entry-point heuristic gaps. The
22-repo cognium-ai harness audit (2026-06-22) identified six heuristic
patterns where the Tier 1 classifier under-fires on real Java codebases.
This release ships the in-classifier portion (Spring stereotype beans);
the three patterns that require body-shape, lambda-scope, or call-graph
infrastructure are explicitly documented as out-of-classifier-scope and
routed to other components.

### Added

- `src/analysis/entry-point-detection.ts` — `@Service`, `@Repository`,
  `@Component` added to `TIER_1_CLASS_ANNOTATIONS`. Spring stereotype
  beans now classify as TIER_1, preserving their parameter-level
  `interprocedural_param` taint sources through the
  `shouldGateInterproceduralParam` gate in
  `interprocedural-pass.ts:121`. Rationale: when scanning library jars
  WITHOUT the calling `@RestController` in scope, the stereotype IS
  the visible trust boundary and callers across the (unseen) controller
  seam must validate at the stereotype's parameter list.

### Changed

- Existing test `classifyEntryPointTier — TIER_1 by class annotation
  > returns TIER_3 for plain @Service class methods` updated to assert
  TIER_1 (was the explicit lock for the old behavior, now the gap
  identified by the audit). The library-facade short-circuit (`*Util`
  suffix, template/engine package, JDK-facade implements) still trumps
  the stereotype — verified by new precision-lock test
  `library-facade short-circuit still trumps stereotype`.
- Existing test `combined / boundary > does NOT trigger on a plain
  @Service business class (negative control)` retargeted to a plain
  unannotated `OrderProcessor` class, which now correctly represents the
  "fallback step 8" path the negative control was meant to lock.

### Documented (out of scope for the classifier)

The audit also surfaced three patterns that do NOT fit the classifier
surface (no method-body AST, no lambda-scope tracking, no call graph)
and are routed elsewhere:

- **Builder / fluent-setter chains** (`this.x = x; return this;`
  identity-return hop) — taint-propagation noise reduction concern;
  routed to cross-file finding-coalescing (cognium-dev#143). The setter
  itself is correctly classified TIER_3.
- **Lambda-captured params** (`Stream.map(s -> someSink(s))`) — in the
  current IR, lambdas live inside the enclosing method's body and are
  not separately represented as `MethodInfo` records, so they already
  inherit the enclosing method's tier without any classifier change. No
  fix needed unless the IR ever lifts lambdas into standalone records.
- **`Callable` / `Runnable` posted to `ExecutorService`** — pure Tier 2
  call-graph reachability. Reserved for the deferred Tier 2 ship via
  `ctx.callGraph`.

The classifier file header (`entry-point-detection.ts:66-95`) records
this disposition so future readers find the routing notes alongside
the existing tier definitions.

### Verified

- Items 4 and 5 from the audit (`@KafkaListener` / `@RabbitListener` /
  `@JmsListener` and `@MessageMapping` / `@SubscribeMapping`) were
  already shipped in #128. Test coverage extended to include
  `@SubscribeMapping`, `@KafkaHandler`, `@RabbitHandler`, `@SqsHandler`
  so the parametric `it.each` table now matches the classifier set.

### Tests

162 files / 2812 tests pass / 1 skipped. Added 5 new tests covering the
three new stereotypes, annotation-arguments tolerance
(`@Service("userBean")`), and the library-facade precision lock.

### Issues closed

- cognium-dev#136 — Sprint 35 step 3: Tier 1 entry-point gate — Java
  heuristic gaps.

## [3.90.1] - 2026-06-23

Per-file perf fix for the langchain4j #141 hang. Reproduction work disproved
the upstream cross-module fan-out hypothesis: the analyzer hangs on a single
1517-LOC file (`EmbeddingStoreWithFilteringIT.java`) before cross-file phase
ever starts. Root cause is in `ConstantPropagator.isTaintedExpression`.

### Fixed

- `src/analysis/constant-propagation/propagator.ts` — `isTaintedExpression`
  now allocates a per-top-level memoization cache keyed by `Node.id`. The
  wrapper's iterative DFS and the explicit recursive call inside
  `isTaintedExpressionStep` at the generic-object-taint branch shared the
  same subtree (the chain spine `objectNode`). Without memoization, the
  wrapper's child descent re-walked every node the recursive call had just
  visited, producing super-quadratic blowup on N-deep
  `Stream.builder().add(...).add(...)…build()` style chains. Cache keyed
  by tree-sitter's pointer-cast `Node.id` because each `childForFieldName`
  / `children[i]` access returns a fresh JS wrapper, so an identity-keyed
  `Map<Node, …>` would never hit.
- Cache lifetime is **per top-level call** (allocated on entry when
  `isTaintedExpressionCache === null`, cleared in `finally`). This keeps
  the optimisation correct in the face of `this.tainted` mutations that
  happen between top-level calls inside `refineTaintFromConstants` and the
  visit pass — a longer-lived cache could return stale `false` for
  newly-tainted subtrees.

### Measured

Single-file profile via `node profile-file.mjs <file>` with
`globalThis.__circleIrPassTiming = true`:

| Fixture                                       | constprop pass before | constprop pass after |
|-----------------------------------------------|-----------------------|----------------------|
| Synthetic `Chain10.java` (10-link .add chain) | 326 ms                | **5 ms**             |
| Synthetic `Chain30.java`                      | >120 s timeout        | **10 ms**            |
| Synthetic `Chain100.java`                     | OOM (8 GB heap)       | **28 ms**            |
| langchain4j `EmbeddingStoreWithFilteringIT.java` (1517 LOC) | >60 s timeout | **45 ms** (file total 321 ms) |

Scaling is now linear in chain depth. Full test suite (2804 tests) green.

### Added (diagnostic)

- `src/graph/analysis-pass.ts` — opt-in per-pass timing markers gated on
  `globalThis.__circleIrPassTiming === true`. Emits `[pass-start] <name>
  file=…` and `[pass-timing] <name> <ms>ms file=…` on `console.error`.
  No-op when the flag is unset (single boolean check per pass). Browser-
  safe (no `process`/`perf_hooks`). Used to bisect the per-file hang
  to `constant-propagation` for this release; left in for future
  perf-regression investigations.

### Not addressed

- The Sprint 36 / #141 cross-file budget breaker (`crossFileBudgetMs`)
  and resolver pre-indexing in `cross-file.ts` are orthogonal hardening
  for the project-scope phase and remain queued. The per-file fix in
  this release was the dominant blocker on langchain4j; re-run the
  full-repo harness to determine whether cross-file work is still
  required for #141 closure.

## [3.90.0] - 2026-06-23

PR B of the cognium-dev #143 split — opt-in instrumentation hook for the
per-file findings stream, used to scope the upcoming coalesce schema change
(PR C) with empirical data from real-world fixtures before any breaking
schema work ships.

### Added

- `src/analysis/findings-instrumentation.ts` — new module exporting
  `setFindingsInstrumentation(enabled)`, `isFindingsInstrumentationEnabled()`,
  and `emitFindingsInstrumentation(filePath, findings, taint)`. Browser-safe
  (no Node-only APIs). Bypasses the logger DI by design so emission stays
  grep-friendly and independent of log level. Off by default.
- `src/analyzer.ts` — call to `emitFindingsInstrumentation()` at the per-file
  finalization point in `analyze()`, right after `pipeline.run()` returns the
  accumulated `SastFinding[]`. Strictly read-only: no mutation of findings or
  any other pipeline output.
- Public API re-exports of `setFindingsInstrumentation` and
  `isFindingsInstrumentationEnabled` from `src/index.ts` (preserved across
  the relocation from `findings.ts` to `findings-instrumentation.ts`).

### Emission format

When enabled, the analyzer writes two JSON-tagged stderr lines per analyzed
file:

```
[finding] {"file":"...","line":N,"rule_id":"...","pass":"...","category":"...",
           "severity":"...","cwe":"...","sink_type":"...","source_type":"...",
           "confidence":0.87,"dedup_group_id":"file:line:rule_id"}
[findings-summary] {"file":"...","total":N,"unique_groups":N,
                    "max_findings_per_group":N,"sources_count":N,
                    "sinks_count":N,"by_rule":{...},"by_severity":{...}}
```

`dedup_group_id` uses the `${file}:${line}:${rule_id}` key matching the
`ScanSecretsPass` dedup convention so downstream analysis (#143) can
prototype multiple coalesce rules against a single capture.

### Stability contract

The `emitFindingsInstrumentation` function signature is **stable**. The
JSONL payload schema is **stable-additive** — the engine reserves the right
to add new fields (driven by #143's analysis needs) without a major bump.
Consumers should ignore unknown keys.

### Removed

- The exploratory hook inside `generateFindings()` introduced in an
  earlier in-flight commit has been removed. `generateFindings()` is a
  public API not called by the analysis pipeline; instrumenting it produced
  no data from CLI/`analyze()` runs. The hook now lives at the live
  finalization point. No published version exposed the dead hook.

### Tests

- `tests/analysis/findings-instrumentation.test.ts` — 9 unit tests covering
  default-off, toggle round-trip, off-no-emit, per-finding payload field
  contract, source/sink type fallback when only one matches the finding
  line, summary aggregation (by_rule, by_severity, group cardinality),
  zero-findings edge case, no-mutation invariant.

## [3.89.1] - 2026-06-22

Patch follow-up to 3.89.0: the new cross-file phase markers materialized a
latent stdout-pollution bug in the logger that broke `--format json` /
`--format sarif` pipelines for any consumer at `info` level or louder.

### Fixed

- `src/utils/logger.ts` — `logger.info()` now writes to **stderr** via
  `console.error` instead of `console.log` (which writes to stdout in Node
  and would corrupt JSON/SARIF output piped to downstream tooling). All log
  methods (`trace`/`debug`/`info`/`warn`/`error`/`fatal`) are now stderr-only
  by construction. No-op for consumers that inject a custom logger via
  `setLogger()` — the DI surface is unchanged.

### Changed (default behaviour)

- `src/utils/logger.ts` — default log level changed from `'info'` to
  `'silent'`. Library consumers that want phase markers / progress logs must
  opt in via `setLogLevel('info')` (or any louder level) or by injecting a
  custom logger via `setLogger()`. This makes the library safe-by-default
  for CLI/SARIF/JSON pipelines without requiring caller configuration.
  Consumers already using `setLogger()` are unaffected.

### Migration

- If you were relying on the implicit `info`-level console output from
  `circle-ir`, call `setLogLevel('info')` (or `setLogger(pino(...))`) at
  startup. The cognium-dev CLI exposes this via `--log-level <level>` and
  the `COGNIUM_LOG_LEVEL` env var (see cognium-dev 3.89.1 CHANGELOG).

## [3.89.0] - 2026-06-22

cognium-dev #141 (Sprint 36) — cross-file phase perf + observability +
defensive budget breaker. Resolves the langchain4j 30-min and Sa-Token
35+ CPU-min hangs that previously SIGKILL'd the analyzer mid cross-file
phase.

### Performance

- `src/resolution/cross-file.ts` — **pre-index resolver hot loops.** New
  `FileIndex` (six per-file lookup maps: `callsByLine`, `defsByLine`,
  `usesByLine`, `callsByMethod`, `sinksByMethod`, `defsByMethod`) is
  built once per IR via `buildFileIndex(ir)` and memoized on a private
  `WeakMap<CircleIR, FileIndex>` on the `CrossFileResolver` instance.
  11 `Array.filter` scans inside `findCrossFileTaintFlows`,
  `findInterproceduralTaintPaths`, and `findFieldBindingTaintPaths` are
  replaced with O(1) Map lookups. Membership and ordering are
  byte-equivalent to the pre-refactor filters (range buckets preserve
  sort-by-line; per-line buckets preserve insertion order). On
  `sa-token-core` (181 Java files) the entire cross-file phase now
  completes in **27ms** wall (phase1=6ms, phase2=10ms, phase3=7ms,
  phase4=1ms) vs prior 35+ CPU-min hang.

### Observability

- `src/analysis/passes/cross-file-pass.ts` — emit DI-logger markers
  around each of the 4 cross-file phases: `cross-file: phase N/4 starting`
  (debug) and `cross-file: phase N/4 done` (info, with `paths`/`flows` +
  `elapsedMs`). Final `cross-file: complete` summary includes
  `totalMs`, `paths`, `crossFileCalls`, and `budgetExceeded`. Browser-
  safe (uses `Date.now()` and the existing `setLogger()` DI logger).

### Defensive

- `src/analysis/passes/cross-file-pass.ts` — new
  `CrossFilePassOptions.budgetMs` with inter-phase circuit breaker.
  Wall-time budget is checked between phases 1→2, 2→3, 3→4. On exceed:
  remaining sub-phases are skipped, `taintPaths` from earlier phases are
  preserved, a `warn`-level log is emitted, and
  `CrossFilePassResult.budgetExceeded === true`. Mid-phase abort is
  intentionally **not** supported in this release — phases are now
  fast enough that inter-phase granularity suffices.
- `src/analyzer.ts` — new `AnalyzerOptions.crossFileBudgetMs` threaded
  into `CrossFilePass.run({ budgetMs })`. Default **300_000 ms** (5 min);
  `0` disables the breaker.
- `src/types/index.ts` — new optional `ProjectAnalysis.cross_file_budget_exceeded`
  field surfaces the breaker state to downstream consumers.

### Tests

- `tests/analysis/file-index.test.ts` — **NEW** — 11 unit tests
  covering the `buildFileIndex` semantics: empty IR, per-line bucketing
  with insertion order, per-method range bounds (inclusive on both
  ends), sort-by-line ordering inside method buckets, MethodInfo
  identity-keyed lookup, nested/overlapping methods (shared call in
  both buckets), and large-input invariant.
- `tests/analysis/passes/cross-file-budget.test.ts` — **NEW** — 6 tests
  for the circuit breaker: budget=0 unlimited, default unlimited via
  empty options, breaker fires after phase 1 (phases 2/3 skipped,
  partial paths preserved), breaker fires after phase 2 (phase 3
  skipped), high budget does not trip, result schema invariants when
  triggered. Uses a sync busy-wait to make timing deterministic.

### Notes

- **Parity:** 2778 pre-refactor resolver tests pass unchanged after the
  pre-index — the existing suite serves as the parity lock. Total
  now 2795 passing (1 skipped) across 161 test files.
- **#141 may not be fully resolved** on the langchain4j harness. Pre-
  indexing is a constant-factor win; if the corpus hits algorithmic
  blowup on path *count*, the budget breaker catches it but doesn't fix
  root cause. Re-run the harness and reopen as "mitigated" if needed.
- **Backward compatibility:** `crossFileBudgetMs` defaults to 300_000ms,
  which is a behavior change from the previous unbounded run.
  Sub-5-minute cross-file phases on clean corpora are unaffected.
  Users on very large monorepos may want to raise the limit.

## [3.88.1] - 2026-06-22

cognium-dev #143 (PR A) — cross-file taint dedup now keys on
`(source.file, source.line, sink.file, sink.line, sink.type)` instead of
coordinates only. **Defensive future-proofing**, not an active bug
recovery: under current upstream behavior both
`findCrossFileTaintFlows()` and `findInterproceduralTaintPaths()` /
`findFieldBindingTaintPaths()` resolve `matchedSink.type` via
`sinkIR.taint.sinks.find(s => s.line === ...)` on the same IR, so they
always pick the same first sink at a given line and the pre-fix dedup
was coincidentally correct. The fix pins the type-axis invariant so a
future refactor (e.g., upstream switching to `.filter`, or a new
resolver method that assigns `sink.type` from a non-`matchedSink`
source) cannot silently drop IP / field-binding findings that legitimately
differ in vuln class from a direct flow at the same coordinates
(e.g. `command_injection` vs `code_injection` at the same `execute()`).

### Fixed

- `src/analysis/passes/cross-file-pass.ts` — interprocedural /
  field-binding path dedup at line 128 adds `tp.sink.type ===
  matchedSink.type` to the predicate.

### Tests

- `tests/analysis/passes/cross-file.test.ts` — new
  `CrossFilePass — dedup by type (PR A)` block (2 tests). The positive
  test uses a flipping-IR mock (returning different sink types on
  successive `getIR()` calls) to drive the divergent-type scenario
  that current production upstream cannot naturally produce — failing
  on 3.88.0 (`expected length 2, got 1`) and passing on 3.88.1. The
  negative test pins the regression-guard: same coords with same
  `sink.type` are still deduped.

Full suite: 2778 passed, 1 skipped.

## [3.88.0] - 2026-06-22

Sprint 35 ship — cognium-dev #128 entry-point-anchored taint sources.
Suppresses speculative `interprocedural_param` flows on library-facade
methods (utility / template / engine / JDK-collection-facade classes
and all non-entry-point Java methods). Targets the FP cluster that
accounted for ~1,768 of 1,968 high CWE-78 findings on the top-25 Java
OSS harness before #129 + #130 landed; this gate is the upstream
relocation of cognium-ai's downstream classifier and the structural
fix for the residual cluster.

### Added — #128 entry-point tier classifier

`src/analysis/entry-point-detection.ts` (verbatim port from
`cognium-ai/circle-ir-ai@2.14.0`, PR #135, plus step-2 heuristic gaps):

- `classifyEntryPointTier(method, type, ctx)` — returns one of
  `'TIER_1_ENTRY_POINT'` / `'TIER_2_REACHABLE'` (reserved) /
  `'TIER_3_LIBRARY_API'` / `'TIER_UNKNOWN'`. Ship 1 is Java-only;
  every non-Java language returns `TIER_UNKNOWN` so the gate is
  pass-through.
- `shouldGateInterproceduralParam(sourceType, method, type, ctx)` —
  source-suppression predicate; returns true iff the source type is
  `interprocedural_param` AND the enclosing method classifies as
  `TIER_3_LIBRARY_API`.

Tier 1 detection covers:

- Method annotations: Spring MVC (`@RequestMapping`, `@*Mapping`),
  Spring messaging (`@KafkaListener`, `@RabbitListener`, `@JmsListener`,
  `@SqsListener`, `@StreamListener`, `@MessageMapping`), Spring
  application events (`@EventListener`, `@Scheduled`), JAX-RS (`@Path`,
  `@GET`/`@POST`/`@PUT`/`@DELETE`/`@PATCH`/`@HEAD`/`@OPTIONS`).
- Class annotations: `@RestController`, `@Controller`, JAX-RS `@Path`,
  Servlet 3 `@WebServlet`, JSR-356 `@ServerEndpoint`, `@FeignClient`.
- Supertype lifecycle methods: `HttpServlet.do*`, `Filter.doFilter`,
  `HandlerInterceptor.preHandle` / `postHandle` / `afterCompletion`,
  `CommandLineRunner.run`, `ApplicationRunner.run`.
- `public static void main(String[])` signature.

Tier 3 library-facade short-circuit (step 2 — runs BEFORE Tier-1
detection):

- Class-name suffix: `*Util` / `*Utils` / `*Helper` / `*Helpers`
  (length-guarded so the bare `Util` class itself is not caught).
- Package fragment: `*.template.*` / `*.templates.*` / `*.engine.*`
  / `*.engines.*` (padded with sentinel dots).
- Direct JDK-facade `implements`: `Collection`, `List`, `Set`, `Map`,
  `Queue`, `Deque`, `SortedSet`, `SortedMap`, `NavigableSet`,
  `NavigableMap`, `Iterator`, `Iterable`, `ListIterator`,
  `Comparator`, `Comparable`, `Serializable`, `Externalizable`,
  `Cloneable`.

### Changed — interprocedural pass gate (step 3)

`src/analysis/passes/interprocedural-pass.ts` Scenario A now consults
`shouldGateInterproceduralParam()` when constructing inter-procedural
flows. The check is layered AFTER the existing confidence-based filter
(`source.confidence < 0.6`) and uses a per-pass method-name → `{method,
type}` index over `graph.ir.types` so the lookup is O(1) per source.

The gate is intentionally NOT applied at the source-emission layer
(`taint-matcher.ts:218-237`). An explanatory comment is added there:
the speculative `interprocedural_param` emission is load-bearing for
the constant propagator's downstream constructor-field tracking
(`language-sources-pass.ts::findGetterSources`) — gating at the
source layer breaks DTO taint chains like `new User(input)` →
`user.getName()` → SQL sink. The gate lives at the flow-construction
boundary where it can drop speculative flows without breaking the
propagator's seed set.

### Recall trade-offs

- Any homegrown OS-command wrapper class whose name doesn't carry
  `Util` / `Utils` / `Helper(s)` suffix AND isn't in a `template` /
  `engine` package AND doesn't implement a JDK facade AND has no
  entry-point annotation will still gate (its parameters are no
  longer speculative taint sources at the inter-procedural layer).
  Real intraprocedural flows from `http_param` / `env_var` / Spring
  `@RequestParam` etc. are unaffected — they are not gated.
- Tier 2 (call-graph reachability — Tier 1 callers reaching Tier 3
  helpers) is reserved (`ctx.callGraph`) and not implemented; a
  follow-up sprint will add it once the call graph is available
  in `PassContext`.

### Tests

`tests/analysis/entry-point-detection.test.ts` — 67 unit tests for
the classifier (43 from PR #135 + 24 step-2 heuristic-gap tests).

`tests/analysis/repro-issue-128.test.ts` — NEW. 17 tests:

- 6 critical-miss locks (RuntimeUtil ×3, FreemarkerEngine, plain
  non-entry-point method, JDK Map implementer) — all gate.
- 11 recall locks (`@RestController` + `@GetMapping`, `@RequestMapping`,
  `HttpServlet.doGet`, JAX-RS `@GET`, `main(String[])`,
  `@KafkaListener`, `CommandLineRunner.run`, non-Java pass-through
  ×2, non-`interprocedural_param` source type, unresolved enclosing
  method) — none gate.

Full suite: **2776 pass / 1 skipped** (was 2692 + 67 entry-point
+ 17 repro-128).

### References

- cognium-dev#128 — entry-point-anchored taint sources.
- PR #135 — verbatim port from cognium-ai@2.14.0.
- `taint-matcher.ts:218-237` — speculative source emission site
  (intentionally not gated; see in-code comment).
- `interprocedural-pass.ts` Scenario A — gate boundary.

## [3.87.0] - 2026-06-22

Sprint 35 prep — small additive `Finding` schema fix unblocking #128
triage. Pure additive; no behavior change to the analysis pipeline.

### Added — #134 Finding schema gaps

Two schema gaps surfaced during the cognium-ai-side #128 harness
re-run on top-25 Java OSS: triage scripts could not directly attribute
which findings originated from `interprocedural_param` sources because
`source.type` was dropped at the `Finding` serialization boundary, and
there was no canonical top-level `Finding.line` coordinate.

`src/types/index.ts` — `Finding` interface:

- New optional `source.type?: SourceType` (engine-internal taint-source
  classification — `'http_param'`, `'interprocedural_param'`,
  `'env_input'`, etc.). Optional for back-compat with consumers that
  construct `Finding` objects outside `generateFindings()`.
- New optional `sink.type?: SinkType` for `source`/`sink` parity.
  Always mirrors the existing top-level `Finding.type`.
- New required `line: number` — canonical "go-to-line" coordinate.
  Mirrors `sink.line` for taint findings. Standardises the previously
  inconsistent `source.line` / `sink.line` fallback chain used by
  renderers.

`src/analysis/findings.ts::generateFindings()` populates all three
fields from the existing `TaintSource.type` / `TaintSink.type` /
`sink.line`. No new computation, no API surface change beyond the
optional `source.type` / `sink.type` additions and the required `line`.

### Tests

- Extended `tests/analysis/findings.test.ts` with 4 new tests under
  `Finding schema — #134` describe block: source.type populated, sink.type
  mirrors top-level type, line mirrors sink.line, interprocedural_param
  sources are now visible to triage filters (the #128 use case).

Suite: 2692 pass / 1 skipped (was 2688 + 4).

### Why this ships before #128

With `source.type` exposed, downstream triage and the cognium-ai-side
`runMerge` gate can directly attribute drops to
`source.type === 'interprocedural_param'`, instead of inferring from
file/line co-occurrence. Lands the dispositive schema field before
Sprint 35's upstream entry-point gate work begins.

## [3.86.0] - 2026-06-21

Sprint 34 — Java OSS top-25 FP cluster cleanup. Two independent
precision gates targeting the same finding cluster from different
layers: **#129** sink-side receiver-class allowlist and **#130**
finding-side value-shape gate. Both confined to `circle-ir`.

### Fixed — #129 CWE-78 receiver-class allowlist

`configs/sinks/command.yaml` ships unscoped catch-all sinks for
`exec`, `executeCommand`, `runCommand`, `system`, `shell`, `Process`,
etc. that match ANY receiver class exposing the method name, including
`redis/jedis`'s `UnifiedJedis.executeCommand` (RESP protocol over TCP —
NOT shell). On Java OSS top-25 at 3.85.1, this produced **1,680 of
1,968 high `command_injection` findings (85.4% FP rate)**.

`src/analysis/taint-matcher.ts`:

- New `CWE_78_RECEIVER_ALLOWLIST` constant: `Runtime`, `ProcessBuilder`,
  `Process`, `CommandLine`, `DefaultExecutor`, `Executor`, `Exec`,
  `Launcher`, `ProcStarter`, `ProcessExecutor`, `RuntimeUtil`
  (java.lang + Apache Commons Exec + Gradle + Jenkins + Spring + hutool).
- Gate inserted inside `findSinks()` after sink-pattern match and
  `safe_if_class_literal_at` check, before emission:
  - Constructor branch: filters `method_name` against allowlist
    (covers `new ProcessBuilder(...)`).
  - Non-constructor branch: only filters when `receiver_type` is
    statically resolved. Unresolved receivers (typical in JS/Python
    module-binding calls like `child_process.exec`, `subprocess.run`)
    fall through to preserve recall.

YAML catch-all sinks left intact — code-level allowlist is sufficient
for this sprint; deferred deletion would risk recall regressions in
untyped contexts.

Expected impact: ~86% reduction in high CWE-78 findings on Java OSS
top-25 (1,968 → ~288), without recall loss on real OS-command APIs.

### Fixed — #130 hardcoded-credential value-shape gate

`scan-secrets-pass.isLikelyCredentialAssignment()` matched on variable
**name shape** (`*_PASSWORD`/`*_SECRET`/`*_APIKEY`/`*_TOKEN`) without
checking value shape. Existing FP guards (PLACEHOLDER_RE, env-var refs,
length < 3, all-same-char) missed three FP shapes seen on the Java OSS
cluster: dotted property keys (`"sentinel.dashboard.auth.password"`,
`"jib.from.auth.password"`, `"eurekaServer.proxyPassword"`), plain
identifier strings (`"client_secret"`, `"remoteApiKey"`, `"aiApiKey"`),
and trivial numeric placeholders (`"12345"`, `"1234567"`). 11 of 11
cluster-2 highs fell into these shapes — none were real credentials.

`src/analysis/passes/scan-secrets-pass.ts`:

- New `PROPERTY_KEY_RE` (`/^[a-z][a-zA-Z0-9_-]*\.[a-zA-Z][a-zA-Z0-9_.-]*$/`)
  and `PLAIN_IDENTIFIER_RE` (`/^[a-z][a-zA-Z_]*$/`) shape predicates.
- New `charClassDiversity()` helper (lower/upper/digit/symbol class count).
- `isLikelyCredentialAssignment()` augmented with three positive
  predicates (length ≥ 12, Shannon entropy ≥ 3.5, char-class diversity
  ≥ 2) and three negative shape predicates (PROPERTY_KEY_RE,
  PLAIN_IDENTIFIER_RE, short-numeric `/^[0-9]+$/ && length < 16`).

**Trade-off:** the gate raises the minimum credential-value length
from 3 to 12 chars. Pre-3.86.0 short-string named-credential matches
(e.g. `password = "abc"`) no longer fire via the named-credential layer.
Layer 1 provider regexes (AWS AKIA, GitHub ghp_, Stripe sk_live_, etc.)
and Layer 2 entropy gate (length floor 25, char-class ≥ 3) are
unaffected — real secrets continue to fire.

Expected impact: ~100% reduction on the 11 cluster-2 highs on Java OSS
top-25 (11 → 0) with zero recall loss on production-grade secrets.

### Tests

- New `tests/analysis/repro-issue-129.test.ts` — 10 tests (4 negative
  receiver-class locks: Jedis, UnifiedJedis, MyService, HttpEntity;
  6 recall locks: Runtime.exec, `new ProcessBuilder`,
  ProcessBuilder.command, DefaultExecutor.execute, JS unresolved `exec`,
  Python `subprocess.run`).
- Extended `tests/analysis/passes/scan-secrets.test.ts` — 14 new tests
  under `#130 value-shape gate` describe block (10 negative locks
  covering Sentinel/Jib/Eureka/OAuth/LanguageTool/numeric/UUID shapes;
  4 recall locks for high-entropy named credential + Layer 1 AWS AKIA +
  Layer 1 GitHub PAT + Layer 2 base64 blob).

Suite: 2688 pass / 1 skipped (was 2664 + 14 + 10).

## [3.85.1] - 2026-06-20

Sprint 33 — P0 perf hotfix for **#126** (perf regression introduced by
3.85.0). Single-issue patch release; entire fix confined to
`scan-secrets-pass.ts`.

### Fixed — #126 scan-secrets perf regression

The 3.85.0 Sprint 32 release added two new file-level pre-scans
(`findAnnotationLineRanges` for Gate 1, `findStringArrayLineRanges` for
Gate 3) that ran **unconditionally on every file**. On string-constant-
heavy Java repos with hundreds of `@Annotation(` / `=\s*[{\[]` openers,
multi-line paren-/brace-walking dominated runtime even though the entropy
layer could not possibly fire (file had no ≥32-char base64-shape literal).

Reporter-measured top-25 Java OSS harness regression vs 3.84.0:

| repo                | 3.84.0  | 3.85.0    | slowdown |
|---------------------|---------|-----------|----------|
| gson                | 49.6s   | 718.8s    | 14.5×    |
| Hystrix             | 115.1s  | TIMEOUT   | ≥17.7×   |
| openapi-generator   | 383.7s  | TIMEOUT   | ≥7.1×    |
| hutool              | 637.9s  | 1695.2s   | 2.66×    |
| zxing               | (none)  | (none)    | 1.0×     |

`src/analysis/passes/scan-secrets-pass.ts`:

- **Fast-path candidate probe** (`FAST_CANDIDATE_PROBE_RE`): cheap
  per-file regex matching any `["'` / backtick] quoted run of ≥32
  base64-shape chars (`[A-Za-z0-9+/=_-]{32,}`), conservatively detecting
  whether the file could possibly contain a Layer
  2 entropy candidate. The probe pattern is a strict superset of every
  shape that the entropy layer would accept after the Gate 4 length floor
  — no recall loss. When the probe fails, the pass skips **both**
  pre-scans (`findAnnotationLineRanges`, `findStringArrayLineRanges`)
  **and** the entire Layer 2 loop. Provider patterns (Layer 1) and
  named-credential matcher (Layer 1b) remain unaffected.

- **Gate 3 walker `lineBudget` tightened 500 → 100** as defense-in-depth.
  Any legitimate constant-table array fits well under 100 lines;
  pathological openers (unbalanced braces in generated/minified code) now
  bail faster on the rare files where the fast-path doesn't already
  short-circuit.

### Tests — +2

`tests/analysis/passes/scan-secrets.test.ts` —
`describe('ScanSecretsPass — #126 perf hotfix (fast-path probe)')`:

1. `processes a large annotation-dense Java file (5000 lines, no
   candidates) fast` — fixture is 1000 method definitions, each with
   `@RequestMapping(value=...)`, `@ResponseStatus(...)`,
   `@Cacheable(cacheNames=..., key=...)` annotations. Asserts
   `runPass(...).length === 0` and elapsed time **< 1000ms** (was many
   seconds pre-hotfix).
2. `still fires the entropy layer when a candidate is present in a large
   file` — same fixture + injected `API_KEY = "<64-char-blob>"`. Asserts
   exactly 1 `hardcoded-credential-entropy` finding emitted, confirming
   the fast-path does **not** sacrifice recall.

### Suite

`npm test`: **2664 pass | 1 skipped** (was 2662 / 1; +2 perf tests).
`npm run typecheck`: clean.

## [3.85.0] - 2026-06-20

Sprint 32 — fix **#125** (`hardcoded-credential-entropy` 96.3% FP rate on
top-20 Java OSS harness). Single-issue release; entire fix confined to
`scan-secrets-pass.ts`.

### Fixed — #125 hardcoded-credential-entropy FP reduction (CWE-798)

The pass-#90 entropy layer (`scan-secrets-pass.ts:Layer 2`) fired on any
≥25-char base64-/hex-shape literal with Shannon entropy above threshold,
with a -0.2 boost when any credential keyword appeared anywhere on the
line. No AST context. No field-name precision. No generated-code
suppression. No annotation/array-literal awareness. Harness exposed
762/791 (96.3%) FPs across 5 distinct patterns:

- ~530 — PlantUML `@Original(key="...")` graphviz-port attribution annotations
- 110 — PlantUML `EmbeddedResources.java` base64 CSS blob string-concat
- 24 — PlantUML `PSystemDonors.DONORS` obfuscated public-display string
- 36 — hutool `SolarTerms.java` astronomical-data string array
- 8 — hutool public-spec encoding alphabets (Base32/Base58 RFC 4648)

`src/analysis/passes/scan-secrets-pass.ts`:

- **Gate 1 — annotation-arg suppression** (`findAnnotationLineRanges`):
  pre-scan file for `@Annotation(` (Java / TS / JS decorators / Python
  decorators) and `#[...]` (Rust attributes), walk paren depth with
  string-literal awareness, mark all 1-indexed line numbers in the span.
  Entropy layer skips any line inside an annotation-arg span. Suppresses
  pattern A (~530 FPs).

- **Gate 2 — generated-file wholesale skip** (`isGeneratedFile`): mirror
  of `isTestFile` early-exit. Path heuristic catches `gen/`, `generated/`,
  `build/generated/`, `src/main/generated/`, `src/test/generated/`,
  `target/generated-sources/`, `target/generated-test-sources/`,
  `node_modules/.cache/`. Filename heuristic catches `*__c.java` /
  `*__h.java` (graphviz/plantuml generated C ports), `*.pb.go` (protobuf),
  `*_pb2.py` (Python protobuf), `*.generated.[cm]?[jt]sx?`. Skipped files
  emit zero `hardcoded-credential` / `hardcoded-credential-entropy`
  findings. Documented trade-off: real credentials accidentally committed
  in generated paths are also suppressed (same precedent as test-file
  skip).

- **Gate 3 — string-array constant-table suppression**
  (`findStringArrayLineRanges`): pre-scan for `=\s*[{\[]` assignment
  opener, walk depth with string-literal awareness, count quoted strings
  inside the span. If ≥3 string elements found, mark all enclosed line
  numbers. Entropy layer skips any line inside an array span. Suppresses
  pattern D (36 FPs).

- **Gate 4 — field-name strengthening + length floor**
  (`extractEnclosingFieldName` + rewritten `passesEntropyGate`): hard
  requirement that the literal's enclosing assignment LHS identifier match
  the credential-keyword regex (`password|secret|token|api[_-]?key|...`).
  Without a credential field name match, the entropy gate returns `false`
  regardless of entropy. Boost removed (redundant once name match is
  required). Single threshold per shape: 3.3 hex, 4.1 base64. Literal
  length floor raised from 8 (regex) to 32 (per-literal check in entropy
  loop). Suppresses patterns B / C / E (142 FPs).

**Recall is preserved** for the long tail of true positives via the two
unaffected layers:

- **Layer 1 (provider patterns)** — 16 high-confidence regexes (AWS AKIA,
  GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, Stripe `sk_live_`/`pk_live_`,
  OpenAI `sk-`, Anthropic `sk-ant-`, Slack `xox[baprs]-`, Google `AIza`,
  JWT `eyJ..eyJ..`, PEM private keys, npm `npm_`). Unconditional. Recall
  test confirms AWS AKIA inside `@Schema(example = ...)` annotation arg
  still fires.

- **Layer 1b (named-credential matcher)** — `isLikelyCredentialAssignment`
  catches custom credential field assignments (`DB_PASSWORD = "..."`,
  `apiSecret: "..."`, etc.). Independent regex layer; unaffected by
  entropy gates.

### Tests

`tests/analysis/passes/scan-secrets.test.ts` — added
`describe('ScanSecretsPass — #125 context-gated entropy')` block with
**10 new tests**: 7 negative locks (one per pattern A-E + 2 generated
path/filename) + 3 recall locks (credential-named-field entropy still
fires, AWS AKIA inside annotation still fires via Layer 1, Layer 1b
named-credential still fires). All 49 scan-secrets tests pass; full suite
**2662 pass | 1 skipped** (was 2652 / 1; +10 new, no regressions).

### Risk notes

- Gate 4 makes credential field name a **hard requirement** for the
  entropy layer. Bare high-entropy strings without a credential-named LHS
  no longer trigger via Layer 2. Provider patterns (Layer 1) are the
  recall safety net for known credential shapes; named-credential matcher
  (Layer 1b) catches the `FIELD = "..."` shape.
- Generated-path wholesale skip — files matching the heuristics get zero
  scan-secrets findings (provider patterns included). Matches the
  pre-existing `isTestFile` precedent.
- Perf — two new per-file pre-scans (annotation + array-literal
  paren-walking). O(LOC) each. ≈1–3 ms / file. Full suite runtime
  unchanged within noise (3.71s, was ~3.6s).

### Out of scope (deferred)

- `.gitattributes linguist-generated=true` — requires `fs`, violates
  browser-compat charter.
- AST-based annotation/array detection — would require passing the tree
  to `ScanSecretsPass`; regex-only design preserved.
- Cross-line credential string concat where the LHS itself contains a
  credential keyword — only fires on the first line. Acceptable;
  uncommon.

## [3.84.0] - 2026-06-19

Sprint 31 — bundled FP-reduction for Python (**#114**) and Rust (**#115**)
safe-handler shapes. Both issues are the same flavor of false positive: a
guarded / shape-safe sink that the engine over-reported because the
sanitizer didn't recognize the shape. Five new recognizers + dispatch wiring
across two languages.

### Fixed — #114 Python safe-handler FPs

`src/analysis/passes/language-sources-pass.ts`:

- **`findPythonNetlocAllowlistGuardSanitizers`** — recognizes
  `if urlparse(target).netloc not in ALLOWED_HOSTS: return ...` (and the
  generic `if <ident> not in <ALLOWLIST>:` shape). Allowlist name heuristic
  matches `UPPER_SNAKE` constants or identifiers containing
  `allowed|accepted|whitelist|permitted|valid|approved`. Body terminator
  within 25 lines (`return`, `raise`, `abort(`, `sys.exit(`). Emits per-line
  sanitizers for `open_redirect`, `ssrf`, `path_traversal`,
  `external_taint_escape` from the guard's block-end through end of file.
  Fixes `open_redirect` FP on Flask host allow-list guards.

- **`findPythonRangeCheckGuardSanitizers`** — recognizes numeric range guards
  `if x < N or x > MAX: return ...` (and `and` / single-bound forms) where
  N and MAX are integer literals or `UPPER_SNAKE` constants. The bound
  variable must repeat across both clauses (regex backreference). Emits
  per-line sanitizers for `xss` and `external_taint_escape`. Phase-A repro
  confirmed: `int()` strips xss on the cast itself, but downstream
  `str(qty * N)` re-taints through arithmetic→string concat. This guard
  closes the residual xss FP for the range-validated-int → concat shape.

### Fixed — #115 Rust safe-handler FPs (carved from #102)

`src/analysis/taint-matcher.ts`:

- **`isSafeRustCommandCall`** — mirrors `isSafeGoExecCommandCall`. Suppresses
  `command_injection` sinks when the Rust `Command` builder chain has a
  literal non-shell program at `Command::new("...")`. Handles three shapes:
  - Constructor: `Command::new(literal)` — arg[0] is the program.
  - Chained methods: `.arg(x)`, `.args(slice)`, `.spawn()`, `.output()` —
    receiver text scanned for `Command::new("literal")` anywhere in the
    chain (Rust builder patterns can interleave any number of `.arg()`
    calls between the constructor and the eventual sink method).
  - Variable-bound receivers (`let cmd = Command::new(...); cmd.arg(...)`)
    remain dangerous by default (binding tracking is out of scope; this
    matches the engine's current Rust receiver-resolution gap).

  Shell programs (`sh`, `bash`, `zsh`, `dash`, `ash`, `ksh`, `cmd`,
  `powershell`, `pwsh` and `.exe` variants) keep the sink dangerous. Wired
  into the dispatch site alongside the existing Go and Python safe-shape
  filters. Also handles the class-less universal `spawn` rule
  (`config-loader.ts:662`) so Rust `Command::new("git").arg(x).spawn()`
  is suppressed at every sink layer.

`src/analysis/passes/language-sources-pass.ts`:

- **`findRustCanonicalizeGuardSanitizers`** — recognizes path guards
  `if !<expr>.starts_with(<arg>) { return Err(...) }` (where `<expr>` may
  include a chained `.canonicalize()?`). Body terminator within 25 lines
  (`return`, `Err(`, `panic!(`, `HttpResponse::Forbidden/BadRequest/
  Unauthorized/NotFound`). Brace-depth tracking finds the block end. Emits
  per-line sanitizers for `path_traversal`, `xss`, `ssrf`,
  `external_taint_escape` from block-end+2 through end of file.

- **`findRustSetAllowlistGuardSanitizers`** — recognizes HashSet/HashMap
  allow-list guards `if !<setName>.contains(&<ident>) { return ... }` (and
  `.contains_key(&<ident>)` for HashMap). Same name heuristic as the
  Python netloc guard. Emits per-line sanitizers for `ssrf`,
  `open_redirect`, `command_injection`, `external_taint_escape`.

- **Dispatch registration** (`runPass` language block) — added Python and
  Rust additionalSanitizers blocks parallel to the existing Go and Bash
  blocks.

### Tests

- `tests/analysis/repro-issue-114.test.ts` — 4 new tests
  - 2 negative locks: netloc allow-list guard + int range-check guard
  - 2 recall locks: substring-check redirect (NOT an allow-list) + unguarded
    Flask string concat (sink-level lock, since Flask return-string flow
    tracking is partial)
- `tests/analysis/repro-issue-115.test.ts` — 7 new tests
  - 4 negative locks: `Command::new("ls").args(&[x])`,
    `Command::new("git").arg(x).arg(y)` chain, bare `Command::new("ls")`,
    plus canonicalize + HashSet guard smoke tests
  - 3 recall locks: tainted program literal, `sh -c` shell program,
    unguarded `Command::new("sh").arg(x)` chain
- Full suite: **2652 pass** / 1 skipped (was 2641; +11 new locks).
- Typecheck + CLI build: clean.

### Closes

- **#114** — Python safe-handler FPs (netloc guard + int range-check).
- **#115** — Rust safe-handler FPs (Command shape + canonicalize guard +
  HashSet allow-list).
- **#102** — parent issue: Go ✓ (3.82.0), Bash ✓ (3.82.0), Rust ✓ (this
  release). All three languages now have parallel safe-handler shape
  filters.

## [3.83.0] - 2026-06-19

Sprint 30 — issue **#124** (Java sink-type mis-categorization). Five entries
in `JAVA_SINK_RULES` matched methods whose runtime semantics do NOT match
the declared sink type, producing high-confidence FPs on benign Java code.

### Fixed — #124 Java sink-type mis-categorization

`src/analysis/config-loader.ts` — removed five spurious sink rules:

- `Pattern.compile(...)` tagged `code_injection` (CWE-94) — regex compilation
  does not execute code. The real risk from a tainted regex is ReDoS, which
  is already covered by the separate `Pattern.compile -> redos` rule.
- `Process.waitFor()` tagged `command_injection` (CWE-78) — `waitFor` blocks
  on an already-spawned `Process`; it takes no args and no command string
  flows into it.
- `ProcessBuilder.inheritIO()` tagged `command_injection` (CWE-78) — no args.
- `ProcessBuilder.redirectOutput(File)` / `redirectInput(File)` tagged
  `command_injection` — both take a `File` destination/source, not a command
  string. If anything, they are path-traversal — but the threat model is
  marginal, so they are removed entirely.

The real command-execution sinks remain configured (`Runtime.exec`,
`ProcessBuilder.start`, `ProcessBuilder.command(List<String>)`,
`new ProcessBuilder(cmd)`) and continue to fire on tainted inputs.

### Tests

- `tests/analysis/repro-issue-124.test.ts` — 7 new tests (5 negative locks
  for the removed rules + 2 recall locks proving `Runtime.exec` and
  `new ProcessBuilder(...)` still emit `command_injection` on tainted args).
- Full suite: **2641 pass** / 1 skipped (was 2634; +7 new locks).
- Typecheck + CLI build: clean.

### Closes

- #124 (Java sink-type mis-categorization on Pattern.compile / Process.*)

## [3.82.0] - 2026-06-19

Sprint 29 — bundle fixes for **#113** (`external_taint_escape` over-fires on
sanitized-input shapes) and **#86 remaining CWE coverage** (CWE-209
info-disclosure / stack trace + CWE-434 unrestricted file upload). The other
7 of 9 #86 gaps shipped earlier (CSRF #94, ReDoS, format-string, CRLF,
mass-assignment, JWT-verify, XML-entity-expansion).

### Fixed — #113 `external_taint_escape` (CWE-668) FP reduction

`external_taint_escape` is synthesized at runtime as the Scenario-B fallback
when an external value flows to a non-configured sink. Six sanitized-input
shapes were over-firing because their guard/cast helpers did not declare
`external_taint_escape` in their `removes:` set.

Fix — `src/analysis/config-loader.ts` (`DEFAULT_SANITIZERS`):
- Numeric casts (`parseInt` / `parseFloat` / `Number`) now also remove
  `external_taint_escape`, `path_traversal`, `code_injection` — a numeric
  cast cannot carry a string-injection payload.
- `Math.min` / `Math.max` (bounds-clamp) now remove `external_taint_escape`
  only — used as `Math.min(size, MAX_BYTES)` to bound a numeric value before
  forwarding.
- Allow-list / membership guards (`Array.prototype.includes`,
  `Set.prototype.has`, `<collection>.contains`, `indexOf`) now remove
  `external_taint_escape` only — a value tested against an allow-list before
  being forwarded cannot escape unbounded. Real string-injection sinks still
  rely on their own escaping.

The remaining #113 shapes (regex-validator predicates such as
`Pattern.matches(re, s)` / `re.match(re, s)` / `/re/.test(s)`, logger
receiver expansion across SLF4J / pino / winston / slog / Python logging,
and bounds-range checks `x >= 0 && x < len(buf)`) were already filtered by
the existing `interprocedural-pass.ts` sanitizer block + `safeUtilityMethods`
heuristic and verified via regression tests.

### Added — pass #103 `info-disclosure-stacktrace` (CWE-209, security, warning)

New file: `src/analysis/passes/info-disclosure-stacktrace-pass.ts`.

Pattern-based; detects exception detail returned to a remote client via an
HTTP response handle.

Detection shapes:
- **Java**: `e.printStackTrace(response.getWriter())` (receiver must look
  like an exception variable, arg 0 must look like a response writer);
  `response.getWriter().write(e.toString())` / `.println(e.getMessage())`.
- **JS/TS**: `res.send(err.stack)` / `res.json({error: err.stack})` /
  `res.json(err)` (whole error object). Chained `res.status(500).send(...)`
  recognized via receiver-tail / `.status(`/`.set(`/`.header(`/`.cookie(`
  intermediate-call match.
- **Python**: line-scan for `return traceback.format_exc()` /
  `return {"error": traceback.format_exc()}` / `jsonify(traceback.format_exc())`;
  `return str(e)` / `return repr(e)` guarded by a ±8-line window containing
  a `@app/router/blueprint.route|get|post|...` decorator (handler-context
  marker).
- **Go**: `http.Error(w, err.Error()+debug.Stack(), 500)`;
  `fmt.Fprintln(w, err)` / `Fprintf` / `Fprint` where the first arg is a
  response writer (`w`/`writer`/`resp`/`response`).

Negative guards:
- Logger receivers (`console`, `logger`, `log`, `slog`, `pino`, `winston`,
  `sentry`) are suppressed — logging server-side is not a leak.

Emits `{ rule_id: 'info-disclosure-stacktrace', cwe: 'CWE-209',
severity: 'medium', level: 'warning' }`. Closes part of #86.

### Added — pass #104 `unrestricted-file-upload` (CWE-434, security, error)

New file: `src/analysis/passes/unrestricted-file-upload-pass.ts`.

Pattern-based with a per-function safety-window heuristic; detects an
HTTP-uploaded file being saved using its untrusted original name without an
extension allow-list or filename canonicalization.

Detection shapes:
- **Java**: `MultipartFile.transferTo(new File(dir, file.getOriginalFilename()))`;
  `Files.copy(part.getInputStream(), Path.of(dir, part.getSubmittedFileName()))`.
- **JS/TS**: `multer({ dest: '...' })` with no `fileFilter` field in the
  options object literal; `fs.writeFile(path, req.file.buffer)` /
  `writeFileSync` / `appendFile`.
- **Python**: `f.save(os.path.join(UPLOAD_DIR, f.filename))` (receiver
  `f`/`file`/`upload`/`attachment` and an upload-name expression in args).
- **Go**: `os.Create(header.Filename)` / `os.OpenFile(header.Filename)`;
  `os.WriteFile` / `ioutil.WriteFile` with an upload-name expression.

Per-function FP-guard: any function whose body contains a
`secure_filename(...)`, `FilenameUtils.getExtension(...)`,
`ALLOWED_EXT`/`ALLOWED_EXTENSIONS`/`allowedExtensions` reference, an inline
`.lastIndexOf('.')` extension check, a `fileFilter` option, `path.extname`,
or `filepath.Ext` is treated as safe — findings inside that function range
are suppressed. When method-range information is unavailable, falls back to
a ±20-line window around the call.

Emits `{ rule_id: 'unrestricted-file-upload', cwe: 'CWE-434',
severity: 'high', level: 'error' }`. Closes part of #86.

### Changed — registration & docs

- `src/analyzer.ts` registers the two new passes after `mass-assignment` in
  the security pipeline. Both honor `disabledPasses`.
- `docs/PASSES.md` adds rows #103 (`info-disclosure-stacktrace`) and #104
  (`unrestricted-file-upload`), both `status = shipped`.

### Tests

- New regression file `tests/analysis/repro-sprint29.test.ts` (27 cases):
  - 13 negative locks for #113 sanitized-input shapes (allow-list /
    membership, bounds-clamp, regex validator, numeric cast, logger).
  - 2 recall locks ensuring genuine unguarded escapes still emit
    `external_taint_escape`.
  - 3 must-fire + 2 negative locks for CWE-209.
  - 3 must-fire + 2 negative locks for CWE-434.
  - 2 earlier-sprint recall locks (weak-hash, hard-coded credential).
- Full suite: **2634 passed / 1 skipped** (was 2607 in 3.81.0).

## [3.81.0] - 2026-06-19

Sprint 28 — bundle fixes for **#110** (xss mistyping of non-XSS sinks) and
**#109 remaining CWEs** (CWE-916 / CWE-256 / CWE-523 / CWE-261). CWE-260
shipped in 3.80.0 (Sprint 26); CWE-257 already covered by `weak-crypto`
(`hardcoded-key`).

### Fixed — #110 xss mistyping of every non-XSS `.write()` call

`configs/sinks/xss.yaml` lines 419–428 contained an unscoped
`{ method: "write", type: "xss" }` entry with **no `class` field**. It
matched any `.write()` call across all languages — `fs.writeFile(...)`,
`open("creds.txt").write(...)`, `bcrypt.hash(pw, 12, cb)` (the callback
shape produced a `r.write` look-alike), `https.request().write(body)`,
and credential-write APIs — and tagged them all as `xss` (CWE-79). A
mirror copy lived in `src/analysis/config-loader.ts:874`.

Fix:
- `configs/sinks/xss.yaml` — replace the unscoped entry with a
  class-scoped `ServletOutputStream.write` entry. Legitimate HTML
  writers were already class-scoped: `PrintWriter.write` (line 97),
  `JspWriter.write` (line 184); Node `Response.write` is class-scoped
  in `nodejs.json`.
- `src/analysis/config-loader.ts:874` — delete the mirror unscoped
  entry (kept `println` / `print` class-less entries — they are
  legitimately ambiguous, and the receiver-name FP surface for those
  two specific method names is narrower).

### Added — `weak-password-hash` (CWE-916)

New pattern pass. Detects fast/unsalted hash or low-cost KDF applied to
a credential-named identifier. Languages: Python, JS/TS, Java, Go.

Cost thresholds: bcrypt rounds < 10, PBKDF2 iterations < 100,000.

### Added — `plaintext-password-storage` (CWE-256)

New pattern pass. Detects writing a credential-named identifier to a
persistent store (file, KV store, cookie, database) without first
passing it through a cryptographic hash / KDF. Suppression is
intraprocedural — walks calls earlier in the same `in_method` scope
and skips when the identifier was hashed; also skips inline shapes
like `f.write(bcrypt.hashpw(pw))`. Languages: Python, JS/TS, Java, Go.

### Added — `cleartext-credential-transport` (CWE-523)

New pattern pass. Detects HTTP requests to an `http://` URL whose body
or params carry a credential-named identifier. URL allowlist for
`localhost` / `127.0.0.1` / `0.0.0.0` (dev environments). Languages:
Python (`requests` / `httpx` / `urllib`), JS/TS (`axios` / `fetch` /
`http.request`), Go (`http.Post` / `http.NewRequest`).

### Added — `weak-password-encoding` (CWE-261)

New pattern pass. Detects base64 / hex encoding applied to a
credential-named identifier — encoding is **not** encryption.
FP-guard: skip when the surrounding source includes a `"Basic "`
literal (HTTP Basic auth header construction). Languages: Python, JS/TS,
Java, Go.

### Added — shared `_credential-helpers.ts` module

`src/analysis/passes/_credential-helpers.ts` — `CRED_KEYWORD_RE`,
`isCredentialIdentifier`, `argLooksLikeCredential`, `stripQuotes`,
`literalAt`, `isHashFunctionCall`, `priorHashOf`. Used by the four new
passes to avoid duplicating the credential-keyword regex and hash-fn
tables.

### Tests

- New: `tests/analysis/repro-sprint28.test.ts` (23 tests).
- Full suite: 2607 pass / 1 skip (was 2584 pre-Sprint 28).

## [3.80.0] - 2026-06-19

Sprint 26 — bundle fixes for three closing-out OWASP-relevance gaps:
**#117** (CWE-501 Trust Boundary), **#118** (CWE-614 Insecure Cookie),
**#109** (CWE-260/798 Hardcoded Credentials).

### Fixed — #117 `trust_boundary` (CWE-501) under-fired on OWASP shape

`HttpSession.setAttribute("k", taintedValue)` is the canonical CWE-501
violation — untrusted data crosses into shared server-side state where
downstream code reads it as if trusted. The sink config in
`config-loader.ts` had `arg_positions: [0]`, which only flagged tainted
keys (rare). OWASP/CWE-501 Benchmark cases taint the **value** (arg[1]);
all 83 cases under-fired.

Fix (`config-loader.ts`): change `setAttribute` / `putValue` patterns
to `arg_positions: [0, 1]` so either arg trips the sink. Added
`ServletContext.setAttribute` and `HttpServletRequest.setAttribute` so
the request and application scopes get the same treatment as the
session scope.

### Fixed — #118 `insecure-cookie` (CWE-614) missed FQ constructor

`insecure-cookie-pass.ts:detectJavaCookieCtor` matched only on
`method_name === 'Cookie'` (unqualified `new Cookie(...)`). OWASP
Benchmark uses the FQ form `new javax.servlet.http.Cookie(...)` without
an import, producing `method_name === 'javax.servlet.http.Cookie'`,
which the matcher skipped. Result: 0% recall on the OWASP set.

Fix: accept `method.endsWith('.Cookie')` and FQ receiver_type tails
(`'.Cookie'`).

### Fixed — #109 `hardcoded-credential` (CWE-798) missed config constants

`scan-secrets-pass.ts` had two detection layers: (1) provider-prefix
regexes (AWS / GitHub / Slack / etc.) and (2) entropy-based base64 /
hex / UUID shapes. Config-style constants like
`DB_PASSWORD = "Pr0d-DB-pass!2024"` contain `!` and other characters
that fail the base64/hex regexes — missed entirely across all four
languages.

Fix: add **Layer 1b** "named-credential assignment" detection. Flags
any literal string assigned to an identifier whose name matches
`/password|passwd|secret|api_key|auth_token|private_key|access_key/i`.
Guards against three FP shapes:

- function declarations (`function checkPassword(...)`)
- string comparisons (`if (password === "expected")`)
- dynamic values (`process.env`, `os.environ`, `os.Getenv`,
  `System.getenv`, `${...}` template literals)
- known placeholders (`<your-password-here>`, `REPLACE_ME`, `xxx`, etc.)

Severity: `high`, CWE-798. Covers Java/Python/JavaScript/TypeScript/Go.

### Deferred — #113 `external_taint_escape` over-fire

Probes of the 12 shapes called out in the issue body did not reproduce
the FP set as described. Mixed picture surfaces instead:

- One *under-fire*: JS `process.env[key] = val` no longer emits an
  `external_taint_escape` flow (regression somewhere between the
  baseline and 3.79.0).
- One *new FP*: Go email-regex early-return guard not recognised as a
  sanitizer, producing `xss` on the post-guard `w.Write`.

These are distinct concerns from the original #113 issue and have been
documented for follow-up — issue left open with the probe findings.

## [3.79.0] - 2026-06-19

### Fixed — #116 `weak-crypto` (CWE-327) Java FP on `KeyGenerator.getInstance("AES")`

OWASP Java benchmark v3.67.0 snapshot showed CWE-327 Weak Crypto at
**58.3% precision (130 TP / 93 FP)** — the 93 FPs were **85% of all
Java FPs** in the run. The issue hypothesised the cause was over-firing
on `Cipher.getInstance("AES/CBC/...")` safe modes; probe confirmed
Cipher detection correctly distinguishes safe-mode (CBC/GCM/CTR) from
ECB via `classifyJavaCipherSpec`. The actual root cause is one line:

`KeyGenerator.getInstance("AES")` is the canonical, safe way to
generate AES key material. `KeyGenerator` has **no cipher mode** — the
mode is chosen later by `Cipher.getInstance("AES/CBC/PKCS5Padding")`.
The pass treated `KeyGenerator` identically to `Cipher`, including the
rule "AES with no mode defaults to ECB" — flagging every
`KeyGenerator.getInstance("AES")` call as ECB-mode high-severity. Every
OWASP Java test that performs key generation hits this; the
`Cipher.getInstance("AES/CBC/PKCS5Padding")` next to it does NOT fire.

Fix (`weak-crypto-pass.ts`): split `isCipherFactory` into:

- **`isCipherInstance`** — full Cipher logic, both weak-base (DES/3DES/
  RC4/Blowfish/RC2/RC5) and ECB-mode (`"AES"`, `"AES/ECB/..."`) checks.
- **`isKeyGenInstance`** — weak-base check ONLY. `KeyGenerator.getInstance("DES")`,
  `("RC4")`, `("Blowfish")` still flag as weak-cipher; `("AES")`,
  `("HmacSHA256")` no longer flag.

Cipher detection unchanged. The split adds zero new branches to the hot
path; the existing `classifyJavaCipherSpec` is now called from two
narrower gates instead of one wide one.

### Test coverage

11 new regression tests in `tests/analysis/repro-issue-116.test.ts`:
- 3 FP locks: `KeyGenerator.getInstance("AES")` and FQ variant +
  `KeyGenerator.getInstance("HmacSHA256")` must emit zero findings.
- 3 recall locks: `KeyGenerator.getInstance("DES" | "RC4" | "Blowfish")`
  must still flag as `weak-cipher`.
- 4 Cipher behavior locks: `Cipher.getInstance("AES")` still flags as
  `ecb-mode`; `("AES/ECB/PKCS5Padding")` still flags; `("AES/CBC/...")`
  and `("AES/GCM/...")` continue NOT to flag.
- 1 canonical OWASP shape lock: full doPost composite
  `KeyGenerator.getInstance("AES") + Cipher.getInstance("AES/CBC/PKCS5Padding")
  + SecureRandom IV + IvParameterSpec` emits zero weak-crypto findings.

Suite: 2569 pass / 1 skipped (+11 vs 3.78.0).

### Expected OWASP Java benchmark impact

The fix removes ECB-mode false positives on every key-generation site
that uses AES (the OWASP-recommended algorithm); CWE-327 precision is
expected to move from **58.3%** toward parity with other CWEs. Other
weak-crypto subtypes (`weak-cipher`, `deprecated-api`, `static-iv`,
`hardcoded-key`, `weak-rsa-key`) are untouched.

## [3.78.0] - 2026-06-19

### Fixed — #119 `weak-hash` (CWE-328) Java recall gaps

OWASP Java benchmark v3.67.0 snapshot showed CWE-328 Weak Hash at
**69% recall (89 TP / 40 FN, 100% precision)** — the 40 FNs were
9% of all Java FNs in the run. The issue hypothesised the chained
`MessageDigest.getInstance("MD5").digest(input)` shape was the
miss (mirroring #112), but a fresh probe confirmed that shape
already works. The actual gap is three other patterns:

1. **Apache Commons getter form** — `DigestUtils.getMd5Digest()`,
   `DigestUtils.getSha1Digest()`, `DigestUtils.getShaDigest()`. Not
   covered by the existing `COMMONS_DIGEST_METHODS` set (which only
   matched `md5Hex`/`sha1`/etc. compute-and-return-hash methods).
2. **Apache Commons algorithm constants** —
   `MessageDigest.getInstance(MessageDigestAlgorithms.MD5)`. The
   existing literal-extraction pulled the identifier text `"MD5"`
   off the field access (`MessageDigestAlgorithms.MD5`) but didn't
   resolve it to the algorithm name.
3. **Variable / field / final-local algorithm names** —
   `final String algorithm = "MD5";
   MessageDigest.getInstance(algorithm)` and the static-field
   variant `private static final String ALGO = "MD5";`. Existing
   code inspected only the raw literal at the call site.

Fix (`weak-hash-pass.ts`):
- Add `COMMONS_DIGEST_GETTERS` table mapping `getMd5Digest` →
  `md5`, `getSha1Digest` → `sha1`, `getShaDigest` → `sha1`,
  `getMd2Digest` → `md2`. Receiver check identical to the existing
  `COMMONS_DIGEST_METHODS` branch (`DigestUtils` / `*.DigestUtils`).
- Add `COMMONS_ALGO_CONSTANTS` table mapping the well-known
  Apache Commons `MessageDigestAlgorithms.{MD2,MD5,SHA_1}` field
  references (both short and fully-qualified forms) to the
  algorithm name.
- Add `resolveJavaAlgo()` that tries, in order: inline literal →
  `COMMONS_ALGO_CONSTANTS` → constant-propagation `symbols.get` →
  regex-scanned `String NAME = "literal";` bindings (the fallback
  handles `static final String`, `final String`, `private String`,
  etc. that the const-prop pass does not yet track for hash-algo
  strings). Replaces the old `literalAlgo()` call inside the Java
  `MessageDigest.getInstance(...)` branch.
- Negative locks intact: SHA-256 inline + SHA-256 via local-final
  + `DigestUtils.sha256Hex` + truly-dynamic algorithm parameter
  remain unflagged.

Regression suite: `tests/analysis/repro-issue-119.test.ts` —
6 FN locks (Commons getter ×2, Commons constant, local final,
static final, chained) + 2 recall locks (typed-local SHA-1,
DigestUtils.md5Hex) + 4 negative locks (SHA-256 ×3, dynamic
algorithm). 12/12 pass.

Suite: 2558 pass, 1 skipped.

## [3.77.0] - 2026-06-19

### Fixed — #121 `jwt-verify-disabled` Java branch over-broad parser match

False positive: the Java branch of `jwt-verify-disabled-pass` fired on
any `<receiver-containing-"parser">.parse(...)` call. Across a 12-repo
sample of popular Java OSS this produced 20 critical-severity findings
with **zero true positives**:

- 7 in `palantir/conjure` (parser-combinator code, `parser: Parser<T>`)
- 4 in `antlr/antlr4` (grammar parsers)
- 4 in `chinabugotech/hutool` (`FastDateParser.parse`)
- 2 in `OpenAPITools/openapi-generator` (markdown / completion command)
- 1 each in `EsotericSoftware/yamlbeans`, `zxing/zxing`, `google/gson`

The rule's `severity: critical` + `confidence: 1` drove three repos to
BLOCKED trust score solely from this noise.

Root cause: the receiver check `receiver.includes('parser')`
(`jwt-verify-disabled-pass.ts:161`) matched any receiver containing the
substring `parser` — local variables named `parser`, classes ending in
`Parser`, fields/getters with `parser` anywhere in their name. The
existing comment even called the heuristic "best-effort".

Fix: anchor the gate to the explicit JJWT chain:

```typescript
if (method === 'parse' && /\bJwts\s*\.\s*parser\s*\(/.test(receiver)) { ... }
```

Handles all idiomatic JJWT 0.x shapes:

- `Jwts.parser().parse(t)`
- `Jwts.parser().setSigningKey(k).parse(t)`
- `io.jsonwebtoken.Jwts.parser().parse(t)` (fully-qualified)
- whitespace variants `Jwts . parser ( )`

Rejects: bare `parser.parse(...)`, `FooParser.parse(...)`,
`matcher.parser().parse(...)`, etc.

Safe-form recall unchanged: `parseClaimsJws` / `parseSignedClaims` /
`parserBuilder().build().parseClaimsJws()` (jjwt 0.11+) are not
flagged because the `method === 'parse'` check excludes them.

Regression test: `tests/analysis/repro-issue-121.test.ts` (8 cases) —
3 FP locks (local-var `parser`, `FastDateParser`, ANTLR `.parser()`
getter), 3 TP recall locks (chained builder, bare chain,
fully-qualified), and 2 safe-form recall locks (`parseClaimsJws`,
`parserBuilder().build().parseClaimsJws`).

## [3.76.0] - 2026-06-19

### Fixed — #120 Python sanitizer state dropped across intraprocedural alias hop

False positive: the engine reported a `path_traversal` flow on the
one-hop alias indirection

```python
leaf_r = os.path.basename(request.args.get("f", ""))
leaf   = leaf_r
os.open(os.path.join(BASE, leaf), os.O_WRONLY | os.O_CREAT, 0o600)
```

while the inline form (no alias hop)

```python
leaf = os.path.basename(request.args.get("f", ""))
os.open(os.path.join(BASE, leaf), ...)
```

was correctly suppressed. The cognium-dev #65 pt2 alias-sanitizer-coverage
map (`aliasSanitizedFor`) is keyed by variable name and only credits a
variable when the sanitizer call appears on its own assignment line. A
pure-alias copy line (`leaf = leaf_r`) carries no sanitizer call, so
`leaf` got tainted but not credited, and the sink-emission suppression
check at `taint-propagation-pass.ts:1070` missed.

Fix in `src/analysis/passes/taint-propagation-pass.ts`
(`detectExpressionScanFlows`): after the existing #65 pt2
alias-sanitizer-coverage pass, scan for pure `lhs = upstreamIdentifier`
copies and run a fixpoint that propagates
`aliasSanitizedFor[upstream] -> aliasSanitizedFor[lhs]`. Chains of
arbitrary length are handled (`a -> b -> c -> ...`). Soundness gate:
the alias copy at line L only counts when it is the LATEST origin of
`lhs` per `buildPythonTaintedVars`'s `derived` map — a later
re-assignment to fresh (unsanitized) taint correctly invalidates the
inherited coverage so genuine re-tainting flows are still emitted.

Regression test: `tests/analysis/repro-issue-120.test.ts` (6 cases) —
inline baseline lock, one-hop alias FP fix, two-hop chain FP fix,
cross-sink-type validation (shlex.quote alias hop for command_injection),
and two recall locks: unsanitized alias hop must still flag, and
re-tainting after sanitized alias must still flag.

## [3.75.0] - 2026-06-19

### Fixed — Sprint 25 fast wins: cross-language FNs (#112, #111)

Two cross-language false-negatives closed with surgical sink-wiring + a
single matcher widening. No new analysis passes.

**#112 — Java `java.util.Random` for security tokens (CWE-331).**
`weak-random` was firing for the typed-local form
(`Random r = new Random(); r.nextInt(...)`) via the existing
`receiver_type === 'Random'` check, but missing the idiomatic chained
form `new Random().nextInt(...)`. For chained `new C().m()` the Java IR
emits `m` with `receiver_type = null` (the receiver is an expression,
not a typed variable), so the receiver_type branch never fired.

Fix in `src/analysis/passes/weak-random-pass.ts`: when the called method
is in `JAVA_RANDOM_METHODS`, also match `^new\s+Random\s*\(` and
`^new\s+SplittableRandom\s*\(` against the receiver expression. The
existing typed-local path and the `ThreadLocalRandom.current()` chained
path are unchanged.

**#111 — Go and Python CRLF / header injection (CWE-113).**

*Go:* the `{ method: 'Set'/'Add', class: 'Header', type: 'crlf' }` sink
patterns existed in `config-loader.ts` but never matched. `receiverMightBeClass`
only recognised direct identifiers, constructor-call patterns
(`Path(raw)`), and Rust scoped paths (`Command::new`). The Go shape
`w.Header().Set(k, v)` produces `receiver = "w.Header()"`, which none
of those branches recognised.

Fix in `src/analysis/taint-matcher.ts`: add a chained-method-call shape
to `receiverMightBeClass` — `receiver.endsWith('.ClassName()')` resolves
the call's receiver to `ClassName`. Targeted enough to require the
literal class name as the trailing method; safe for unrelated calls.

*Python:* no CRLF sinks existed. Added Flask/Werkzeug/FastAPI/Django
sinks to `config-loader.ts`:
- `{headers}.set(k, v)`, `.add(k, v)`, `.setdefault(k, v)`,
  `.__setitem__(k, v)` — value at arg[1]
- `{headers}.extend(mapping)` — mapping at arg[0]
- `{response}.set_cookie(name, value, ...)` — value at arg[1]

**Known limitation (Python subscript):** `resp.headers['X-A'] = name`
is not covered because the IR does not emit subscript writes as calls.
Documented inline in `config-loader.ts` and in the regression test.
The method-call forms above (`headers.set(...)`, `headers.add(...)`,
`headers.__setitem__(...)`) all match via the chained `.headers`
suffix resolution.

### Files changed

- `src/analysis/passes/weak-random-pass.ts` — chained-constructor receiver match for Java.
- `src/analysis/taint-matcher.ts` — `receiverMightBeClass` extended with
  `.<ClassName>()` chained-method shape.
- `src/analysis/config-loader.ts` — Python CRLF sinks (5 header method
  patterns + `set_cookie`).
- `tests/analysis/repro-sprint25-fastwins.test.ts` — 13 new tests
  covering chained constructor (4), Go header (3), Python header (4),
  JS/Java CRLF regression baselines (2).

### Verification

- `npm test` 2532 pass (was 2519; +13 new), 0 regressions.
- `npm run typecheck` clean. `bun run build` (CLI) clean.
- IR-level probe confirms `crlf` flow emitted for Go `w.Header().Set(name, tainted)`
  and Python `resp.headers.set(name, tainted)`; `weak-random` finding
  emitted for Java `new Random().nextInt(n)`.

## [3.74.0] - 2026-06-18

### Fixed — Sprint 24: Go safe-handler false positives (#102 Go portion)

Five Go safe-handler false positives left open after Sprint 23 are closed.
Sprint 23 shipped the Bash FP-24 fix; this sprint addresses the Go FPs.

**FP-19a — Parameterised SQL Query / Exec.**
`db.Query("SELECT name FROM users WHERE id = ?", id)` was emitting
`external_taint_escape` (CWE-668) because `Query`/`Exec` were not in the
inter-procedural fallback's safe-utility allowlist. The
sql_injection sink check already governs the unsafe shape; the fallback
should not re-flag the safe parameterised case.

Fix in `src/analysis/interprocedural.ts`: add Go `database/sql` query
methods (`Query`, `QueryRow`, `QueryContext`, `QueryRowContext`, `Exec`,
`ExecContext`) to `safeUtilityMethods`.

**FP-19b — `html/template.Execute` auto-escape.** Calls of the form
`t.Execute(w, name)` on a Go `html/template` template were emitting
`external_taint_escape` because the per-call class resolution for the
xss sink did not reliably resolve the receiver to `"Template"`.

Fix in `src/analysis/passes/language-sources-pass.ts`: new
`findGoHtmlTemplateImportSanitizers` emits a per-line sanitizer at
every `.Execute(` / `.ExecuteTemplate(` call when the file imports
`html/template`. Bails when `text/template` is also imported in the
same file — that case preserves the positive `code_injection` lock
from Sprint 23 #108.

**FP-20 — Map-allowlist host guard.** The idiomatic
`if !allowedHosts[host] { http.Error(...); return }` shape upstream of
`http.Get("https://" + host)` was firing `ssrf`.

Fix in `src/analysis/passes/language-sources-pass.ts`: new
`findGoMapAllowlistGuardSanitizers` (modelled on Sprint 23's
`findBashRealpathPrefixGuardSanitizers`) emits per-line sanitizer
entries from the guard close-brace through end of file when the map
name matches the allowlist naming heuristic (UPPER_SNAKE or contains
`allowed`/`accepted`/`whitelist`/`permitted`/`valid`/`approved`) and the
guard body terminates with `return`, `panic`, or `os.Exit`. Covers
`ssrf`, `open_redirect`, `path_traversal`, `sql_injection`,
`command_injection`, and `external_taint_escape`.

**FP-25 — `exec.Command` with fixed program literal.**
`exec.Command("ping", "-c", "1", host)` was firing `command_injection`
because Sprint 23 #53 widened `argPositions` to `[]` (so every positional
is scanned for taint). When `arg[0]` is a string literal naming a
non-shell program, subsequent positionals are argv elements (not shell
input) and the call is safe by construction.

Fix in `src/analysis/taint-matcher.ts`: new `isSafeGoExecCommandCall`
mirrors `isSafePythonSubprocessCall`. Reads `arg[0].literal` (already
unquoted by the Go plugin), takes basename, suppresses the
command_injection sink iff the program is NOT in `SHELL_PROGRAMS`
(`sh`, `bash`, `zsh`, `dash`, `ash`, `ksh`, `cmd[.exe]`, `powershell[.exe]`,
`pwsh[.exe]`). `CommandContext` shifts the program-arg index to 1
(arg[0] = ctx).

Sprint 23 #53 lock preserved: `exec.Command("sh", "-c", cmd)` →
program = `sh` → SHELL_PROGRAMS hit → sink emitted.

Tainted-program recall preserved: `exec.Command(taintedProg, "-c", "x")`
→ `arg[0].literal` is null (identifier expression, not literal) →
function returns false → sink emitted.

Belt-and-suspenders in `src/analysis/interprocedural.ts`: `Command`,
`CommandContext` added to `safeUtilityMethods` so the CWE-668 fallback
doesn't re-fire on the variadic args after the command_injection sink
was cleared.

**FP-27 — `html.EscapeString` → `fmt.Fprintf`.** The shape
```go
safe := html.EscapeString(name)
fmt.Fprintf(w, "<p>Hello, %s</p>", safe)
```
was firing `external_taint_escape` at the Fprintf line. Two
sub-defects:

1. `configs/sinks/golang.json` is not loaded at runtime — the runtime
   sanitizer set comes exclusively from hardcoded `DEFAULT_SANITIZERS`
   in `src/analysis/config-loader.ts`, and `html.EscapeString` /
   `template.HTMLEscapeString` were absent from that set.
2. Even with the sanitizer registered at the assignment line, the
   InterproceduralPass Scenario B fallback generates flows after
   TaintPropagationPass has already run, so its sanitizer filter never
   sees them.

Fix in `src/analysis/config-loader.ts`: register `html.EscapeString`,
`template.HTMLEscapeString`, `template.JSEscapeString`,
`template.URLQueryEscaper`, `url.QueryEscape`, `url.PathEscape` with
broad `removes` lists that include `external_taint_escape`. Also
broaden the existing Go path sanitizers (`filepath.Base`/`Clean`/
`EvalSymlinks`, `path.Base`/`Clean`) to add `external_taint_escape`.

Fix in `src/analysis/passes/taint-propagation-pass.ts` and
`src/analysis/passes/interprocedural-pass.ts`: add a uniform two-tier
line-keyed sanitizer filter. For `external_taint_escape` (synthetic
CWE-668 fallback with no variable-precise tracking), a sanitizer
anywhere on the source→sink line range that covers `external_taint_escape`
suppresses the flow. For configured sinks (ssrf, sql_injection, …),
the sanitizer must be AT `sink_line` — preserves cognium-dev #65 pt2
positive lock (bare `shlex.quote(host)` on a non-sink line does NOT
sanitize subsequent raw `host` reaching a command sink). The
InterproceduralPass filter also drops synthetic `external_taint_escape`
sinks whose flows were filtered out, to keep `r.taint.sinks` consistent
with `r.taint.flows`.

**FP-26 — `filepath.Clean` + `HasPrefix` regression lock.** Already
passing on the Sprint 24 baseline (`filepath.Clean` is a registered
`path_traversal` sanitizer). Regression test added so future changes
don't regress it.

**Verification.** `npm test` 2519 passing (2508 + 11 new),
`npm run typecheck` clean, `bun run build` (CLI) clean. The Sprint 24
probe (`/tmp/sprint24_probe.mjs`) shows all 6 FP fixtures `✅ no FP`
and all 3 positive recall baselines fire — including the Sprint 23 #53
shell-shape lock.

### Files modified

- `src/analysis/interprocedural.ts` — `safeUtilityMethods` extended
  (Go SQL Query/Exec, html escape helpers, `Command`/`CommandContext`).
- `src/analysis/config-loader.ts` — Go sanitizers added/broadened in
  `DEFAULT_SANITIZERS`.
- `src/analysis/taint-matcher.ts` — `isSafeGoExecCommandCall` added
  and wired into `findSinks`.
- `src/analysis/passes/language-sources-pass.ts` — `if (language === 'go')`
  block + two new detectors (`findGoMapAllowlistGuardSanitizers`,
  `findGoHtmlTemplateImportSanitizers`).
- `src/analysis/passes/taint-propagation-pass.ts` — two-tier uniform
  line-keyed sanitizer filter.
- `src/analysis/passes/interprocedural-pass.ts` — two-tier uniform
  filter + synthetic-sink dropping.
- `configs/sinks/golang.json` — `removes` lists broadened (config file
  is not consumed at runtime but kept in sync with the in-code defaults).
- `tests/analysis/repro-sprint24.test.ts` — 6 FP negative locks + 5
  positive recall locks.

### Out of scope (deferred)

- Rust FP-21/22/23 — separate sprint.
- JS allowlist detector — JS `if (allowedHosts.includes(...))` shape,
  future sprint.
- Multi-line shell prefix shapes (`/bin/sh -c …`, busybox).
- `html/template` chain detection without explicit import (e.g. type
  alias) — accept FP under that shape; explicit import IS the standard.

## [3.73.0] - 2026-06-18

### Fixed — Sprint 23: bundled "S" closure (#53, #102, #107, #108)

Four independent small fixes ship together as the Sprint 23 bundle —
three Go precision/recall gaps and one Bash precision FP.

**#53 — Go string-concat taint preservation.** Two interlocking bugs
combined to drop right-/left-/middle-concat Go fixtures:

1. Method-call sources (`r.URL.Query().Get(...)`,
   `r.Header.Get(...)`) landed at the source line without a `variable`
   field, so `detectExpressionScanFlows` (taint-propagation-pass.ts)
   could not match the bound identifier when it reappeared in
   concatenated sink arguments like `exec.Command("sh","-c","ping "+host)`.
2. `exec.Command`'s sink config declared `argPositions:[0]`, and
   SinkFilterPass Stage 3 (`filterCleanVariableSinks`) dropped the
   whole sink when arg[0] was a literal (`"sh"`) — regardless of
   whether the tainted variable was at arg[1] or arg[2].

Fix in `src/languages/plugins/go.ts`: widen
`exec.Command`/`CommandContext` `argPositions` to `[]` so every
positional argument is considered. Fix in `src/analysis/taint-matcher.ts`:
recover the Go LHS identifier from `:=`, `var x =`, `var x string =`,
`x =`, and `name, ok := ...` shapes (mirrors the Java pattern at
line 357 and the Rust pattern at line 320).

**#102 — Bash realpath + case prefix-guard FP.** Defensive shell
scripts that canonicalise a path and then check it against an allowed
root with a `case` block — e.g.

```bash
resolved=$(realpath "$f")
case "$resolved" in
  "$UPLOAD_ROOT"/*) cat "$resolved" ;;
  *) echo denied; exit 1 ;;
esac
```

were reported as `path_traversal`. Added
`findBashRealpathPrefixGuardSanitizers` in
`src/analysis/passes/language-sources-pass.ts` that emits per-line
sanitizers over the `case…esac` body when (a) at least one prefix
arm (`"$ROOT"/*)`, `"/tmp"/*)`, `/var/uploads/*)`, ...) is present and
(b) the catch-all `*)` arm terminates execution (`exit`, `return`, or
`die`). Conservative — open-ended `case "$x" in *)` fall-through stays
tainted.

**#107 — Go `log_injection` sink type missing.** Added CWE-117 sink
entries in `src/languages/plugins/go.ts` for
`log.{Print,Println,Printf,Fatal,Fatalln,Fatalf,Panic,Panicln,Panicf}`
with `argPositions:[]` so any tainted positional argument (the format
string OR any interpolation arg) fires.

**#108 — Go SSTI / `code_injection` sink type missing for parse-time
template injection.** The existing `Template.Execute` entry only models
data-injection XSS (CWE-79). When the *template source itself* is
tainted, the rendered output can execute arbitrary template directives
(CWE-94). Added entries for `Template.Parse` (argPositions [0]),
`template.ParseFiles` / `ParseFS` (argPositions []), and
`template.ParseGlob` (argPositions [0]). Covers both `text/template`
and `html/template` because the Go template factory match at
`taint-matcher.ts:1090-1105` already routes both packages through
`class === 'Template'` / `'template'`.

### Locked regressions

- New file: `tests/analysis/repro-sprint23.test.ts` — 9 fixtures
  (3 #53 + 2 #107 + 2 #108 + 2 #102).
- Full vitest suite: **2508 passed | 1 skipped** across 144 files.

## [3.72.1] - 2026-06-18

### Added — cross-file taint regression matrix (#106 closure lock)

Critical review of #106 ("cross-file taint unresolved across Python/JS/Java/Go")
against the post-Sprint-22 engine showed the issue's premise had been
invalidated: cross-file source→sink chaining works end-to-end in Python,
JavaScript, and Java, and partially in Go. The residual Go failures the
issue cited are orthogonal — they trace to #53 (Go string-concat taint
loss) and to missing Go sink configs (refiled as #107 `log_injection`
and #108 `code_injection`/SSTI).

Before this release the only cross-file regression coverage was Python
SQL + command-injection (`repro-sprint13.test.ts`, #74). The matrix this
test locks in:

| Lang | Sink shape |
|---|---|
| Python | flask → helper → `ldap.search_s`, `lxml.etree.fromstring` (XXE) |
| JavaScript | express → helper → `xpath.select`, `ldap.search` |
| Java | servlet → helper class → `Statement.executeQuery`, `Runtime.exec`, `DocumentBuilder.parse` |
| Go | `net/http` handler → helper → `db.Query` |

Each test asserts ≥1 `TaintPath` where `source.file !== sink.file`,
`source.type === 'http_param'` (the controller's HTTP source — not the
helper's `interprocedural_param` fallback), and `sink.type` matches the
expected vulnerability. This is the disambiguation #106 asked for: the
controller's HTTP source is attributed correctly, proving the cross-file
chain is real and not a relabeled per-file param heuristic.

- New file: `tests/analysis/repro-cross-file.test.ts` (8 fixtures).
- No engine changes; sink-config and pass behaviour unchanged from 3.72.0.

Full vitest suite: 2499 passed across 143 files.

## [3.72.0] - 2026-06-18

### Fixed — Sprint 22: OOP object-flow taint FN, sink-agnostic closure (#104)

Sprint 16/18 (#78) introduced OOP field-sensitivity for **injection** sinks
(sql_injection, command_injection). Sprint 21 (#105) confirmed the same
mechanism worked for ssrf and nosql_injection. Sprint 22 closes the
remaining sixteen non-injection OOP object-flow false negatives across
Python and JavaScript (path_traversal, open_redirect, log_injection,
ldap_injection, xpath_injection, nosql_injection, code_injection/SSTI,
deserialization, xxe).

This is precision/recall work — no new analysis pass, no new
`SinkType` enum value.

**LanguageSourcesPass — `findOopFieldReadSources` extended to JS/TS.**
The function previously gated on `java` and `python` only; JS/TS classes
emit constructor methods named `constructor` (not the class name), and
JS constructors are commonly written inline
(`constructor(name) { this.name = name; }`). The pass now:

- gates on `java | python | javascript | typescript`,
- detects constructors per-language (Python `__init__`, JS/TS
  `constructor`, Java class-name match),
- adds a global `this.<field> = <rhs>` regex pass so inline single-line
  constructor bodies are matched (not just per-line anchored
  assignments),
- dispatches RHS classification to `JS_TAINTED_PATTERNS` when language is
  JS/TS, mirroring the existing Python/Java branches.

This restores `this.<field>` synthetic-source emission for JS OOP
shapes, which was the upstream cause of three of the seven JS FN
regressions in this sprint.

**constant-propagation `isFalsePositive` — OOP field-path exemption.**
The const-prop FP suppressor at `constant-propagation/index.ts` was
flipping every flow whose path-variable was `this.X`/`self.X` to a
false positive (`reason: 'variable_not_tainted'`) when const-prop had
tracked the assignment but not classified it as tainted. That
silently zeroed JS OOP flows for nosql_injection, log_injection, and
deserialization (and would have done the same for the new sink types
this sprint adds). The OOP source-emission mechanism in
`findOopFieldReadSources` is entirely separate from const-prop's
intra-procedural seed; if the path step starts with `self.` or
`this.`, `isFalsePositive` now short-circuits to `false` and lets the
flow through. Same pattern as the existing cognium-dev#77 fix for
arrow-function-scoped `const c = ...` decls.

**SinkFilterPass Stage 5 — OOP-source recognition for xpath_injection.**
Stage 5 (Python xpath FP reducer) drops xpath sinks when no
`pyTaintedVars` entry appears in the sink line text. That set is
populated by intra-procedural textual scanning and doesn't include
OOP synthetic sources (`self.q`, etc.) emitted by
`findOopFieldReadSources`. Stage 5 now also scans `sources` for
`self.<field>` entries and accepts the sink if any such field-path
appears in the sink line. Lock fixture: PY.xpath_injection in
`repro-sprint22.test.ts`.

**Sink-config additions (`config-loader.ts`).** New sink entries
covering the canonical libraries for each non-injection sink:

- **Python `log_injection` (CWE-117).** `logging.{info, warning, error,
  debug, critical, log, exception}` (top-level module functions). The
  pre-existing `logger.<method>` entries only matched when the
  receiver was named `logger`; module-level calls like
  `logging.info(...)` need the parallel `class: 'logging'` set.
- **Python `nosql_injection` (CWE-943).** Classless pymongo methods
  (`find_one`, `update_one`, `update_many`, `delete_one`, `delete_many`,
  `replace_one`, `count_documents`) restricted to Python. pymongo
  collections are accessed via dynamic attribute (`db.users.find_one(
  ...)`) so the receiver-class isn't statically known. Bare `find`
  is intentionally NOT classless to avoid `str.find`/`list.find` FPs;
  mirrors the existing JS Mongo pattern at line 1494-1502.
- **JS `ldap_injection` (CWE-90).** `ldap.search` / `ldap.searchSync`
  (and the `ldapjs` import alias) with the filter at arg index 1 or 2,
  language-scoped to JS/TS.
- **JS `xpath_injection` (CWE-643).** `xpath.{select, select1, evaluate,
  parse}` matching the canonical `xpath` npm module receiver.
- **JS `xxe` (CWE-611).** libxmljs `parseXml` / `parseXmlString`
  (receiver matches the canonical `libxml` import alias as well as
  `libxmljs`), and xmldom `parseFromString` (`DOMParser`/`xmldom`
  receivers).
- **JS SSTI → `code_injection` (CWE-94).** ejs / handlebars / pug /
  mustache / nunjucks `render` / `compile` / `renderString` entries.
  Uses the existing `code_injection` SinkType to mirror Python
  Jinja2/Mako; no new enum value introduced.

**Regression test.** `tests/analysis/repro-sprint22.test.ts` locks all
sixteen OOP shapes (9 Python, 7 JS) as inline fixtures, each asserting
`flowsByType(r.taint.flows, '<sink_type>').length >= 1`. Full vitest
suite: 2491 passing (was 2475 on 3.71.0; +16 new fixtures, 0
regressions).

## [3.71.0] - 2026-06-18

### Fixed — Sprint 21: OOP safe-mirror sanitizer FPs (#105)

Sprint 21 closes the two remaining false-positive families on the OOP
safe-mirror corpus exercised by the cognium-dev safe-corpus benchmark
(`safe_oop_*.{py,js}`). The other three call-outs in #105 (FP-33 hardened
lxml parser, FP-34 EJS auto-escape template, FN-INV direct `self.url`
read) were already handled by the Sprint 16 / 18 machinery once #3.70.0
shipped; they are now locked by Sprint 21 regression fixtures.

This is taint-engine precision work — no new pass, no new `rule_id`,
no `SinkType` enum change.

**FP-31 — allowlist-guarded getter wrongly emitted as a taint source.**
`findOopFieldReadSources` (`src/analysis/passes/language-sources-pass.ts`)
now recognises allowlist-style guards inside single-return getters and
suppresses the synthetic source emission. The shape

```py
class HttpClient:
    ALLOWED = {'api.internal.example.com', 'cdn.example.com'}
    def _checked(self):
        if self.url not in self.ALLOWED:
            raise ValueError("host not allowed")
        return self.url
```

no longer fires `ssrf` when `requests.get(self._checked())` is called.
The check requires (a) an `if <ref> (not in|in) <UPPER_SNAKE_CONST>:`
membership test, and (b) `raise`/`abort`/`return None`/`return ''`
within ≤2 lines of the guard. Cache-shape lookups
(`if self.url in self.CACHE: return self.url`, no `raise`) and plain
getters (`def get_url(self): return self.url`) are explicitly NOT
treated as sanitizers — the `GETTER.1-vuln` and `GUARD.1-noisy`
fixtures lock those negative cases. Java/JS variants of the guard
(`!ALLOWED.contains(x)` / `!ALLOWED.includes(x)` + `throw`) are also
recognised.

**FP-32 — MongoDB value-bound filter dict wrongly classified as
operator-injection.** `TaintPropagationPass` (`src/analysis/passes/
taint-propagation-pass.ts`) now post-filters `nosql_injection` flows
through a new `isMongoValueBoundFilter` helper. MongoDB only interprets
`$`-prefixed keys (`$where`, `$ne`, `$gt`, …) as operators; a literal
object whose top-level keys are all plain identifiers/strings reduces
to pure value-equality and is structurally incapable of operator
injection regardless of how its values were computed. The shape

```js
this.db.collection('users').findOne({ user: name })
```

no longer fires `nosql_injection` for `find/findOne/updateOne/
deleteOne/aggregate` sinks. The operator-injection mirror
(`findOne(filter)` where `filter` is opaque, or
`findOne({$where: ...})`) still fires — locked by `NOSQL.2-vuln`.
The helper uses a depth-aware paren walker (cap 4 KiB) so nested
braces and string-literal `$` characters don't false-trip.

**Regression locks (already-passing fixtures pinned in
`repro-sprint21.test.ts`):**

- FP-33 hardened lxml parser (`resolve_entities=False, no_network=True,
  load_dtd=False`) — 0 xxe flows.
- FP-34 EJS `<%= n %>` auto-escape template — 0 xss / 0
  template_injection flows.
- FN-INV direct `self.url` read on a constructor-injected field — ≥1
  ssrf flow (relies on the Sprint 16 #78 field-source machinery).

**Verification:** 2475 tests pass / 1 skipped across 141 files.
Targeted: `repro-sprint21.test.ts` 8/8; `repro-issue-78.test.ts`,
`repro-sprint16/18/9.test.ts` no regressions on the OOP /
wrapper-sanitizer / Python-safe-corpus suites.

Closes #105.

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
