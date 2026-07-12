/**
 * Entry-point tier classifier (cognium-dev#128).
 *
 * Deterministic, AST-based classification of a method's position relative
 * to a program's *real* entry points (HTTP handlers, message-queue
 * listeners, scheduled jobs, CLI main, etc.). Designed to drive the
 * `interprocedural_param` source-suppression gate in `taint-matcher.ts`
 * and `interprocedural-pass.ts` — preventing the speculative
 * engine-emitted sources on Tier 3 (library API) methods from
 * propagating through verification.
 *
 * # Why
 *
 * `taint-matcher.ts:218-237` currently emits an `interprocedural_param`
 * source for every parameter of every method in a file, regardless of
 * whether that method is reachable from a program entry point. On the
 * top-25 Java OSS corpus this produces ~1,768 of 1,968 high-severity
 * findings against `redis/jedis`'s `UnifiedJedis.executeCommand` /
 * `Jedis.executeCommand` facade methods — pure signature amplification
 * on a library that is called *by* its users, never *by* a network
 * boundary.
 *
 * This classifier returns the tier of the enclosing method so callers
 * (taint-matcher, interprocedural-pass) can drop the speculative source
 * before it reaches the verifier.
 *
 * # Provenance
 *
 * Ported verbatim from
 * `cognium-ai/circle-ir-ai/src/analysis/entry-point-detection.ts`
 * (shipped in `circle-ir-ai@2.14.0`, 2026-06-21) — the same classifier
 * that currently runs as a downstream `runMerge` gate in the
 * cognium-ai stack. The downstream gate becomes a no-op once this
 * pass is wired into `taint-matcher.ts:findSinks()`, after which it
 * will be retired in a follow-up cognium-ai bump.
 *
 * No behavioral wiring in this commit — the file lands as a no-op
 * (not yet consumed by any pass). Wiring + heuristic gap-closures
 * (`*Util` / `*Utils` / `*Helper`, `*.template.*` / `*.engine.*`,
 * JDK facade interface-implements via `TypeHierarchyResolver`) come
 * in follow-up commits per the cognium-dev#128 Sprint 35 plan.
 *
 * # Tiers
 *
 * - **TIER_1_ENTRY_POINT** — Method itself is annotated as an entry
 *   point (`@RequestMapping`, `@KafkaListener`, etc.), is a method of
 *   an entry-point class (`@RestController`, JAX-RS `@Path` resource,
 *   `extends HttpServlet`), or matches the `main(String[])` signature.
 *   These methods *are* the trust boundary.
 *
 * - **TIER_2_REACHABLE** — Method called by a Tier 1 method (1-hop).
 *   Not implemented in ship 1; requires `ProjectGraph` call-graph
 *   traversal. Reserved by the `ctx.callGraph` parameter so the
 *   classifier surface does not change when Tier 2 ships. Ship 1
 *   classifies every non-Tier-1 Java method as Tier 3.
 *
 * - **TIER_3_LIBRARY_API** — Public method, no entry-point annotation,
 *   no entry-point class context, no `main` signature. Library API
 *   surface — callers validate, not us.
 *
 * - **TIER_UNKNOWN** — Non-Java language, or insufficient AST info to
 *   classify. Callers should treat UNKNOWN as pass-through (no
 *   filtering), so ship 1's Java-only scope does not affect Python /
 *   Node / Go / Rust / Bash analysis.
 *
 * # Deferred heuristic gaps (cognium-dev#136 audit)
 *
 * The 22-repo audit also surfaced three patterns that do NOT fit the
 * classifier surface (which sees only `MethodInfo` + `TypeInfo`
 * shape, no body AST, no call graph, no lambda-scope tracking) and
 * are routed to other components:
 *
 * - **Builder / fluent-setter chains** (`this.x = x; return this;`
 *   identity-return hop) — body-shape concern. Noise reduction is
 *   the job of cross-file finding-coalescing (cognium-dev#143), not
 *   tier classification. The setter itself is correctly TIER_3.
 *
 * - **Lambda-captured params** (`Stream.map(s -> someSink(s))`) — in
 *   the current IR, lambdas live inside the enclosing method's body
 *   and are not separately represented as `MethodInfo` records, so
 *   they already inherit the enclosing method's tier without any
 *   classifier change. If the IR ever lifts lambdas into standalone
 *   method records, a follow-up should propagate the parent tier.
 *
 * - **`Callable` / `Runnable` posted to `ExecutorService`** — pure
 *   Tier 2 call-graph reachability concern (the TIER_1 method posts
 *   the `Runnable`, which becomes reachable in a worker thread).
 *   Reserved for the deferred Tier 2 ship; see `ctx.callGraph`.
 *
 * # Reference
 *
 * - cognium-dev#128 — entry-point-anchored taint sources.
 * - cognium-dev#136 — Tier 1 heuristic gaps audit (Spring stereotypes).
 * - cognium-dev#154 — Netty handler classes (CVE-2022-26884
 *   dolphinscheduler `NettyRequestProcessor.process`).
 * - `taint-matcher.ts:218-237` — speculative source emission site.
 * - `interprocedural-pass.ts:137-146` — engine's awareness comment.
 */

import type {
  TypeInfo,
  MethodInfo,
  CallInfo,
  RuntimeRegistration,
} from '../types/index.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type EntryPointTier =
  | 'TIER_1_ENTRY_POINT'
  | 'TIER_2_REACHABLE'
  | 'TIER_3_LIBRARY_API'
  | 'TIER_UNKNOWN';

export interface EntryPointContext {
  /** All TypeInfo records in this file. */
  types?: ReadonlyArray<TypeInfo> | null;
  /** Language from CircleIR.language (e.g. 'java', 'python'). */
  language?: string | null;
  /**
   * Project-wide call graph — Tier 2 reachability. Reserved for a
   * follow-up; ship 1 classifies every non-Tier-1 method as Tier 3.
   */
  callGraph?: unknown;
  /**
   * File path (`CircleIR.meta.file`) — used by the polyglot library-
   * facade path heuristic for Python / JS-TS / Go / Bash where package
   * metadata is thin. Java classification does not require this.
   *
   * Added 3.166.0 for cognium-dev #237 polyglot expansion.
   */
  filePath?: string | null;
  /**
   * All `CallInfo` records for the file (`CircleIR.calls`). Consumed by
   * the Go classifier for the `http.HandleFunc` / gin / chi framework-
   * registration walk (no runtime-registration extractor exists for Go
   * — the classifier walks `ir.calls` inline).
   *
   * Added 3.166.0 for cognium-dev #237.
   */
  calls?: ReadonlyArray<CallInfo> | null;
  /**
   * `RuntimeRegistration[]` records for the file
   * (`CircleIR.runtime_registrations`). Consumed by the JS/TS and
   * Python classifiers to resolve handler methods registered via
   * Express / Fastify / Flask / FastAPI / Django / Click / Celery
   * calls (already extracted per `core/extractors/runtime-registrations.ts`).
   *
   * Added 3.166.0 for cognium-dev #237.
   */
  runtimeRegistrations?: ReadonlyArray<RuntimeRegistration> | null;
}

// ---------------------------------------------------------------------------
// Tier 1 annotation tables (Java, ship 1)
// ---------------------------------------------------------------------------

/**
 * Method-level annotations that make the method itself an entry point.
 * Simple-name match; any args / generics are stripped before lookup.
 */
const TIER_1_METHOD_ANNOTATIONS = new Set([
  // Spring MVC
  'RequestMapping',
  'GetMapping',
  'PostMapping',
  'PutMapping',
  'DeleteMapping',
  'PatchMapping',
  // Spring messaging / WebSocket
  'MessageMapping',
  'SubscribeMapping',
  // Spring messaging listeners
  'KafkaListener',
  'KafkaHandler',
  'RabbitListener',
  'RabbitHandler',
  'JmsListener',
  'StreamListener',
  // Spring Cloud AWS
  'SqsListener',
  'SqsHandler',
  // Spring application events (borderline — inclusive in ship 1)
  'EventListener',
  // CRON / scheduled
  'Scheduled',
  // JAX-RS
  'Path',
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'HEAD',
  'OPTIONS',
  // Jenkins Stapler form-binding (#224 — CVE-2022-20617 docker-commons).
  // `@DataBoundConstructor` / `@DataBoundSetter` mark the trust boundary
  // between Jenkins UI (or `config.xml` unmarshal) and the plugin: the
  // Stapler runtime invokes the annotated constructor / setter with
  // user-supplied strings from a submitted form or a persisted job
  // config. Every parameter is a user-supplied taint source.
  'DataBoundConstructor',
  'DataBoundSetter',
]);

/**
 * Class-level annotations that make every public method of the class
 * a Tier 1 entry point. Spring MVC / JAX-RS / Servlet 3 conventions,
 * plus Spring stereotype beans (`@Service` / `@Repository` /
 * `@Component`) per cognium-dev#136.
 *
 * # Why @Service/@Repository/@Component are Tier 1 (#136)
 *
 * The 22-repo harness audit (2026-06-22) found that scanning a
 * library jar containing `@Service` / `@Repository` / `@Component`
 * stereotypes WITHOUT the `@RestController` that invokes them caused
 * the classifier to fall through to TIER_3 and drop every speculative
 * `interprocedural_param` source — including legitimate ones at the
 * business-layer trust boundary that callers actually rely on. For a
 * SAST tool scanning library jars, the stereotype IS the visible
 * trust boundary: callers across the (unseen) controller seam must
 * validate at the stereotype's parameter list. Recall-positive,
 * precision-acceptable: the library-facade short-circuit (step 2,
 * `*Util` / template-package / JDK-facade-implements) still trumps,
 * so a stereotype accidentally placed on a `*Util` class stays
 * TIER_3.
 */
const TIER_1_CLASS_ANNOTATIONS = new Set([
  // Spring MVC
  'RestController',
  'Controller',
  // Spring stereotype beans (#136 — see header)
  'Service',
  'Repository',
  'Component',
  // JAX-RS resource class
  'Path',
  // Servlet 3.0 annotation-based servlet
  'WebServlet',
  // JSR-356 WebSocket endpoint
  'ServerEndpoint',
  // Declarative HTTP client (borderline — inclusive in ship 1; contract-defined
  // parameter shapes are downstream-relevant trust boundaries)
  'FeignClient',
]);

/**
 * Class names (matched via `implements` or `extends`) whose lifecycle
 * methods are Tier 1. For each, the set of lifecycle method names that
 * qualify.
 */
const TIER_1_BY_SUPERTYPE: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  // Servlet API
  ['HttpServlet', new Set(['doGet', 'doPost', 'doPut', 'doDelete', 'doHead', 'doOptions', 'doTrace', 'service'])],
  ['GenericServlet', new Set(['service'])],
  ['Filter', new Set(['doFilter'])],
  // Spring web
  ['HandlerInterceptor', new Set(['preHandle', 'postHandle', 'afterCompletion'])],
  ['AsyncHandlerInterceptor', new Set(['preHandle', 'postHandle', 'afterCompletion', 'afterConcurrentHandlingStarted'])],
  // Spring boot CLI entry points
  ['CommandLineRunner', new Set(['run'])],
  ['ApplicationRunner', new Set(['run'])],
  // Netty channel handlers (#154 — CVE-2022-26884 dolphinscheduler).
  // `SimpleChannelInboundHandler<T>.channelRead0(ctx, msg)` is the
  // standard typed read entry; `ChannelInboundHandler.channelRead(ctx,
  // Object)` is the untyped base. `ChannelInboundHandlerAdapter` and
  // `ChannelDuplexHandler` are the most-common adapter classes user
  // handlers extend. `NettyRequestProcessor` is the dolphinscheduler-
  // specific (and other Netty-RPC projects') wire-message processor
  // surface — `process(channel, command)` is the network entry point.
  ['SimpleChannelInboundHandler', new Set(['channelRead0', 'messageReceived'])],
  ['ChannelInboundHandler', new Set(['channelRead', 'channelReadComplete'])],
  ['ChannelInboundHandlerAdapter', new Set(['channelRead', 'channelReadComplete'])],
  ['ChannelDuplexHandler', new Set(['channelRead', 'channelReadComplete'])],
  ['NettyRequestProcessor', new Set(['process'])],
  // XStream deserialization converters (#224 — CVE-2020-26217,
  // CVE-2021-21345). The xstream deserializer invokes `unmarshal`
  // with attacker-controlled `HierarchicalStreamReader` state whenever
  // untrusted XML reaches `XStream.fromXML`. Each converter is a
  // deserialization gadget surface — its `unmarshal` parameters are
  // network-facing taint sources even though the enclosing class
  // carries no framework annotation. `marshal` is included for the
  // symmetric round-trip surface but is rarely exploitable on its
  // own; the fixup targets `unmarshal` primarily.
  //
  // `SingleValueConverter` is the string-form variant (fromString
  // parses an attacker string; toString is the sink half of the
  // round-trip). `ConverterMatcher` is the shared base and some
  // downstream projects subclass it directly.
  ['Converter', new Set(['marshal', 'unmarshal'])],
  ['SingleValueConverter', new Set(['fromString', 'toString'])],
  ['ConverterMatcher', new Set(['marshal', 'unmarshal'])],
  // XStream abstract base classes — direct-parent `extends` match
  // covers the common shape where user converters subclass a base
  // rather than implementing `Converter` directly.
  ['AbstractReflectionConverter', new Set(['marshal', 'unmarshal', 'doMarshal', 'doUnmarshal'])],
  ['AbstractSingleValueConverter', new Set(['fromString', 'toString'])],
  ['AbstractCollectionConverter', new Set(['marshal', 'unmarshal'])],
]);

// ---------------------------------------------------------------------------
// Tier 3 strengthening — library-facade shape heuristics
// (cognium-dev#128 step 2)
// ---------------------------------------------------------------------------

/**
 * Class-name suffixes that mark a type as a static-utility / helper
 * facade. Hutool's `RuntimeUtil`, Apache Commons' `StringUtils`,
 * custom `*Helper` wrappers — all called BY user code, never invoked
 * AT a network trust boundary. Their parameters are not
 * entry-point-anchored taint sources.
 *
 * Matched case-sensitively against the suffix of `TypeInfo.name` with
 * a length guard (suffix length must be strictly less than class
 * name length) so a bare-suffix class like `Util` itself is not
 * caught.
 */
const TIER_3_CLASS_SUFFIXES: ReadonlyArray<string> = [
  'Util', 'Utils', 'Helper', 'Helpers',
];

/**
 * Package fragments that mark a type as part of a templating / engine
 * library surface. FreeMarker's `freemarker.template.*`, Apache
 * Velocity's `org.apache.velocity.template`, custom `*.engine.*`
 * wrappers — facades over user-supplied template content, not
 * network entry points.
 *
 * Matched against the dotted package name with sentinel dots on both
 * sides so `.template.` matches `freemarker.template.Configuration`
 * but not a hypothetical `freemarker.templatemap.Foo`.
 */
const TIER_3_PACKAGE_FRAGMENTS: ReadonlyArray<string> = [
  '.template.', '.templates.', '.engine.', '.engines.',
];

/**
 * JDK collection / iterator / serialization interfaces. A type that
 * directly implements one of these is a library data-structure facade
 * — its methods are invoked BY user code, not AT a trust boundary.
 *
 * Direct-`implements` only — no transitive `TypeHierarchyResolver`
 * traversal in ship 1; that variant is deferred. The current
 * predicate is sufficient for the #128 cluster and avoids dragging
 * the resolver into a leaf classifier.
 */
const TIER_3_JDK_FACADE_INTERFACES: ReadonlySet<string> = new Set([
  // Collection root + common containers
  'Collection', 'List', 'Set', 'Map', 'Queue', 'Deque',
  'SortedSet', 'SortedMap', 'NavigableSet', 'NavigableMap',
  // Iteration / ordering / equality contracts
  'Iterator', 'Iterable', 'ListIterator',
  'Comparator', 'Comparable',
  // Serialization / cloning contracts
  'Serializable', 'Externalizable', 'Cloneable',
]);

function classNameLooksLikeUtility(name: string | undefined): boolean {
  if (!name) return false;
  for (const suffix of TIER_3_CLASS_SUFFIXES) {
    if (name.length > suffix.length && name.endsWith(suffix)) return true;
  }
  return false;
}

function packageLooksLikeTemplateOrEngine(pkg: string | null | undefined): boolean {
  if (!pkg) return false;
  const padded = `.${pkg}.`;
  for (const frag of TIER_3_PACKAGE_FRAGMENTS) {
    if (padded.includes(frag)) return true;
  }
  return false;
}

function implementsJdkFacade(t: TypeInfo | undefined): boolean {
  if (!t) return false;
  for (const impl of t.implements ?? []) {
    if (TIER_3_JDK_FACADE_INTERFACES.has(simpleTypeName(impl))) return true;
  }
  return false;
}

/**
 * Returns true if the enclosing type's shape (class name suffix,
 * package fragment, direct JDK-facade `implements`) is unmistakably
 * a library / utility / engine facade.
 *
 * Used as a TIER_3 short-circuit that runs BEFORE Tier-1 annotation
 * detection — conservative FP-reducing choice for the #128 cluster
 * (`RuntimeUtil.exec` ×3 + `FreemarkerEngine` slipping through the
 * downstream gate). Any one of the three predicates flips the
 * classification.
 *
 * Trade-off: a real entry point class accidentally named with a
 * `*Util` suffix AND carrying a Tier-1 annotation would be
 * incorrectly downgraded. This pattern is vanishingly rare in
 * practice (utility classes don't carry `@RestController`); the
 * false-positive reduction on the real cluster outweighs the
 * theoretical recall loss.
 */
function classShapeIsLibraryFacade(enclosingType: TypeInfo | undefined): boolean {
  if (!enclosingType) return false;
  if (classNameLooksLikeUtility(enclosingType.name)) return true;
  if (packageLooksLikeTemplateOrEngine(enclosingType.package)) return true;
  if (implementsJdkFacade(enclosingType)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if `annotations` contains any of the targets. Tolerates
 * the `@Annotation(args)` and `Annotation<T>` forms.
 */
function annotationsInclude(
  annotations: ReadonlyArray<string> | undefined,
  targets: ReadonlySet<string>,
): boolean {
  if (!annotations || annotations.length === 0) return false;
  for (const raw of annotations) {
    const simple = raw
      .replace(/^@/, '')
      .replace(/[<(].*$/, '')
      .trim();
    if (targets.has(simple)) return true;
  }
  return false;
}

/**
 * Strip generic parameters from a type reference (`Foo<Bar>` → `Foo`).
 */
function simpleTypeName(ref: string): string {
  return ref.replace(/<.*$/, '').trim();
}

/**
 * Returns true if the method signature looks like `public static void main(String[])`.
 * We don't have full signature info on every codebase, so this is best-effort
 * based on name + a single `String[]` / `String...` parameter.
 */
function looksLikeMainMethod(method: MethodInfo): boolean {
  if (method.name !== 'main') return false;
  const params = method.parameters ?? [];
  if (params.length !== 1) return false;
  const t = (params[0].type ?? '').replace(/\s+/g, '');
  return t === 'String[]' || t === 'String...' || t === 'java.lang.String[]';
}

/**
 * Returns true if the enclosing type is a Servlet / Filter / Interceptor
 * subclass AND the method name matches a lifecycle entry-point of that
 * supertype.
 */
function methodIsSupertypeLifecycleEntryPoint(
  method: MethodInfo,
  enclosingType: TypeInfo | undefined,
): boolean {
  if (!method.name) return false;
  if (!enclosingType) return false;
  const candidates: string[] = [];
  if (enclosingType.extends) candidates.push(simpleTypeName(enclosingType.extends));
  for (const i of enclosingType.implements ?? []) candidates.push(simpleTypeName(i));
  for (const supertype of candidates) {
    const lifecycleMethods = TIER_1_BY_SUPERTYPE.get(supertype);
    if (lifecycleMethods?.has(method.name)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Public classifier
// ---------------------------------------------------------------------------

/**
 * Classify a method's entry-point tier.
 *
 * Order:
 *   1. UNKNOWN short-circuit for non-Java languages (ship 1 scope).
 *   2. Library-facade short-circuit (#128 step 2) — `*Util` / `*Utils`
 *      / `*Helper(s)` class name, `*.template|engine.*` package, or
 *      direct JDK-facade `implements` → TIER_3, overriding any
 *      spurious framework-shaped annotations on the type.
 *   3. Method-level annotation match → TIER_1.
 *   4. Class-level annotation match → TIER_1.
 *   5. Supertype lifecycle method match → TIER_1.
 *   6. `main(String[])` signature → TIER_1.
 *   7. Tier 2 reachability (not implemented in ship 1).
 *   8. Fallback → TIER_3_LIBRARY_API.
 */
export function classifyEntryPointTier(
  method: MethodInfo | undefined,
  enclosingType: TypeInfo | undefined,
  ctx: EntryPointContext,
): EntryPointTier {
  if (!method) return 'TIER_UNKNOWN';
  const language = (ctx.language ?? '').toLowerCase();

  // Language dispatch — Java retains the original in-line logic below;
  // Python / JS-TS / Go / Bash route to dedicated classifiers added
  // 3.166.0 (cognium-dev #237). Anything else routes via UNKNOWN so
  // consumers pass the finding through unchanged.
  switch (language) {
    case 'java':
      return classifyJavaEntryPoint(method, enclosingType);
    case 'python':
      return classifyPythonEntryPoint(method, enclosingType, ctx);
    case 'javascript':
    case 'typescript':
    case 'tsx':
    case 'jsx':
      return classifyJsTsEntryPoint(method, enclosingType, ctx);
    case 'go':
      return classifyGoEntryPoint(method, enclosingType, ctx);
    case 'bash':
    case 'shell':
      return classifyBashEntryPoint(method, enclosingType, ctx);
    default:
      return 'TIER_UNKNOWN';
  }
}

/**
 * Java classifier (original ship 1 logic — kept verbatim under the new
 * language dispatch). Order:
 *   1. Library-facade short-circuit (#128 step 2).
 *   2. Method-level annotation → TIER_1.
 *   3. Class-level annotation → TIER_1.
 *   4. Supertype lifecycle method → TIER_1.
 *   5. `main(String[])` → TIER_1.
 *   6. Fallback → TIER_3_LIBRARY_API.
 */
function classifyJavaEntryPoint(
  method: MethodInfo,
  enclosingType: TypeInfo | undefined,
): EntryPointTier {
  // 1. Library-facade short-circuit.
  if (classShapeIsLibraryFacade(enclosingType)) {
    return 'TIER_3_LIBRARY_API';
  }

  // 2. Method-level annotation
  if (annotationsInclude(method.annotations, TIER_1_METHOD_ANNOTATIONS)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 3. Class-level annotation (every public method of a controller is TIER_1)
  if (enclosingType && annotationsInclude(enclosingType.annotations, TIER_1_CLASS_ANNOTATIONS)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4. Supertype lifecycle method
  if (methodIsSupertypeLifecycleEntryPoint(method, enclosingType)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 5. `public static void main(String[])`
  if (looksLikeMainMethod(method)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 6. Fallback
  return 'TIER_3_LIBRARY_API';
}

/**
 * Source-suppression predicate for callers that emit speculative taint
 * sources from method-parameter shape alone.
 *
 * Returns true iff the source should be DROPPED. Only fires on
 * `interprocedural_param` sources whose enclosing method classifies
 * as TIER_3_LIBRARY_API. LLM-discovered sources (which carry other
 * type tags) and statically-confirmed framework sources are never
 * gated by this predicate.
 *
 * Intentionally narrow: post-verify severity rubrics elsewhere in the
 * pipeline still apply to whatever passes this gate. The two filters
 * are layered, not overlapping.
 */
export function shouldGateInterproceduralParam(
  sourceType: string | null | undefined,
  enclosingMethod: MethodInfo | undefined,
  enclosingType: TypeInfo | undefined,
  ctx: EntryPointContext,
): boolean {
  if (sourceType !== 'interprocedural_param') return false;
  if (!enclosingMethod) return false; // can't classify → preserve recall
  const tier = classifyEntryPointTier(enclosingMethod, enclosingType, ctx);
  return tier === 'TIER_3_LIBRARY_API';
}

// ===========================================================================
// Polyglot classifiers (cognium-dev #237 — 3.166.0)
// ===========================================================================
//
// Java-primary Tier-1 detection has been in production since 3.128.0. The
// classifier is extended to Python / JS-TS / Go / Bash to close the ~14
// polyglot FP tail surfaced by the 2026-06 Tier-2 audit. Each classifier
// is designed to preserve recall on the OWASP BenchmarkPython
// (TPR ≥81.2% floor) / Express-family / net/http / Bash test corpora
// while identifying library-facade methods that should NOT be treated as
// trust boundaries.
//
// Common design:
//   1. Library-facade PATH short-circuit (`/lib/`, `/libapi/`, `/utils/`,
//      `/helpers/`, `/vendor/`, `/node_modules/`, test dirs) → TIER_3
//      before any framework check. Cheap, high-precision.
//   2. Framework Tier-1 detection using whatever signal is available
//      per-language (decorator strings, `RuntimeRegistration[]`, call
//      site walk, script-body scan).
//   3. Fallback: TIER_UNKNOWN — safer than TIER_3 for languages where
//      the classifier's negative signal is thin. `require-entry-path.ts`
//      applies an "empty-entry-point-keys → keep" safety guard for the
//      same reason.
//
// ---------------------------------------------------------------------------

/**
 * Path substrings that mark a file as a library / helper / vendored
 * dependency / test file — the enclosing method is invoked BY user
 * code, not AT a trust boundary. Shared across Python / JS-TS / Go /
 * Bash. Matched case-insensitively against the forward-slash-normalized
 * file path with sentinel slashes so `/lib/` matches `src/lib/x.py`
 * but not `src/library-not-quite/x.py`.
 */
const POLYGLOT_LIBRARY_PATH_FRAGMENTS: ReadonlyArray<string> = [
  '/lib/',
  '/libapi/',
  '/libs/',
  '/utils/',
  '/util/',
  '/helpers/',
  '/helper/',
  '/interop/',
  '/vendor/',
  '/vendored/',
  '/node_modules/',
  '/dist/',
  '/build/',
  '/_internal/',
  '/__tests__/',
  '/tests/',
  '/test/',
  '/testing/',
  '/spec/',
  '/specs/',
  '/fixtures/',
  '/mocks/',
  '/__mocks__/',
];

/**
 * Filename suffixes / substrings for test files. Matched against the
 * lowercased basename after the last `/`.
 */
const POLYGLOT_TEST_FILE_MARKERS: ReadonlyArray<string> = [
  '.test.',
  '.spec.',
  '_test.',
  '_spec.',
  '.tests.',
];

function pathLooksLikeLibraryOrTest(filePath: string | null | undefined): boolean {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const padded = `/${normalized}/`;
  for (const frag of POLYGLOT_LIBRARY_PATH_FRAGMENTS) {
    if (padded.includes(frag)) return true;
  }
  const slash = normalized.lastIndexOf('/');
  const base = slash >= 0 ? normalized.slice(slash + 1) : normalized;
  for (const marker of POLYGLOT_TEST_FILE_MARKERS) {
    if (base.includes(marker)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Python classifier
// ---------------------------------------------------------------------------

/**
 * Python decorator names (bare, without the leading `@` and any
 * dotted receiver) that mark a function as a framework entry point.
 * The classifier tolerates receiver prefixes (`app.route`,
 * `router.get`, `blueprint.post`) — see `pythonDecoratorLooksTier1`.
 *
 * Rationale — recall guard: this list covers Flask, FastAPI, Django
 * view decorators, Click/Typer CLI commands, and Celery/RQ task
 * handlers. OWASP BenchmarkPython is Flask-heavy — `route` alone
 * covers the majority.
 */
const PYTHON_TIER_1_DECORATOR_NAMES: ReadonlySet<string> = new Set([
  // Flask
  'route',
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'options',
  'head',
  'before_request',
  'after_request',
  'errorhandler',
  'teardown_request',
  // FastAPI
  'websocket',
  'websocket_route',
  'api_route',
  'middleware',
  // Django
  'login_required',
  'csrf_exempt',
  'csrf_protect',
  'require_http_methods',
  'require_GET',
  'require_POST',
  'require_safe',
  'permission_required',
  'user_passes_test',
  'staff_member_required',
  'api_view',
  'action',
  'detail_route',
  'list_route',
  'renderer_classes',
  'authentication_classes',
  'permission_classes',
  // Click / Typer
  'command',
  'group',
  // Celery / RQ / dramatiq
  'task',
  'shared_task',
  'periodic_task',
  'actor',
  // aiohttp
  'view',
  // pytest fixtures ARE library callback surfaces (test framework calls
  // them), so we mark them TIER_1 too — a taint sink inside a fixture
  // is genuinely reachable when the test runs.
  'fixture',
]);

/**
 * Classify a Python function.
 */
function classifyPythonEntryPoint(
  method: MethodInfo,
  enclosingType: TypeInfo | undefined,
  ctx: EntryPointContext,
): EntryPointTier {
  // 1. Library / test / vendored path → TIER_3.
  if (pathLooksLikeLibraryOrTest(ctx.filePath)) {
    return 'TIER_3_LIBRARY_API';
  }

  // 2. Decorator match. Python decorators are stored in
  //    `MethodInfo.annotations` by the core extractor (same channel Java
  //    uses). Tolerate `@app.route(...)`, `@blueprint.get(...)`, bare
  //    `@task`, etc.
  if (pythonDecoratorLooksTier1(method.annotations)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 3. RuntimeRegistration handler match. Phase-2 Python extractor
  //    populates `runtime_registrations` with resolved handler names
  //    for decorator-registered functions — reuse.
  if (methodIsRuntimeRegistrationHandler(method, ctx.runtimeRegistrations)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4. Module-level `main()` → TIER_1. This is the CLI-entry convention.
  //    `enclosingType === undefined` (or a synthesized module-scope type)
  //    means the function is at module top-level.
  if (method.name === 'main' && !enclosingType) {
    return 'TIER_1_ENTRY_POINT';
  }
  if (method.name === 'main' && enclosingType && looksLikeModuleType(enclosingType)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 5. Convention-private helper (`_foo`) → TIER_3 signal. Weak — only
  //    fires as TIER_3 when no framework signal was found.
  if (method.name.startsWith('_') && !method.name.startsWith('__')) {
    return 'TIER_3_LIBRARY_API';
  }

  // 6. Fallback — UNKNOWN keeps recall in the tail. `require-entry-path`
  //    only drops when the sink method classifies to a strong Tier via
  //    the classifier + reverse-BFS combination.
  return 'TIER_UNKNOWN';
}

function pythonDecoratorLooksTier1(annotations: string[] | undefined): boolean {
  if (!annotations || annotations.length === 0) return false;
  for (const raw of annotations) {
    // Strip leading `@`, argument list `(...)`, generic `<...>`.
    let name = raw.replace(/^@/, '').replace(/[<(].*$/, '').trim();
    if (!name) continue;
    // Take the last dotted segment: `app.route` → `route`,
    // `flask_restful.Api.add_resource` → `add_resource`.
    const dot = name.lastIndexOf('.');
    if (dot >= 0) name = name.slice(dot + 1);
    if (PYTHON_TIER_1_DECORATOR_NAMES.has(name)) return true;
  }
  return false;
}

function looksLikeModuleType(t: TypeInfo): boolean {
  // Python extractor emits module-level functions under a synthesized
  // container whose name matches the module (or is empty). Treat any
  // container with no `extends` / `implements` / annotations as a
  // module-scope wrapper.
  return (
    !t.extends &&
    (!t.implements || t.implements.length === 0) &&
    (!t.annotations || t.annotations.length === 0)
  );
}

// ---------------------------------------------------------------------------
// JS/TS classifier
// ---------------------------------------------------------------------------

/**
 * NestJS method-level decorator names. Match against the bare name
 * (leading `@` and `(args)` stripped).
 */
const JSTS_TIER_1_METHOD_DECORATORS: ReadonlySet<string> = new Set([
  // NestJS HTTP method decorators
  'Get', 'Post', 'Put', 'Delete', 'Patch', 'Head', 'Options', 'All',
  // NestJS WebSocket
  'SubscribeMessage', 'MessageBody', 'ConnectedSocket',
  // NestJS microservices / event
  'EventPattern', 'MessagePattern', 'GrpcMethod', 'GrpcStreamMethod',
  // Angular / other DI-registered handler hooks
  'HostListener',
]);

/**
 * NestJS class-level decorator names.
 */
const JSTS_TIER_1_CLASS_DECORATORS: ReadonlySet<string> = new Set([
  'Controller',
  'RestController',
  'Resolver',
  'WebSocketGateway',
  'Gateway',
]);

/**
 * Named exports that mark a file as a Lambda / Next.js App Router
 * route module. Matched against the method name when the enclosing
 * TypeInfo looks like a module-scope container.
 */
const JSTS_TIER_1_MODULE_EXPORTS: ReadonlySet<string> = new Set([
  // AWS Lambda / Google Cloud Functions / Netlify / Vercel
  'handler',
  // Next.js App Router — HTTP method exports
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
  // SvelteKit / Remix
  'load',
  'action',
  // Next.js middleware
  'middleware',
]);

function classifyJsTsEntryPoint(
  method: MethodInfo,
  enclosingType: TypeInfo | undefined,
  ctx: EntryPointContext,
): EntryPointTier {
  // 1. Library / test / vendored path → TIER_3.
  if (pathLooksLikeLibraryOrTest(ctx.filePath)) {
    return 'TIER_3_LIBRARY_API';
  }

  // 2. NestJS method-level decorator.
  if (annotationsInclude(method.annotations, JSTS_TIER_1_METHOD_DECORATORS)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 3. NestJS class-level decorator (every public method of a
  //    controller is TIER_1).
  if (enclosingType && annotationsInclude(enclosingType.annotations, JSTS_TIER_1_CLASS_DECORATORS)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4. Phase-1 RuntimeRegistration handler match. Covers
  //    Express (`app.get`, `router.post`, `app.use`), Fastify,
  //    Koa, EventEmitter (`.on`).
  if (methodIsRuntimeRegistrationHandler(method, ctx.runtimeRegistrations)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4.5. File-level TIER_1 escalation (cognium-dev #252 workaround).
  //      The JS/TS extractor currently doesn't surface anonymous
  //      arrow / function-expression handlers as MethodInfo records,
  //      so `runtime_registrations.handler.name` comes back as `null`
  //      for the common `app.get('/x', (req, res) => …)` shape.
  //      Without this escalation, files that ARE framework entry
  //      points contribute zero TIER_1 keys, the per-language safety
  //      guard in `require-entry-path.ts` fires, and every JS finding
  //      is kept — including obviously-orphan library-file findings.
  //
  //      Fallback rule: if the file has ≥1 http_route / middleware /
  //      event_listener registration attributable to a known web
  //      framework, treat every module-scope function in that file
  //      as TIER_1. False positives from this rule are recall wins
  //      (module-scope helpers in a route file ARE reachable from a
  //      trust boundary); the drop path from `require-entry-path`
  //      still requires BFS reachability, so unrelated files are
  //      unaffected.
  if (
    fileHasJsTsFrameworkRegistration(ctx.runtimeRegistrations) &&
    (!enclosingType || looksLikeModuleType(enclosingType))
  ) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 5. Module-level named-export entry point (Lambda `handler`,
  //    Next.js `GET`, SvelteKit `load`, …).
  if (JSTS_TIER_1_MODULE_EXPORTS.has(method.name) && (!enclosingType || looksLikeModuleType(enclosingType))) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 6. Convention: `main()` at module scope → TIER_1.
  if (method.name === 'main' && (!enclosingType || looksLikeModuleType(enclosingType))) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 7. Fallback — UNKNOWN keeps recall.
  return 'TIER_UNKNOWN';
}

/**
 * JS/TS framework labels whose presence in a `runtime_registrations[]`
 * entry means the enclosing file is a framework entry-point host.
 * Kept narrow — only web / RPC frameworks whose handlers process
 * external input.
 */
const JSTS_FILE_LEVEL_TIER_1_FRAMEWORKS: ReadonlySet<string> = new Set([
  'express',
  'fastify',
  'koa',
  'nestjs',
]);

function fileHasJsTsFrameworkRegistration(
  regs: ReadonlyArray<RuntimeRegistration> | null | undefined,
): boolean {
  if (!regs || regs.length === 0) return false;
  for (const reg of regs) {
    if (
      reg.kind !== 'http_route' &&
      reg.kind !== 'middleware' &&
      reg.kind !== 'event_listener'
    ) {
      continue;
    }
    if (reg.framework && JSTS_FILE_LEVEL_TIER_1_FRAMEWORKS.has(reg.framework)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Go classifier
// ---------------------------------------------------------------------------

/**
 * Method / function names on receivers that register HTTP handlers.
 * Matched against `CallInfo.method_name` when the receiver looks like
 * a Go HTTP framework (see `GO_HTTP_REGISTRAR_RECEIVERS`).
 */
const GO_HTTP_REGISTRAR_METHODS: ReadonlySet<string> = new Set([
  // net/http
  'HandleFunc', 'Handle',
  // gorilla/mux, chi, echo, gin
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'Any',
  'Get', 'Post', 'Put', 'Delete', 'Patch', 'Head', 'Options',
  // gorilla/chi/gin sub-routers
  'Route', 'Mount', 'Method',
]);

/**
 * Receiver expressions that indicate an HTTP router / mux / gin
 * engine / echo group / chi router. Simple string match on the
 * `CallInfo.receiver` field.
 */
const GO_HTTP_REGISTRAR_RECEIVERS: ReadonlyArray<string> = [
  'http',       // net/http.HandleFunc
  'mux',        // gorilla/mux
  'router',     // chi/gin/gorilla common
  'r',          // gin/chi convention
  'e',          // echo convention
  'g',          // gin group convention
  'app',        // fiber convention
  'engine',     // gin engine convention
  'srv', 'server',
];

/**
 * Classify a Go function.
 */
function classifyGoEntryPoint(
  method: MethodInfo,
  enclosingType: TypeInfo | undefined,
  ctx: EntryPointContext,
): EntryPointTier {
  // 1. Library / test / vendored path → TIER_3. `_test.go` is picked
  //    up by the shared test-marker set below (Go test naming convention).
  if (pathLooksLikeLibraryOrTest(ctx.filePath)) {
    return 'TIER_3_LIBRARY_API';
  }
  // Go-specific test naming: `*_test.go`.
  if (ctx.filePath && ctx.filePath.toLowerCase().endsWith('_test.go')) {
    return 'TIER_3_LIBRARY_API';
  }

  // 2. `main` in `main` package → TIER_1. Go's package is per-file
  //    stored on `TypeInfo.package` for the synthesized module type.
  if (method.name === 'main' && enclosingType?.package === 'main') {
    return 'TIER_1_ENTRY_POINT';
  }

  // 3. Function signature shape:
  //      func(w http.ResponseWriter, r *http.Request)
  //    matches the net/http handler contract. Robust across router
  //    frameworks that adapt the same signature.
  if (methodHasNetHttpHandlerSignature(method)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4. gRPC handler convention:
  //      func (s *server) MethodName(ctx context.Context, req *pb.Req) (*pb.Resp, error)
  //    Weak signal alone; require receiver look like `*Server` + first
  //    param be `context.Context`.
  if (methodLooksLikeGrpcHandler(method, enclosingType)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 5. `ir.calls` walk — was this function registered via
  //    `http.HandleFunc`, `router.GET`, etc. anywhere in the file?
  //    We match the registrar call's second argument (handler
  //    identifier) against the method name.
  if (methodIsRegisteredByGoHttpFramework(method, ctx.calls)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 6. Fallback — UNKNOWN keeps recall.
  return 'TIER_UNKNOWN';
}

function methodHasNetHttpHandlerSignature(method: MethodInfo): boolean {
  const params = method.parameters ?? [];
  if (params.length !== 2) return false;
  const p0 = normalizeGoType(params[0]?.type ?? '');
  const p1 = normalizeGoType(params[1]?.type ?? '');
  const p0IsWriter = p0.includes('http.ResponseWriter') || p0.endsWith('ResponseWriter');
  const p1IsRequest = p1.includes('http.Request') || p1.endsWith('*Request') || p1.endsWith('Request');
  return p0IsWriter && p1IsRequest;
}

function methodLooksLikeGrpcHandler(method: MethodInfo, enclosingType: TypeInfo | undefined): boolean {
  if (!enclosingType) return false;
  const params = method.parameters ?? [];
  if (params.length < 2) return false;
  const p0 = normalizeGoType(params[0]?.type ?? '');
  if (!p0.includes('context.Context') && !p0.endsWith('Context')) return false;
  const typeName = enclosingType.name ?? '';
  // Common gRPC server struct suffixes.
  if (!/(Server|Service|Handler)$/.test(typeName)) return false;
  return true;
}

function normalizeGoType(t: string): string {
  return t.replace(/\s+/g, '').replace(/^\*+/, '');
}

function methodIsRegisteredByGoHttpFramework(
  method: MethodInfo,
  calls: ReadonlyArray<CallInfo> | null | undefined,
): boolean {
  if (!calls || calls.length === 0) return false;
  for (const call of calls) {
    if (!GO_HTTP_REGISTRAR_METHODS.has(call.method_name)) continue;
    const receiver = call.receiver ?? '';
    if (!goRegistrarReceiverMatches(receiver)) continue;
    const args = call.arguments ?? [];
    // net/http.HandleFunc(pattern, handler)  → handler is arg 1.
    // router.GET(pattern, handler)           → handler is arg 1.
    // Variadic chi middleware chains put handler last; scan every arg.
    for (const arg of args) {
      const expr = (arg.expression ?? arg.variable ?? arg.value ?? '').trim();
      if (!expr) continue;
      // Strip package qualifier (`pkg.Handler` → `Handler`).
      const short = expr.slice(expr.lastIndexOf('.') + 1);
      if (short === method.name) return true;
    }
  }
  return false;
}

function goRegistrarReceiverMatches(receiver: string): boolean {
  const trimmed = receiver.trim();
  if (!trimmed) return false;
  for (const target of GO_HTTP_REGISTRAR_RECEIVERS) {
    if (trimmed === target) return true;
    // Method-chain suffix (`app.Group("/api")` → subsequent receiver
    // is a Group value that still holds a router; be permissive).
    if (trimmed.endsWith(`.${target}`)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Bash classifier
// ---------------------------------------------------------------------------

/**
 * Positional-parameter tokens whose presence in the script body
 * indicates the script consumes command-line arguments — a real
 * entry point from the OS's perspective.
 */
const BASH_POSITIONAL_TOKENS: ReadonlyArray<string> = [
  '$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8', '$9',
  '$@', '$*', '$#',
  '${1', '${2', '${3', '${@',
  'getopts',
];

/**
 * Filename prefixes that mark a script as a benign / safe fixture
 * (per the ticket's `benign_*.sh` corpus convention) or a helper
 * library that is `source`d from another script.
 */
const BASH_LIBRARY_FILENAME_PREFIXES: ReadonlyArray<string> = [
  'benign_',
  'safe_',
  'lib_',
  'common_',
  'helpers_',
  '_',
];

function classifyBashEntryPoint(
  method: MethodInfo,
  enclosingType: TypeInfo | undefined,
  ctx: EntryPointContext,
): EntryPointTier {
  // 1. Library / test / vendored path → TIER_3.
  if (pathLooksLikeLibraryOrTest(ctx.filePath)) {
    return 'TIER_3_LIBRARY_API';
  }

  // 2. Benign / safe / library filename prefix → TIER_3.
  if (bashFilenameLooksLikeLibrary(ctx.filePath)) {
    return 'TIER_3_LIBRARY_API';
  }

  // 3. `main()` function → TIER_1. Bash convention: script-body
  //    dispatches to `main "$@"`.
  if (method.name === 'main') {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4. Positional-parameter use scan — walk `ir.calls` in this
  //    method's line range and look for `$1` / `$@` / `getopts` in
  //    argument text. If the method reads positional args, it IS
  //    the entry point.
  if (methodConsumesPositionalArgs(method, ctx.calls)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 5. Script-body top-level → the enclosing "method" for Bash is
  //    typically the file-level statement block. If we're in the
  //    module-scope container and the file has ANY positional-arg
  //    use, treat as TIER_1.
  if (enclosingType && looksLikeModuleType(enclosingType) && fileHasPositionalArgUse(ctx.calls)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 6. Fallback — UNKNOWN keeps recall.
  return 'TIER_UNKNOWN';
}

function bashFilenameLooksLikeLibrary(filePath: string | null | undefined): boolean {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/');
  const slash = normalized.lastIndexOf('/');
  const base = (slash >= 0 ? normalized.slice(slash + 1) : normalized).toLowerCase();
  for (const prefix of BASH_LIBRARY_FILENAME_PREFIXES) {
    if (base.startsWith(prefix)) return true;
  }
  // `.test.sh` / `_test.sh` — test scripts.
  if (base.includes('.test.') || base.includes('_test.')) return true;
  return false;
}

function methodConsumesPositionalArgs(
  method: MethodInfo,
  calls: ReadonlyArray<CallInfo> | null | undefined,
): boolean {
  if (!calls || calls.length === 0) return false;
  for (const call of calls) {
    if (call.location.line < method.start_line) continue;
    if (call.location.line > method.end_line) continue;
    if (callHasPositionalToken(call)) return true;
  }
  return false;
}

function fileHasPositionalArgUse(calls: ReadonlyArray<CallInfo> | null | undefined): boolean {
  if (!calls || calls.length === 0) return false;
  for (const call of calls) {
    if (callHasPositionalToken(call)) return true;
  }
  return false;
}

function callHasPositionalToken(call: CallInfo): boolean {
  // Check argument text for `$1` / `$@` / `getopts`.
  for (const arg of call.arguments ?? []) {
    const expr = arg.expression ?? arg.variable ?? arg.value ?? '';
    for (const tok of BASH_POSITIONAL_TOKENS) {
      if (expr.includes(tok)) return true;
    }
  }
  // Also check method_name — `getopts` shows up as a call.
  if (call.method_name === 'getopts') return true;
  return false;
}

// ---------------------------------------------------------------------------
// Shared runtime-registration handler lookup
// ---------------------------------------------------------------------------

/**
 * Returns true when `method` is the named handler for any HTTP-route
 * / event-listener registration recorded in
 * `ctx.runtimeRegistrations`. Handler name match is exact — inline
 * arrow / anonymous handlers (`handler.name === null`) do not
 * match any named method and are ignored.
 */
function methodIsRuntimeRegistrationHandler(
  method: MethodInfo,
  regs: ReadonlyArray<RuntimeRegistration> | null | undefined,
): boolean {
  if (!regs || regs.length === 0) return false;
  for (const reg of regs) {
    // Only http_route / decorator / event_listener kinds mark a method
    // as an entry point. `trait_impl` is a Rust-only concept and
    // `middleware` alone is weak (framework middlewares often wrap
    // library code) — include middleware because our engine treats it
    // as a boundary.
    if (
      reg.kind !== 'http_route' &&
      reg.kind !== 'decorator' &&
      reg.kind !== 'event_listener' &&
      reg.kind !== 'middleware'
    ) {
      continue;
    }
    const handlerName = reg.handler?.name;
    if (!handlerName) continue;
    if (handlerName === method.name) return true;
  }
  return false;
}
