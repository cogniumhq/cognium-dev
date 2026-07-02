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

import type { TypeInfo, MethodInfo } from '../types/index.js';

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
  // Ship 1: Java only. Other languages route via UNKNOWN = pass-through.
  const language = (ctx.language ?? '').toLowerCase();
  if (language !== 'java') return 'TIER_UNKNOWN';

  if (!method) return 'TIER_UNKNOWN';

  // 2. Library-facade short-circuit. Runs BEFORE Tier-1 annotation
  // detection — see `classShapeIsLibraryFacade` for the trade-off.
  if (classShapeIsLibraryFacade(enclosingType)) {
    return 'TIER_3_LIBRARY_API';
  }

  // 3. Method-level annotation
  if (annotationsInclude(method.annotations, TIER_1_METHOD_ANNOTATIONS)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 4. Class-level annotation (every public method of a controller is TIER_1)
  if (enclosingType && annotationsInclude(enclosingType.annotations, TIER_1_CLASS_ANNOTATIONS)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 5. Supertype lifecycle method
  if (methodIsSupertypeLifecycleEntryPoint(method, enclosingType)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 6. `public static void main(String[])`
  if (looksLikeMainMethod(method)) {
    return 'TIER_1_ENTRY_POINT';
  }

  // 7. Tier 2 reachability — deferred. See header doc.
  // (Intentionally no fall-through here; ctx.callGraph is reserved.)

  // 8. Fallback
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
