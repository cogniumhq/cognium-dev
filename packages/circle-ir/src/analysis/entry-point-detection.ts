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
 * # Reference
 *
 * - cognium-dev#128 — entry-point-anchored taint sources.
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
]);

/**
 * Class-level annotations that make every public method of the class
 * a Tier 1 entry point. Spring MVC / JAX-RS / Servlet 3 conventions.
 */
const TIER_1_CLASS_ANNOTATIONS = new Set([
  // Spring MVC
  'RestController',
  'Controller',
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
]);

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
 *   2. Method-level annotation match → TIER_1.
 *   3. Class-level annotation match → TIER_1.
 *   4. Supertype lifecycle method match → TIER_1.
 *   5. `main(String[])` signature → TIER_1.
 *   6. Tier 2 reachability (not implemented in ship 1).
 *   7. Fallback → TIER_3_LIBRARY_API.
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

  // 6. Tier 2 reachability — deferred. See header doc.
  // (Intentionally no fall-through here; ctx.callGraph is reserved.)

  // 7. Fallback
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
