/**
 * cognium-dev #256 — same-file argument-type resolver.
 *
 * Two sink-shape gates ship in circle-ir today match only the DIRECT/LITERAL
 * argument form and miss argument indirection:
 *
 *   1. `safe_if_class_literal_at` (taint-matcher.ts, #22) — matches
 *      `readValue(json, Foo.class)` but not `readValue(json, templateClass)`
 *      where `templateClass` is a `Class<T>` parameter.
 *   2. Stage-11 `PROCESS_BUILDER_ARGV_FORM_RE` (sink-filter-pass.ts, #179)
 *      matches `new ProcessBuilder(Arrays.asList(...))` but not
 *      `new ProcessBuilder(buildCommand(...))` where `buildCommand` returns
 *      `List<String>`.
 *
 * This module provides two pure, same-file, `TypeInfo[]`-based helpers to
 * resolve the effective type of an argument that is either:
 *   - a bare identifier (parameter or field name), or
 *   - a method-call expression (callee name).
 *
 * Same-file only — locals declared inside method bodies and cross-file
 * resolutions are deferred. Both #256 repros (jib, flyingsaucer) are
 * same-method-parameter / same-class-static-callee, so this scope suffices.
 *
 * Design guarantee: both resolvers return null liberally. A null return
 * flows to the existing gate's default-dangerous behavior (sink fires) —
 * so any resolver bug regresses gracefully to current (over-firing)
 * behavior, never to false-negative.
 */

import type { TypeInfo } from '../types/index.js';

/**
 * Locate the TypeInfo whose `methods` list contains a method named
 * `callInMethod`. Falls back to `null` if not found (e.g. top-level
 * function, or method name collision that our best-effort match misses).
 */
function findEnclosingType(
  callInMethod: string | null | undefined,
  types: TypeInfo[],
): TypeInfo | null {
  if (!callInMethod) return null;
  for (const t of types) {
    for (const m of t.methods) {
      if (m.name === callInMethod) return t;
    }
  }
  return null;
}

/**
 * Resolve the declared type of a bare-identifier argument (parameter or
 * field) visible at `callInMethod` scope.
 *
 * Lookup order:
 *   1. Parameters of the enclosing method (matching `callInMethod`).
 *   2. Fields of the enclosing type (any visibility).
 *   3. If enclosing type not found, scan ALL types' method params + fields
 *      (best-effort for top-level functions or method-name collisions).
 *
 * Returns the raw type string as extracted (`"Class<T>"`, `"List<String>"`,
 * `"java.util.List<String>"`, `"Class<? extends JsonTemplate>"`, …) or null.
 */
export function resolveIdentifierType(
  name: string,
  callInMethod: string | null | undefined,
  types: TypeInfo[],
): string | null {
  if (!name) return null;
  const enclosing = findEnclosingType(callInMethod, types);
  if (enclosing) {
    // Parameter check (preferred — narrower scope, shadows fields).
    for (const m of enclosing.methods) {
      if (m.name !== callInMethod) continue;
      for (const p of m.parameters) {
        if (p.name === name && p.type) return p.type;
      }
    }
    // Field check on the enclosing type.
    for (const f of enclosing.fields) {
      if (f.name === name && f.type) return f.type;
    }
    return null;
  }
  // Fallback: scan all types (top-level function case, or extractor didn't
  // populate `in_method` reliably for this language).
  for (const t of types) {
    for (const m of t.methods) {
      for (const p of m.parameters) {
        if (p.name === name && p.type) return p.type;
      }
    }
    for (const f of t.fields) {
      if (f.name === name && f.type) return f.type;
    }
  }
  return null;
}

/**
 * Resolve the declared return type of a same-file method invoked by
 * `calleeName`. Accepts a bare callee name (as extracted into
 * `ArgumentInfo.variable` for call expressions like `buildCommand(x, y)`).
 *
 * Preference order:
 *   1. Method on the enclosing type matching `callInMethod`.
 *   2. Method on any type in the file (static call `MyClass.foo()` case).
 *
 * Overload handling: if the enclosing type has multiple methods with the
 * same name, returns the first one whose `return_type` is non-null. Full
 * overload resolution would need argument-expression typing that we don't
 * have; ambiguity is rare in practice and biases toward null (which
 * flows to the current default-dangerous behavior).
 */
export function resolveCallReturnType(
  calleeName: string,
  callInMethod: string | null | undefined,
  types: TypeInfo[],
): string | null {
  if (!calleeName) return null;
  const enclosing = findEnclosingType(callInMethod, types);
  if (enclosing) {
    for (const m of enclosing.methods) {
      if (m.name === calleeName && m.return_type) return m.return_type;
    }
  }
  // Fallback: any type in file. Static calls / helper classes.
  for (const t of types) {
    for (const m of t.methods) {
      if (m.name === calleeName && m.return_type) return m.return_type;
    }
  }
  return null;
}

/**
 * true when the raw type string represents a Java `Class` type (any bound):
 * `Class`, `Class<T>`, `Class<? extends X>`, `Class<Foo>`, `java.lang.Class<...>`.
 *
 * NEVER matches:
 *   - `Class.forName(x)` — that's a call expression, not a declared type;
 *      lookups against `ir.types` won't find it (JDK reflection isn't
 *      user code).
 *   - `getClass()` return type — for the same reason.
 *   - Raw types missing generic bounds are Jackson-safe in the same way
 *     as the generic form: a bare `Class` param still has a compile-time
 *     type identity, so we accept it.
 */
export function isBoundedClassType(rawType: string | null): boolean {
  if (!rawType) return false;
  const stripped = rawType.trim().replace(/^(?:java\.lang\.)+/, '');
  return /^Class(?:\s*<[\s\S]*>)?$/.test(stripped);
}

/**
 * true when the raw type resolves to a container shape that
 * `ProcessBuilder(argv)` accepts as non-exploitable — the JVM passes the
 * elements to `fork(2)` directly, no shell interpolation:
 *
 *   - `List<String>` (any parameterization narrower than `Object`)
 *   - `ArrayList<String>`, `LinkedList<String>`
 *   - `Collection<String>`, `Iterable<String>`, `Deque<String>`, `Queue<String>`
 *   - `String[]`, `String ...` (varargs)
 *   - Fully qualified variants: `java.util.List<String>`, etc.
 *
 * Excludes bare `List` / `List<Object>` / `Collection<?>` — those permit
 * arbitrary element types that could carry non-String content the JVM
 * would `.toString()` unsafely.
 */
export function isArgvContainerType(rawType: string | null): boolean {
  if (!rawType) return false;
  const s = rawType.trim().replace(/^(?:java\.util\.|java\.lang\.)+/, '');
  // String[] or String...
  if (/^String\s*(?:\[\s*\]|\.\.\.)$/.test(s)) return true;
  // Container<String>-like — permit CharSequence too (String subtype narrower
  // than Object). Reject `<?>`, `<? extends Object>`, bare `<Object>`.
  return /^(?:List|ArrayList|LinkedList|Collection|Iterable|Deque|Queue)\s*<\s*(?:String|CharSequence|java\.lang\.String)\b/.test(
    s,
  );
}
