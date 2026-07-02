/**
 * Types for YAML configuration files (configs/sources/, configs/sinks/)
 */

import type { SarifLevel, Severity, SinkType, SourceType, SupportedLanguage } from './index.js';

// =============================================================================
// Source Configuration (configs/sources/*.yaml)
// =============================================================================

export interface SourceConfig {
  sources: SourcePattern[];
}

export interface SourcePattern {
  // Method-based source (Java style: request.getParameter())
  method?: string;
  class?: string;

  // Property-based source (JS style: req.params, req.query)
  property?: string;         // Property name (e.g., 'params', 'query', 'body')
  object?: string;           // Object name (e.g., 'req', 'request')

  // Annotation-based source — annotation appears on a parameter
  // (e.g. Spring @RequestParam, JAX-RS @QueryParam). Pair with `param_tainted`.
  annotation?: string;

  // Annotation-based source — annotation appears on a method/constructor;
  // ALL its parameters are tainted (e.g. Jenkins @DataBoundConstructor).
  method_annotation?: string;

  type: SourceType;
  severity: Severity;

  // Which part is tainted
  return_tainted?: boolean;  // Return value is tainted
  param_tainted?: boolean;   // Annotated parameter is tainted
  property_tainted?: boolean; // Property access is tainted (for JS)

  /**
   * Restrict the pattern to specific source languages. When omitted, the
   * pattern matches regardless of language. Use this for sources whose
   * method name collides across language ecosystems (e.g. Rust Axum's
   * `Path<T>` extractor vs Python's `pathlib.Path` constructor).
   */
  languages?: SupportedLanguage[];

  note?: string;
}

// =============================================================================
// Sink Configuration (configs/sinks/*.yaml)
// =============================================================================

export interface SinkConfig {
  sinks: SinkPattern[];
  sanitizers?: SanitizerPattern[];
}

export interface SinkPattern {
  method: string;
  class?: string;
  type: SinkType;
  cwe: string;
  severity: Severity;
  arg_positions: number[];  // Which arguments are dangerous (0-indexed)
  /**
   * Restrict the pattern to specific source languages. When omitted, the
   * pattern matches calls regardless of language. Use this for sinks whose
   * method name collides across language ecosystems (e.g. Python/Rust
   * `cursor.execute()` vs Java `Executor.execute()`).
   */
  languages?: SupportedLanguage[];
  /**
   * Suppress the sink when the argument at the given 0-indexed position is a
   * class literal (e.g. `Foo.class`, `com.example.Bar.class`). Used by
   * deserialization sinks whose typed overload — `ObjectMapper.readValue(json,
   * User.class)`, `Gson.fromJson(json, User.class)`, `JSON.parseObject(json,
   * User.class)` — is safe because the deserialized type is fixed at compile
   * time. The untyped overload (1 arg) and the dynamic overload
   * (`Class.forName(...)`, `getClass()`, any non-literal expression) remain
   * dangerous and still match.
   */
  safe_if_class_literal_at?: number;
  /**
   * When true, the sink matches even if `receiver_type` is unresolved at the
   * call site, provided the receiver expression is a dotted property chain
   * (e.g. `req.db.query`, `ctx.app.db.execute`). This handles Express-style
   * runtime decoration where middleware attaches a DB client to the request
   * object — the static type is opaque but the call shape is unambiguous.
   * Use sparingly: each opt-in entry widens the FP surface. (cognium-dev #95)
   */
  allow_unresolved_receiver?: boolean;
  note?: string;
}

export interface SanitizerPattern {
  method?: string;
  class?: string;
  annotation?: string;
  removes: SinkType[];  // Which sink types this sanitizes
  note?: string;
}

// =============================================================================
// Sink-Semantics Registry (configs/sink-semantics.json) — cognium-dev #139
// =============================================================================

/**
 * Sink-semantics registry entry. Maps a `<ClassName>#<methodName>`
 * signature to the real-behavior class of the sink and the list of
 * `SinkType` values that must be dropped when a sink with that
 * signature is emitted with that type.
 *
 * See `docs/PASSES.md` #109 (`sink-semantics`) and cognium-dev #139
 * for the rationale and the seed entries.
 */
export interface SinkSemanticsEntry {
  /**
   * `<ClassName>#<methodName>` — simple names only. Match is
   * case-sensitive; class is compared to `sink.class` (the
   * simple-name tail of `call.receiver_type`).
   */
  signature: string;

  /**
   * Informational label for the sink's real behavior. One of:
   *   - `db_protocol`         — DB driver wire-protocol serialization
   *   - `jdk_internal`        — JDK-internal reflective bridge
   *   - `functional_dispatch` — RxJava / Function.apply dispatch
   *   - `admin_config`        — admin-configured binary path
   *   - `logging`             — logging/observability sink
   *
   * Not consumed at runtime; documents intent for contributors.
   */
  real_class:
    | 'db_protocol'
    | 'jdk_internal'
    | 'functional_dispatch'
    | 'admin_config'
    | 'logging';

  /**
   * `SinkType` values to drop for this signature. When a sink's
   * `type` field appears in this list AND the signature matches,
   * the sink is removed from `graph.ir.taint.sinks` before flow
   * generation runs.
   */
  overrides: SinkType[];

  note?: string;
}

export interface SinkSemanticsConfig {
  sinks: SinkSemanticsEntry[];
}

// =============================================================================
// Combined Config (loaded at runtime)
// =============================================================================

export interface TaintConfig {
  sources: SourcePattern[];
  sinks: SinkPattern[];
  sanitizers: SanitizerPattern[];
  /**
   * Optional sink-semantics registry (cognium-dev #139 Tier A). When
   * present, `SinkSemanticsPass` consults it to drop sinks whose
   * `type` label disagrees with the registry's declared
   * `real_class`. Omitting this field disables the gate — no sink
   * is dropped.
   */
  sinkSemantics?: SinkSemanticsEntry[];
}

// =============================================================================
// Security Headers Rules
// =============================================================================

/**
 * A rule evaluated by SecurityHeadersPass against HTTP response header
 * writes (setHeader/addHeader) and handler presence. Emits SastFindings
 * without going through the taint source→sink machinery, since headers
 * are a call-site literal inspection problem, not a data-flow problem.
 */
export interface HeaderRule {
  /** Rule id (matches docs/PASSES.md rule_id column). */
  rule_id: string;
  /** CWE identifier (e.g. 'CWE-1021', 'CWE-346', 'CWE-942'). */
  cwe: string;
  /** SARIF level: 'error' | 'warning' | 'note' | 'none'. */
  level: SarifLevel;
  /** Severity bucket: 'critical' | 'high' | 'medium' | 'low'. */
  severity: Severity;
  /** HTTP response header this rule applies to (case-insensitive). */
  header: string;
  /**
   * Rule kind:
   *  - 'missing'       → file has an HTTP handler but never writes this header
   *  - 'weak-value'    → header written with a value matching `matcher`
   *                      (e.g. 'ALLOW-FROM', 'null', 'http://…')
   *  - 'unsafe-value'  → value is dynamic / reflected (not a string literal)
   */
  kind: 'missing' | 'weak-value' | 'unsafe-value';
  /**
   * Value pattern for 'weak-value' rules. Matched against the literal
   * second argument of setHeader/addHeader (case-insensitive).
   */
  valuePattern?: RegExp;
  /**
   * If true (the default for kind='missing'), the rule only fires when
   * the file contains at least one HTTP handler (annotated controller
   * method, Express/Koa route, Rust extractor, etc.). Prevents noise on
   * library code, configuration files, and tests.
   */
  requiresHandler?: boolean;
  /** Human-readable message (header name interpolated with ${header}). */
  message: string;
  /** Suggested fix rendered into SastFinding.fix. */
  fix?: string;
  /** Optional note for PASSES.md / debugging. */
  note?: string;
}
