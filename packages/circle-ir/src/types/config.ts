/**
 * Types for YAML configuration files (configs/sources/, configs/sinks/)
 */

import type { SarifLevel, Severity, SinkType, SourceType } from './index.js';

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

  // Annotation-based source
  annotation?: string;

  type: SourceType;
  severity: Severity;

  // Which part is tainted
  return_tainted?: boolean;  // Return value is tainted
  param_tainted?: boolean;   // Annotated parameter is tainted
  property_tainted?: boolean; // Property access is tainted (for JS)

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
// Combined Config (loaded at runtime)
// =============================================================================

export interface TaintConfig {
  sources: SourcePattern[];
  sinks: SinkPattern[];
  sanitizers: SanitizerPattern[];
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
