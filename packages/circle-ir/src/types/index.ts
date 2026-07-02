/**
 * Circle-IR 3.0 TypeScript Type Definitions
 *
 * These types conform to docs/SPEC.md
 */

// =============================================================================
// 1. Meta
// =============================================================================

export type SupportedLanguage = "java" | "c" | "cpp" | "javascript" | "typescript" | "tsx" | "python" | "rust" | "bash" | "html" | "vue" | "go";

export interface Meta {
  circle_ir: "3.0";
  file: string;
  language: SupportedLanguage;
  loc: number;
  hash: string;  // SHA256 prefix (16 chars)
  package?: string;
}

// =============================================================================
// 2. Types (Classes, Interfaces, Enums)
// =============================================================================

export interface TypeInfo {
  name: string;
  kind: "class" | "interface" | "enum";
  package: string | null;
  extends: string | null;
  implements: string[];
  annotations: string[];
  methods: MethodInfo[];
  fields: FieldInfo[];
  start_line: number;
  end_line: number;
}

export interface MethodInfo {
  name: string;
  return_type: string | null;
  parameters: ParameterInfo[];
  annotations: string[];
  modifiers: string[];  // ["public", "static", etc.]
  start_line: number;
  end_line: number;
}

export interface ParameterInfo {
  name: string;
  type: string | null;
  annotations: string[];  // ["RequestParam", "PathVariable", etc.]
  line?: number;  // Line number where parameter is defined (for taint tracking)
}

export interface FieldInfo {
  name: string;
  type: string | null;
  modifiers: string[];
  annotations: string[];
}

// =============================================================================
// 3. Calls
// =============================================================================

export interface CallInfo {
  method_name: string;
  receiver: string | null;
  /**
   * Resolved class/interface name of the receiver — the simple type name
   * the receiver expression was declared as (local variable type, method
   * parameter type, field type, or static class). `null` when the receiver
   * cannot be resolved (dynamic dispatch, complex expression, missing decl).
   */
  receiver_type?: string | null;
  /**
   * Fully-qualified name of `receiver_type` when resolvable via the file's
   * import declarations or by being declared in the same package. `null`
   * when the simple type was resolved but its FQN cannot be determined
   * (e.g. wildcard imports, same-package types without explicit imports).
   */
  receiver_type_fqn?: string | null;
  arguments: ArgumentInfo[];
  location: {
    line: number;
    column: number;
  };
  in_method?: string | null;
  is_constructor?: boolean;
  // PENDING: Call resolution
  resolved?: boolean;
  resolution?: CallResolution;
}

export interface ArgumentInfo {
  position: number;  // 0-indexed
  expression: string;  // Full expression text
  variable?: string | null;  // Variable name if simple reference
  literal?: string | null;  // Literal value if constant
  value?: string | null;  // Argument value (for simple values)
}

export interface CallResolution {
  status: "resolved" | "external_method" | "interface_method" | "reflection";
  target?: string;  // Fully qualified method name
  candidates?: string[];  // For interface/virtual dispatch
}

// =============================================================================
// 4. CFG (Control Flow Graph)
// =============================================================================

export interface CFG {
  blocks: CFGBlock[];
  edges: CFGEdge[];
}

export interface CFGBlock {
  id: number;
  type: "entry" | "exit" | "normal" | "conditional" | "loop";
  start_line: number;
  end_line: number;
}

export interface CFGEdge {
  from: number;
  to: number;
  type: "sequential" | "true" | "false" | "exception" | "back" | "break" | "continue";
}

// =============================================================================
// 5. DFG (Data Flow Graph)
// =============================================================================

export interface DFG {
  defs: DFGDef[];
  uses: DFGUse[];
  chains?: DFGChain[];  // PENDING
}

export interface DFGDef {
  id: number;
  variable: string;
  line: number;
  column?: number;
  kind: "param" | "local" | "field" | "return";
  expression?: string;
}

export interface DFGUse {
  id: number;
  variable: string;
  line: number;
  column?: number;
  def_id: number | null;  // Reaching definition
}

export interface DFGChain {
  from_def: number;  // Definition ID
  to_def: number;  // Downstream definition ID
  via: string;  // Variable name
}

// =============================================================================
// 6. Taint
// =============================================================================

export interface Taint {
  sources: TaintSource[];
  sinks: TaintSink[];
  sanitizers?: TaintSanitizer[];
  flows?: TaintFlowInfo[];  // Verified dataflow paths from sources to sinks
  interprocedural?: InterproceduralInfo;  // Cross-method taint tracking
}

export interface InterproceduralInfo {
  tainted_methods: string[];  // Methods that handle tainted data
  taint_bridges: string[];  // Methods that receive and propagate taint
  method_flows: MethodTaintFlow[];  // Taint flow through method calls
}

export interface MethodTaintFlow {
  caller: string;
  callee: string;
  call_line: number;
  tainted_args: number[];  // Argument positions that are tainted
  returns_taint: boolean;
}

export interface TaintFlowInfo {
  source_line: number;
  sink_line: number;
  source_type: SourceType;
  sink_type: SinkType;
  path: TaintFlowStep[];
  confidence: number;
  sanitized: boolean;
  /**
   * Optional metadata tags carried from the originating `TaintSink` (added
   * in 3.105.0). Used by CLI/SARIF consumers for policy-aware presentation
   * (e.g. `'library-api-surface:caller-responsibility'` causes a severity
   * downgrade to MEDIUM and a `[library-api-surface]` text badge).
   */
  tags?: string[];
}

export interface TaintFlowStep {
  variable: string;
  line: number;
  type: 'source' | 'assignment' | 'use' | 'return' | 'field' | 'sink';
}

export type SourceType =
  | "http_param"
  | "http_body"
  | "http_header"
  | "http_cookie"
  | "http_path"
  | "http_query"
  | "io_input"
  | "env_input"
  | "db_input"
  | "network_input"
  | "file_input"
  | "dom_input"
  | "config_param"
  | "interprocedural_param"
  | "plugin_param"
  | "constructor_field";

export type SinkType =
  | "sql_injection"
  | "nosql_injection"
  | "command_injection"
  | "path_traversal"
  | "xss"
  | "xxe"
  | "deserialization"
  | "ldap_injection"
  | "xpath_injection"
  | "ssrf"
  | "open_redirect"
  | "code_injection"
  | "log_injection"
  // ReDoS (CWE-1333): tainted regex pattern reaches a regex compile/match
  // call (e.g. Python `re.match`, Java `Pattern.compile`, JS `new RegExp`).
  // Issue #86 — Sprint 5.
  | "redos"
  // Format-string injection (CWE-134): tainted format string reaches a
  // format-string sink (e.g. Java `String.format`, Python `str.format`,
  // C-style `printf`). Issue #86 — Sprint 5.
  | "format_string"
  // CRLF / HTTP response splitting (CWE-113): tainted value reaches a
  // response-header / cookie / status-line sink that has not been validated
  // against \r and \n. Distinct from xss because the attack vector is the
  // response header (cache poisoning, session fixation, smuggling), not the
  // response body. Issue #86 — Sprint 6.
  | "crlf"
  // Mass-assignment / over-posting (CWE-915): an untrusted bag of
  // attributes (HTTP body / form / JSON) is splatted into a domain object
  // constructor or assignment helper without an allow-list, letting
  // attackers set privileged fields (`is_admin`, `role`, `owner_id`).
  // Issue #86 — Sprint 6.
  | "mass_assignment"
  // MyBatis ORM mapper-interface call — the actual SQL lives in the mapper's
  // XML/annotation binding, not at the call site. Distinct from sql_injection
  // so consumers can route, downgrade, or require an interprocedural binding
  // check (e.g. `${...}` interpolation) before reporting.
  | "mybatis_mapper_call"
  // Weak cryptography (no taint flow required)
  | "weak_random"
  | "weak_hash"
  | "weak_crypto"
  | "insecure_cookie"
  | "trust_boundary"
  // Inter-procedural: tainted data passed to external method call
  | "external_taint_escape";

export type Severity = "critical" | "high" | "medium" | "low";

/**
 * Project shape axis of the project-profile model (added in 3.106.0).
 * See `docs/ARCHITECTURE.md` ADR-008.
 */
export type ProjectShape = 'library' | 'application' | 'cli' | 'server' | 'plugin';

/**
 * Project environment axis of the project-profile model (added in 3.106.0).
 * See `docs/ARCHITECTURE.md` ADR-008.
 */
export type ProjectEnv = 'production' | 'dev' | 'sample' | 'benchmark' | 'test';

/**
 * Project profile for a file or scan (added in 3.106.0).
 *
 * Format: `<shape>/<env>` (e.g. 'library/production') or 'unknown'.
 * The 'unknown' value preserves pre-3.106.0 behavior — no
 * profile-conditional severity transform is applied.
 *
 * The profile is **caller-supplied**: circle-ir never reads the
 * filesystem (Pillar I + browser/Node compatibility). cognium-dev CLI
 * and circle-ir-ai detect the profile and pass it through
 * `analyzeOptions.projectProfile`.
 *
 * See `docs/ARCHITECTURE.md` ADR-008 for the full decision tree and
 * detection contract.
 */
export type ProjectProfile = `${ProjectShape}/${ProjectEnv}` | 'unknown';

export interface TaintSource {
  type: SourceType;
  location: string;  // Human-readable description
  severity: Severity;
  line: number;
  confidence: number;  // 0.0 - 1.0

  // Optional fields for LLM enrichment
  variable?: string;       // Variable name that is tainted
  method?: string;         // Method that produces tainted data
  annotation?: string;     // Annotation that marks parameter as tainted
  code?: string;           // Trimmed source-line text at `line` (when available)

  /**
   * Name of the enclosing method/function that contains this source. When set,
   * variable-name-based flow detectors (e.g. `detectExpressionScanFlows`)
   * restrict source→sink matching to sinks in the same method, so that
   * unrelated methods that happen to reuse a common variable name (e.g. `cmd`,
   * `name`, `id`) don't produce spurious cross-method flows. cognium-dev #101.
   */
  in_method?: string;

  /**
   * How this source was discovered. `'static'` (or absent) = identified by
   * circle-ir's deterministic pattern-matching. `'llm'` = identified by an
   * upstream LLM-enhanced consumer (e.g. circle-ir-ai). Used by
   * `generateFindings` to stamp provenance onto the resulting Finding so
   * downstream reporters can filter/weight LLM-discovered vulnerabilities
   * differently. Has no effect on the DFG-reachability gate.
   */
  discoveryMethod?: 'static' | 'llm';

  /**
   * Source-semantics tags set by `SourceSemanticsPass` (cognium-dev #138).
   * These are consumed by `sourceSemanticsAllowed(source, sinkType)` in
   * `findings.ts` to gate flow emission at the taint-propagation stage,
   * and by `ScanSecretsPass` to downgrade hardcoded-credential severity
   * on demo/example paths.
   *
   * - `constant`  — source value resolves to a compile-time constant
   *                 (string literal, `static final` initialized from a
   *                 literal, enum-constant reference). Constant sources
   *                 cannot carry attacker-controlled data and are dropped
   *                 for all taint sinks; `hardcoded-credential` continues
   *                 to fire (that is precisely the rule's purpose).
   * - `spi`       — source value came from a Service Provider Interface
   *                 lookup (`ServiceLoader.load/loadInstalled/stream`,
   *                 or `Class.forName` co-located with a
   *                 `META-INF/services/…` resource lookup). SPI-loaded
   *                 values are provider-controlled configuration, not
   *                 attacker-controlled input; dropped for all sinks
   *                 EXCEPT `code_injection` (already tagged
   *                 library-API-surface by Stage 9f — dropping again
   *                 would double-suppress).
   * - `demoPath`  — source file's path contains `/demo/`, `/example/`,
   *                 `/examples/`, `/samples/`, `/integration-tests/`, or
   *                 `/integration_tests/`. Never dropped by the gate;
   *                 `scan-secrets-pass` downgrades hardcoded-credential
   *                 findings on demo paths from `high` → `info` and
   *                 `warning/error` → `note`.
   */
  constant?: boolean;
  spi?: boolean;
  demoPath?: boolean;
}

export interface TaintSink {
  type: SinkType;
  cwe: string;  // "CWE-89", etc.
  location: string;
  line: number;
  confidence: number;

  // Optional fields for LLM enrichment
  method?: string;          // Method being called
  argPositions?: number[];  // Which arguments are dangerous
  code?: string;            // Trimmed source-line text at `line` (when available)

  /**
   * Simple-name receiver type at the sink call site (e.g. `Jedis`,
   * `Runtime`, `ProcessBuilder`). Populated from the taint-matcher's
   * resolved `call.receiver_type` (fully-qualified names are reduced
   * to the tail segment). Nullable when the receiver cannot be
   * resolved statically. Consumed by `SinkSemanticsPass`
   * (cognium-dev #139) to key into the sink-semantics registry — a
   * missing value falls through to the normal flow generator
   * (false-negative-safe).
   */
  class?: string;

  /**
   * How this sink was discovered. `'static'` (or absent) = identified by
   * circle-ir's deterministic pattern-matching. `'llm'` = identified by an
   * upstream LLM-enhanced consumer (e.g. circle-ir-ai). Used by
   * `generateFindings` to stamp provenance onto the resulting Finding so
   * downstream reporters can filter/weight LLM-discovered vulnerabilities
   * differently. Has no effect on the DFG-reachability gate.
   */
  discoveryMethod?: 'static' | 'llm';

  /**
   * Optional metadata tags carried by the sink, propagated onto any
   * `SastFinding` emitted from it. Used by post-processing hooks (e.g.
   * `applyLibraryApiSurfaceDowngrade`) to adjust severity and by downstream
   * consumers (SARIF properties, CLI badges) to surface policy context.
   * Example: `'library-api-surface:caller-responsibility'`.
   */
  tags?: string[];
}

export interface TaintSanitizer {
  type: string;
  method: string;
  line: number;
  sanitizes: SinkType[];  // Which sink types it sanitizes
}

// =============================================================================
// 7. Imports
// =============================================================================

export interface ImportInfo {
  imported_name: string;
  from_package: string | null;
  alias: string | null;
  is_wildcard: boolean;
  line_number: number | null;
}

// =============================================================================
// 8. Exports (PENDING)
// =============================================================================

export interface ExportInfo {
  symbol: string;
  kind: "class" | "interface" | "method" | "field";
  visibility: "public" | "protected" | "package";
}

// =============================================================================
// 9. Unresolved (PENDING)
// =============================================================================

export interface UnresolvedItem {
  type: "virtual_dispatch" | "taint_propagation" | "reflection" | "dynamic_call";
  call_id?: number;
  reason: string;
  context: {
    code: string;
    line: number;
    candidates?: string[];
  };
  llm_question: string;
}

// =============================================================================
// 10. Enriched (PENDING)
// =============================================================================

export interface Enriched {
  functions?: EnrichedFunction[];
  additional_sources?: TaintSource[];
  additional_sinks?: TaintSink[];
  resolved_calls?: ResolvedCall[];
  llmVerification?: LLMVerificationResult;
}

export interface LLMVerificationResult {
  verified: LLMVerifiedVulnerability[];
  stats?: {
    enrichmentTimeMs?: number;
    verificationTimeMs?: number;
    totalTimeMs?: number;
    sourcesFound?: number;
    sinksFound?: number;
    vulnerabilitiesVerified?: number;
  };
}

export interface LLMVerifiedVulnerability {
  sourceFile: string;
  sourceLine: number;
  sinkLine: number;
  cwe: string;
  type: string;
  verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'UNCERTAIN';
  confidence: number;
  reasoning: string;
  exploitability: 'high' | 'medium' | 'low' | 'none';
  attackVector?: string;
  prerequisites?: string[];
}

export interface EnrichedFunction {
  method_name: string;
  role: "controller" | "service" | "repository" | "utility";
  risk: Severity;
  trust_boundary: "entry_point" | "internal" | "external";
  summary: string;
}

export interface ResolvedCall {
  call_id: number;
  resolved_to: string;
  confidence: number;
  reason: string;
}

// =============================================================================
// 11a. SAST Pass Taxonomy (CWE + ISO 25010 aligned)
// =============================================================================

/**
 * Category of an analysis pass, aligned with ISO/IEC 25010:2023 quality
 * characteristics and SonarQube/PMD conventions.
 *
 * - security       → Confidentiality / Integrity (CWE vulnerability classes)
 * - reliability    → Faultlessness, resource safety (CWE-4xx / CWE-7xx)
 * - performance    → Performance Efficiency (CWE-10xx)
 * - maintainability → Analysability, Modifiability (documentation, complexity)
 * - architecture   → Modularity, reusability (dependency / coupling issues)
 */
export type PassCategory =
  | 'security'
  | 'reliability'
  | 'performance'
  | 'maintainability'
  | 'architecture';

/**
 * SARIF 2.1.0 result level (OASIS standard).
 * Maps to SonarQube severity: error→blocker/critical, warning→major, note→minor/info.
 */
export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/**
 * A finding produced directly by an analysis pass — no LLM enrichment required.
 *
 * Field alignment:
 *  - `cwe`      → CWE Base-level ID (e.g. "CWE-89", "CWE-476", "CWE-1047")
 *  - `level`    → SARIF 2.1.0 result.level
 *  - `severity` → circle-ir Severity (maps from level: error→critical/high,
 *                 warning→medium, note→low)
 *  - `evidence` → pass-specific structured details (non-breaking extensibility)
 *
 * CWE mapping guide by category:
 *  security:       CWE-89 SQL inj, CWE-79 XSS, CWE-78 command inj, …
 *  reliability:    CWE-476 null-deref, CWE-772 resource-leak, CWE-561 dead-code,
 *                  CWE-252 unchecked-return, CWE-391 unchecked-exception
 *  performance:    CWE-1049 N+1 query, CWE-1046 string-concat-loop,
 *                  CWE-1050 resource-consumption-in-loop
 *  maintainability: CWE-1109 variable-shadowing, CWE-1041 duplicate-code
 *  architecture:   CWE-1047 circular-deps, CWE-1060 excessive-coupling
 */
export interface SastFinding {
  /** Unique finding ID: `<rule_id>-<hash(file+line)>` */
  id: string;
  /** Name of the AnalysisPass that produced this finding. */
  pass: string;
  /** ISO 25010 category. */
  category: PassCategory;
  /** Rule identifier, e.g. "dead-code", "n-plus-one", "missing-await". */
  rule_id: string;
  /** CWE reference (optional for findings without a CWE mapping). */
  cwe?: string;
  /** Actionable severity aligned with circle-ir Severity type. */
  severity: Severity;
  /** SARIF 2.1.0 level for tool-chain integration. */
  level: SarifLevel;
  /** Human-readable description of the finding. */
  message: string;
  /** Source file path. */
  file: string;
  /** 1-based line number of the finding. */
  line: number;
  /** 1-based end line (for multi-line findings). */
  end_line?: number;
  /** 0-based column offset. */
  column?: number;
  /** Code snippet at the finding location. */
  snippet?: string;
  /** Suggested remediation (optional). */
  fix?: string;
  /** Pass-specific structured details for downstream consumers. */
  evidence?: Record<string, unknown>;
  /**
   * Confidence that this finding represents a real, actionable defect.
   *
   * Semantics (added in 3.94.0 — speculative-finding suppression infra):
   *  - `'high'` (or omitted): pass is structurally confident. Always emitted.
   *  - `'medium'`: dominator/heuristic pattern with known FP modes; emitted
   *    only when the consumer opts into `AnalyzerOptions.includeSpeculative`.
   *    Intended for findings that should be adjudicated by a downstream
   *    verifier (e.g., the forthcoming `missing-sanitizer-gate` pass tracked
   *    by #153) before user presentation.
   *  - `'low'`: experimental; same suppression behaviour as `'medium'`.
   *
   * Existing passes (pre-3.94.0) do not set this field and therefore retain
   * their default `'high'` treatment — no behavioural change for the 40-pass
   * pipeline. Filtering happens in `analyze()` between the instrumentation
   * hook and the per-file finding cap, so the diagnostic stream still
   * observes the uncapped, unfiltered findings.
   */
  confidence?: 'high' | 'medium' | 'low';
  /**
   * Optional metadata tags carried by the finding (added in 3.105.0). Tags
   * are pass-emitted strings (e.g. `'library-api-surface:caller-responsibility'`)
   * consumed by post-processing hooks for centralized severity adjustment
   * (`applyLibraryApiSurfaceDowngrade`) and by downstream consumers (SARIF
   * `properties.tags`, CLI text badges) for policy-aware presentation.
   *
   * Pre-3.105.0 passes do not set this field; consumers MUST treat it as
   * optional. The field is additive and non-breaking.
   */
  tags?: string[];
  /**
   * Severity of the finding before any post-pipeline transform (added in
   * 3.106.0). Set automatically by `applyLibraryApiSurfaceDowngrade` so
   * downstream `applyProjectProfileTransform` can restore the pre-downgrade
   * severity under `application` profile.
   *
   * Consumers should always read `severity` for display; this field is
   * metadata for the transform pipeline and downstream auditors who want
   * to recover the engine's original signal. See `docs/ARCHITECTURE.md`
   * ADR-008 for the composition rules.
   */
  original_severity?: Severity;
}

// =============================================================================
// 11b. Metrics Taxonomy (CK suite + Halstead + ISO 25010 aligned)
// =============================================================================

/**
 * Category of a software metric, aligned with ISO/IEC 25010:2023
 * quality sub-characteristics.
 *
 * | Category        | ISO 25010 sub-characteristic | Standard metric family |
 * |----------------|-------------------------------|------------------------|
 * | complexity      | Analysability, Testability    | McCabe v(G), Halstead  |
 * | size            | Analysability                 | LOC, NLOC, WMC         |
 * | coupling        | Modularity                    | CBO, RFC (CK suite)    |
 * | inheritance     | Reusability                   | DIT, NOC (CK suite)    |
 * | cohesion        | Modularity                    | LCOM (CK suite)        |
 * | documentation   | Analysability                 | doc_coverage ratio     |
 * | duplication     | Analysability, Modifiability  | duplicate_ratio        |
 */
export type MetricCategory =
  | 'complexity'
  | 'size'
  | 'coupling'
  | 'inheritance'
  | 'cohesion'
  | 'documentation'
  | 'duplication';

/**
 * A single metric observation.
 *
 * Standard `name` values (use these exact strings for interoperability):
 *
 * Complexity (McCabe / Halstead):
 *   "v(G)"                 McCabe Cyclomatic Complexity (IEEE Std 1008)
 *   "cognitive_complexity"  SonarSource Cognitive Complexity
 *   "halstead_volume"       Halstead Volume (V = N × log₂ n)
 *   "halstead_difficulty"   Halstead Difficulty (D)
 *   "halstead_effort"       Halstead Effort (E)
 *   "halstead_bugs"         Halstead Bug estimate (B = E^(2/3) / 3000)
 *
 * Size (Chidamber & Kemerer + standard):
 *   "LOC"      Lines of Code (total, including comments/blanks)
 *   "NLOC"     Non-comment Non-blank Lines of Code
 *   "WMC"      Weighted Methods per Class (sum of v(G) per method)
 *   "statements" Statement count
 *
 * Coupling (CK suite):
 *   "CBO"      Coupling Between Objects
 *   "RFC"      Response For a Class
 *
 * Inheritance (CK suite):
 *   "DIT"      Depth of Inheritance Tree
 *   "NOC"      Number of Children
 *
 * Cohesion (CK suite):
 *   "LCOM"     Lack of Cohesion in Methods
 *
 * Documentation:
 *   "doc_coverage"  Ratio 0–1 of public methods/types with doc comments
 *
 * Duplication:
 *   "duplicate_ratio"  Ratio 0–1 of duplicate lines in the file
 */
export interface MetricValue {
  /** Standard metric name (see JSDoc above for canonical values). */
  name: string;
  /** ISO 25010 category. */
  category: MetricCategory;
  /** Numeric value of the metric. */
  value: number;
  /**
   * Unit of measurement.
   * Common values: "lines", "count", "ratio" (0–1), "bits", "tokens"
   */
  unit?: string;
  /**
   * ISO 25010:2023 sub-characteristic path, e.g.
   * "Maintainability.Analysability" or "Reliability.Faultlessness".
   */
  iso_25010?: string;
  /** Optional human-readable description. */
  description?: string;
}

/**
 * Metrics for a single file, aggregated across all metric passes.
 * The `metrics` array may contain both method-level and file-level values —
 * method-level entries carry a `method` field in `evidence` if needed.
 */
export interface FileMetrics {
  file: string;
  metrics: MetricValue[];
}

// =============================================================================
// 11. Findings (PENDING — LLM-enriched findings, distinct from SastFinding)
// =============================================================================

export interface Finding {
  id: string;
  type: SinkType;
  cwe: string;
  severity: Severity;
  confidence: number;
  /**
   * Canonical "go-to-line" coordinate for this finding. For taint findings
   * mirrors `sink.line` (the primary actionable location); for single-point
   * findings mirrors the sole location. Added in 3.87.0 (#134) to give
   * downstream renderers a stable top-level line without an inconsistent
   * `source.line` / `sink.line` fallback chain.
   */
  line: number;
  source: {
    /**
     * Engine-internal taint-source classification (e.g. `'http_param'`,
     * `'interprocedural_param'`, `'env_input'`). Added in 3.87.0 (#134)
     * so triage scripts and downstream classifiers can filter by source
     * kind without re-deriving from debug logs. Optional for backwards
     * compatibility with consumers that construct `Finding` objects
     * outside `generateFindings`.
     */
    type?: SourceType;
    file: string;
    line: number;
    code: string;
  };
  sink: {
    /**
     * Engine-internal taint-sink classification (e.g. `'sql_injection'`,
     * `'command_injection'`). Mirrors the top-level `Finding.type` field
     * (kept for `source`/`sink` parity). Added in 3.87.0 (#134).
     */
    type?: SinkType;
    file: string;
    line: number;
    code: string;
  };
  path?: TaintHop[];
  exploitable: boolean;
  explanation: string;
  remediation: string;
  verification: {
    graph_path_exists: boolean;
    llm_verified: boolean;
    llm_confidence: number;
    /**
     * Provenance of the source/sink pair that produced this finding.
     * `'static'` (or absent) = both inputs came from circle-ir's
     * pattern-matching. `'llm'` = both inputs came from an LLM-enhanced
     * consumer. `'mixed'` = one of each (e.g. LLM-discovered source flowing
     * to a statically-detected sink). Lets downstream reporters filter or
     * weight LLM-influenced findings without re-deriving provenance.
     */
    discoveryMethod?: 'static' | 'llm' | 'mixed';
  };
  evidence?: Record<string, unknown>;
}

export interface TaintHop {
  file: string;
  method: string;
  line: number;
  code: string;
  variable: string;
}

// =============================================================================
// 12. Project-Level Analysis
// =============================================================================

export interface ProjectMeta {
  name: string;
  root: string;
  language: SupportedLanguage;
  framework?: string;
  framework_version?: string;
  build_tool?: "maven" | "gradle" | "ant" | "unknown";
  total_files: number;
  total_loc: number;
  analyzed_at: string;  // ISO timestamp
}

export interface CrossFileCall {
  id: string;
  from: {
    file: string;
    method: string;
    line: number;
  };
  to: {
    file: string;
    method: string;
    line: number;
  };
  args_mapping: ArgMapping[];
  resolved: boolean;
}

export interface ArgMapping {
  caller_arg: number;
  callee_param: number;
  taint_propagates: boolean;
}

export interface TypeHierarchy {
  classes: Record<string, ClassHierarchyInfo>;
  interfaces: Record<string, InterfaceHierarchyInfo>;
}

export interface ClassHierarchyInfo {
  file: string;
  extends: string | null;
  implements: string[];
  subclasses: string[];  // Classes that extend this class
}

export interface InterfaceHierarchyInfo {
  file: string;
  extends: string[];  // Interfaces this interface extends
  implementations: string[];  // Classes that implement this interface
}

export interface TaintPath {
  id: string;
  source: {
    file: string;
    line: number;
    type: SourceType;
    code: string;
  };
  sink: {
    file: string;
    line: number;
    type: SinkType;
    cwe: string;
    code: string;
  };
  hops: TaintHop[];
  sanitizers_in_path: string[];
  path_exists: boolean;
  confidence: number;
}

export interface ProjectAnalysis {
  meta: ProjectMeta;
  files: FileAnalysis[];
  type_hierarchy: TypeHierarchy;
  cross_file_calls: CrossFileCall[];
  taint_paths: TaintPath[];
  findings: Finding[];
  /**
   * Set to `true` when the cross-file phase exceeded its wall-time budget
   * (see `AnalyzerOptions.crossFileBudgetMs`). When `true`, `taint_paths`
   * may be incomplete — remaining inter-procedural / field-binding / aliasing
   * sub-phases were skipped. Downstream consumers should not treat
   * `taint_paths` as authoritative when this flag is set.
   *
   * Added in circle-ir 3.89.0 (mitigates #141 langchain4j hang).
   */
  cross_file_budget_exceeded?: boolean;
}

export interface FileAnalysis {
  file: string;
  analysis: CircleIR;
}

// =============================================================================
// Top-Level Circle-IR Structure (Single File)
// =============================================================================

export interface CircleIR {
  meta: Meta;
  types: TypeInfo[];
  calls: CallInfo[];
  cfg: CFG;
  dfg: DFG;
  taint: Taint;
  imports: ImportInfo[];
  exports: ExportInfo[];
  unresolved: UnresolvedItem[];
  enriched: Enriched;
  /** SAST findings produced by analysis passes (no LLM enrichment required). */
  findings?: SastFinding[];
  /** Software metrics computed by metric passes (CK suite, Halstead, etc.). */
  metrics?: FileMetrics;
  /**
   * Runtime registration patterns (HTTP routes, middlewares, event listeners)
   * that establish call-graph edges not visible in the static AST.
   *
   * Phase 1 (issue #15): JS/TS Express-family route registration.
   * Phase 2: Python decorators (Flask/FastAPI routes, pytest fixtures, …).
   * Phase 3: Rust trait dispatch (`impl Trait for Type`, `inventory::submit!`,
   *          `#[linkme::distributed_slice]`).
   * Consumers (e.g. cognium-ai dead-code) treat `handler` targets as virtual
   * entry roots when computing reachability.
   */
  runtime_registrations?: RuntimeRegistration[];
  /**
   * Structured report of tree-sitter parse health for this file (issue #27).
   * Populated on every `analyze()` call. When `success: false`, downstream
   * IR fields (`types`, `calls`, `cfg`, `dfg`) were derived from a partial
   * parse and may be incomplete — extractors run on whatever ERROR / MISSING
   * nodes tree-sitter recovered, so taint sources/sinks can be silently
   * dropped. Consumers (CLI, circle-ir-ai) should surface this to the user
   * instead of treating an empty `findings` array as a clean bill of health.
   */
  parse_status?: ParseStatus;
}

/**
 * Tree-sitter parse health for a single analyzed file. See `CircleIR.parse_status`.
 *
 * `tree.rootNode.hasError` returns true when tree-sitter encountered any
 * grammar mismatch and inserted ERROR or MISSING nodes during error
 * recovery. The parse still produces a Tree (extractors run), but the
 * sub-tree under every ERROR node is opaque to the extractors.
 */
export interface ParseStatus {
  /**
   * `true` when tree-sitter parsed the file without any ERROR or MISSING
   * nodes. Equivalent to `!tree.rootNode.hasError`.
   */
  success: boolean;
  /**
   * Mirror of `tree.rootNode.hasError`. `true` indicates the parse is
   * partial — at least one ERROR or MISSING node exists somewhere in the
   * tree and IR derived from it may be incomplete.
   */
  has_errors: boolean;
  /**
   * Total count of ERROR and MISSING nodes the recovery walk found. `0`
   * when `success: true`. Useful for ranking which files in a project
   * scan have the worst parse health.
   */
  error_count: number;
  /**
   * 1-based line / 0-based column of each ERROR or MISSING node, in
   * tree-walk order, capped at 50 entries to bound memory. Lets consumers
   * highlight specific lines without re-walking the tree.
   */
  error_locations: Array<{ line: number; column: number }>;
}

/**
 * A runtime registration recording that a handler is wired into a framework
 * dispatch table at module-load time. See issue #15.
 */
export interface RuntimeRegistration {
  kind: 'http_route' | 'middleware' | 'event_listener' | 'decorator' | 'trait_impl';
  framework?:
    | 'express' | 'fastify' | 'koa' | 'nestjs'
    | 'flask' | 'fastapi' | 'django' | 'click' | 'pytest' | 'celery' | 'numba'
    | 'actix' | 'axum' | 'rocket' | 'tokio' | 'serde' | 'inventory' | 'linkme'
    | 'stdlib' | 'unknown';
  /**
   * The registration call site itself.
   *  - JS Phase 1: `app.get(...)`, `router.use(...)`, `server.on(...)` — receiver
   *    is the runtime object, method is the verb.
   *  - Python Phase 2: a `@receiver.method` decorator — receiver is everything
   *    before the last dotted segment (empty string for bare `@name`),
   *    method is the last segment.
   *  - Rust Phase 3: an `impl Trait for Type` block — receiver is the Self type
   *    (e.g. `'PingHandler'`), method is the trait method name (e.g. `'handle'`).
   *    For `inventory::submit!` / `#[linkme::distributed_slice]`, receiver is
   *    the collector module (`'inventory'` / `'linkme'`) and method is the
   *    registration verb (`'submit'` / `'distributed_slice'`).
   */
  registrar: {
    method: string;     // 'get' | 'post' | 'use' | 'on' | 'route' | 'fixture' | 'handle' | 'submit' | ...
    receiver: string;   // 'app' | 'router' | 'pytest' | 'PingHandler' | 'inventory' | '' (bare)
    line: number;
    column: number;
  };
  /**
   * Literal route path, event name, or — for `trait_impl` — the trait path
   * (e.g. `'Handler'`, `'std::fmt::Display'`).
   */
  path?: string;
  /** Resolved handler. `name === null` for inline arrow / function expression. */
  handler: {
    name: string | null;
    line: number;
    column: number;
  };
}

// =============================================================================
// API Response Format (for CF Workers)
// =============================================================================

export interface AnalysisResponse {
  success: boolean;
  analysis: {
    sources: TaintSource[];
    sinks: TaintSink[];
    vulnerabilities: Vulnerability[];
  };
  meta: {
    parseTimeMs: number;
    analysisTimeMs: number;
    totalTimeMs: number;
  };
}

export interface Vulnerability {
  type: SinkType;
  cwe: string;
  severity: Severity;
  source: { line: number; type: SourceType };
  sink: { line: number; type: SinkType };
  confidence: number;
  path?: string[];
}
