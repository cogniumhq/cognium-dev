/**
 * Circle-IR 3.0 TypeScript Type Definitions
 *
 * These types conform to docs/SPEC.md
 */

// =============================================================================
// 1. Meta
// =============================================================================

export type SupportedLanguage = "java" | "c" | "cpp" | "javascript" | "typescript" | "python" | "rust" | "bash" | "html" | "go";

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
  receiver_type?: string | null;
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
  // Weak cryptography (no taint flow required)
  | "weak_random"
  | "weak_hash"
  | "weak_crypto"
  | "insecure_cookie"
  | "trust_boundary"
  // Inter-procedural: tainted data passed to external method call
  | "external_taint_escape";

export type Severity = "critical" | "high" | "medium" | "low";

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
  source: {
    file: string;
    line: number;
    code: string;
  };
  sink: {
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
