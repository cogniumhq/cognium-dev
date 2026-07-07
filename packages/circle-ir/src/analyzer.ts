/**
 * Circle-IR Analyzer
 *
 * Main entry point for analyzing source code and producing Circle-IR output.
 * This is the core static analyzer. LLM-based verification and discovery are out of scope for this library.
 *
 * The analysis pipeline runs forty sequential passes over a shared CodeGraph:
 *   1. TaintMatcherPass        — config-based source/sink extraction
 *   2. ConstantPropagationPass — dead-code detection, symbol table, field taint
 *   3. LanguageSourcesPass     — language-specific sources/sinks (JS, Python, getters)
 *   4. SinkFilterPass          — four-stage false-positive elimination
 *   5. TaintPropagationPass    — DFG-based flow verification
 *   6. InterproceduralPass     — cross-method taint propagation
 *   7. DeadCodePass            — CFG blocks unreachable from entry (CWE-561)
 *   8. MissingAwaitPass        — unawaited async calls in JS/TS (CWE-252)
 *   9. NPlusOnePass            — DB/HTTP calls inside loop bodies (CWE-1049)
 *  10. MissingPublicDocPass    — public methods/types without doc comments
 *  11. TodoInProdPass          — TODO/FIXME/HACK markers in production code
 *  12. StringConcatLoopPass    — string += inside loops, O(n²) allocations (CWE-1046)
 *  13. SyncIoAsyncPass         — blocking *Sync calls inside async functions (CWE-1050)
 *  14. UncheckedReturnPass     — ignored boolean return from File.delete etc. (CWE-252)
 *  15. NullDerefPass           — null-assigned var dereferenced without guard (CWE-476)
 *  16. ResourceLeakPass        — stream/connection opened but never closed (CWE-772)
 *  17. VariableShadowingPass   — inner scope re-declares outer name (CWE-1109)
 *  18. LeakedGlobalPass        — assignment without declaration in JS/TS (CWE-1109)
 *  19. UnusedVariablePass      — local variable declared but value never read (CWE-561)
 *  20. DependencyFanOutPass    — module imports 20+ other modules (architecture smell)
 *  21. StaleDocRefPass         — doc comment references unknown symbol (CWE: none)
 *  22. InfiniteLoopPass        — loops with no reachable exit edge (CWE-835)
 *  23. DeepInheritancePass     — class inheritance depth > 5 (CWE-1086)
 *  24. RedundantLoopPass       — loop-invariant .length/.size()/Math.* (CWE-1050)
 *  25. UnboundedCollectionPass — collection grows in loop with no size limit (CWE-770)
 *  26. SerialAwaitPass         — sequential awaits with no data dependency (performance)
 *  27. ReactInlineJsxPass      — inline objects/functions in JSX props (performance)
 *  28. SwallowedExceptionPass  — catch blocks with no throw/log/return (CWE-390)
 *  29. BroadCatchPass          — catch(Exception) / bare except (CWE-396)
 *  30. UnhandledExceptionPass  — throw/raise outside any try/catch (CWE-390)
 *  31. DoubleClosePass         — resource closed twice in same method (CWE-675)
 *  32. UseAfterClosePass       — method call on resource after close() (CWE-672)
 *  33. CleanupVerifyPass       — close() does not post-dominate acquisition (CWE-772)
 *  34. MissingOverridePass     — overriding method lacks @Override (Java)
 *  35. UnusedInterfaceMethodPass — interface method never called in file
 *  36. BlockingMainThreadPass  — blocking crypto/*Sync calls in request handlers (CWE-1050)
 *  37. ExcessiveAllocationPass — collection/object allocation inside loop bodies (CWE-770)
 *  38. MissingStreamPass       — whole-file read without streaming (performance)
 *  39. GodClassPass            — class with high WMC/LCOM2/CBO metrics (CWE-1060)
 *  40. NamingConventionPass    — class/method names violate language conventions
 *  41. ScanSecretsPass         — hardcoded credentials: provider regexes + Shannon entropy (CWE-798)
 *  42. Spring4ShellPass        — Spring MVC implicit form-data binding RCE (CVE-2022-22965, CWE-94)
 *  43. MissingSanitizerGatePass — HTML output reached without sanitizer call on dominating path (CWE-79, speculative)
 *
 * Removed from default pipeline (raw IR signals still available for circle-ir-ai):
 *  – MissingGuardDomPass  — false positives in framework-auth codebases (see pass file)
 *  – FeatureEnvyPass      — fires on legitimate delegation patterns (see pass file)
 */

import type { CircleIR, AnalysisResponse, Vulnerability, Enriched, ProjectAnalysis, ProjectMeta, ProjectProfile, ProjectProfileSummary, ProjectShape, ProjectEnv, SastFinding } from './types/index.js';
import type { TaintConfig } from './types/config.js';
import {
  initParser,
  parse,
  disposeTree,
  extractParseStatus,
  extractMeta,
  extractTypes,
  extractCalls,
  extractImports,
  extractExports,
  buildCFG,
  buildDFG,
  extractRuntimeRegistrations,
  collectAllNodes,
  type SupportedLanguage,
} from './core/index.js';
import {
  analyzeTaint,
  getDefaultConfig,
  detectUnresolved,
  analyzeConstantPropagation,
  isFalsePositive,
} from './analysis/index.js';
import { emitFindingsInstrumentation } from './analysis/findings-instrumentation.js';
import {
  applyPerFileFindingCap,
  DEFAULT_PER_FILE_FINDING_CAP,
} from './analysis/per-file-finding-cap.js';
import { applyConfidenceFilter } from './analysis/confidence-filter.js';
import { applyLibraryApiSurfaceDowngrade } from './analysis/library-api-surface-downgrade.js';
import { applyRequireEntryPath } from './analysis/require-entry-path.js';
import { applyProjectProfileTransform, type ProfileResolver } from './analysis/project-profile-transform.js';
import { registerBuiltinPlugins } from './languages/index.js';
import { logger } from './utils/logger.js';
import { CodeGraph, AnalysisPipeline, ProjectGraph } from './graph/index.js';
import { CrossFilePass } from './analysis/passes/cross-file-pass.js';

// HTML preprocessor
import { extractHtmlContent } from './analysis/html/html-extractor.js';
import { runHtmlAttributeSecurityChecks } from './analysis/html/html-attribute-security-pass.js';
import { runVueTemplateXssChecks } from './analysis/html/vue-template-xss-pass.js';
import { mergeHtmlResults } from './analysis/html/html-merge.js';
import type { ScriptBlockResult } from './analysis/html/html-merge.js';

// Pass classes
import { TaintMatcherPass } from './analysis/passes/taint-matcher-pass.js';
import { ConstantPropagationPass } from './analysis/passes/constant-propagation-pass.js';
import { LanguageSourcesPass } from './analysis/passes/language-sources-pass.js';
import { SourceSemanticsPass } from './analysis/passes/source-semantics-pass.js';
import { LibraryProfileSourceGatePass } from './analysis/passes/library-profile-source-gate-pass.js';
import { MyBatisAnnotationSqlSinkPass } from './analysis/passes/mybatis-annotation-sql-sink-pass.js';
import { SinkFilterPass, filterCleanVariableSinks, filterSanitizedSinks } from './analysis/passes/sink-filter-pass.js';
import { SinkSemanticsPass } from './analysis/passes/sink-semantics-pass.js';
import { CliMainReflectionSuppressPass } from './analysis/passes/cli-main-reflection-suppress-pass.js';
import { LibraryProfileSinkGatePass, LibraryProfileCwe22PathGatePass } from './analysis/passes/library-profile-sink-gate-pass.js';
import { LibraryProfileXssGatePass } from './analysis/passes/library-profile-xss-gate-pass.js';
import { TaintPropagationPass } from './analysis/passes/taint-propagation-pass.js';
import { InterproceduralPass } from './analysis/passes/interprocedural-pass.js';
import { DeadCodePass } from './analysis/passes/dead-code-pass.js';
import { MissingAwaitPass } from './analysis/passes/missing-await-pass.js';
import { NPlusOnePass } from './analysis/passes/n-plus-one-pass.js';
import { MissingPublicDocPass } from './analysis/passes/missing-public-doc-pass.js';
import { TodoInProdPass } from './analysis/passes/todo-in-prod-pass.js';
import { StringConcatLoopPass } from './analysis/passes/string-concat-loop-pass.js';
import { SyncIoAsyncPass } from './analysis/passes/sync-io-async-pass.js';
import { UncheckedReturnPass } from './analysis/passes/unchecked-return-pass.js';
import { NullDerefPass } from './analysis/passes/null-deref-pass.js';
import { ResourceLeakPass } from './analysis/passes/resource-leak-pass.js';
import { VariableShadowingPass } from './analysis/passes/variable-shadowing-pass.js';
import { LeakedGlobalPass } from './analysis/passes/leaked-global-pass.js';
import { UnusedVariablePass } from './analysis/passes/unused-variable-pass.js';
import { DependencyFanOutPass, type DependencyFanOutOptions } from './analysis/passes/dependency-fan-out-pass.js';
import { StaleDocRefPass } from './analysis/passes/stale-doc-ref-pass.js';
import { InfiniteLoopPass } from './analysis/passes/infinite-loop-pass.js';
import { DeepInheritancePass } from './analysis/passes/deep-inheritance-pass.js';
import { RedundantLoopPass } from './analysis/passes/redundant-loop-pass.js';
import { UnboundedCollectionPass, type UnboundedCollectionOptions } from './analysis/passes/unbounded-collection-pass.js';
import { SerialAwaitPass } from './analysis/passes/serial-await-pass.js';
import { ReactInlineJsxPass } from './analysis/passes/react-inline-jsx-pass.js';
import { SwallowedExceptionPass } from './analysis/passes/swallowed-exception-pass.js';
import { BroadCatchPass } from './analysis/passes/broad-catch-pass.js';
import { UnhandledExceptionPass } from './analysis/passes/unhandled-exception-pass.js';
import { DoubleClosePass } from './analysis/passes/double-close-pass.js';
import { UseAfterClosePass } from './analysis/passes/use-after-close-pass.js';
import { CleanupVerifyPass } from './analysis/passes/cleanup-verify-pass.js';
import { MissingOverridePass } from './analysis/passes/missing-override-pass.js';
import { UnusedInterfaceMethodPass } from './analysis/passes/unused-interface-method-pass.js';
import { BlockingMainThreadPass } from './analysis/passes/blocking-main-thread-pass.js';
import { ExcessiveAllocationPass } from './analysis/passes/excessive-allocation-pass.js';
import { MissingStreamPass } from './analysis/passes/missing-stream-pass.js';
import { GodClassPass } from './analysis/passes/god-class-pass.js';
import { NamingConventionPass, type NamingConventionOptions } from './analysis/passes/naming-convention-pass.js';
import { SecurityHeadersPass, type SecurityHeadersOptions, checkInheritedCorsHeaders } from './analysis/passes/security-headers-pass.js';
import { ScanSecretsPass } from './analysis/passes/scan-secrets-pass.js';
import { Spring4ShellPass } from './analysis/passes/spring4shell-pass.js';
import { InsecureCookiePass } from './analysis/passes/insecure-cookie-pass.js';
import { WeakHashPass } from './analysis/passes/weak-hash-pass.js';
import { WeakCryptoPass } from './analysis/passes/weak-crypto-pass.js';
import { WeakRandomPass } from './analysis/passes/weak-random-pass.js';
import { WeakPasswordHashPass } from './analysis/passes/weak-password-hash-pass.js';
import { WeakPasswordEncodingPass } from './analysis/passes/weak-password-encoding-pass.js';
import { InfoDisclosureStacktracePass } from './analysis/passes/info-disclosure-stacktrace-pass.js';
import { UnrestrictedFileUploadPass } from './analysis/passes/unrestricted-file-upload-pass.js';
import { MissingSanitizerGatePass } from './analysis/passes/missing-sanitizer-gate-pass.js';
import { PlaintextPasswordStoragePass } from './analysis/passes/plaintext-password-storage-pass.js';
import { CleartextCredentialTransportPass } from './analysis/passes/cleartext-credential-transport-pass.js';
import { TlsVerifyDisabledPass } from './analysis/passes/tls-verify-disabled-pass.js';
import { ModuleSideEffectPass } from './analysis/passes/module-side-effect-pass.js';
import { CacheNoVaryPass } from './analysis/passes/cache-no-vary-pass.js';
import { JwtVerifyDisabledPass } from './analysis/passes/jwt-verify-disabled-pass.js';
import { CsrfProtectionDisabledPass } from './analysis/passes/csrf-protection-disabled-pass.js';
import { XmlEntityExpansionPass } from './analysis/passes/xml-entity-expansion-pass.js';
import { MassAssignmentPass } from './analysis/passes/mass-assignment-pass.js';

// Project-level pass imports
import { ImportGraph } from './graph/import-graph.js';
import { CircularDependencyPass } from './analysis/passes/circular-dependency-pass.js';
import { OrphanModulePass } from './analysis/passes/orphan-module-pass.js';

// Metrics
import { MetricRunner } from './analysis/metrics/index.js';

// Helpers used by analyzeForAPI
import {
  buildPythonTaintedVars,
  buildPythonSanitizedVars,
  findPythonTrustBoundaryViolations,
} from './analysis/passes/language-sources-pass.js';

// Pass result types (used to read typed results from the pipeline map)
import type { SinkFilterResult } from './analysis/passes/sink-filter-pass.js';
import type { InterproceduralPassResult } from './analysis/passes/interprocedural-pass.js';

export interface AnalyzerOptions {
  /**
   * Path to tree-sitter.wasm for parser initialization.
   */
  wasmPath?: string;

  /**
   * Pre-compiled WebAssembly.Module for tree-sitter.wasm.
   * For Cloudflare Workers where dynamic WASM compilation is blocked.
   */
  wasmModule?: WebAssembly.Module;

  /**
   * Paths to language-specific WASM files.
   */
  languagePaths?: Partial<Record<SupportedLanguage, string>>;

  /**
   * Pre-compiled WebAssembly.Module for language grammars.
   * For Cloudflare Workers where dynamic WASM compilation is blocked.
   */
  languageModules?: Partial<Record<SupportedLanguage, WebAssembly.Module>>;

  /**
   * Custom taint configuration.
   */
  taintConfig?: TaintConfig;

  /**
   * Per-pass configuration options.
   */
  passOptions?: PassOptions;

  /**
   * Passes to disable entirely. Use pass names (e.g., 'naming-convention').
   */
  disabledPasses?: string[];

  /**
   * Wall-time budget (ms) for the entire cross-file phase
   * (`CrossFilePass.run()` — direct flows, interprocedural, field-binding,
   * cross-instance aliasing). When exceeded, the remaining sub-phases are
   * skipped, any taint paths produced so far are kept, and the resulting
   * `ProjectAnalysis.cross_file_budget_exceeded` flag is set to `true`.
   *
   * - `0` disables the breaker (unlimited).
   * - Omitting the field uses the default of `300_000` (5 minutes), chosen
   *   to comfortably cover large monorepos (~2K files) at post-3.89.0
   *   pre-index speeds while still catching pathological hangs.
   * - Consumers operating in CI on >5K-file projects may want to bump this.
   *
   * Added in circle-ir 3.89.0 to mitigate #141 (langchain4j 30-min hang).
   */
  crossFileBudgetMs?: number;

  /**
   * Defensive per-file finding cap (#142).
   *
   * A single file producing more than this many findings is treated as a
   * structural failure of the analysis pipeline (cross-product blow-up,
   * mislabelled sink class, or pathological generated code) rather than a
   * legitimate detection burst. When the cap is exceeded, all individual
   * findings for that file are dropped and replaced by a single
   * `saturated-file` advisory carrying the suppressed count, so the signal
   * stays visible without flooding downstream consumers.
   *
   * - `0` disables the cap (unlimited; pre-3.92.0 behaviour).
   * - Omitting the field uses the default of `1000`, chosen well above the
   *   realistic per-file ceiling (~200 for jedis-shape library facades) and
   *   below the empirical structural-failure floor observed on langchain4j
   *   (~10K findings on a single file before the cross-file phase hang).
   *
   * The cap is applied after the pipeline runs but before the result is
   * returned, so per-pass instrumentation (#145 PR B) still observes the
   * uncapped findings stream for diagnostic purposes.
   *
   * Added in circle-ir 3.92.0 as a defensive tripwire; #143 (the proposed
   * (source, sink) coalescing schema) was closed as unjustified by
   * empirical capture data, leaving this as the standalone safeguard.
   */
  perFileFindingCap?: number;

  /**
   * Opt into emission of speculative (`confidence: 'medium' | 'low'`) findings.
   *
   * Default `false`: only `confidence: 'high'` (or unset, which is the
   * pre-3.94.0 default for every existing pass) findings reach the consumer.
   * Speculative findings emitted by dominator/heuristic passes such as the
   * forthcoming `missing-sanitizer-gate` (#153) are dropped silently.
   *
   * Set `true` when a downstream verifier is going to adjudicate the
   * speculative findings before user presentation; the engine then preserves
   * the full unfiltered finding stream and the caller is responsible for
   * filtering the `'medium'`/`'low'` entries.
   *
   * Filtering happens in `analyze()` after `emitFindingsInstrumentation` and
   * before `applyPerFileFindingCap`, so per-pass diagnostics still observe
   * the full uncapped, unfiltered stream.
   *
   * Added in circle-ir 3.94.0 as the pre-req infrastructure for #153.
   */
  includeSpeculative?: boolean;

  /**
   * Enable the Tier 1/2/3 entry-point classifier gate that suppresses
   * `interprocedural_param` taint sources on library-API methods that are
   * not reachable from a recognised HTTP / RPC / lifecycle entry point.
   *
   * Default `true`. The gate has been the unconditional behaviour for
   * Java since 3.88.0 (#128) and was extended to cover Netty wire-message
   * handlers in 3.93.0 (#154). 3.95.0 surfaces it as an option so callers
   * can disable it for debugging, recall-vs-precision tuning, or third-
   * party harness comparisons that need the un-gated source set.
   *
   * Language behaviour:
   *  - `language === 'java'`: gate fires; library-API methods drop their
   *    `interprocedural_param` sources.
   *  - All other languages: gate is a no-op (the classifier returns
   *    `TIER_UNKNOWN` for non-Java, which does not match the drop predicate).
   *
   * Set `false` to receive the pre-#128 source set on Java. Useful for:
   *  - Diagnosing why an expected interprocedural flow is missing.
   *  - Comparing against IRIS / CodeQL baselines that don't gate.
   *  - Recall-targeted runs in `circle-ir-ai`.
   *
   * Added in 3.95.0 (cognium-dev#137).
   */
  enableEntryPointGate?: boolean;

  /**
   * Project profile for the analysis, used by the post-pipeline profile
   * transform to gate severity changes on findings tagged
   * `library-api-surface:caller-responsibility` (Sprint 47). See
   * `docs/ARCHITECTURE.md` ADR-008 for the full decision tree.
   *
   * Three forms supported:
   *  - omitted (or `'unknown'`) → 3.105.0 behavior preserved (no
   *    profile-conditional transform applied).
   *  - single `ProjectProfile` string → applies to every file in the scan.
   *  - `Map<file, ProjectProfile>` → per-file profile (for monorepos with
   *    mixed library/application modules).
   *
   * Pillar I: circle-ir never reads the filesystem to detect the profile.
   * Detection is the caller's responsibility (cognium-dev CLI does it;
   * circle-ir-ai may provide a richer detector). When the caller cannot
   * resolve a file, supplying `'unknown'` is the safe default.
   *
   * Added in circle-ir 3.106.0 (#169).
   */
  projectProfile?: ProjectProfile | Map<string, ProjectProfile>;
}

/**
 * Per-pass configuration options.
 * Each key corresponds to a pass name with pass-specific settings.
 */
export interface PassOptions {
  /** Options for NamingConventionPass (#88). */
  namingConvention?: NamingConventionOptions;
  /** Options for DependencyFanOutPass (#72). */
  dependencyFanOut?: DependencyFanOutOptions;
  /** Options for UnboundedCollectionPass (#31). */
  unboundedCollection?: UnboundedCollectionOptions;
  /** Options for SecurityHeadersPass (#89). */
  securityHeaders?: SecurityHeadersOptions;
}

let initialized = false;

/**
 * Initialize the analyzer. Must be called before analyze().
 */
export async function initAnalyzer(options: AnalyzerOptions = {}): Promise<void> {
  if (initialized) return;

  // Register built-in language plugins
  registerBuiltinPlugins();

  await initParser({
    wasmPath: options.wasmPath,
    wasmModule: options.wasmModule,
    languagePaths: options.languagePaths,
    languageModules: options.languageModules,
  });

  initialized = true;
}

/**
 * Build enriched metadata section from analysis results.
 */
function buildEnriched(
  types: CircleIR['types'],
  _calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks']
): Enriched {
  // Classify functions by role based on analysis
  const functions: Enriched['functions'] = [];

  for (const type of types) {
    for (const method of type.methods) {
      // Determine role based on annotations and naming
      let role: 'controller' | 'service' | 'repository' | 'utility' = 'utility';
      let trustBoundary: 'entry_point' | 'internal' | 'external' = 'internal';

      // Check for controller annotations
      if (method.annotations.some(a =>
        a.includes('RequestMapping') ||
        a.includes('GetMapping') ||
        a.includes('PostMapping') ||
        a.includes('RestController') ||
        a.includes('Controller')
      )) {
        role = 'controller';
        trustBoundary = 'entry_point';
      }
      // Check for repository/DAO patterns
      else if (type.name.toLowerCase().includes('repository') ||
               type.name.toLowerCase().includes('dao') ||
               method.annotations.some(a => a.includes('Repository'))) {
        role = 'repository';
      }
      // Check for service patterns
      else if (type.name.toLowerCase().includes('service') ||
               method.annotations.some(a => a.includes('Service'))) {
        role = 'service';
      }

      // Determine risk level
      const hasSources = sources.some(s => s.method === method.name);
      const hasSinks = sinks.some(s => s.method === method.name);
      let risk: 'critical' | 'high' | 'medium' | 'low' = 'low';
      if (hasSinks) risk = 'high';
      else if (hasSources) risk = 'medium';

      // Only include functions with meaningful roles
      if (role !== 'utility' || risk !== 'low') {
        functions.push({
          method_name: `${type.name}.${method.name}`,
          role,
          risk,
          trust_boundary: trustBoundary,
          summary: `${role} method in ${type.name}`,
        });
      }
    }
  }

  return {
    functions: functions.length > 0 ? functions : undefined,
  };
}

// ---------------------------------------------------------------------------
// Node type collection — shared by analyze() and analyzeForAPI()
// ---------------------------------------------------------------------------

function getNodeTypesForLanguage(language: SupportedLanguage): Set<string> {
  switch (language) {
    case 'rust':
      return new Set([
        'call_expression', 'macro_invocation', 'function_item', 'struct_item',
        'impl_item', 'enum_item', 'trait_item', 'mod_item', 'use_declaration',
        'let_declaration', 'field_expression', 'scoped_identifier',
        'attribute_item', 'static_item',
      ]);
    case 'python':
      return new Set([
        'call', 'function_definition', 'class_definition', 'import_statement',
        'import_from_statement', 'assignment', 'attribute', 'subscript',
        'decorated_definition', 'decorator',
      ]);
    case 'javascript':
    case 'typescript':
    case 'tsx':
      return new Set([
        'call_expression', 'new_expression', 'class_declaration', 'function_declaration',
        'arrow_function', 'method_definition', 'variable_declaration', 'lexical_declaration',
        'import_statement', 'export_statement', 'member_expression', 'assignment_expression',
        // JSX node types — tree-sitter-tsx grammar (.tsx/.jsx routing)
        'jsx_element', 'jsx_self_closing_element', 'jsx_opening_element',
        'jsx_attribute', 'jsx_expression',
      ]);
    case 'bash':
      return new Set([
        'command', 'function_definition', 'variable_assignment', 'declaration_command',
        'if_statement', 'for_statement', 'c_style_for_statement', 'while_statement',
      ]);
    case 'html':
    case 'vue':
      return new Set([
        'element', 'script_element', 'style_element', 'attribute',
        'start_tag', 'self_closing_tag', 'text',
      ]);
    case 'go':
      return new Set([
        'call_expression', 'function_declaration', 'method_declaration',
        'package_clause', 'import_declaration', 'import_spec',
        'var_declaration', 'short_var_declaration', 'assignment_statement',
        'type_declaration', 'if_statement', 'for_statement',
        'return_statement', 'defer_statement', 'go_statement',
        'selector_expression', 'identifier',
      ]);
    default:
      return new Set([
        'method_invocation', 'object_creation_expression', 'class_declaration',
        'method_declaration', 'constructor_declaration', 'field_declaration',
        'import_declaration', 'interface_declaration', 'enum_declaration',
      ]);
  }
}

// ---------------------------------------------------------------------------
// Project-profile resolver helper
// ---------------------------------------------------------------------------

/**
 * Build a `ProfileResolver` from the caller-supplied `projectProfile`
 * option. Three forms are supported (see `AnalyzerOptions.projectProfile`):
 *
 *  - `undefined` → every file resolves to `'unknown'` (no profile-conditional
 *    transform applied; preserves 3.105.0 behavior).
 *  - single `ProjectProfile` string → every file resolves to that profile.
 *  - `Map<file, ProjectProfile>` → per-file lookup; files missing from the
 *    map fall back to `'unknown'`.
 *
 * Added in circle-ir 3.106.0 (#169). See `docs/ARCHITECTURE.md` ADR-008.
 */
function makeProfileResolver(
  p: ProjectProfile | Map<string, ProjectProfile> | undefined,
): ProfileResolver {
  if (p === undefined) return () => 'unknown';
  if (typeof p === 'string') return () => p;
  return (file: string) => p.get(file) ?? 'unknown';
}

/**
 * Compute a per-scan rollup of resolved `ProjectProfile` values across a
 * set of per-file analyses. Returns `null` if none of the analyses carry
 * a `meta.projectProfile` field (i.e. the caller did not supply
 * `options.projectProfile`).
 *
 * Buckets:
 *  - `byShape` counts the leading `ProjectShape` segment (or `'unknown'`)
 *  - `byEnv`   counts the trailing `ProjectEnv` segment (or `'unknown'`)
 *  - `totalFiles` is the total number of analyzed files
 *
 * Added in circle-ir 3.150.1 (#235). See `docs/ARCHITECTURE.md` ADR-008.
 */
function computeProjectProfileSummary(
  fileAnalyses: Array<{ file: string; analysis: CircleIR }>,
): ProjectProfileSummary {
  const byShape: Record<ProjectShape | 'unknown', number> = {
    library: 0, application: 0, cli: 0, server: 0, plugin: 0, unknown: 0,
  };
  const byEnv: Record<ProjectEnv | 'unknown', number> = {
    production: 0, dev: 0, sample: 0, benchmark: 0, test: 0, unknown: 0,
  };
  for (const { analysis } of fileAnalyses) {
    const profile = analysis.meta.projectProfile ?? 'unknown';
    if (profile === 'unknown') {
      byShape.unknown += 1;
      byEnv.unknown += 1;
      continue;
    }
    const slash = profile.indexOf('/');
    const shape = profile.slice(0, slash) as ProjectShape;
    const env   = profile.slice(slash + 1) as ProjectEnv;
    byShape[shape] += 1;
    byEnv[env]     += 1;
  }
  return { byShape, byEnv, totalFiles: fileAnalyses.length };
}

// ---------------------------------------------------------------------------
// Main analysis function
// ---------------------------------------------------------------------------

/**
 * Analyze source code and produce Circle-IR output.
 */
export async function analyze(
  code: string,
  filePath: string,
  language: SupportedLanguage,
  options: AnalyzerOptions = {}
): Promise<CircleIR> {
  if (!initialized) {
    await initAnalyzer(options);
  }

  // Markup preprocessor path (HTML + Vue SFC) — extract scripts and
  // delegate to the JS/TS analyzer. Vue SFCs are HTML-syntax-wrapped, so
  // the tree-sitter-html grammar parses `<template>` / `<script>` /
  // `<style>` blocks identically. (cognium-dev #184 sprint 1 of 2 —
  // adds .vue routing; template-attribute sinks like v-html land in
  // the follow-up sprint.)
  if (language === 'html' || language === 'vue') {
    return analyzeMarkupFile(code, filePath, options, language);
  }

  // JSX/TSX routing: tree-sitter-typescript does NOT parse JSX. Route
  // `.tsx`/`.jsx` files to the sibling `tree-sitter-tsx` grammar (loaded
  // from `tree-sitter-tsx.wasm`) which is a JSX-aware superset. We keep
  // `language` as 'javascript'/'typescript' so all downstream extractors
  // and passes treat the tree the same way; only the grammar used to
  // produce the tree differs. (cognium-dev #88.2)
  let parseGrammar: SupportedLanguage = language;
  if (language === 'javascript' || language === 'typescript') {
    const lower = filePath.toLowerCase();
    if (lower.endsWith('.tsx') || lower.endsWith('.jsx')) {
      parseGrammar = 'tsx';
    }
  }

  logger.debug('Analyzing file', { filePath, language, parseGrammar, codeLength: code.length });

  // Parse the code. The Tree holds tree-sitter WASM memory; we MUST dispose
  // it before returning, otherwise the WASM heap grows unboundedly across
  // many analyze() calls in the same process (issue #16).
  const tree = await parse(code, parseGrammar);
  try {
  logger.trace('Parsed AST', { rootNodeType: tree.rootNode.type });

  // Issue #27: surface parse health to the caller. Tree-sitter happily
  // returns a Tree object for files it can't fully grok (it inserts
  // ERROR / MISSING nodes and recovers), so downstream silence is not a
  // signal that the file parsed cleanly. Compute the report once here and
  // attach it to the IR so consumers can distinguish "no findings" from
  // "no findings because the parser dropped half the file".
  const parseStatus = extractParseStatus(tree);
  if (parseStatus.has_errors) {
    logger.warn('Partial parse — IR may be incomplete', {
      filePath,
      language,
      errorCount: parseStatus.error_count,
      firstErrorLine: parseStatus.error_locations[0]?.line,
    });
  }

  // Collect all node types in a single traversal for better performance
  const nodeCache = collectAllNodes(tree.rootNode, getNodeTypesForLanguage(language));

  // Extract all IR components
  const meta    = extractMeta(code, tree, filePath, language);
  // #235 (3.150.1) — surface the resolved ProjectProfile on per-file meta
  // when the caller supplied one, so downstream consumers can see the exact
  // profile the ADR-008 transform used. Absent when the caller did not pass
  // `options.projectProfile` (preserves 3.150.0 behavior).
  if (options.projectProfile !== undefined) {
    meta.projectProfile = makeProfileResolver(options.projectProfile)(filePath);
  }
  const types   = extractTypes(tree, nodeCache, language);
  const calls   = extractCalls(tree, nodeCache, language);
  const imports = extractImports(tree, language);
  const exports = extractExports(types);
  const cfg     = buildCFG(tree, language);
  const dfg     = buildDFG(tree, nodeCache, language);
  const runtimeRegistrations = extractRuntimeRegistrations(tree, nodeCache, language, imports);

  // Build CodeGraph once — shared across all passes.
  // Taint is empty at construction time; sources/sinks/sanitizers are populated by passes.
  const graph = new CodeGraph({
    meta, types, calls, cfg, dfg,
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports, exports, unresolved: [], enriched: {},
  });

  const config = options.taintConfig ?? getDefaultConfig();

  // Build the analysis pipeline with configurable pass options
  const disabledPasses = new Set(options.disabledPasses ?? []);
  const passOpts = options.passOptions ?? {};

  const pipeline = new AnalysisPipeline();

  // Core taint analysis passes (always enabled)
  pipeline.add(new TaintMatcherPass());
  pipeline.add(new ConstantPropagationPass(tree));
  pipeline.add(new LanguageSourcesPass());
  // cognium-dev #138: tags sources with constant/spi/demoPath booleans;
  // consumed by findings.ts:sourceSemanticsAllowed (via
  // TaintPropagationPass) and by scan-secrets-pass demo-path downgrade.
  // Guarded on disabledPasses so users can opt out.
  if (!disabledPasses.has('source-semantics')) pipeline.add(new SourceSemanticsPass());
  // cognium-dev #236: under `library/*` project profile, drop
  // speculative `interprocedural_param` / `constructor_field` sources
  // before flow generation so `external_taint_escape` (CWE-668) and
  // other `interprocedural_param → *` flows are never emitted. Reads
  // `graph.ir.meta.projectProfile` (populated in 3.150.1 via #235).
  // No-op when profile is absent, `'unknown'`, or non-library shape.
  if (!disabledPasses.has('library-profile-source-gate'))
    pipeline.add(new LibraryProfileSourceGatePass());
  // cognium-dev #241 Java: scan MyBatis @Select/@Update/@Insert/@Delete
  // annotation bodies for `${varname}` interpolation and emit synthetic
  // `sql_injection` sinks on the call sites of the annotated Mapper
  // methods. Runs before SinkFilterPass so the four-stage FP-elimination
  // filter sees the added sinks. Java-only; no-op on other languages.
  if (!disabledPasses.has('mybatis-annotation-sql-sink'))
    pipeline.add(new MyBatisAnnotationSqlSinkPass());
  pipeline.add(new SinkFilterPass());
  // cognium-dev #139 Tier A: drops sinks whose SinkType label disagrees
  // with the curated <Class>#<method> registry (configs/sink-semantics.json).
  // Runs after SinkFilterPass so upstream FP suppressions have already fired,
  // and before TaintPropagationPass so flow generators never see dropped sinks.
  if (!disabledPasses.has('sink-semantics')) pipeline.add(new SinkSemanticsPass());
  // cognium-dev #162 Option B: drops Java reflection `code_injection`
  // sinks in files that declare `main(String[])` AND carry no
  // web-framework Tier-1 signal (annotation OR supertype OR method
  // annotation). Same trust-boundary reasoning as `javac` / `java -jar`:
  // the user IS the CLI. Runs after SinkSemanticsPass so its curated
  // drops fire first, and before TaintPropagationPass so flow
  // generators never see the dropped sinks.
  if (!disabledPasses.has('cli-main-reflection-suppress'))
    pipeline.add(new CliMainReflectionSuppressPass());
  // cognium-dev #232: under `library/*` project profile, drop the
  // entire `log_injection` (CWE-117) sink class before flow generation.
  // Rationale: CWE-117 requires a downstream log-viewer executing
  // content — an application-integration concern, not a library defect.
  // Empirically ~10% of H+C findings on Tier 2 library repos are
  // `log_injection` (cognium-ai#189 §1). Sink-side companion to #236
  // (source-side drop). Reads `graph.ir.meta.projectProfile` (#235).
  // No-op when profile is absent, `'unknown'`, or non-library shape.
  if (!disabledPasses.has('library-profile-sink-gate'))
    pipeline.add(new LibraryProfileSinkGatePass());
  // cognium-dev #244: under `library/*` project profile, drop `xss`
  // (CWE-79) sinks whose simple-name receiver class is on a curated
  // non-HTML-output denylist (`StringBuilder`, `PrintStream`,
  // `HttpSession`, `HttpRequest`, jedis wire-writers, JSON parsers,
  // Loggers, Zuul `RequestContext`, Sentinel `Context`). Runs after
  // #112 so the sink list is already free of `log_injection` sinks;
  // runs before `TaintPropagationPass` so flow generators never see
  // the dropped sinks. Empirically drops 507 H+C FPs across the 10-repo
  // Tier 2 cohort (cognium-ai#189 §3, 2026-07).
  if (!disabledPasses.has('library-profile-xss-gate'))
    pipeline.add(new LibraryProfileXssGatePass());
  pipeline.add(new TaintPropagationPass());
  pipeline.add(new InterproceduralPass({
    enableEntryPointGate: options.enableEntryPointGate ?? true,
  }));
  // cognium-dev #245 RC1 (belt-and-suspenders): under `library/*`
  // profile, drop CWE-22 (`path_traversal`) flows whose source shape
  // is `interprocedural_param` / `constructor_field` — the same
  // speculative shapes `LibraryProfileSourceGatePass` (#236) already
  // drops from `graph.ir.taint.sources`. Belt-and-suspenders because
  // 170/246 CWE-22 H+C findings on the Tier 2 10-repo cohort
  // (cognium-ai#189 §4) carried an `interprocedural_param` source
  // with empty `source.code`. Runs post-`InterproceduralPass` so it
  // filters the authoritative `taint.flows` list. No-op when profile
  // is absent, `'unknown'`, or non-library shape.
  if (!disabledPasses.has('library-profile-cwe22-path-gate'))
    pipeline.add(new LibraryProfileCwe22PathGatePass());

  // Secret scanner runs after LanguageSourcesPass so the legacy Bash
  // `hardcoded-credential` findings are already in the dedup buffer.
  if (!disabledPasses.has('scan-secrets'))          pipeline.add(new ScanSecretsPass());

  // Optional passes — can be disabled via disabledPasses
  if (!disabledPasses.has('dead-code'))             pipeline.add(new DeadCodePass());
  if (!disabledPasses.has('missing-await'))         pipeline.add(new MissingAwaitPass());
  if (!disabledPasses.has('n-plus-one'))            pipeline.add(new NPlusOnePass());
  if (!disabledPasses.has('missing-public-doc'))    pipeline.add(new MissingPublicDocPass());
  if (!disabledPasses.has('todo-in-prod'))          pipeline.add(new TodoInProdPass());
  if (!disabledPasses.has('string-concat-loop'))    pipeline.add(new StringConcatLoopPass());
  if (!disabledPasses.has('sync-io-async'))         pipeline.add(new SyncIoAsyncPass());
  if (!disabledPasses.has('unchecked-return'))      pipeline.add(new UncheckedReturnPass());
  if (!disabledPasses.has('null-deref'))            pipeline.add(new NullDerefPass());
  if (!disabledPasses.has('resource-leak'))         pipeline.add(new ResourceLeakPass());
  if (!disabledPasses.has('variable-shadowing'))    pipeline.add(new VariableShadowingPass());
  if (!disabledPasses.has('leaked-global'))         pipeline.add(new LeakedGlobalPass());
  if (!disabledPasses.has('unused-variable'))       pipeline.add(new UnusedVariablePass());
  if (!disabledPasses.has('dependency-fan-out'))    pipeline.add(new DependencyFanOutPass(passOpts.dependencyFanOut));
  if (!disabledPasses.has('stale-doc-ref'))         pipeline.add(new StaleDocRefPass());
  if (!disabledPasses.has('infinite-loop'))         pipeline.add(new InfiniteLoopPass());
  if (!disabledPasses.has('deep-inheritance'))      pipeline.add(new DeepInheritancePass());
  if (!disabledPasses.has('redundant-loop-computation')) pipeline.add(new RedundantLoopPass());
  if (!disabledPasses.has('unbounded-collection'))  pipeline.add(new UnboundedCollectionPass(passOpts.unboundedCollection));
  if (!disabledPasses.has('serial-await'))          pipeline.add(new SerialAwaitPass());
  if (!disabledPasses.has('react-inline-jsx'))      pipeline.add(new ReactInlineJsxPass());
  if (!disabledPasses.has('swallowed-exception'))   pipeline.add(new SwallowedExceptionPass());
  if (!disabledPasses.has('broad-catch'))           pipeline.add(new BroadCatchPass());
  if (!disabledPasses.has('unhandled-exception'))   pipeline.add(new UnhandledExceptionPass());
  if (!disabledPasses.has('double-close'))          pipeline.add(new DoubleClosePass());
  if (!disabledPasses.has('use-after-close'))       pipeline.add(new UseAfterClosePass());
  if (!disabledPasses.has('cleanup-verify'))        pipeline.add(new CleanupVerifyPass());
  if (!disabledPasses.has('missing-override'))      pipeline.add(new MissingOverridePass());
  if (!disabledPasses.has('unused-interface-method')) pipeline.add(new UnusedInterfaceMethodPass());
  if (!disabledPasses.has('blocking-main-thread'))  pipeline.add(new BlockingMainThreadPass());
  if (!disabledPasses.has('excessive-allocation'))  pipeline.add(new ExcessiveAllocationPass());
  if (!disabledPasses.has('missing-stream'))        pipeline.add(new MissingStreamPass());
  if (!disabledPasses.has('god-class'))             pipeline.add(new GodClassPass());
  if (!disabledPasses.has('naming-convention'))     pipeline.add(new NamingConventionPass(passOpts.namingConvention));
  if (!disabledPasses.has('security-headers'))      pipeline.add(new SecurityHeadersPass(passOpts.securityHeaders));
  if (!disabledPasses.has('spring4shell'))          pipeline.add(new Spring4ShellPass());
  if (!disabledPasses.has('insecure-cookie'))       pipeline.add(new InsecureCookiePass());
  if (!disabledPasses.has('weak-hash'))             pipeline.add(new WeakHashPass());
  if (!disabledPasses.has('weak-crypto'))           pipeline.add(new WeakCryptoPass());
  if (!disabledPasses.has('weak-random'))           pipeline.add(new WeakRandomPass());
  if (!disabledPasses.has('weak-password-hash'))    pipeline.add(new WeakPasswordHashPass());
  if (!disabledPasses.has('weak-password-encoding')) pipeline.add(new WeakPasswordEncodingPass());
  if (!disabledPasses.has('plaintext-password-storage')) pipeline.add(new PlaintextPasswordStoragePass());
  if (!disabledPasses.has('cleartext-credential-transport')) pipeline.add(new CleartextCredentialTransportPass());
  if (!disabledPasses.has('tls-verify-disabled'))   pipeline.add(new TlsVerifyDisabledPass());
  if (!disabledPasses.has('module-side-effect'))    pipeline.add(new ModuleSideEffectPass());
  if (!disabledPasses.has('cache-no-vary'))         pipeline.add(new CacheNoVaryPass());
  if (!disabledPasses.has('jwt-verify-disabled'))   pipeline.add(new JwtVerifyDisabledPass());
  if (!disabledPasses.has('csrf-protection-disabled')) pipeline.add(new CsrfProtectionDisabledPass());
  if (!disabledPasses.has('xml-entity-expansion'))  pipeline.add(new XmlEntityExpansionPass());
  if (!disabledPasses.has('mass-assignment'))       pipeline.add(new MassAssignmentPass());
  if (!disabledPasses.has('info-disclosure-stacktrace')) pipeline.add(new InfoDisclosureStacktracePass());
  if (!disabledPasses.has('unrestricted-file-upload')) pipeline.add(new UnrestrictedFileUploadPass());
  if (!disabledPasses.has('missing-sanitizer-gate')) pipeline.add(new MissingSanitizerGatePass());

  // Run the pipeline
  const { results, findings } = pipeline.run(graph, code, language, config);

  const sinkFilter = results.get('sink-filter')    as SinkFilterResult;
  const interProc  = results.get('interprocedural') as InterproceduralPassResult;

  const taint: CircleIR['taint'] = {
    sources:    sinkFilter.sources,
    sinks:      [...sinkFilter.sinks, ...interProc.additionalSinks],
    sanitizers: sinkFilter.sanitizers,
    flows:      interProc.additionalFlows,
    interprocedural: interProc.interprocedural,
  };

  // 3.105.0 — propagate tags from `TaintSink.tags` onto every emitted
  // `TaintFlowInfo.tags` so downstream consumers (CLI, SARIF) can apply
  // policy-aware rendering. Matched by (sink_line, sink_type). Sinks
  // without tags are no-ops; existing flow.tags are preserved.
  if (taint.flows && taint.flows.length > 0 && taint.sinks.length > 0) {
    const sinkTagsByKey = new Map<string, string[]>();
    for (const s of taint.sinks) {
      if (!s.tags || s.tags.length === 0) continue;
      sinkTagsByKey.set(`${s.line}:${s.type}`, s.tags);
    }
    if (sinkTagsByKey.size > 0) {
      for (const f of taint.flows) {
        const tags = sinkTagsByKey.get(`${f.sink_line}:${f.sink_type}`);
        if (tags && !f.tags) f.tags = [...tags];
      }
    }
  }

  const unresolved = detectUnresolved(calls, types, dfg);
  const enriched   = buildEnriched(types, calls, taint.sources, taint.sinks);

  // Compute software metrics (CK suite, Halstead, composite scores)
  const metricValues = new MetricRunner().run(
    { meta, types, calls, cfg, dfg, taint, imports, exports, unresolved, enriched },
    code,
    language
  );

  logger.debug('Analysis complete', {
    filePath,
    finalSources: taint.sources.length,
    finalSinks:   taint.sinks.length,
    flows:        taint.flows?.length ?? 0,
    unresolvedItems: unresolved.length,
  });

  // #145 PR B — opt-in per-file findings instrumentation. No-op unless
  // toggled via setFindingsInstrumentation(true). Strictly read-only.
  // Runs before the confidence filter + per-file cap so diagnostics observe
  // the uncapped, unfiltered stream.
  emitFindingsInstrumentation(filePath, findings, taint);

  // #153 pre-req (3.94.0) — confidence-based suppression. By default, drop
  // speculative (`confidence: 'medium' | 'low'`) findings; with
  // `options.includeSpeculative === true`, preserve the full stream for
  // downstream adjudication. Existing passes (which do not set `confidence`)
  // are treated as `'high'` and pass through unchanged.
  const verifiedFindings = applyConfidenceFilter(findings, options.includeSpeculative === true);

  // #161/#165/#168 (3.105.0) — central library-API-surface downgrade. Findings
  // carrying the `library-api-surface:caller-responsibility` tag (emitted by
  // SinkFilterPass Stages 9e/9f/9g) are downgraded to medium/warning. Non-tagged
  // findings pass through unchanged. The pre-downgrade severity is preserved
  // on each downgraded finding as `original_severity` so the profile transform
  // below can restore it under `application` profile.
  const downgradedFindings = applyLibraryApiSurfaceDowngrade(verifiedFindings);

  // #169 (3.106.0) — project-profile-conditional transform. Under `library`
  // profile, eligible tagged findings get CRIT-protected bucketing; under
  // `application` profile, tagged findings are restored to `original_severity`.
  // `unknown` (default) is a no-op. See `docs/ARCHITECTURE.md` ADR-008.
  const profiledFindings = applyProjectProfileTransform(
    downgradedFindings,
    makeProfileResolver(options.projectProfile),
  );

  // #142 defensive per-file finding cap. If a file produces more than
  // `cap` findings, drop the individual results and emit a single
  // `saturated-file` advisory in their place. Default cap = 1000;
  // `perFileFindingCap: 0` disables.
  const cappedFindings = applyPerFileFindingCap(
    filePath,
    profiledFindings,
    options.perFileFindingCap ?? DEFAULT_PER_FILE_FINDING_CAP,
  );

  return {
    meta, types, calls, cfg, dfg, taint, imports, exports, unresolved, enriched,
    findings: cappedFindings.length > 0 ? cappedFindings : undefined,
    metrics: { file: filePath, metrics: metricValues },
    runtime_registrations: runtimeRegistrations.length > 0 ? runtimeRegistrations : undefined,
    parse_status: parseStatus,
  };
  } finally {
    disposeTree(tree);
  }
}

// ---------------------------------------------------------------------------
// HTML preprocessor
// ---------------------------------------------------------------------------

/**
 * Analyze an HTML-grammar markup file (`.html`, `.htm`, `.xhtml`, `.vue`)
 * by extracting script blocks and event handlers, delegating JS analysis
 * to the standard pipeline, and running attribute-level security checks.
 *
 * Vue SFCs reuse this path because `<template>` / `<script>` / `<style>`
 * blocks parse identically under tree-sitter-html (cognium-dev #184).
 */
async function analyzeMarkupFile(
  code: string,
  filePath: string,
  options: AnalyzerOptions,
  language: SupportedLanguage,
): Promise<CircleIR> {
  logger.debug('Analyzing markup file', { filePath, language, codeLength: code.length });

  // Parse with the HTML grammar (Vue SFCs are HTML-syntax-wrapped).
  const tree = await parse(code, 'html');
  try {
  const meta = extractMeta(code, tree, filePath, language);

  const htmlParseStatus = extractParseStatus(tree);
  if (htmlParseStatus.has_errors) {
    logger.warn('Partial parse — IR may be incomplete', {
      filePath,
      language,
      errorCount: htmlParseStatus.error_count,
      firstErrorLine: htmlParseStatus.error_locations[0]?.line,
    });
  }

  // Extract script blocks and event handlers
  const { scriptBlocks, eventHandlers } = extractHtmlContent(tree.rootNode);

  logger.debug('HTML extraction', {
    filePath,
    inlineScripts: scriptBlocks.filter(b => b.kind === 'inline').length,
    externalScripts: scriptBlocks.filter(b => b.kind === 'external-src').length,
    eventHandlers: eventHandlers.length,
  });

  // Analyze each inline script block via standard JS pipeline
  const scriptResults: ScriptBlockResult[] = [];

  for (const block of scriptBlocks) {
    if (block.kind !== 'inline' || !block.code.trim()) continue;

    // Determine script language from type/lang attribute
    const scriptLang: SupportedLanguage =
      block.scriptType === 'ts' || block.scriptType === 'typescript' ||
      block.scriptType === 'text/typescript'
        ? 'typescript'
        : 'javascript';

    try {
      const ir = await analyze(block.code, filePath, scriptLang, options);
      scriptResults.push({ ir, lineOffset: block.lineOffset });
    } catch (e) {
      logger.warn('Failed to analyze script block', {
        filePath,
        lineOffset: block.lineOffset,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  // Analyze inline event handlers (wrap in synthetic function)
  for (const handler of eventHandlers) {
    const wrappedCode = `function __${handler.eventName}_handler() { ${handler.code} }`;
    try {
      const ir = await analyze(wrappedCode, filePath, 'javascript', options);
      scriptResults.push({ ir, lineOffset: handler.line });
    } catch (e) {
      logger.warn('Failed to analyze event handler', {
        filePath,
        eventName: handler.eventName,
        line: handler.line,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  // Run attribute-level security checks
  const attributeFindings = runHtmlAttributeSecurityChecks(tree.rootNode, filePath);

  // Vue-only: walk the <template> subtree for dangerous attribute
  // bindings (v-html / :innerHTML / etc.) that reference identifiers
  // tainted in the file's script blocks. Sprint 64 / cognium-dev #184.
  if (language === 'vue') {
    const vueXss = runVueTemplateXssChecks(tree.rootNode, filePath, scriptResults);
    if (vueXss.length > 0) attributeFindings.push(...vueXss);
  }

  // Merge everything
  const result = mergeHtmlResults(meta, scriptResults, attributeFindings);
  result.parse_status = htmlParseStatus;

  logger.debug('HTML analysis complete', {
    filePath,
    scriptBlocks: scriptResults.length,
    attributeFindings: attributeFindings.length,
    totalFindings: result.findings?.length ?? 0,
  });

  return result;
  } finally {
    disposeTree(tree);
  }
}

// ---------------------------------------------------------------------------
// Simplified API response format
// ---------------------------------------------------------------------------

/**
 * Analyze code and return a simplified API response format.
 */
export async function analyzeForAPI(
  code: string,
  filePath: string,
  language: SupportedLanguage,
  options: AnalyzerOptions = {}
): Promise<AnalysisResponse> {
  const startTime = performance.now();

  if (!initialized) {
    await initAnalyzer(options);
  }

  const parseStart = performance.now();
  const tree = await parse(code, language);
  const parseTime = performance.now() - parseStart;

  try {
  const analysisStart = performance.now();

  const nodeCache = collectAllNodes(tree.rootNode, getNodeTypesForLanguage(language));

  const types = extractTypes(tree, nodeCache, language);
  const calls = extractCalls(tree, nodeCache, language);

  // Run constant propagation
  const constPropResult = analyzeConstantPropagation(tree, code);

  const config = options.taintConfig ?? getDefaultConfig();
  const taint = analyzeTaint(calls, types, config, undefined, language, code);

  // Filter sinks in dead code
  let filteredSinks = taint.sinks.filter(sink => !constPropResult.unreachableLines.has(sink.line));

  // Filter sinks whose arguments are proven clean (string literals, constants, etc.)
  filteredSinks = filterCleanVariableSinks(
    filteredSinks,
    calls,
    constPropResult.tainted,
    constPropResult.symbols,
    undefined,
    constPropResult.sanitizedVars,
    constPropResult.synchronizedLines
  );

  // Filter sinks wrapped by sanitizers on the same line
  filteredSinks = filterSanitizedSinks(filteredSinks, taint.sanitizers ?? [], calls);

  // Python: reduce XPath false-positives using forward taint propagation +
  // apostrophe-guard sanitizer detection.
  let pythonTaintedVars: Map<string, number> = new Map();
  if (language === 'python') {
    pythonTaintedVars = buildPythonTaintedVars(code);
    const pythonSanitizedVars = buildPythonSanitizedVars(code, pythonTaintedVars);
    const sourceLines = code.split('\n');
    filteredSinks = filteredSinks.filter(sink => {
      if (sink.type !== 'xpath_injection') return true;
      const sinkLineText = sourceLines[sink.line - 1] ?? '';
      const taintedVarOnLine = [...pythonTaintedVars.keys()].find(v =>
        new RegExp(`\\b${v}\\b`).test(sinkLineText)
      );
      if (!taintedVarOnLine) return false;
      if (pythonSanitizedVars.has(taintedVarOnLine)) return false;
      if (new RegExp(`\\.xpath\\s*\\([^)]*\\b\\w+\\s*=\\s*\\b${taintedVarOnLine}\\b`).test(sinkLineText)) return false;
      return true;
    });
  }

  // Generate vulnerabilities from source-sink pairs
  const vulnerabilities = findVulnerabilities(taint.sources, filteredSinks, calls, constPropResult);

  // Python: detect trust boundary violations (flask.session[key] = taintedVal)
  if (language === 'python') {
    const trustViolations = findPythonTrustBoundaryViolations(code, pythonTaintedVars);
    for (const v of trustViolations) {
      const alreadyReported = vulnerabilities.some(
        existing => existing.sink.line === v.sinkLine && existing.type === 'trust_boundary'
      );
      if (!alreadyReported) {
        vulnerabilities.push({
          type: 'trust_boundary',
          cwe: 'CWE-501',
          severity: 'medium',
          source: { line: v.sourceLine, type: 'http_param' },
          sink: { line: v.sinkLine, type: 'trust_boundary' },
          confidence: 0.85,
        });
      }
    }
  }

  const analysisTime = performance.now() - analysisStart;
  const totalTime = performance.now() - startTime;

  return {
    success: true,
    analysis: {
      sources: taint.sources,
      sinks: filteredSinks,
      vulnerabilities,
    },
    meta: {
      parseTimeMs: Math.round(parseTime),
      analysisTimeMs: Math.round(analysisTime),
      totalTimeMs: Math.round(totalTime),
    },
  };
  } finally {
    disposeTree(tree);
  }
}

// ---------------------------------------------------------------------------
// Vulnerability matching (used by analyzeForAPI)
// ---------------------------------------------------------------------------

/**
 * Find potential vulnerabilities by matching sources to sinks.
 */
function findVulnerabilities(
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  calls?: CircleIR['calls'],
  constPropResult?: { tainted: Set<string>; symbols: Map<string, { type: string; value: unknown }> }
): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  const sourceToSinkMapping: Record<string, string[]> = {
    http_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf'],
    http_body: ['sql_injection', 'command_injection', 'deserialization', 'xxe', 'xss', 'code_injection'],
    http_header: ['sql_injection', 'xss', 'ssrf'],
    http_cookie: ['sql_injection', 'xss'],
    http_path: ['path_traversal', 'sql_injection', 'ssrf'],
    http_query: ['sql_injection', 'command_injection', 'xss', 'ssrf'],
    io_input: ['command_injection', 'path_traversal', 'deserialization', 'xxe', 'code_injection', 'xss'],
    env_input: ['command_injection', 'path_traversal'],
    db_input: ['xss', 'sql_injection'],
    file_input: ['deserialization', 'xxe', 'path_traversal', 'command_injection', 'code_injection', 'xss'],
    network_input: ['sql_injection', 'command_injection', 'xss', 'ssrf'],
    config_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'ssrf'],
    interprocedural_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'code_injection'],
    plugin_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'code_injection'],
    constructor_field: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'code_injection', 'deserialization', 'xxe'],
  };

  for (const source of sources) {
    const potentialSinks = sourceToSinkMapping[source.type] ?? [];

    for (const sink of sinks) {
      if (potentialSinks.includes(sink.type)) {
        // Check if we have constant propagation data to verify actual taint flow
        if (calls && constPropResult) {
          const sinkCall = calls.find(c => c.location.line === sink.line);
          if (sinkCall) {
            if (sink.type === 'sql_injection' && sinkCall.arguments.length > 0) {
              const queryArg = sinkCall.arguments[0];
              if (queryArg.variable) {
                const isConstant = constPropResult.symbols.has(queryArg.variable) &&
                  constPropResult.symbols.get(queryArg.variable)?.type === 'string';
                const isTainted = constPropResult.tainted.has(queryArg.variable);
                if (isConstant && !isTainted) {
                  continue;
                }
              }
              if (queryArg.expression) {
                const hasConcatenation = queryArg.expression.includes('+');
                if (!hasConcatenation) {
                  const anyArgTainted = sinkCall.arguments.some(arg =>
                    arg.variable && constPropResult.tainted.has(arg.variable)
                  );
                  if (!anyArgTainted || !queryArg.expression?.includes('+')) {
                    const queryValue = constPropResult.symbols.get(queryArg.variable || '')?.value;
                    if (typeof queryValue === 'string' &&
                        (queryValue.includes('?') || queryValue.includes('$') || queryValue.includes(':'))) {
                      continue;
                    }
                  }
                }
              }
            }
          }
        }

        const confidence = calculateVulnConfidence(source, sink);

        vulnerabilities.push({
          type: sink.type,
          cwe: sink.cwe,
          severity: sink.confidence > 0.9 ? 'critical' : 'high',
          source: {
            line: source.line,
            type: source.type,
          },
          sink: {
            line: sink.line,
            type: sink.type,
          },
          confidence,
        });
      }
    }
  }

  // Deduplicate vulnerabilities
  const vulnMap = new Map<string, typeof vulnerabilities[0]>();
  for (const vuln of vulnerabilities) {
    const key = `${vuln.source.line}:${vuln.sink.line}:${vuln.type}`;
    const existing = vulnMap.get(key);
    if (!existing || vuln.confidence > existing.confidence) {
      vulnMap.set(key, vuln);
    }
  }
  const dedupedVulns = Array.from(vulnMap.values());
  dedupedVulns.sort((a, b) => b.confidence - a.confidence);

  return dedupedVulns;
}

function calculateVulnConfidence(
  source: CircleIR['taint']['sources'][0],
  sink: CircleIR['taint']['sinks'][0]
): number {
  let confidence = 0.5;
  const lineDiff = Math.abs(source.line - sink.line);
  if (lineDiff < 10) {
    confidence += 0.3;
  } else if (lineDiff < 50) {
    confidence += 0.15;
  }
  if (source.severity === 'high') {
    confidence += 0.1;
  }
  confidence = confidence * sink.confidence;
  return Math.min(confidence, 1.0);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/**
 * Check if the analyzer is initialized.
 */
export function isAnalyzerInitialized(): boolean {
  return initialized;
}

/**
 * Reset the analyzer (mainly for testing).
 */
export function resetAnalyzer(): void {
  initialized = false;
}

// ---------------------------------------------------------------------------
// Project-level analysis (multi-file)
// ---------------------------------------------------------------------------

/**
 * Analyze a set of files as a project, finding cross-file taint flows.
 *
 * Runs single-file `analyze()` on each file in order, then uses
 * `ProjectGraph` + `CrossFileResolver` to surface flows that cross file
 * boundaries.  The per-file `CircleIR` outputs are preserved unchanged in
 * `ProjectAnalysis.files`.
 *
 * `findings` is always empty — it requires LLM enrichment which is out of
 * scope for this library (see CLAUDE.md and SPEC.md section 11).
 */
export async function analyzeProject(
  files: Array<{ code: string; filePath: string; language: SupportedLanguage }>,
  options: AnalyzerOptions = {},
): Promise<ProjectAnalysis> {
  const fileAnalyses: Array<{ file: string; analysis: CircleIR }> = [];
  const projectGraph = new ProjectGraph();
  const sourceLinesByFile = new Map<string, string[]>();

  // 1. Per-file analysis
  for (const { code, filePath, language } of files) {
    const ir = await analyze(code, filePath, language, options);
    fileAnalyses.push({ file: filePath, analysis: ir });
    projectGraph.addFile(filePath, new CodeGraph(ir));
    sourceLinesByFile.set(filePath, code.split('\n'));
  }

  // 2. Cross-file analysis
  //    Apply default budget of 300s if not specified by caller. `0` disables.
  const crossFileBudgetMs = options.crossFileBudgetMs ?? 300_000;
  const crossFileResult = new CrossFilePass().run(
    projectGraph,
    sourceLinesByFile,
    { budgetMs: crossFileBudgetMs },
  );

  // 2.5 Cross-file security-header inheritance (CORS via virtual methods)
  const disabledPasses = options.disabledPasses ?? [];
  if (!disabledPasses.includes('security-headers')) {
    const inheritedFindings = checkInheritedCorsHeaders(
      fileAnalyses, projectGraph.typeHierarchy, sourceLinesByFile,
    );
    for (const finding of inheritedFindings) {
      const fa = fileAnalyses.find(f => f.file === finding.file);
      if (fa) {
        fa.analysis.findings = [...(fa.analysis.findings ?? []), finding];
      }
    }
  }

  // 3. Import-graph analysis (circular deps + orphan modules)
  const importGraph = new ImportGraph(projectGraph);
  const circularFindings = disabledPasses.includes('circular-dependency')
    ? []
    : new CircularDependencyPass().run(projectGraph, importGraph);
  const orphanFindings = disabledPasses.includes('orphan-module')
    ? []
    : new OrphanModulePass().run(projectGraph, importGraph);

  // Attach project-level findings to the appropriate per-file CircleIR.findings
  for (const finding of [...circularFindings, ...orphanFindings]) {
    const fa = fileAnalyses.find(f => f.file === finding.file);
    if (fa) {
      fa.analysis.findings = [...(fa.analysis.findings ?? []), finding];
    }
  }

  // 3.5 (3.153.0, #234) — require-entry-path gate. After every pass has
  // deposited its findings into per-file `analysis.findings`, walk the
  // full project method graph and drop H+C security findings that have
  // no reachable path from a classified Tier-1 entry point. Findings
  // that ARE reachable get annotated with `entryPath[]`. Runs BEFORE
  // ProjectMeta assembly so downstream consumers see the gated stream.
  // No-op when the caller disabled the rule via `disabledPasses`.
  applyRequireEntryPath(fileAnalyses, {
    projectProfile: options.projectProfile,
    disabledPasses: options.disabledPasses,
  });

  // 4. Assemble ProjectMeta
  const filePaths = files.map(f => f.filePath);
  const totalLoc  = fileAnalyses.reduce((sum, f) => sum + (f.analysis.meta.loc ?? 0), 0);
  const meta: ProjectMeta = {
    name:         deriveProjectName(filePaths),
    root:         deriveProjectRoot(filePaths),
    language:     files[0]?.language ?? 'java',
    total_files:  files.length,
    total_loc:    totalLoc,
    analyzed_at:  new Date().toISOString(),
  };
  // #235 (3.150.1) — attach a per-scan ProjectProfile rollup so consumers
  // (cognium-ai#189 Tier 2 audit; cognium-ai#130 detector; downstream
  // ledgers) can verify what fraction of the repo was classified as
  // `library/*` before treating tagged findings as caller-driven FPs.
  // Only emitted when the caller supplied `options.projectProfile`; a
  // no-op absence preserves 3.150.0 output shape.
  if (options.projectProfile !== undefined) {
    meta.projectProfileSummary = computeProjectProfileSummary(fileAnalyses);
  }

  const projectAnalysis: ProjectAnalysis = {
    meta,
    files: fileAnalyses,
    type_hierarchy:  crossFileResult.typeHierarchy,
    cross_file_calls: crossFileResult.crossFileCalls,
    taint_paths:     crossFileResult.taintPaths,
    findings: [],
  };
  if (crossFileResult.budgetExceeded) {
    projectAnalysis.cross_file_budget_exceeded = true;
  }
  return projectAnalysis;
}

/** Derive a project name from the common root directory of the file paths. */
function deriveProjectName(paths: string[]): string {
  if (paths.length === 0) return 'unknown';
  const root = deriveProjectRoot(paths);
  return root.split('/').filter(Boolean).pop() ?? 'unknown';
}

/** Derive the common ancestor directory from a list of file paths. */
function deriveProjectRoot(paths: string[]): string {
  if (paths.length === 0) return '/';
  const segments = paths[0].split('/');
  let common = segments.slice(0, -1); // strip filename
  for (const p of paths.slice(1)) {
    const segs = p.split('/');
    common = common.filter((seg, i) => segs[i] === seg);
  }
  return common.join('/') || '/';
}

// Re-export isFalsePositive for consumers that use it directly
export { isFalsePositive };
