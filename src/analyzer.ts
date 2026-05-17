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
 *
 * Removed from default pipeline (raw IR signals still available for circle-ir-ai):
 *  – MissingGuardDomPass  — false positives in framework-auth codebases (see pass file)
 *  – FeatureEnvyPass      — fires on legitimate delegation patterns (see pass file)
 */

import type { CircleIR, AnalysisResponse, Vulnerability, Enriched, ProjectAnalysis, ProjectMeta } from './types/index.js';
import type { TaintConfig } from './types/config.js';
import {
  initParser,
  parse,
  extractMeta,
  extractTypes,
  extractCalls,
  extractImports,
  extractExports,
  buildCFG,
  buildDFG,
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
import { registerBuiltinPlugins } from './languages/index.js';
import { logger } from './utils/logger.js';
import { CodeGraph, AnalysisPipeline, ProjectGraph } from './graph/index.js';
import { CrossFilePass } from './analysis/passes/cross-file-pass.js';

// HTML preprocessor
import { extractHtmlContent } from './analysis/html/html-extractor.js';
import { runHtmlAttributeSecurityChecks } from './analysis/html/html-attribute-security-pass.js';
import { mergeHtmlResults } from './analysis/html/html-merge.js';
import type { ScriptBlockResult } from './analysis/html/html-merge.js';

// Pass classes
import { TaintMatcherPass } from './analysis/passes/taint-matcher-pass.js';
import { ConstantPropagationPass } from './analysis/passes/constant-propagation-pass.js';
import { LanguageSourcesPass } from './analysis/passes/language-sources-pass.js';
import { SinkFilterPass, filterCleanVariableSinks, filterSanitizedSinks } from './analysis/passes/sink-filter-pass.js';
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
      ]);
    case 'python':
      return new Set([
        'call', 'function_definition', 'class_definition', 'import_statement',
        'import_from_statement', 'assignment', 'attribute', 'subscript',
      ]);
    case 'javascript':
    case 'typescript':
      return new Set([
        'call_expression', 'new_expression', 'class_declaration', 'function_declaration',
        'arrow_function', 'method_definition', 'variable_declaration', 'lexical_declaration',
        'import_statement', 'export_statement', 'member_expression', 'assignment_expression',
      ]);
    case 'bash':
      return new Set([
        'command', 'function_definition', 'variable_assignment', 'declaration_command',
        'if_statement', 'for_statement', 'c_style_for_statement', 'while_statement',
      ]);
    case 'html':
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

  // HTML preprocessor path — extract scripts and delegate to JS analyzer
  if (language === 'html') {
    return analyzeHtmlFile(code, filePath, options);
  }

  logger.debug('Analyzing file', { filePath, language, codeLength: code.length });

  // Parse the code
  const tree = await parse(code, language);
  logger.trace('Parsed AST', { rootNodeType: tree.rootNode.type });

  // Collect all node types in a single traversal for better performance
  const nodeCache = collectAllNodes(tree.rootNode, getNodeTypesForLanguage(language));

  // Extract all IR components
  const meta    = extractMeta(code, tree, filePath, language);
  const types   = extractTypes(tree, nodeCache, language);
  const calls   = extractCalls(tree, nodeCache, language);
  const imports = extractImports(tree, language);
  const exports = extractExports(types);
  const cfg     = buildCFG(tree, language);
  const dfg     = buildDFG(tree, nodeCache, language);

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
  pipeline.add(new SinkFilterPass());
  pipeline.add(new TaintPropagationPass());
  pipeline.add(new InterproceduralPass());

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

  return {
    meta, types, calls, cfg, dfg, taint, imports, exports, unresolved, enriched,
    findings: findings.length > 0 ? findings : undefined,
    metrics: { file: filePath, metrics: metricValues },
  };
}

// ---------------------------------------------------------------------------
// HTML preprocessor
// ---------------------------------------------------------------------------

/**
 * Analyze an HTML file by extracting script blocks and event handlers,
 * delegating JS analysis to the standard pipeline, and running
 * attribute-level security checks.
 */
async function analyzeHtmlFile(
  code: string,
  filePath: string,
  options: AnalyzerOptions,
): Promise<CircleIR> {
  logger.debug('Analyzing HTML file', { filePath, codeLength: code.length });

  // Parse HTML
  const tree = await parse(code, 'html');
  const meta = extractMeta(code, tree, filePath, 'html');

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

  // Merge everything
  const result = mergeHtmlResults(meta, scriptResults, attributeFindings);

  logger.debug('HTML analysis complete', {
    filePath,
    scriptBlocks: scriptResults.length,
    attributeFindings: attributeFindings.length,
    totalFindings: result.findings?.length ?? 0,
  });

  return result;
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

  const analysisStart = performance.now();

  const nodeCache = collectAllNodes(tree.rootNode, getNodeTypesForLanguage(language));

  const types = extractTypes(tree, nodeCache, language);
  const calls = extractCalls(tree, nodeCache, language);

  // Run constant propagation
  const constPropResult = analyzeConstantPropagation(tree, code);

  const config = options.taintConfig ?? getDefaultConfig();
  const taint = analyzeTaint(calls, types, config);

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
  const crossFileResult = new CrossFilePass().run(projectGraph, sourceLinesByFile);

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

  return {
    meta,
    files: fileAnalyses,
    type_hierarchy:  crossFileResult.typeHierarchy,
    cross_file_calls: crossFileResult.crossFileCalls,
    taint_paths:     crossFileResult.taintPaths,
    findings: [],
  };
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
