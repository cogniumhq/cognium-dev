/**
 * Circle-IR TypeScript Library
 *
 * A universal library for static analysis and taint tracking.
 */

// Main analyzer
export {
  initAnalyzer,
  analyze,
  analyzeForAPI,
  analyzeProject,
  isAnalyzerInitialized,
  resetAnalyzer,
  type AnalyzerOptions,
} from './analyzer.js';

// Per-pass option types (exported so consumers can type passOptions without importing from deep paths)
export type { NamingConventionOptions } from './analysis/passes/naming-convention-pass.js';
export type { DependencyFanOutOptions } from './analysis/passes/dependency-fan-out-pass.js';
export type { UnboundedCollectionOptions } from './analysis/passes/unbounded-collection-pass.js';
export type { PassOptions } from './analyzer.js';

// Types
export type {
  // Core IR types
  CircleIR,
  Meta,
  TypeInfo,
  MethodInfo,
  ParameterInfo,
  FieldInfo,
  CallInfo,
  ArgumentInfo,
  CallResolution,
  CFG,
  CFGBlock,
  CFGEdge,
  DFG,
  DFGDef,
  DFGUse,
  DFGChain,
  Taint,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  ImportInfo,
  ExportInfo,
  UnresolvedItem,
  Enriched,
  EnrichedFunction,
  ResolvedCall,
  Finding,
  TaintHop,
  Vulnerability,
  AnalysisResponse,

  // Utility types
  SourceType,
  SinkType,
  Severity,

  // Project profile types (3.106.0, #169)
  ProjectShape,
  ProjectEnv,
  ProjectProfile,

  // SAST taxonomy types (Phase 1+)
  PassCategory,
  SarifLevel,
  SastFinding,
  MetricCategory,
  MetricValue,
  FileMetrics,

  // Project-level types
  ProjectAnalysis,
  ProjectMeta,
  FileAnalysis,
  TypeHierarchy,
  ClassHierarchyInfo,
  InterfaceHierarchyInfo,
  CrossFileCall,
  ArgMapping,
  TaintPath,
} from './types/index.js';

// Config types
export type {
  SourceConfig,
  SinkConfig,
  TaintConfig,
  SourcePattern,
  SinkPattern,
  SanitizerPattern,
} from './types/config.js';

// Core utilities (for advanced usage)
export {
  initParser,
  parse,
  walkTree,
  findNodes,
  findAncestor,
  getNodeText,
  collectAllNodes,
  type SupportedLanguage,
  type SyntaxNode,
  type Node,
  type NodeCache,
  type Tree,
} from './core/index.js';

// Core extractors
export {
  extractMeta,
  extractTypes,
  extractCalls,
  extractImports,
  extractExports,
  buildCFG,
  buildDFG,
} from './core/index.js';

// Analysis utilities
export {
  getDefaultConfig,
  createTaintConfig,
  analyzeTaint,
  attachSourceLineCode,
  detectUnresolved,
  propagateTaint,
  generateFindings,
  setFindingsInstrumentation,
  isFindingsInstrumentationEnabled,
  analyzeConstantPropagation,
  ConstantPropagator,
  isKnown,
  createUnknown,
  getNodeLine,
  DEFAULT_SOURCES,
  DEFAULT_SINKS,
  DEFAULT_SANITIZERS,
  type ConstantValue,
  type ConstantPropagatorResult,
  type TaintPropagationResult,
  type TaintedVariable,
  type TaintFlow,
} from './analysis/index.js';

// Rule definitions
export {
  getRuleInfo,
  RULE_DEFINITIONS,
  type RuleInfo,
} from './analysis/rules.js';

// Graph utilities
export { DominatorGraph } from './graph/dominator-graph.js';
export { ExceptionFlowGraph, type TryCatchInfo } from './graph/exception-flow-graph.js';

// Resolution utilities
export {
  TypeHierarchyResolver,
  createWithJdkTypes,
  SymbolTable,
  buildSymbolTable,
  CrossFileResolver,
  buildCrossFileResolver,
} from './resolution/index.js';

// Language plugins
export {
  getLanguageRegistry,
  registerLanguage,
  getLanguagePlugin,
  getLanguageForFile,
  detectLanguage,
  isLanguageSupported,
  registerBuiltinPlugins,
  JavaPlugin,
  JavaScriptPlugin,
  PythonPlugin,
  RustPlugin,
  HtmlPlugin,
  BaseLanguagePlugin,
} from './languages/index.js';

export type {
  LanguagePlugin,
  LanguageRegistry,
  LanguageNodeTypes,
  ExtractionContext,
  FrameworkInfo,
  TaintSourcePattern,
  TaintSinkPattern,
} from './languages/index.js';

// Logger (dependency injection)
export {
  logger,
  setLogger,
  configureLogger,
  setLogLevel,
  getLogLevel,
  type LogLevel,
  type LoggerConfig,
  type LoggerInstance,
} from './utils/logger.js';
