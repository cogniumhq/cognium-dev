/**
 * Circle-IR Core Library
 *
 * Environment-agnostic core library for IR generation and taint analysis.
 * Works in both browser and Node.js without LLM dependencies.
 *
 * @example
 * ```typescript
 * import {
 *   initParser, parse, collectAllNodes,
 *   extractMeta, extractTypes, extractCalls, buildCFG, buildDFG,
 *   analyzeTaint, propagateTaint, analyzeConstantPropagation, isFalsePositive
 * } from 'circle-ir/core';
 *
 * // Node types needed for analysis
 * const NODE_TYPES = new Set([
 *   'method_invocation', 'object_creation_expression', 'class_declaration',
 *   'method_declaration', 'constructor_declaration', 'field_declaration',
 *   'import_declaration', 'interface_declaration', 'enum_declaration',
 * ]);
 *
 * // Initialize parser (loads tree-sitter WASM)
 * await initParser();
 *
 * // Parse code
 * const tree = await parse(code, 'java');
 * const nodeCache = collectAllNodes(tree.rootNode, NODE_TYPES);
 *
 * // Extract IR components
 * const types = extractTypes(tree, nodeCache);
 * const calls = extractCalls(tree, nodeCache);
 * const cfg = buildCFG(tree);
 * const dfg = buildDFG(tree, nodeCache);
 *
 * // Analyze taint
 * const taint = analyzeTaint(calls, types);
 * const flows = propagateTaint(dfg, calls, taint.sources, taint.sinks, taint.sanitizers);
 *
 * // Filter false positives
 * const constProp = analyzeConstantPropagation(tree, code);
 * const verified = flows.flows.filter(flow => {
 *   for (const step of flow.path) {
 *     if (isFalsePositive(constProp, step.line, step.variable).isFalsePositive) {
 *       return false;
 *     }
 *   }
 *   return true;
 * });
 * ```
 */

// Parser initialization and parsing
export {
  initParser,
  loadLanguage,
  parse,
  walkTree,
  findNodes,
  findAncestor,
  getNodeText,
  collectAllNodes,
  isInitialized,
  isLanguageLoaded,
  resetParser,
  type SupportedLanguage,
  type SyntaxNode,
  type Tree,
  type NodeCache,
} from './core/parser.js';

// IR extractors
export {
  extractMeta,
  extractTypes,
  extractCalls,
  extractImports,
  extractExports,
  buildCFG,
  buildDFG,
} from './core/extractors/index.js';

// Taint analysis - import directly to avoid LLM dependencies
export { analyzeTaint } from './analysis/taint-matcher.js';

export {
  getDefaultConfig,
  createTaintConfig,
} from './analysis/config-loader.js';

export {
  propagateTaint,
  type TaintPropagationResult,
  type TaintFlow,
  type TaintedVariable,
} from './analysis/taint-propagation.js';

export {
  analyzeConstantPropagation,
  isFalsePositive,
  isCorrelatedPredicateFP,
  type ConstantPropagatorResult,
} from './analysis/constant-propagation.js';

// Path finding
export {
  PathFinder,
  findTaintPaths,
  formatTaintPath,
  type TaintPath,
  type TaintHop,
} from './analysis/path-finder.js';

// IR Types
export type {
  CircleIR,
  Meta,
  TypeInfo,
  MethodInfo,
  ParameterInfo,
  FieldInfo,
  CallInfo,
  ArgumentInfo,
  CFG,
  CFGBlock,
  CFGEdge,
  DFG,
  DFGDef,
  DFGUse,
  Taint,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  TaintFlowInfo,
  ImportInfo,
  ExportInfo,
} from './types/index.js';

// Config types
export type {
  TaintConfig,
  SourcePattern,
  SinkPattern,
  SanitizerPattern,
} from './types/config.js';
