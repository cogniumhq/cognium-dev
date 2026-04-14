/**
 * Language Plugin System
 *
 * Defines the interface for language-specific analysis plugins.
 * Each language (Java, JavaScript, Python, Rust, Bash, HTML) implements this interface.
 */

import type { Parser, Node as SyntaxNode, Tree } from 'web-tree-sitter';
import type {
  TypeInfo,
  MethodInfo,
  CallInfo,
  ImportInfo,
  TaintSource,
  TaintSink,
} from '../types/index.js';

/**
 * Supported languages for analysis
 */
export type SupportedLanguage = 'java' | 'c' | 'cpp' | 'javascript' | 'typescript' | 'python' | 'rust' | 'bash' | 'html';

/**
 * AST node type mappings for a language
 */
export interface LanguageNodeTypes {
  // Type declarations
  classDeclaration: string[];
  interfaceDeclaration: string[];
  enumDeclaration: string[];
  functionDeclaration: string[];
  methodDeclaration: string[];

  // Expressions
  methodCall: string[];
  functionCall: string[];
  assignment: string[];
  variableDeclaration: string[];

  // Parameters and arguments
  parameter: string[];
  argument: string[];

  // Annotations/decorators
  annotation: string[];
  decorator: string[];

  // Imports
  importStatement: string[];

  // Control flow
  ifStatement: string[];
  forStatement: string[];
  whileStatement: string[];
  tryStatement: string[];
  returnStatement: string[];
}

/**
 * Framework detection result
 */
export interface FrameworkInfo {
  name: string;                    // e.g., "spring", "express", "django"
  version?: string;
  confidence: number;              // 0.0 - 1.0
  indicators: string[];            // What triggered detection
}

/**
 * Language-specific extraction context
 */
export interface ExtractionContext {
  filePath: string;
  sourceCode: string;
  tree: Tree;
  package?: string;
  imports: ImportInfo[];
  framework?: FrameworkInfo;
}

/**
 * Language Plugin Interface
 *
 * Each supported language must implement this interface.
 */
export interface LanguagePlugin {
  /**
   * Language identifier
   */
  readonly id: SupportedLanguage;

  /**
   * Human-readable name
   */
  readonly name: string;

  /**
   * File extensions handled by this plugin
   */
  readonly extensions: string[];

  /**
   * Path to tree-sitter WASM grammar
   */
  readonly wasmPath: string;

  /**
   * AST node type mappings for this language
   */
  readonly nodeTypes: LanguageNodeTypes;

  /**
   * Initialize the plugin (load WASM, etc.)
   */
  initialize(parser: Parser): Promise<void>;

  /**
   * Check if a file path is handled by this plugin
   */
  canHandle(filePath: string): boolean;

  /**
   * Detect framework from imports and code patterns
   */
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined;

  /**
   * Extract type definitions (classes, interfaces, etc.)
   */
  extractTypes(context: ExtractionContext): TypeInfo[];

  /**
   * Extract method/function calls
   */
  extractCalls(context: ExtractionContext): CallInfo[];

  /**
   * Extract import statements
   */
  extractImports(context: ExtractionContext): ImportInfo[];

  /**
   * Get the package/module name from the file
   */
  extractPackage(context: ExtractionContext): string | undefined;

  /**
   * Language-specific taint source patterns
   * Returns additional sources beyond YAML config
   */
  getBuiltinSources(): TaintSourcePattern[];

  /**
   * Language-specific taint sink patterns
   * Returns additional sinks beyond YAML config
   */
  getBuiltinSinks(): TaintSinkPattern[];

  /**
   * Get receiver type from a method call node
   */
  getReceiverType(node: SyntaxNode, context: ExtractionContext): string | undefined;

  /**
   * Check if a node represents a string literal
   */
  isStringLiteral(node: SyntaxNode): boolean;

  /**
   * Get string value from a literal node
   */
  getStringValue(node: SyntaxNode): string | undefined;
}

/**
 * Taint source pattern definition
 */
export interface TaintSourcePattern {
  // Match by method call
  method?: string;
  class?: string;

  // Match by annotation/decorator
  annotation?: string;

  // Match by parameter pattern
  parameterPattern?: RegExp;

  // Source metadata
  type: string;                    // e.g., "http_param", "http_body"
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;

  // Which part is tainted
  returnTainted?: boolean;
  paramPositions?: number[];
}

/**
 * Taint sink pattern definition
 */
export interface TaintSinkPattern {
  // Match by method call
  method: string;
  class?: string;

  // Sink metadata
  type: string;                    // e.g., "sql_injection", "command_injection"
  cwe: string;                     // e.g., "CWE-89"
  severity: 'critical' | 'high' | 'medium' | 'low';

  // Which arguments are dangerous
  argPositions: number[];

  // Does this sink sanitize certain types?
  sanitizes?: string[];
}

/**
 * Language plugin registry
 */
export interface LanguageRegistry {
  /**
   * Register a language plugin
   */
  register(plugin: LanguagePlugin): void;

  /**
   * Get plugin for a language
   */
  get(language: SupportedLanguage): LanguagePlugin | undefined;

  /**
   * Get plugin for a file path
   */
  getForFile(filePath: string): LanguagePlugin | undefined;

  /**
   * Get all registered plugins
   */
  getAll(): LanguagePlugin[];

  /**
   * Get all supported languages
   */
  getSupportedLanguages(): SupportedLanguage[];
}
