/**
 * Rust Language Plugin
 *
 * Provides Rust-specific AST handling, taint patterns, and framework detection.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type {
  TypeInfo,
  CallInfo,
  ImportInfo,
} from '../../types/index.js';
import type {
  LanguageNodeTypes,
  ExtractionContext,
  FrameworkInfo,
  TaintSourcePattern,
  TaintSinkPattern,
} from '../types.js';
import { BaseLanguagePlugin } from './base.js';

/**
 * Rust language plugin implementation.
 */
export class RustPlugin extends BaseLanguagePlugin {
  readonly id = 'rust' as const;
  readonly name = 'Rust';
  readonly extensions = ['.rs'];
  readonly wasmPath = 'tree-sitter-rust.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations
    classDeclaration: ['struct_item'],
    interfaceDeclaration: ['trait_item'],
    enumDeclaration: ['enum_item'],
    functionDeclaration: ['function_item'],
    methodDeclaration: ['function_item'],  // Methods are function_item inside impl

    // Expressions
    methodCall: ['call_expression'],
    functionCall: ['call_expression'],
    assignment: ['assignment_expression', 'let_declaration'],
    variableDeclaration: ['let_declaration'],

    // Parameters and arguments
    parameter: ['parameter', 'self_parameter'],
    argument: ['arguments'],

    // Annotations/decorators
    annotation: ['attribute_item'],
    decorator: [],

    // Imports
    importStatement: ['use_declaration'],

    // Control flow
    ifStatement: ['if_expression'],
    forStatement: ['for_expression'],
    whileStatement: ['while_expression'],
    tryStatement: [],  // Rust uses Result/Option, not try-catch
    returnStatement: ['return_expression'],
  };

  /**
   * Detect Rust frameworks from imports.
   */
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    const indicators: string[] = [];
    let framework: string | undefined;
    let confidence = 0;

    for (const imp of context.imports) {
      const path = imp.from_package || imp.imported_name;

      // Actix-web
      if (path.startsWith('actix_web') || path.startsWith('actix-web')) {
        framework = 'actix-web';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`use: ${path}`);
      }

      // Rocket
      if (path.startsWith('rocket')) {
        framework = 'rocket';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`use: ${path}`);
      }

      // Axum
      if (path.startsWith('axum')) {
        framework = 'axum';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`use: ${path}`);
      }

      // Warp
      if (path.startsWith('warp')) {
        framework = 'warp';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`use: ${path}`);
      }

      // Hyper
      if (path.startsWith('hyper')) {
        framework = framework || 'hyper';
        confidence = Math.max(confidence, 0.85);
        indicators.push(`use: ${path}`);
      }

      // Tokio (async runtime)
      if (path.startsWith('tokio')) {
        indicators.push(`use: ${path}`);
      }
    }

    if (framework) {
      return { name: framework, confidence, indicators };
    }

    return undefined;
  }

  /**
   * Rust taint source patterns.
   */
  getBuiltinSources(): TaintSourcePattern[] {
    return [
      // Actix-web request extractors
      // NOTE: `Query` (http_param), `Json` (http_body) and `Path` (http_path)
      // are registered identically in DEFAULT_SOURCES; the duplicates here
      // emitted a second, byte-identical source at every call site
      // (`findSources` has no dedup). Removed in the #4 follow-up
      // consolidation — DEFAULT_SOURCES is the canonical registry (ADR-004).
      // `Form` stays because the two surfaces disagree on its type
      // `Form` is registered in DEFAULT_SOURCES, retyped there to `http_body`
      // to match this entry (actix/axum `Form<T>` decodes the urlencoded
      // request body, not the query string — `Query<T>` is the query one).
      // The duplicate that used to sit here made every extractor emit two
      // sources with different types.

      // Standard library sources
      {
        method: 'args',
        class: 'std::env',
        type: 'cli_arg',
        severity: 'medium',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'var',
        class: 'std::env',
        type: 'env_var',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'vars',
        class: 'std::env',
        type: 'env_var',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },

      // File I/O
      {
        method: 'read_to_string',
        class: 'std::fs',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'read',
        class: 'std::fs',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'read_line',
        class: 'BufRead',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },

      // NOTE: `TcpStream.read` (network_input) is registered identically in
      // DEFAULT_SOURCES — duplicate removed in the #4 follow-up consolidation.
    ];
  }

  /**
   * Rust taint sink patterns.
   *
   * Only patterns that have NO counterpart in `DEFAULT_SINKS` belong here —
   * `DEFAULT_SINKS` (`analysis/config-loader.ts`) is the canonical registry
   * (ADR-004). Duplicated entries were dead weight: `TaintMatcherPass` merges
   * plugin builtins *after* the config patterns, and `findSinks` dedupes by
   * `location:line:cwe` keeping the higher-confidence match, so the config
   * copy always won the slot. Removed in the #4 follow-up consolidation
   * (`Command.arg/args`, classless `execute`, `File.open/create`,
   * `serde_json.from_str/from_slice`, `reqwest.get/post`).
   */
  getBuiltinSinks(): TaintSinkPattern[] {
    return [
      // Command Injection
      {
        method: 'Command',
        class: 'std::process',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },

      // SQL Injection
      {
        method: 'query',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'query_raw',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },

      // Path Traversal
      {
        method: 'read_to_string',
        class: 'std::fs',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'write',
        class: 'std::fs',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },

      // Format String — `format!` is NOT a CWE-134 sink in Rust. Its template
      // is a compile-time string literal; a non-literal template does not
      // compile, so an attacker-controlled format string is not expressible.
      // Interpolating data into `format!` is the ordinary, safe way to build a
      // string. (cognium-dev #294 part 1 — removed as a format_string sink.)

      // Unsafe operations
      {
        method: 'from_raw_parts',
        type: 'unsafe_memory',
        cwe: 'CWE-119',
        severity: 'high',
        argPositions: [0, 1],
      },
      {
        method: 'transmute',
        type: 'unsafe_memory',
        cwe: 'CWE-119',
        severity: 'critical',
        argPositions: [0],
      },

      // Regex DoS
      {
        method: 'new',
        class: 'Regex',
        type: 'regex_dos',
        cwe: 'CWE-1333',
        severity: 'medium',
        argPositions: [0],
      },
    ];
  }

  /**
   * Get receiver type from a call expression.
   */
  getReceiverType(node: SyntaxNode, context: ExtractionContext): string | undefined {
    if (node.type !== 'call_expression') return undefined;

    const func = node.childForFieldName('function');
    if (!func) return undefined;

    // For field expressions like obj.method()
    if (func.type === 'field_expression') {
      const value = func.childForFieldName('value');
      if (value) {
        return value.text;
      }
    }

    // For scoped identifiers like Module::function()
    if (func.type === 'scoped_identifier') {
      const path = func.childForFieldName('path');
      if (path) {
        return path.text;
      }
    }

    return undefined;
  }

  /**
   * Check if node is a Rust string literal.
   */
  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'string_literal' ||
           node.type === 'raw_string_literal';
  }

  /**
   * Get string value from Rust string literal.
   */
  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;

    const text = node.text;

    // Handle raw strings r"..." or r#"..."#
    const rawMatch = text.match(/^r#*"(.*)"#*$/s);
    if (rawMatch) {
      return rawMatch[1];
    }

    // Handle regular strings
    if (text.startsWith('"') && text.endsWith('"')) {
      return text.slice(1, -1);
    }

    return text;
  }

  // Extraction methods - delegate to existing extractors for now

  extractTypes(context: ExtractionContext): TypeInfo[] {
    return [];
  }

  extractCalls(context: ExtractionContext): CallInfo[] {
    return [];
  }

  extractImports(context: ExtractionContext): ImportInfo[] {
    return [];
  }

  extractPackage(context: ExtractionContext): string | undefined {
    // Rust uses crate and module paths
    // Could look for Cargo.toml
    return undefined;
  }
}
