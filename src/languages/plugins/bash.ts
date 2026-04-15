/**
 * Bash/Shell Language Plugin
 *
 * Provides Bash-specific AST handling and taint patterns for Shell scripts.
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
 * Bash/Shell language plugin implementation.
 */
export class BashPlugin extends BaseLanguagePlugin {
  readonly id = 'bash' as const;
  readonly name = 'Bash/Shell';
  readonly extensions = ['.sh', '.bash', '.zsh', '.ksh'];
  readonly wasmPath = 'tree-sitter-bash.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations — shell has no OOP types
    classDeclaration: [],
    interfaceDeclaration: [],
    enumDeclaration: [],
    functionDeclaration: ['function_definition'],
    methodDeclaration: ['function_definition'],

    // Expressions — commands are treated as calls
    methodCall: ['command'],
    functionCall: ['command'],
    assignment: ['variable_assignment'],
    variableDeclaration: ['variable_assignment', 'declaration_command'],

    // Parameters and arguments — positional args are child words
    parameter: [],
    argument: [],

    // Annotations/decorators — none in shell
    annotation: [],
    decorator: [],

    // Imports — shell uses `source` / `.` but no formal import system
    importStatement: [],

    // Control flow
    ifStatement: ['if_statement'],
    forStatement: ['for_statement', 'c_style_for_statement'],
    whileStatement: ['while_statement'],
    tryStatement: [],
    returnStatement: [],
  };

  /**
   * Shell scripts don't have a formal framework concept.
   */
  detectFramework(_context: ExtractionContext): FrameworkInfo | undefined {
    return undefined;
  }

  /**
   * Bash taint source patterns.
   * In shell, tainted data enters via `read` (stdin) and
   * `curl`/`wget` (HTTP responses for supply-chain attack detection).
   */
  getBuiltinSources(): TaintSourcePattern[] {
    return [
      // read built-in reads user input from stdin.
      {
        method: 'read',
        type: 'io_input',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      // curl/wget output as taint sources for supply-chain attack patterns
      // (e.g., curl ... | sh, $(curl ...) piped to eval/bash).
      {
        method: 'curl',
        type: 'http_response',
        severity: 'high',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'wget',
        type: 'http_response',
        severity: 'high',
        confidence: 0.8,
        returnTainted: true,
      },
    ];
  }

  /**
   * Bash taint sink patterns.
   * Key sinks: eval (CWE-94), bash/sh -c (CWE-78), DB clients (CWE-89),
   * file operations (CWE-22), SSRF via curl/wget (CWE-918).
   */
  getBuiltinSinks(): TaintSinkPattern[] {
    return [
      // Code / command injection via eval
      {
        method: 'eval',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },

      // Command injection: spawning a sub-shell with -c flag
      {
        method: 'bash',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [1],
      },
      {
        method: 'sh',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [1],
      },
      {
        method: 'zsh',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [1],
      },
      {
        method: 'ksh',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [1],
      },

      // SQL injection via DB CLI clients (first arg is query/expression)
      {
        method: 'mysql',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [1],
      },
      {
        method: 'psql',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [1],
      },
      {
        method: 'sqlite3',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [1],
      },

      // Path traversal via file operations (first arg is path)
      {
        method: 'cat',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'rm',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'cp',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'mv',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'chmod',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'medium',
        argPositions: [1],
      },
      {
        method: 'chown',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'medium',
        argPositions: [1],
      },

      // SSRF — curl/wget with externally-controlled URL
      {
        method: 'curl',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'wget',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
    ];
  }

  /**
   * Shell has no OOP receiver types.
   */
  getReceiverType(_node: SyntaxNode, _context: ExtractionContext): string | undefined {
    return undefined;
  }

  /**
   * Bash string literals: quoted strings and raw ($'...') strings.
   */
  isStringLiteral(node: SyntaxNode): boolean {
    return (
      node.type === 'string' ||
      node.type === 'raw_string' ||
      node.type === 'ansi_c_string'
    );
  }

  /**
   * Extract string value from bash string literal, stripping quotes.
   */
  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;

    const text = node.text;
    // raw_string: 'content' → strip single quotes
    if (node.type === 'raw_string') {
      return text.slice(1, -1);
    }
    // ansi_c_string: $'content' → strip $' and '
    if (node.type === 'ansi_c_string') {
      return text.slice(2, -1);
    }
    // string: "content" → strip double quotes
    const match = text.match(/^"(.*)"$/s);
    if (match) return match[1];

    return text;
  }

  // Extraction methods — delegate to base extractors via generic walker

  extractTypes(_context: ExtractionContext): TypeInfo[] {
    return [];
  }

  extractCalls(_context: ExtractionContext): CallInfo[] {
    return [];
  }

  extractImports(_context: ExtractionContext): ImportInfo[] {
    return [];
  }

  extractPackage(_context: ExtractionContext): string | undefined {
    return undefined;
  }
}
