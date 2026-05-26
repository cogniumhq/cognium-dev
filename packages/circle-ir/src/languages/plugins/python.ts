/**
 * Python Language Plugin
 *
 * Provides Python-specific AST handling, taint patterns, and framework detection.
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
 * Python language plugin implementation.
 */
export class PythonPlugin extends BaseLanguagePlugin {
  readonly id = 'python' as const;
  readonly name = 'Python';
  readonly extensions = ['.py', '.pyw'];
  readonly wasmPath = 'tree-sitter-python.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations
    classDeclaration: ['class_definition'],
    interfaceDeclaration: [],  // Python doesn't have interfaces
    enumDeclaration: [],  // Python enums are classes
    functionDeclaration: ['function_definition'],
    methodDeclaration: ['function_definition'],  // Methods are function_definition inside class

    // Expressions
    methodCall: ['call'],
    functionCall: ['call'],
    assignment: ['assignment', 'augmented_assignment'],
    variableDeclaration: ['assignment'],  // Python doesn't have explicit declarations

    // Parameters and arguments
    parameter: ['parameters', 'typed_parameter', 'default_parameter'],
    argument: ['argument_list'],

    // Annotations/decorators
    annotation: [],
    decorator: ['decorator'],

    // Imports
    importStatement: ['import_statement', 'import_from_statement'],

    // Control flow
    ifStatement: ['if_statement'],
    forStatement: ['for_statement'],
    whileStatement: ['while_statement'],
    tryStatement: ['try_statement'],
    returnStatement: ['return_statement'],
  };

  /**
   * Detect Python frameworks from imports.
   */
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    const indicators: string[] = [];
    let framework: string | undefined;
    let confidence = 0;

    for (const imp of context.imports) {
      const path = imp.from_package || imp.imported_name;

      // Flask
      if (path === 'flask' || path.startsWith('flask.')) {
        framework = 'flask';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Django
      if (path.startsWith('django.') || path === 'django') {
        framework = 'django';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // FastAPI
      if (path === 'fastapi' || path.startsWith('fastapi.')) {
        framework = 'fastapi';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Tornado
      if (path.startsWith('tornado.')) {
        framework = 'tornado';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }

      // aiohttp
      if (path === 'aiohttp' || path.startsWith('aiohttp.')) {
        framework = 'aiohttp';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }

      // Pyramid
      if (path.startsWith('pyramid.')) {
        framework = 'pyramid';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }
    }

    if (framework) {
      return { name: framework, confidence, indicators };
    }

    return undefined;
  }

  /**
   * Python taint source patterns.
   */
  getBuiltinSources(): TaintSourcePattern[] {
    return [
      // Flask request object
      {
        method: 'args',
        class: 'request',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'form',
        class: 'request',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'json',
        class: 'request',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'data',
        class: 'request',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'headers',
        class: 'request',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'cookies',
        class: 'request',
        type: 'http_cookie',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'files',
        class: 'request',
        type: 'file_upload',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },

      // Django request object
      {
        method: 'GET',
        class: 'request',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'POST',
        class: 'request',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'META',
        class: 'request',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },

      // Standard library sources
      {
        method: 'input',
        type: 'user_input',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'argv',
        class: 'sys',
        type: 'cli_arg',
        severity: 'medium',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'environ',
        class: 'os',
        type: 'env_var',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'getenv',
        class: 'os',
        type: 'env_var',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },

      // File reading
      {
        method: 'read',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'readline',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'readlines',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
    ];
  }

  /**
   * Python taint sink patterns.
   */
  getBuiltinSinks(): TaintSinkPattern[] {
    return [
      // Command Injection
      {
        method: 'system',
        class: 'os',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'popen',
        class: 'os',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'run',
        class: 'subprocess',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'call',
        class: 'subprocess',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'Popen',
        class: 'subprocess',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },

      // Code Injection
      {
        method: 'eval',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'exec',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'compile',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'high',
        argPositions: [0],
      },

      // SQL Injection
      {
        method: 'execute',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'executemany',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'raw',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },

      // Path Traversal
      {
        method: 'open',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'read',
        class: 'pathlib',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },

      // XSS (template injection)
      {
        method: 'Markup',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'safe',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },

      // SSRF
      {
        method: 'get',
        class: 'requests',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'post',
        class: 'requests',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'urlopen',
        class: 'urllib',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },

      // Deserialization
      {
        method: 'loads',
        class: 'pickle',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'load',
        class: 'pickle',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'safe_load',
        class: 'yaml',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'high',
        argPositions: [0],
        sanitizes: ['yaml_unsafe'],  // safe_load is safe for YAML
      },
      {
        method: 'load',
        class: 'yaml',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'critical',
        argPositions: [0],
      },

      // LDAP Injection
      {
        method: 'search_s',
        type: 'ldap_injection',
        cwe: 'CWE-90',
        severity: 'high',
        argPositions: [1, 2],
      },
    ];
  }

  /**
   * Get receiver type from a call expression.
   */
  getReceiverType(node: SyntaxNode, context: ExtractionContext): string | undefined {
    if (node.type !== 'call') return undefined;

    const func = node.childForFieldName('function');
    if (!func) return undefined;

    // For attribute access like obj.method()
    if (func.type === 'attribute') {
      const object = func.childForFieldName('object');
      if (object) {
        return object.text;
      }
    }

    return undefined;
  }

  /**
   * Check if node is a Python string literal.
   */
  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'string' ||
           node.type === 'concatenated_string';
  }

  /**
   * Get string value from Python string literal.
   */
  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;

    const text = node.text;

    // Handle various Python string prefixes (f, r, b, etc.)
    const match = text.match(/^[frbFRB]*['"`]{1,3}(.*)['"`]{1,3}$/s);
    if (match) {
      return match[1];
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
    // Python uses file path as module path
    return undefined;
  }
}
