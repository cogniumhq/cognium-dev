/**
 * Java Language Plugin
 *
 * Provides Java-specific AST handling, taint patterns, and framework detection.
 */

import type { Node as SyntaxNode, Tree } from 'web-tree-sitter';
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
 * Java language plugin implementation.
 */
export class JavaPlugin extends BaseLanguagePlugin {
  readonly id = 'java' as const;
  readonly name = 'Java';
  readonly extensions = ['.java'];
  readonly wasmPath = 'tree-sitter-java.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations
    classDeclaration: ['class_declaration'],
    interfaceDeclaration: ['interface_declaration'],
    enumDeclaration: ['enum_declaration'],
    functionDeclaration: [],
    methodDeclaration: ['method_declaration', 'constructor_declaration'],

    // Expressions
    methodCall: ['method_invocation'],
    functionCall: [],
    assignment: ['assignment_expression'],
    variableDeclaration: ['local_variable_declaration', 'field_declaration'],

    // Parameters and arguments
    parameter: ['formal_parameter', 'spread_parameter'],
    argument: ['argument_list'],

    // Annotations/decorators
    annotation: ['marker_annotation', 'annotation'],
    decorator: [],

    // Imports
    importStatement: ['import_declaration'],

    // Control flow
    ifStatement: ['if_statement'],
    forStatement: ['for_statement', 'enhanced_for_statement'],
    whileStatement: ['while_statement'],
    tryStatement: ['try_statement', 'try_with_resources_statement'],
    returnStatement: ['return_statement'],
  };

  /** Cache: maps a parse Tree to its var-name → simple-type map. */
  private readonly _typeMapCache = new WeakMap<Tree, Map<string, string>>();

  /**
   * Detect Java frameworks from imports and annotations.
   */
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    const indicators: string[] = [];
    let framework: string | undefined;
    let confidence = 0;

    // Check imports for framework patterns
    for (const imp of context.imports) {
      const path = imp.from_package || imp.imported_name;

      // Spring Framework
      if (path.startsWith('org.springframework')) {
        framework = 'spring';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }

      // Jakarta EE / Java EE
      if (path.startsWith('jakarta.') || path.startsWith('javax.')) {
        if (path.includes('servlet')) {
          framework = framework || 'servlet';
          confidence = Math.max(confidence, 0.8);
          indicators.push(`import: ${path}`);
        }
        if (path.includes('ws.rs')) {
          framework = 'jax-rs';
          confidence = Math.max(confidence, 0.85);
          indicators.push(`import: ${path}`);
        }
      }

      // Struts
      if (path.startsWith('org.apache.struts')) {
        framework = 'struts';
        confidence = Math.max(confidence, 0.85);
        indicators.push(`import: ${path}`);
      }

      // Quarkus
      if (path.startsWith('io.quarkus')) {
        framework = 'quarkus';
        confidence = Math.max(confidence, 0.85);
        indicators.push(`import: ${path}`);
      }
    }

    if (framework) {
      return { name: framework, confidence, indicators };
    }

    return undefined;
  }

  /**
   * Java-specific taint source patterns.
   * These supplement the YAML configuration.
   */
  getBuiltinSources(): TaintSourcePattern[] {
    return [
      // Spring MVC annotations
      {
        annotation: 'RequestParam',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        annotation: 'RequestBody',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        annotation: 'PathVariable',
        type: 'http_path',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        annotation: 'RequestHeader',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        annotation: 'CookieValue',
        type: 'http_cookie',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        annotation: 'MatrixVariable',
        type: 'http_param',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },

      // JAX-RS annotations
      {
        annotation: 'QueryParam',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        annotation: 'PathParam',
        type: 'http_path',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        annotation: 'FormParam',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        annotation: 'HeaderParam',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },

      // Servlet API
      {
        method: 'getParameter',
        class: 'HttpServletRequest',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'getParameterValues',
        class: 'HttpServletRequest',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'getHeader',
        class: 'HttpServletRequest',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'getCookies',
        class: 'HttpServletRequest',
        type: 'http_cookie',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'getInputStream',
        class: 'HttpServletRequest',
        type: 'http_body',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'getReader',
        class: 'HttpServletRequest',
        type: 'http_body',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
    ];
  }

  /**
   * Java-specific taint sink patterns.
   * These supplement the YAML configuration.
   */
  getBuiltinSinks(): TaintSinkPattern[] {
    return [
      // SQL Injection
      {
        method: 'executeQuery',
        class: 'Statement',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'executeUpdate',
        class: 'Statement',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'execute',
        class: 'Statement',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },

      // Command Injection
      {
        method: 'exec',
        class: 'Runtime',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'start',
        class: 'ProcessBuilder',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [],  // Constructor args are dangerous
      },

      // Path Traversal
      {
        method: 'FileInputStream',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'FileOutputStream',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },

      // XSS
      {
        method: 'write',
        class: 'PrintWriter',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'println',
        class: 'PrintWriter',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },

      // LDAP Injection
      {
        method: 'search',
        class: 'DirContext',
        type: 'ldap_injection',
        cwe: 'CWE-90',
        severity: 'high',
        argPositions: [0, 1],
      },

      // XPath Injection
      {
        method: 'evaluate',
        class: 'XPath',
        type: 'xpath_injection',
        cwe: 'CWE-643',
        severity: 'high',
        argPositions: [0],
      },

      // Deserialization
      {
        method: 'readObject',
        class: 'ObjectInputStream',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'critical',
        argPositions: [],
      },
    ];
  }

  /**
   * Walk `tree` once and build a map of { variableName → simpleTypeName }.
   * Covers both field declarations and local variable declarations.
   * Generics and array brackets are stripped: `List<String>` → `List`, `int[]` → `int`.
   * Result is cached per Tree instance so subsequent calls are O(1).
   */
  private buildVarTypeMap(tree: Tree): Map<string, string> {
    const cached = this._typeMapCache.get(tree);
    if (cached) return cached;

    const map = new Map<string, string>();

    const collectDecl = (declNode: SyntaxNode): void => {
      const typeNode = declNode.childForFieldName('type');
      if (!typeNode) return;
      const raw = typeNode.text;
      const baseType = raw.includes('<')
        ? raw.substring(0, raw.indexOf('<')).trim()
        : raw.replace(/\[\]/g, '').trim();

      for (let i = 0; i < declNode.childCount; i++) {
        const child = declNode.child(i);
        if (child?.type === 'variable_declarator') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) map.set(nameNode.text, baseType);
        }
      }
    };

    const walk = (node: SyntaxNode): void => {
      if (node.type === 'field_declaration' || node.type === 'local_variable_declaration') {
        collectDecl(node);
      }
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) walk(child);
      }
    };

    walk(tree.rootNode);
    this._typeMapCache.set(tree, map);
    return map;
  }

  /**
   * Get receiver type from a method invocation node.
   */
  getReceiverType(node: SyntaxNode, context: ExtractionContext): string | undefined {
    if (node.type !== 'method_invocation') return undefined;

    const receiver = node.childForFieldName('object');
    if (!receiver) return undefined;

    // If receiver is an identifier, resolve its declared type from the parse tree
    if (receiver.type === 'identifier') {
      const typeMap = this.buildVarTypeMap(context.tree);
      return typeMap.get(receiver.text);
    }

    // If receiver is a field access, return the field text (class or qualified name)
    if (receiver.type === 'field_access') {
      return receiver.text;
    }

    return undefined;
  }

  /**
   * Check if node is a Java string literal.
   */
  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'string_literal';
  }

  /**
   * Get string value from Java string literal.
   */
  getStringValue(node: SyntaxNode): string | undefined {
    if (node.type !== 'string_literal') return undefined;
    const text = node.text;
    // Remove surrounding quotes
    if (text.startsWith('"') && text.endsWith('"')) {
      return text.slice(1, -1);
    }
    return text;
  }

  // Extraction methods - delegate to existing extractors for now
  // These will be migrated into the plugin in future iterations

  extractTypes(context: ExtractionContext): TypeInfo[] {
    // Delegated to existing extractor
    return [];
  }

  extractCalls(context: ExtractionContext): CallInfo[] {
    // Delegated to existing extractor
    return [];
  }

  extractImports(context: ExtractionContext): ImportInfo[] {
    // Delegated to existing extractor
    return [];
  }

  extractPackage(context: ExtractionContext): string | undefined {
    // Find package declaration in tree
    const packages = this.findNodes(context.tree.rootNode, 'package_declaration');
    if (packages.length === 0) return undefined;

    const pkgDecl = packages[0];
    const nameNode = pkgDecl.childForFieldName('name');
    if (nameNode) {
      return this.getNodeText(nameNode);
    }

    // Fallback: find scoped_identifier or identifier
    for (let i = 0; i < pkgDecl.childCount; i++) {
      const child = pkgDecl.child(i);
      if (child && (child.type === 'scoped_identifier' || child.type === 'identifier')) {
        return this.getNodeText(child);
      }
    }

    return undefined;
  }
}
