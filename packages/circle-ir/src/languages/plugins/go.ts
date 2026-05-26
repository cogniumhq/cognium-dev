/**
 * Go Language Plugin
 *
 * Provides Go-specific AST handling, taint patterns, and framework detection.
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
 * Go language plugin implementation.
 */
export class GoPlugin extends BaseLanguagePlugin {
  readonly id = 'go' as const;
  readonly name = 'Go';
  readonly extensions = ['.go'];
  readonly wasmPath = 'tree-sitter-go.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations
    classDeclaration: ['type_declaration'],
    interfaceDeclaration: ['type_declaration'],
    enumDeclaration: [],  // Go has no enums (uses iota constants)
    functionDeclaration: ['function_declaration'],
    methodDeclaration: ['method_declaration'],

    // Expressions
    methodCall: ['call_expression'],
    functionCall: ['call_expression'],
    assignment: ['short_var_declaration', 'assignment_statement', 'var_declaration'],
    variableDeclaration: ['short_var_declaration', 'var_declaration'],

    // Parameters and arguments
    parameter: ['parameter_declaration'],
    argument: ['argument_list'],

    // Annotations/decorators
    annotation: [],  // Go has no annotations
    decorator: [],   // Go has no decorators

    // Imports
    importStatement: ['import_declaration'],

    // Control flow
    ifStatement: ['if_statement'],
    forStatement: ['for_statement'],
    whileStatement: [],  // Go uses for with condition
    tryStatement: [],    // Go uses defer/recover
    returnStatement: ['return_statement'],
  };

  /**
   * Detect Go web frameworks from imports.
   */
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    const indicators: string[] = [];
    let framework: string | undefined;
    let confidence = 0;

    for (const imp of context.imports) {
      const path = imp.from_package || imp.imported_name;

      // Gin
      if (path.includes('gin-gonic/gin')) {
        framework = 'gin';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Echo
      if (path.includes('labstack/echo')) {
        framework = 'echo';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Fiber
      if (path.includes('gofiber/fiber')) {
        framework = 'fiber';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Chi
      if (path.includes('go-chi/chi')) {
        framework = 'chi';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }

      // GORM
      if (path.includes('gorm.io/gorm')) {
        indicators.push(`import: ${path}`);
      }

      // net/http (stdlib)
      if (path === 'net/http') {
        framework = framework || 'net/http';
        confidence = Math.max(confidence, 0.8);
        indicators.push(`import: ${path}`);
      }
    }

    if (framework) {
      return { name: framework, confidence, indicators };
    }

    return undefined;
  }

  /**
   * Go taint source patterns.
   */
  getBuiltinSources(): TaintSourcePattern[] {
    return [
      // net/http request methods
      {
        method: 'FormValue',
        class: 'Request',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'PostFormValue',
        class: 'Request',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'Query',
        class: 'URL',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'Get',
        class: 'Header',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'Cookie',
        class: 'Request',
        type: 'http_cookie',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },

      // Gin framework
      {
        method: 'Query',
        class: 'Context',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'Param',
        class: 'Context',
        type: 'http_path',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'PostForm',
        class: 'Context',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'GetRawData',
        class: 'Context',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },

      // Standard library I/O
      {
        method: 'Getenv',
        class: 'os',
        type: 'env_var',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'ReadAll',
        class: 'io',
        type: 'io_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'ReadFile',
        class: 'os',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'Text',
        class: 'Scanner',
        type: 'io_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
    ];
  }

  /**
   * Go taint sink patterns.
   */
  getBuiltinSinks(): TaintSinkPattern[] {
    return [
      // SQL Injection
      {
        method: 'Query',
        class: 'DB',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'QueryRow',
        class: 'DB',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'Exec',
        class: 'DB',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'Query',
        class: 'Tx',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },

      // Command Injection
      {
        method: 'Command',
        class: 'exec',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'CommandContext',
        class: 'exec',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [1],
      },

      // Path Traversal
      {
        method: 'Open',
        class: 'os',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'ReadFile',
        class: 'os',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'WriteFile',
        class: 'os',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },

      // XSS (writing to http.ResponseWriter without escaping)
      {
        method: 'Fprintf',
        class: 'fmt',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [1],
      },
      {
        method: 'Write',
        class: 'ResponseWriter',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },

      // SSRF
      {
        method: 'Get',
        class: 'http',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'Post',
        class: 'http',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0, 2],
      },

      // Deserialization
      {
        method: 'Unmarshal',
        class: 'json',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'medium',
        argPositions: [0],
      },
      {
        method: 'Decode',
        class: 'Decoder',
        type: 'deserialization',
        cwe: 'CWE-502',
        severity: 'medium',
        argPositions: [0],
      },
    ];
  }

  /**
   * Get receiver type from a Go call expression.
   */
  getReceiverType(node: SyntaxNode, _context: ExtractionContext): string | undefined {
    if (node.type !== 'call_expression') return undefined;

    const func = node.childForFieldName('function');
    if (!func) return undefined;

    // selector_expression: obj.Method() or pkg.Function()
    if (func.type === 'selector_expression') {
      const operand = func.childForFieldName('operand');
      if (operand) {
        return operand.text;
      }
    }

    return undefined;
  }

  /**
   * Check if node is a Go string literal.
   */
  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'interpreted_string_literal' ||
           node.type === 'raw_string_literal';
  }

  /**
   * Get string value from Go string literal.
   */
  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;

    const text = node.text;

    // Handle raw strings `...`
    if (text.startsWith('`') && text.endsWith('`')) {
      return text.slice(1, -1);
    }

    // Handle interpreted strings "..."
    if (text.startsWith('"') && text.endsWith('"')) {
      return text.slice(1, -1);
    }

    return text;
  }

  /**
   * Extract type information from Go source.
   */
  extractTypes(context: ExtractionContext): TypeInfo[] {
    const types: TypeInfo[] = [];
    const root = context.tree.rootNode;

    // Find type_declaration nodes (type Foo struct {...} or type Bar interface {...})
    const typeDecls = this.findNodes(root, 'type_declaration');
    for (const decl of typeDecls) {
      // type_declaration contains type_spec children
      for (let i = 0; i < decl.childCount; i++) {
        const spec = decl.child(i);
        if (!spec || spec.type !== 'type_spec') continue;

        const nameNode = spec.childForFieldName('name');
        const typeNode = spec.childForFieldName('type');
        if (!nameNode || !typeNode) continue;

        const name = nameNode.text;
        const isInterface = typeNode.type === 'interface_type';
        const isStruct = typeNode.type === 'struct_type';

        if (isStruct || isInterface) {
          const fields: TypeInfo['fields'] = [];
          const methods: TypeInfo['methods'] = [];

          if (isStruct) {
            // Extract struct fields
            const fieldList = typeNode.childForFieldName('fields') ??
              this.findChildByType(typeNode, 'field_declaration_list');
            if (fieldList) {
              for (let j = 0; j < fieldList.childCount; j++) {
                const field = fieldList.child(j);
                if (!field || field.type !== 'field_declaration') continue;
                const fieldName = field.childForFieldName('name');
                const fieldType = field.childForFieldName('type');
                if (fieldName) {
                  fields.push({
                    name: fieldName.text,
                    type: fieldType?.text || null,
                    modifiers: [],
                    annotations: [],
                  });
                }
              }
            }
          }

          // Find methods declared for this type (method_declaration with matching receiver)
          const methodDecls = this.findNodes(root, 'method_declaration');
          for (const md of methodDecls) {
            const receiver = md.childForFieldName('receiver');
            if (!receiver) continue;
            const receiverText = receiver.text;
            // Match (t *TypeName) or (t TypeName)
            if (receiverText.includes(name)) {
              const methodName = md.childForFieldName('name');
              const params = md.childForFieldName('parameters');
              const result = md.childForFieldName('result');
              if (methodName) {
                methods.push({
                  name: methodName.text,
                  return_type: result?.text || null,
                  parameters: params ? this.extractGoParams(params) : [],
                  annotations: [],
                  modifiers: [],
                  start_line: md.startPosition.row + 1,
                  end_line: md.endPosition.row + 1,
                });
              }
            }
          }

          types.push({
            name,
            kind: isInterface ? 'interface' : 'class',
            package: context.package || null,
            extends: null,
            implements: [],
            annotations: [],
            methods,
            fields,
            start_line: decl.startPosition.row + 1,
            end_line: decl.endPosition.row + 1,
          });
        }
      }
    }

    return types;
  }

  /**
   * Extract call information from Go source.
   */
  extractCalls(context: ExtractionContext): CallInfo[] {
    const calls: CallInfo[] = [];
    const root = context.tree.rootNode;

    const callExprs = this.findNodes(root, 'call_expression');
    for (const call of callExprs) {
      const func = call.childForFieldName('function');
      if (!func) continue;

      let methodName: string;
      let receiver: string | null = null;

      if (func.type === 'selector_expression') {
        // pkg.Function() or obj.Method()
        const operand = func.childForFieldName('operand');
        const field = func.childForFieldName('field');
        receiver = operand?.text || null;
        methodName = field?.text || func.text;
      } else {
        // Plain function call: funcName()
        methodName = func.text;
      }

      const args = call.childForFieldName('arguments');
      const argInfos: CallInfo['arguments'] = [];
      let argPos = 0;
      if (args) {
        for (let i = 0; i < args.childCount; i++) {
          const arg = args.child(i);
          if (arg && arg.type !== '(' && arg.type !== ')' && arg.type !== ',') {
            argInfos.push({
              position: argPos++,
              expression: arg.text,
              variable: arg.type === 'identifier' ? arg.text : null,
              literal: (arg.type === 'interpreted_string_literal' || arg.type === 'int_literal') ? arg.text : null,
            });
          }
        }
      }

      calls.push({
        method_name: methodName,
        receiver,
        arguments: argInfos,
        location: {
          line: call.startPosition.row + 1,
          column: call.startPosition.column,
        },
      });
    }

    return calls;
  }

  /**
   * Extract import information from Go source.
   */
  extractImports(context: ExtractionContext): ImportInfo[] {
    const imports: ImportInfo[] = [];
    const root = context.tree.rootNode;

    const importDecls = this.findNodes(root, 'import_declaration');
    for (const decl of importDecls) {
      // Single import: import "fmt"
      const singleSpec = this.findChildByType(decl, 'import_spec');
      if (singleSpec) {
        const parsed = this.parseImportSpec(singleSpec);
        if (parsed) imports.push(parsed);
        continue;
      }

      // Grouped imports: import ( "fmt"; "net/http" )
      const specList = this.findChildByType(decl, 'import_spec_list');
      if (specList) {
        for (let i = 0; i < specList.childCount; i++) {
          const spec = specList.child(i);
          if (!spec || spec.type !== 'import_spec') continue;
          const parsed = this.parseImportSpec(spec);
          if (parsed) imports.push(parsed);
        }
      }
    }

    return imports;
  }

  /**
   * Extract package name from Go source.
   */
  extractPackage(context: ExtractionContext): string | undefined {
    const root = context.tree.rootNode;
    const pkgClause = this.findChildByType(root, 'package_clause');
    if (!pkgClause) return undefined;

    // package_clause has a child with the package name
    for (let i = 0; i < pkgClause.childCount; i++) {
      const child = pkgClause.child(i);
      if (child && child.type === 'package_identifier') {
        return child.text;
      }
    }

    return undefined;
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private parseImportSpec(spec: SyntaxNode): ImportInfo | null {
    // import_spec: optional alias + path (interpreted_string_literal)
    let alias: string | null = null;
    let path: string | undefined;

    for (let i = 0; i < spec.childCount; i++) {
      const child = spec.child(i);
      if (!child) continue;
      if (child.type === 'package_identifier' || child.type === 'blank_identifier' || child.type === 'dot') {
        alias = child.text;
      }
      if (child.type === 'interpreted_string_literal') {
        path = child.text.slice(1, -1); // Remove quotes
      }
    }

    if (!path) return null;

    // Extract short name from path (e.g., "net/http" → "http")
    const shortName = alias || path.split('/').pop() || path;

    return {
      imported_name: shortName,
      from_package: path,
      alias,
      is_wildcard: alias === '.',
      line_number: spec.startPosition.row + 1,
    };
  }

  private extractGoParams(params: SyntaxNode): TypeInfo['methods'][0]['parameters'] {
    const result: TypeInfo['methods'][0]['parameters'] = [];
    for (let i = 0; i < params.childCount; i++) {
      const param = params.child(i);
      if (!param || param.type !== 'parameter_declaration') continue;
      const nameNode = param.childForFieldName('name');
      const typeNode = param.childForFieldName('type');
      if (nameNode) {
        result.push({
          name: nameNode.text,
          type: typeNode?.text || null,
          annotations: [],
        });
      }
    }
    return result;
  }
}
