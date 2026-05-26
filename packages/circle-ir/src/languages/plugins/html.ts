/**
 * HTML Language Plugin
 *
 * Provides HTML-specific AST handling for the web extraction preprocessor.
 * HTML is a preprocessor language — it does not produce full IR.
 * Instead, <script> blocks are extracted and delegated to the JS analyzer,
 * and attribute-level security checks are run directly on the HTML AST.
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
 * HTML language plugin implementation.
 * Acts as a preprocessor — delegates script analysis to JS plugin.
 */
export class HtmlPlugin extends BaseLanguagePlugin {
  readonly id = 'html' as const;
  readonly name = 'HTML';
  readonly extensions = ['.html', '.htm', '.xhtml'];
  readonly wasmPath = 'tree-sitter-html.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // HTML has no OOP constructs
    classDeclaration: [],
    interfaceDeclaration: [],
    enumDeclaration: [],
    functionDeclaration: [],
    methodDeclaration: [],

    // No expressions in HTML
    methodCall: [],
    functionCall: [],
    assignment: [],
    variableDeclaration: [],

    // No parameters
    parameter: [],
    argument: [],

    // No annotations
    annotation: [],
    decorator: [],

    // No imports
    importStatement: [],

    // No control flow
    ifStatement: [],
    forStatement: [],
    whileStatement: [],
    tryStatement: [],
    returnStatement: [],
  };

  detectFramework(_context: ExtractionContext): FrameworkInfo | undefined {
    return undefined;
  }

  getBuiltinSources(): TaintSourcePattern[] {
    return [];
  }

  getBuiltinSinks(): TaintSinkPattern[] {
    return [];
  }

  getReceiverType(_node: SyntaxNode, _context: ExtractionContext): string | undefined {
    return undefined;
  }

  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'attribute_value' || node.type === 'quoted_attribute_value';
  }

  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;
    const text = node.text;
    if ((text.startsWith('"') && text.endsWith('"')) ||
        (text.startsWith("'") && text.endsWith("'"))) {
      return text.slice(1, -1);
    }
    return text;
  }

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
