/**
 * Base Language Plugin
 *
 * Provides common functionality for all language plugins.
 */

import type { Parser, Node as SyntaxNode, Tree } from 'web-tree-sitter';
import type {
  TypeInfo,
  CallInfo,
  ImportInfo,
} from '../../types/index.js';
import type {
  LanguagePlugin,
  LanguageNodeTypes,
  ExtractionContext,
  FrameworkInfo,
  TaintSourcePattern,
  TaintSinkPattern,
  SupportedLanguage,
} from '../types.js';

/**
 * Abstract base class for language plugins.
 * Provides default implementations for common methods.
 */
export abstract class BaseLanguagePlugin implements LanguagePlugin {
  abstract readonly id: SupportedLanguage;
  abstract readonly name: string;
  abstract readonly extensions: string[];
  abstract readonly wasmPath: string;
  abstract readonly nodeTypes: LanguageNodeTypes;

  protected parser: Parser | null = null;

  async initialize(parser: Parser): Promise<void> {
    this.parser = parser;
  }

  canHandle(filePath: string): boolean {
    const lowerPath = filePath.toLowerCase();
    return this.extensions.some(ext => {
      const normalizedExt = ext.startsWith('.') ? ext : `.${ext}`;
      return lowerPath.endsWith(normalizedExt);
    });
  }

  // Abstract methods that must be implemented by each language
  abstract extractTypes(context: ExtractionContext): TypeInfo[];
  abstract extractCalls(context: ExtractionContext): CallInfo[];
  abstract extractImports(context: ExtractionContext): ImportInfo[];
  abstract extractPackage(context: ExtractionContext): string | undefined;
  abstract getBuiltinSources(): TaintSourcePattern[];
  abstract getBuiltinSinks(): TaintSinkPattern[];

  // Default implementations for optional methods
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    return undefined;
  }

  getReceiverType(node: SyntaxNode, context: ExtractionContext): string | undefined {
    return undefined;
  }

  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'string_literal' || node.type === 'string';
  }

  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;
    const text = node.text;
    // Remove quotes
    if ((text.startsWith('"') && text.endsWith('"')) ||
        (text.startsWith("'") && text.endsWith("'"))) {
      return text.slice(1, -1);
    }
    return text;
  }

  /**
   * Helper to get text from a node
   */
  protected getNodeText(node: SyntaxNode): string {
    return node.text;
  }

  /**
   * Helper to find all nodes of a given type
   */
  protected findNodes(root: SyntaxNode, type: string): SyntaxNode[] {
    const nodes: SyntaxNode[] = [];
    const cursor = root.walk();

    const visit = (): void => {
      if (cursor.nodeType === type) {
        nodes.push(cursor.currentNode);
      }
      if (cursor.gotoFirstChild()) {
        do {
          visit();
        } while (cursor.gotoNextSibling());
        cursor.gotoParent();
      }
    };

    visit();
    return nodes;
  }

  /**
   * Helper to find first child of given type
   */
  protected findChildByType(node: SyntaxNode, type: string): SyntaxNode | null {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.type === type) {
        return child;
      }
    }
    return null;
  }
}
