/**
 * Vue Language Plugin
 *
 * Provides routing for Vue Single-File Components (.vue files). Vue SFCs
 * are HTML-syntax-wrapped: `<template>` / `<script>` / `<style>` blocks
 * are valid HTML elements, so tree-sitter-html parses them correctly.
 * The plugin therefore reuses the html grammar (no new WASM dependency)
 * and acts as a thin preprocessor — `<script>` and `<script setup>`
 * blocks are extracted by the same machinery as HTML inline scripts and
 * routed to the JS / TS pipeline.
 *
 * Sprint 63 (cognium-dev #184): JS-side detection only. Template-attribute
 * sinks like `v-html`, `v-text`, `:innerHTML` are not detected by this
 * plugin and land in Sprint 64 via a dedicated vue-template-xss pass.
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
 * Vue SFC plugin. Reuses the tree-sitter-html grammar at parse time;
 * the analyzer routes .vue extraction through `analyzeMarkupFile()`
 * which performs script-block extraction and delegates each block to
 * the JS/TS pipeline.
 */
export class VuePlugin extends BaseLanguagePlugin {
  readonly id = 'vue' as const;
  readonly name = 'Vue';
  readonly extensions = ['.vue'];
  // Reuse the HTML grammar — Vue SFCs are HTML-syntax-wrapped and parse
  // identically. Avoids shipping an extra tree-sitter-vue WASM.
  readonly wasmPath = 'tree-sitter-html.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Vue SFC root has no OOP constructs — those live inside <script> blocks
    // and are extracted via the JS/TS pipeline post-extraction.
    classDeclaration: [],
    interfaceDeclaration: [],
    enumDeclaration: [],
    functionDeclaration: [],
    methodDeclaration: [],

    methodCall: [],
    functionCall: [],
    assignment: [],
    variableDeclaration: [],

    parameter: [],
    argument: [],

    annotation: [],
    decorator: [],

    importStatement: [],

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
