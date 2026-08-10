/**
 * C# Language Plugin — Phase-0 spike scaffold (cognium-dev C#/.NET epic).
 *
 * SPIKE STATUS: minimal registration + nodeTypes only. The main analysis path
 * (`analyze()` → core extractors in `src/core/extractors/*`) dispatches by
 * language and currently has NO `csharp` branch, so C# rides the Java default
 * extractors + `buildJavaDFG` — intentional for the Day-3 go/no-go DFG
 * experiment. `extract*`/`getBuiltin*` here are unused by the main path (they
 * exist to satisfy the LanguagePlugin contract) and stay stubbed until Phase 1.
 */

import type { TypeInfo, CallInfo, ImportInfo } from '../../types/index.js';
import type {
  LanguageNodeTypes,
  ExtractionContext,
  FrameworkInfo,
  TaintSourcePattern,
  TaintSinkPattern,
} from '../types.js';
import { BaseLanguagePlugin } from './base.js';

/**
 * C# language plugin (spike scaffold). Node-type names verified against
 * tree-sitter-c-sharp on a parsed ASP.NET controller (2026-08-10):
 * `class_declaration`, `method_declaration`, `invocation_expression`,
 * `local_declaration_statement`, `object_creation_expression`,
 * `member_access_expression`, `interpolated_string_expression`.
 */
export class CSharpPlugin extends BaseLanguagePlugin {
  readonly id = 'csharp' as const;
  readonly name = 'C#';
  readonly extensions = ['.cs'];
  readonly wasmPath = 'tree-sitter-csharp.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations
    classDeclaration: ['class_declaration', 'record_declaration', 'struct_declaration'],
    interfaceDeclaration: ['interface_declaration'],
    enumDeclaration: ['enum_declaration'],
    functionDeclaration: [],
    methodDeclaration: ['method_declaration', 'constructor_declaration', 'local_function_statement'],

    // Expressions — NB these diverge from Java (invocation_expression vs
    // method_invocation, local_declaration_statement vs local_variable_declaration).
    methodCall: ['invocation_expression'],
    functionCall: [],
    assignment: ['assignment_expression'],
    variableDeclaration: ['local_declaration_statement', 'field_declaration', 'variable_declaration'],

    // Parameters and arguments
    parameter: ['parameter'],
    argument: ['argument_list'],

    // Attributes (C# analogue of annotations/decorators)
    annotation: ['attribute', 'attribute_list'],
    decorator: [],

    // Imports
    importStatement: ['using_directive'],

    // Control flow
    ifStatement: ['if_statement'],
    forStatement: ['for_statement', 'for_each_statement'],
    whileStatement: ['while_statement'],
    tryStatement: ['try_statement'],
    returnStatement: ['return_statement'],
  };

  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    for (const imp of context.imports) {
      const path = imp.from_package || imp.imported_name;
      if (path.startsWith('Microsoft.AspNetCore') || path.startsWith('Microsoft.Extensions')) {
        return { name: 'aspnetcore', confidence: 0.9, indicators: [`using: ${path}`] };
      }
      if (path.startsWith('Microsoft.EntityFrameworkCore')) {
        return { name: 'efcore', confidence: 0.9, indicators: [`using: ${path}`] };
      }
    }
    return undefined;
  }

  // --- LanguagePlugin contract (unused by the main analyze() path; Phase-1) ---
  extractTypes(_context: ExtractionContext): TypeInfo[] { return []; }
  extractCalls(_context: ExtractionContext): CallInfo[] { return []; }
  extractImports(_context: ExtractionContext): ImportInfo[] { return []; }
  extractPackage(_context: ExtractionContext): string | undefined { return undefined; }
  getBuiltinSources(): TaintSourcePattern[] { return []; }
  getBuiltinSinks(): TaintSinkPattern[] { return []; }
}
