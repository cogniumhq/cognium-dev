/**
 * Cross-file resolution module
 *
 * Provides type hierarchy tracking, symbol table, and cross-file
 * call resolution for multi-file analysis.
 */

export { TypeHierarchyResolver, createWithJdkTypes } from './type-hierarchy.js';
export type { TypeNode } from './type-hierarchy.js';
export { SymbolTable, buildSymbolTable } from './symbol-table.js';
export type { ExportedSymbol } from './symbol-table.js';
export { CrossFileResolver, buildCrossFileResolver } from './cross-file.js';
export type {
  ResolvedCall,
  MethodTaintInfo,
  CrossFileTaintFlow,
} from './cross-file.js';
