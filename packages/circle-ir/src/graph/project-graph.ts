/**
 * ProjectGraph
 *
 * Wraps multiple per-file CodeGraph instances with lazy cross-file resolution
 * infrastructure (SymbolTable, TypeHierarchyResolver, CrossFileResolver).
 *
 * Usage:
 *   const pg = new ProjectGraph();
 *   pg.addFile('/src/A.java', graphA);
 *   pg.addFile('/src/B.java', graphB);
 *   const flows = pg.resolver.findCrossFileTaintFlows();
 */

import type { CircleIR } from '../types/index.js';
import { CodeGraph } from './code-graph.js';
import {
  SymbolTable,
  TypeHierarchyResolver,
  CrossFileResolver,
} from '../resolution/index.js';

export class ProjectGraph {
  private readonly files = new Map<string, { graph: CodeGraph; ir: CircleIR }>();

  // Lazy caches — nulled whenever a new file is added
  private _symbolTable:   SymbolTable | null = null;
  private _typeHierarchy: TypeHierarchyResolver | null = null;
  private _resolver:      CrossFileResolver | null = null;

  /**
   * Register a file's CodeGraph.  Invalidates all lazy caches.
   */
  addFile(filePath: string, graph: CodeGraph): void {
    this.files.set(filePath, { graph, ir: graph.ir });
    this._symbolTable   = null;
    this._typeHierarchy = null;
    this._resolver      = null;
  }

  /** Registered file paths in insertion order. */
  get filePaths(): string[] {
    return [...this.files.keys()];
  }

  /** Total number of registered files. */
  get fileCount(): number {
    return this.files.size;
  }

  /** Retrieve a file's CodeGraph, or undefined if not registered. */
  getGraph(filePath: string): CodeGraph | undefined {
    return this.files.get(filePath)?.graph;
  }

  /** Retrieve a file's CircleIR, or undefined if not registered. */
  getIR(filePath: string): CircleIR | undefined {
    return this.files.get(filePath)?.ir;
  }

  /** Lazily-built SymbolTable covering all registered files. */
  get symbolTable(): SymbolTable {
    if (!this._symbolTable) {
      const st = new SymbolTable();
      for (const [path, { ir }] of this.files) st.addFromIR(ir, path);
      this._symbolTable = st;
    }
    return this._symbolTable;
  }

  /** Lazily-built TypeHierarchyResolver covering all registered files. */
  get typeHierarchy(): TypeHierarchyResolver {
    if (!this._typeHierarchy) {
      const th = new TypeHierarchyResolver();
      for (const [path, { ir }] of this.files) th.addFromIR(ir, path);
      this._typeHierarchy = th;
    }
    return this._typeHierarchy;
  }

  /**
   * Lazily-built CrossFileResolver.
   * Accesses `this.symbolTable` and `this.typeHierarchy` (also lazy) so all
   * three are computed together on the first call after any `addFile()`.
   */
  get resolver(): CrossFileResolver {
    if (!this._resolver) {
      const r = new CrossFileResolver(this.symbolTable, this.typeHierarchy);
      for (const [path, { ir }] of this.files) r.addFile(path, ir);
      this._resolver = r;
    }
    return this._resolver;
  }
}
