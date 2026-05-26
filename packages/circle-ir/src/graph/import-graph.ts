/**
 * ImportGraph
 *
 * Builds a directed file→file import graph from a ProjectGraph.
 * Only relative imports (from_package starting with '.') are resolved to edges —
 * stdlib and npm package imports are ignored.
 *
 * Used by CircularDependencyPass and OrphanModulePass.
 */

import type { ProjectGraph } from './project-graph.js';

// ---------------------------------------------------------------------------
// Path helpers (no Node.js 'path' module — must run in browser too)
// ---------------------------------------------------------------------------

function dirname(filePath: string): string {
  const idx = filePath.lastIndexOf('/');
  return idx >= 0 ? filePath.slice(0, idx) : '';
}

function normalizePath(p: string): string {
  const isAbsolute = p.startsWith('/');
  const parts = p.split('/');
  const result: string[] = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      result.pop();
    } else {
      result.push(part);
    }
  }
  return (isAbsolute ? '/' : '') + result.join('/');
}

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.rs', ''];

// Entry-point filenames (base without extension) — not treated as orphans
const ENTRY_POINT_NAMES = /^(index|main|app|server|mod|cli|bin|start|run|entry|init)$/i;

// ---------------------------------------------------------------------------
// ImportGraph
// ---------------------------------------------------------------------------

export class ImportGraph {
  /** file → set of files it imports */
  private readonly outEdges: Map<string, Set<string>>;
  /** file → set of files that import it */
  private readonly inEdges: Map<string, Set<string>>;
  /** All known file paths */
  private readonly allFiles: Set<string>;

  constructor(projectGraph: ProjectGraph) {
    this.outEdges = new Map();
    this.inEdges  = new Map();
    this.allFiles = new Set(projectGraph.filePaths);

    // Initialize edge sets for all files
    for (const file of this.allFiles) {
      this.outEdges.set(file, new Set());
      this.inEdges.set(file, new Set());
    }

    // Build edges from imports
    for (const filePath of projectGraph.filePaths) {
      const ir = projectGraph.getIR(filePath);
      if (!ir) continue;

      const dir = dirname(filePath);

      for (const imp of ir.imports) {
        const pkg = imp.from_package;
        if (!pkg || !pkg.startsWith('.')) continue; // skip stdlib/npm

        // Resolve relative path
        const rawCandidate = dir ? `${dir}/${pkg}` : pkg;
        const base = normalizePath(rawCandidate);

        // Try with each extension
        let resolved: string | null = null;
        for (const ext of EXTENSIONS) {
          const candidate = base + ext;
          if (this.allFiles.has(candidate)) {
            resolved = candidate;
            break;
          }
        }

        // TypeScript ESM convention: `import './foo.js'` refers to `./foo.ts` on disk.
        // Strip the .js suffix and retry with TypeScript extensions.
        if (!resolved && base.endsWith('.js')) {
          const stripped = base.slice(0, -3);
          for (const ext of ['.ts', '.tsx', '.js']) {
            const candidate = stripped + ext;
            if (this.allFiles.has(candidate)) {
              resolved = candidate;
              break;
            }
          }
        }

        if (resolved && resolved !== filePath) {
          this.outEdges.get(filePath)!.add(resolved);
          this.inEdges.get(resolved)!.add(filePath);
        }
      }
    }
  }

  /** Files directly imported by `filePath`. */
  edgesFrom(filePath: string): string[] {
    return [...(this.outEdges.get(filePath) ?? [])];
  }

  /** Files that directly import `filePath`. */
  edgesTo(filePath: string): string[] {
    return [...(this.inEdges.get(filePath) ?? [])];
  }

  /**
   * Tarjan's SCC — returns groups of files that form import cycles.
   * Each returned Set has size ≥ 2 (only actual cycles).
   */
  findCycles(): Set<string>[] {
    const index:   Map<string, number>  = new Map();
    const lowlink: Map<string, number>  = new Map();
    const onStack: Map<string, boolean> = new Map();
    const stack:   string[]             = [];
    const cycles:  Set<string>[]        = [];
    let   counter  = 0;

    const strongConnect = (v: string): void => {
      index.set(v, counter);
      lowlink.set(v, counter);
      counter++;
      stack.push(v);
      onStack.set(v, true);

      for (const w of (this.outEdges.get(v) ?? [])) {
        if (!index.has(w)) {
          strongConnect(w);
          lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
        } else if (onStack.get(w)) {
          lowlink.set(v, Math.min(lowlink.get(v)!, index.get(w)!));
        }
      }

      if (lowlink.get(v) === index.get(v)) {
        // Root of SCC — pop the component
        const scc: Set<string> = new Set();
        let w: string;
        do {
          w = stack.pop()!;
          onStack.set(w, false);
          scc.add(w);
        } while (w !== v);

        if (scc.size > 1) {
          cycles.push(scc);
        }
      }
    };

    for (const v of this.allFiles) {
      if (!index.has(v)) {
        strongConnect(v);
      }
    }

    return cycles;
  }

  /**
   * Returns file paths with zero incoming import edges that are not entry points.
   * Entry points: filename base (without extension) matches /^(index|main|app|server|mod)$/i
   */
  findOrphans(): string[] {
    const orphans: string[] = [];
    for (const file of this.allFiles) {
      if ((this.inEdges.get(file)?.size ?? 0) > 0) continue;
      // Check if entry point
      const base = file.split('/').pop() ?? '';
      const baseName = base.includes('.') ? base.slice(0, base.lastIndexOf('.')) : base;
      if (ENTRY_POINT_NAMES.test(baseName)) continue;
      orphans.push(file);
    }
    return orphans.sort();
  }
}
