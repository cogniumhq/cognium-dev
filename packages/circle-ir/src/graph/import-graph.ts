/**
 * ImportGraph
 *
 * Builds a directed file→file import graph from a ProjectGraph.
 * Only relative imports (from_package starting with '.') are resolved to edges —
 * stdlib and npm package imports are ignored. A page's <script src> (HTML, Vue)
 * is an edge too, when it names a file in the project by a relative path.
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

const EXTENSIONS = [
  '.ts', '.tsx', '.mts', '.cts',
  '.js', '.jsx', '.mjs', '.cjs',
  '.vue',
  '.py', '.java', '.rs',
  '',
];

// Entry-point filenames (base without extension) — not treated as orphans
const ENTRY_POINT_NAMES = /^(index|main|app|server|mod|cli|bin|start|run|entry|init)$/i;

// Files whose modules are referenced by relative path, which this graph
// resolves. Elsewhere a file in use can have no edge here (Java's package
// imports and same-package names, Python's absolute imports, Go, Rust, C#,
// shell, HTML), so it is never judged an orphan.
const ORPHAN_JUDGED_FILES = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs|vue)$/i;

// Minified files (`x.min.js`, `x-min.js`) are build output: a page or a
// bundler loads them, often from outside the scanned tree.
const MINIFIED_FILE = /[.-]min\.(js|mjs|cjs)$/i;

// A <script src> that is not a path inside the project: a URL with a scheme
// (https:, data:), protocol-relative (//host) or root-relative (/x.js, whose
// web root the graph does not know).
const NON_RELATIVE_SRC = /^([a-z][a-z0-9+.-]*:|\/)/i;

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

  /**
   * @param scriptSrcs page file → the `src` of each `<script src>` it has
   *   (HTML, Vue). Each one that names a project file is an edge.
   */
  constructor(
    projectGraph: ProjectGraph,
    scriptSrcs: ReadonlyMap<string, readonly string[]> = new Map(),
  ) {
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
          for (const ext of ['.ts', '.tsx', '.mts', '.cts', '.js', '.mjs', '.cjs']) {
            const candidate = stripped + ext;
            if (this.allFiles.has(candidate)) {
              resolved = candidate;
              break;
            }
          }
        }

        // Likewise `./foo.mjs` → `./foo.mts` and `./foo.cjs` → `./foo.cts`.
        if (!resolved && /\.[mc]js$/.test(base)) {
          const candidate = base.slice(0, -2) + 'ts';
          if (this.allFiles.has(candidate)) resolved = candidate;
        }

        if (resolved) this.addEdge(filePath, resolved);
      }
    }

    // A page's <script src="content/js/app.js"> is relative to the page.
    for (const [page, srcs] of scriptSrcs) {
      if (!this.allFiles.has(page)) continue;
      const dir = dirname(page);
      for (const src of srcs) {
        const path = src.trim().split(/[?#]/, 1)[0];
        if (!path || NON_RELATIVE_SRC.test(path)) continue;
        const resolved = normalizePath(dir ? `${dir}/${path}` : path);
        if (this.allFiles.has(resolved)) this.addEdge(page, resolved);
      }
    }
  }

  private addEdge(from: string, to: string): void {
    if (from === to) return;
    this.outEdges.get(from)!.add(to);
    this.inEdges.get(to)!.add(from);
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
   * Returns JS/TS file paths with zero incoming import edges that are not entry points.
   * Entry points: filename base (without extension) matches ENTRY_POINT_NAMES.
   * Files of other languages are never returned (see ORPHAN_JUDGED_FILES), nor
   * are minified files or a script shipped beside its own minified build
   * (`x.js` next to `x.min.js`: a vendored library's source and dist copy).
   */
  findOrphans(): string[] {
    const orphans: string[] = [];
    for (const file of this.allFiles) {
      if (!ORPHAN_JUDGED_FILES.test(file)) continue;
      if (MINIFIED_FILE.test(file)) continue;
      if (this.hasMinifiedTwin(file)) continue;
      if ((this.inEdges.get(file)?.size ?? 0) > 0) continue;
      // Check if entry point
      const base = file.split('/').pop() ?? '';
      const baseName = base.includes('.') ? base.slice(0, base.lastIndexOf('.')) : base;
      if (ENTRY_POINT_NAMES.test(baseName)) continue;
      orphans.push(file);
    }
    return orphans.sort();
  }

  private hasMinifiedTwin(file: string): boolean {
    const m = /\.(js|mjs|cjs)$/i.exec(file);
    if (!m) return false;
    const stem = file.slice(0, -m[0].length);
    return this.allFiles.has(`${stem}.min${m[0]}`) || this.allFiles.has(`${stem}-min${m[0]}`);
  }
}
