/**
 * Tests for ImportGraph — directed file→file import graph + Tarjan SCC
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ProjectGraph } from '../../src/graph/project-graph.js';
import { CodeGraph } from '../../src/graph/code-graph.js';
import { ImportGraph } from '../../src/graph/import-graph.js';
import type { CircleIR, ImportInfo } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(file: string, relImports: string[]): CircleIR {
  const imports: ImportInfo[] = relImports.map((from, i) => ({
    imported_name: 'default',
    from_package:  from,
    alias:         null,
    is_wildcard:   false,
    line_number:   i + 1,
  }));
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 5, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports,
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function buildProject(files: Array<[string, string[]]>): ProjectGraph {
  const pg = new ProjectGraph();
  for (const [file, rels] of files) {
    pg.addFile(file, new CodeGraph(makeIR(file, rels)));
  }
  return pg;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ImportGraph', () => {
  it('builds outEdges and inEdges for relative imports', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts')).toContain('/src/b.ts');
    expect(g.edgesTo('/src/b.ts')).toContain('/src/a.ts');
  });

  it('ignores non-relative imports (stdlib / npm)', () => {
    const pg = buildProject([
      ['/src/a.ts', ['react', 'fs', 'lodash']],
      ['/src/b.ts', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts')).toHaveLength(0);
  });

  it('resolves extension-less imports by trying known extensions', () => {
    // a.ts imports './utils' which resolves to '/src/utils.ts'
    const pg = buildProject([
      ['/src/a.ts', ['./utils']],
      ['/src/utils.ts', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts')).toContain('/src/utils.ts');
  });

  it('resolves extension-less imports to .mts, .cts, .mjs and .cjs files', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./esm', './cjs', './plain-esm', './plain-cjs']],
      ['/src/esm.mts', []],
      ['/src/cjs.cts', []],
      ['/src/plain-esm.mjs', []],
      ['/src/plain-cjs.cjs', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts').sort()).toEqual([
      '/src/cjs.cts', '/src/esm.mts', '/src/plain-cjs.cjs', '/src/plain-esm.mjs',
    ]);
  });

  it('resolves ./x.mjs and ./x.cjs to x.mts and x.cts on disk', () => {
    const pg = buildProject([
      ['/src/a.mts', ['./b.mjs', './c.cjs']],
      ['/src/b.mts', []],
      ['/src/c.cts', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.mts').sort()).toEqual(['/src/b.mts', '/src/c.cts']);
  });

  it('resolves an extension-less import to a .vue file, and to the TS source before its .js twin', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./Widget', './lib']],
      ['/src/Widget.vue', []],
      ['/src/lib.mts', []],
      ['/src/lib.js', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts').sort()).toEqual(['/src/Widget.vue', '/src/lib.mts']);
  });

  it('adds an edge from an HTML page to a script it loads with <script src>', () => {
    const pg = buildProject([
      ['/site/page.html', []],
      ['/site/js/app-ui.js', []],
    ]);
    const g = new ImportGraph(pg, new Map([['/site/page.html', ['js/app-ui.js']]]));
    expect(g.edgesFrom('/site/page.html')).toEqual(['/site/js/app-ui.js']);
    expect(g.edgesTo('/site/js/app-ui.js')).toEqual(['/site/page.html']);
  });

  it('detects a direct 2-file cycle', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./a']],
    ]);
    const g = new ImportGraph(pg);
    const cycles = g.findCycles();
    expect(cycles).toHaveLength(1);
    expect(cycles[0]).toContain('/src/a.ts');
    expect(cycles[0]).toContain('/src/b.ts');
  });

  it('detects a 3-file cycle', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./c']],
      ['/src/c.ts', ['./a']],
    ]);
    const g = new ImportGraph(pg);
    const cycles = g.findCycles();
    expect(cycles).toHaveLength(1);
    expect(cycles[0].size).toBe(3);
  });

  it('returns no cycles for a DAG', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./c']],
      ['/src/c.ts', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.findCycles()).toHaveLength(0);
  });

  it('identifies orphan modules (no incoming imports, not an entry point)', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', []],
      ['/src/orphan.ts', []],
    ]);
    const g = new ImportGraph(pg);
    const orphans = g.findOrphans();
    expect(orphans).toContain('/src/orphan.ts');
    // 'a.ts' has no incoming either but it's a root, and b.ts has incoming from a
    expect(orphans).not.toContain('/src/b.ts');
  });

  it('resolves extension-less imports to .mjs and .cjs modules', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./util']],
      ['/src/util.mjs', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts')).toContain('/src/util.mjs');
    expect(g.findOrphans()).not.toContain('/src/util.mjs');
  });

  it('resolves ESM .js import specifier to a .mts source file', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./foo.js']],
      ['/src/foo.mts', []],
    ]);
    const g = new ImportGraph(pg);
    expect(g.edgesFrom('/src/a.ts')).toContain('/src/foo.mts');
  });

  it('does NOT flag index/main/app/server/mod files as orphans', () => {
    const pg = buildProject([
      ['/src/index.ts', []],
      ['/src/main.ts', []],
      ['/src/app.ts', []],
      ['/src/server.ts', []],
      ['/src/orphan.ts', []],
    ]);
    const g = new ImportGraph(pg);
    const orphans = g.findOrphans();
    expect(orphans).not.toContain('/src/index.ts');
    expect(orphans).not.toContain('/src/main.ts');
    expect(orphans).not.toContain('/src/app.ts');
    expect(orphans).not.toContain('/src/server.ts');
    expect(orphans).toContain('/src/orphan.ts');
  });
});
