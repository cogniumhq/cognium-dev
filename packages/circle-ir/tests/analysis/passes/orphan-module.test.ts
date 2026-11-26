/**
 * Tests for Pass #71: orphan-module (project-level)
 */

import { describe, it, expect } from 'vitest';
import { ProjectGraph } from '../../../src/graph/project-graph.js';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { ImportGraph } from '../../../src/graph/import-graph.js';
import { OrphanModulePass } from '../../../src/analysis/passes/orphan-module-pass.js';
import type { CircleIR, ImportInfo } from '../../../src/types/index.js';

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
    imports, exports: [], unresolved: [],
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

describe('OrphanModulePass', () => {
  it('flags a file with no incoming imports that is not an entry point', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', []],          // imported by a → not orphan
      ['/src/orphan.ts', []],     // no imports from anyone → orphan
    ]);
    const ig = new ImportGraph(pg);
    const findings = new OrphanModulePass().run(pg, ig);

    const orphanFiles = findings.map(f => f.file);
    expect(orphanFiles).toContain('/src/orphan.ts');
    expect(orphanFiles).not.toContain('/src/b.ts');
  });

  it('returns no findings when all files have incoming imports', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./a']], // mutual cycle → each has incoming
    ]);
    const ig = new ImportGraph(pg);
    // Both have incoming edges (from each other). findOrphans returns [] (no zero-in-degree).
    // Note: a.ts has no external incoming so it might show as orphan — but a.ts IS imported by b.ts
    const findings = new OrphanModulePass().run(pg, ig);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag index.ts as an orphan (entry point)', () => {
    const pg = buildProject([
      ['/src/index.ts', []],
      ['/src/helper.ts', []],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new OrphanModulePass().run(pg, ig);

    const orphanFiles = findings.map(f => f.file);
    expect(orphanFiles).not.toContain('/src/index.ts');
    expect(orphanFiles).toContain('/src/helper.ts');
  });

  it('does NOT flag main.ts / app.ts / server.ts / mod.ts as orphans', () => {
    const pg = buildProject([
      ['/src/main.ts', []],
      ['/src/app.ts', []],
      ['/src/server.ts', []],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new OrphanModulePass().run(pg, ig);
    expect(findings).toHaveLength(0);
  });

  it('flags utils.ts with no incoming imports', () => {
    const pg = buildProject([
      ['/src/index.ts', []],   // entry point — not flagged
      ['/src/utils.ts', []],   // orphan — flagged
    ]);
    const ig = new ImportGraph(pg);
    const findings = new OrphanModulePass().run(pg, ig);

    expect(findings.map(f => f.file)).toContain('/src/utils.ts');
  });

  it('includes correct pass metadata in findings', () => {
    const pg = buildProject([
      ['/src/orphan.ts', []],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new OrphanModulePass().run(pg, ig);

    expect(findings).toHaveLength(1);
    expect(findings[0].pass).toBe('orphan-module');
    expect(findings[0].category).toBe('architecture');
    expect(findings[0].level).toBe('note');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].line).toBe(1);
  });
});

describe('OrphanModulePass: only files whose imports the graph resolves are judged', () => {
  // Java refers to a class by its package import or, in the same package, by
  // its bare name; neither is a relative path, so the import graph never has
  // an edge into a Java file. A Maven project of 208 classes was reported as
  // 208 orphans.
  it('does NOT flag Java classes, which are referenced by package, not path', () => {
    const pg = buildProject([
      ['/repo/plugin/src/main/java/org/example/score/Score.java', []],
      ['/repo/library/src/main/java/org/example/helpers/Categories.java', []],
    ]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg));
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag Python, Go, Rust, C#, shell or HTML files', () => {
    const pg = buildProject([
      ['/repo/pkg/util.py', []],
      ['/repo/internal/store.go', []],
      ['/repo/src/parser.rs', []],
      ['/repo/src/Service.cs', []],
      ['/repo/scripts/run-tool.sh', []],
      ['/repo/report/template.html', []],
    ]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg));
    expect(findings).toHaveLength(0);
  });

  it('still flags an unimported JS/TS module beside them', () => {
    const pg = buildProject([
      ['/repo/src/Score.java', []],
      ['/repo/web/index.ts', ['./used']],
      ['/repo/web/used.ts', []],
      ['/repo/web/stale.tsx', []],
      ['/repo/web/legacy.mjs', []],
    ]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg));
    expect(findings.map(f => f.file)).toEqual(['/repo/web/legacy.mjs', '/repo/web/stale.tsx']);
  });
});

describe('OrphanModulePass: scripts loaded by HTML and minified files', () => {
  // A page loads a script with <script src>, which is not an import, so a
  // script used only by a page had no incoming edge.
  it('does NOT flag a script an HTML page loads with <script src>', () => {
    const pg = buildProject([
      ['/repo/report/template.html', []],
      ['/repo/report/content/js/charts.js', []],
      ['/repo/report/content/js/stale.js', []],
    ]);
    const scriptSrcs = new Map([['/repo/report/template.html', ['content/js/charts.js']]]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg, scriptSrcs));
    expect(findings.map(f => f.file)).toEqual(['/repo/report/content/js/stale.js']);
  });

  it('resolves ./ and ../ script paths and ignores a query string or fragment', () => {
    const pg = buildProject([
      ['/repo/site/pages/about.html', []],
      ['/repo/site/js/menu.js', []],
      ['/repo/site/pages/local.js', []],
    ]);
    const scriptSrcs = new Map([
      ['/repo/site/pages/about.html', ['../js/menu.js?v=3', './local.js#top']],
    ]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg, scriptSrcs));
    expect(findings).toHaveLength(0);
  });

  it('gives no edge for a remote, protocol-relative, data: or root-relative src', () => {
    const pg = buildProject([
      ['/repo/site/index.html', []],
      ['/repo/site/jquery.js', []],
      ['/repo/site/widget.js', []],
    ]);
    const scriptSrcs = new Map([['/repo/site/index.html', [
      'https://cdn.example.com/jquery.js',
      '//cdn.example.com/jquery.js',
      'data:text/javascript,alert(1)',
      '/widget.js',
    ]]]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg, scriptSrcs));
    expect(findings.map(f => f.file)).toEqual(['/repo/site/jquery.js', '/repo/site/widget.js']);
  });

  it('does NOT flag minified files (.min.js, -min.js), which are build output', () => {
    const pg = buildProject([
      ['/repo/static/js/vendor.min.js', []],
      ['/repo/static/js/lib-min.js', []],
      ['/repo/static/js/esm.min.mjs', []],
      ['/repo/static/js/minimal.js', []],
      ['/repo/static/js/admin.js', []],
    ]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg));
    expect(findings.map(f => f.file)).toEqual(['/repo/static/js/admin.js', '/repo/static/js/minimal.js']);
  });

  it('does NOT flag a script shipped beside its own minified build (x.js + x.min.js)', () => {
    const pg = buildProject([
      ['/repo/static/js/bootstrap.js', []],
      ['/repo/static/js/bootstrap.min.js', []],
      ['/repo/static/js/theme.js', []],
      ['/repo/other/theme.min.js', []],
    ]);
    const findings = new OrphanModulePass().run(pg, new ImportGraph(pg));
    expect(findings.map(f => f.file)).toEqual(['/repo/static/js/theme.js']);
  });
});
