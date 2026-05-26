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
