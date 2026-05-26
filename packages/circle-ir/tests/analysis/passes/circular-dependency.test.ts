/**
 * Tests for Pass #68: circular-dependency (project-level, CWE-1047)
 */

import { describe, it, expect } from 'vitest';
import { ProjectGraph } from '../../../src/graph/project-graph.js';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { ImportGraph } from '../../../src/graph/import-graph.js';
import { CircularDependencyPass } from '../../../src/analysis/passes/circular-dependency-pass.js';
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

describe('CircularDependencyPass', () => {
  it('detects a direct 2-file cycle and emits one finding', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./a']],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new CircularDependencyPass().run(pg, ig);

    expect(findings).toHaveLength(1);
    // Finding is anchored to alphabetically-first file
    expect(findings[0].file).toBe('/src/a.ts');
    expect(findings[0].message).toContain('/src/a.ts');
    expect(findings[0].message).toContain('/src/b.ts');
  });

  it('detects a 3-file cycle and emits one finding', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./c']],
      ['/src/c.ts', ['./a']],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new CircularDependencyPass().run(pg, ig);

    expect(findings).toHaveLength(1);
    expect(findings[0].evidence?.['size']).toBe(3);
  });

  it('returns no findings for a DAG (no cycles)', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./c']],
      ['/src/c.ts', []],
    ]);
    const ig = new ImportGraph(pg);
    expect(new CircularDependencyPass().run(pg, ig)).toHaveLength(0);
  });

  it('returns no findings for a single file', () => {
    const pg = buildProject([['/src/a.ts', []]]);
    const ig = new ImportGraph(pg);
    expect(new CircularDependencyPass().run(pg, ig)).toHaveLength(0);
  });

  it('detects two separate cycles and emits two findings', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./a']],
      ['/src/x.ts', ['./y']],
      ['/src/y.ts', ['./x']],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new CircularDependencyPass().run(pg, ig);

    expect(findings).toHaveLength(2);
  });

  it('includes correct metadata (cwe, category, level)', () => {
    const pg = buildProject([
      ['/src/a.ts', ['./b']],
      ['/src/b.ts', ['./a']],
    ]);
    const ig = new ImportGraph(pg);
    const findings = new CircularDependencyPass().run(pg, ig);

    expect(findings[0].cwe).toBe('CWE-1047');
    expect(findings[0].category).toBe('architecture');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].pass).toBe('circular-dependency');
  });
});
