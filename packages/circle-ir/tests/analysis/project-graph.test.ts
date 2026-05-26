/**
 * Tests for ProjectGraph, CrossFilePass, and analyzeProject().
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { ProjectGraph } from '../../src/graph/index.js';
import { CrossFilePass } from '../../src/analysis/passes/cross-file-pass.js';
import { CodeGraph } from '../../src/graph/index.js';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await initAnalyzer();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 10, hash: 'abc' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// ProjectGraph — unit tests
// ---------------------------------------------------------------------------

describe('ProjectGraph', () => {
  it('starts empty', () => {
    const pg = new ProjectGraph();
    expect(pg.filePaths).toEqual([]);
    expect(pg.fileCount).toBe(0);
  });

  it('registers files and reports filePaths in insertion order', () => {
    const pg = new ProjectGraph();
    const graphA = new CodeGraph(makeIR({ meta: { circle_ir: '3.0', file: 'A.java', language: 'java', loc: 5, hash: 'a' } }));
    const graphB = new CodeGraph(makeIR({ meta: { circle_ir: '3.0', file: 'B.java', language: 'java', loc: 5, hash: 'b' } }));

    pg.addFile('/src/A.java', graphA);
    pg.addFile('/src/B.java', graphB);

    expect(pg.filePaths).toEqual(['/src/A.java', '/src/B.java']);
    expect(pg.fileCount).toBe(2);
  });

  it('getGraph returns registered graph', () => {
    const pg = new ProjectGraph();
    const graph = new CodeGraph(makeIR());
    pg.addFile('/src/A.java', graph);

    expect(pg.getGraph('/src/A.java')).toBe(graph);
    expect(pg.getGraph('/src/Unknown.java')).toBeUndefined();
  });

  it('getIR returns the underlying CircleIR', () => {
    const pg = new ProjectGraph();
    const ir = makeIR();
    pg.addFile('/src/A.java', new CodeGraph(ir));

    expect(pg.getIR('/src/A.java')).toBe(ir);
    expect(pg.getIR('/nope.java')).toBeUndefined();
  });

  it('resolver is built lazily on first access', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    // Access resolver — should not throw
    const r = pg.resolver;
    expect(r).toBeDefined();
    // Second access returns same instance (cached)
    expect(pg.resolver).toBe(r);
  });

  it('addFile invalidates the lazy resolver cache', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    const r1 = pg.resolver;

    // Adding another file invalidates the cache
    pg.addFile('/src/B.java', new CodeGraph(makeIR()));
    const r2 = pg.resolver;

    // A new resolver instance must have been created
    expect(r2).not.toBe(r1);
  });

  it('symbolTable is built lazily', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    const st = pg.symbolTable;
    expect(st).toBeDefined();
    expect(pg.symbolTable).toBe(st); // same instance on second access
  });

  it('typeHierarchy is built lazily', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    const th = pg.typeHierarchy;
    expect(th).toBeDefined();
    expect(pg.typeHierarchy).toBe(th); // same instance on second access
  });
});

// ---------------------------------------------------------------------------
// CrossFilePass — unit tests with minimal fixtures
// ---------------------------------------------------------------------------

describe('CrossFilePass', () => {
  it('returns empty results for a single file with no sources', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));

    const result = new CrossFilePass().run(pg, new Map([['/src/A.java', ['line1']]]));

    expect(result.crossFileCalls).toEqual([]);
    expect(result.taintPaths).toEqual([]);
    expect(result.typeHierarchy).toBeDefined();
    expect(result.typeHierarchy.classes).toBeDefined();
    expect(result.typeHierarchy.interfaces).toBeDefined();
  });

  it('returns well-formed TypeHierarchy even with no types', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));

    const { typeHierarchy } = new CrossFilePass().run(pg, new Map());
    expect(typeof typeHierarchy.classes).toBe('object');
    expect(typeof typeHierarchy.interfaces).toBe('object');
  });
});

// ---------------------------------------------------------------------------
// analyzeProject() — structural tests
// ---------------------------------------------------------------------------

const JAVA_FILE_A = `
package com.example.controller;

import javax.servlet.http.HttpServletRequest;

public class UserController {
    public void handleRequest(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        java.sql.Connection conn = null;
        try {
            java.sql.Statement stmt = conn.createStatement();
            stmt.executeQuery(query);
        } catch (Exception e) {}
    }
}
`.trim();

const JAVA_FILE_B = `
package com.example.service;

import javax.servlet.http.HttpServletRequest;

public class UserService {
    public String getInput(HttpServletRequest request) {
        return request.getParameter("name");
    }
}
`.trim();

describe('analyzeProject()', () => {
  it('returns correct meta for empty file list', async () => {
    const result = await analyzeProject([]);
    expect(result.meta.total_files).toBe(0);
    expect(result.meta.total_loc).toBe(0);
    expect(result.files).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it('returns correct meta for single file', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/UserController.java', language: 'java' },
    ]);

    expect(result.meta.total_files).toBe(1);
    expect(result.meta.language).toBe('java');
    expect(result.files).toHaveLength(1);
    expect(result.files[0].file).toBe('/src/UserController.java');
    expect(result.cross_file_calls).toHaveLength(0); // no cross-file calls with one file
    expect(result.findings).toEqual([]);
    expect(new Date(result.meta.analyzed_at).toISOString()).toBe(result.meta.analyzed_at);
  });

  it('returns a CircleIR for each file', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    expect(result.files).toHaveLength(2);
    expect(result.files[0].file).toBe('/src/A.java');
    expect(result.files[1].file).toBe('/src/B.java');

    for (const fa of result.files) {
      const ir = fa.analysis;
      expect(ir.meta.circle_ir).toBe('3.0');
      expect(ir.types).toBeDefined();
      expect(ir.calls).toBeDefined();
      expect(ir.taint).toBeDefined();
    }
  });

  it('total_files and total_loc are correct', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    expect(result.meta.total_files).toBe(2);
    const expectedLoc = result.files.reduce((sum, f) => sum + (f.analysis.meta.loc ?? 0), 0);
    expect(result.meta.total_loc).toBe(expectedLoc);
  });

  it('analyzed_at is a valid ISO timestamp', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
    ]);
    const d = new Date(result.meta.analyzed_at);
    expect(isNaN(d.getTime())).toBe(false);
  });

  it('type_hierarchy has classes and interfaces objects', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);
    expect(typeof result.type_hierarchy.classes).toBe('object');
    expect(typeof result.type_hierarchy.interfaces).toBe('object');
  });

  it('findings is always empty (LLM enrichment out of scope)', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
    ]);
    expect(result.findings).toEqual([]);
  });

  it('taint_paths entries have required fields when present', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    for (const path of result.taint_paths) {
      expect(typeof path.id).toBe('string');
      expect(typeof path.source.file).toBe('string');
      expect(typeof path.source.line).toBe('number');
      expect(typeof path.sink.file).toBe('string');
      expect(typeof path.sink.line).toBe('number');
      expect(typeof path.confidence).toBe('number');
      expect(typeof path.path_exists).toBe('boolean');
      expect(Array.isArray(path.hops)).toBe(true);
    }
  });

  it('cross_file_calls entries have required fields when present', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    for (const call of result.cross_file_calls) {
      expect(typeof call.id).toBe('string');
      expect(typeof call.from.file).toBe('string');
      expect(typeof call.from.line).toBe('number');
      expect(typeof call.to.file).toBe('string');
      expect(typeof call.resolved).toBe('boolean');
      expect(Array.isArray(call.args_mapping)).toBe(true);
      // Cross-file calls must reference different files
      expect(call.from.file).not.toBe(call.to.file);
    }
  });

  it('deriveProjectRoot produces a common prefix', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/project/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/project/src/B.java', language: 'java' },
    ]);
    expect(result.meta.root).toBe('/project/src');
    expect(result.meta.name).toBe('src');
  });
});
