/**
 * Tests for `meta.projectProfile` + `meta.projectProfileSummary` — the
 * observability rollup shipped in circle-ir 3.150.1 (#235).
 *
 * The infrastructure that resolves and applies `ProjectProfile` values
 * lives in ADR-008 / #169 (3.106.0); this test suite locks in only the
 * new output surface:
 *
 *  - `analyze()` populates `meta.projectProfile` iff caller supplies
 *    `options.projectProfile` (string or Map).
 *  - `analyzeProject()` populates `meta.projectProfileSummary` iff caller
 *    supplies `options.projectProfile`, and the rollup counts match the
 *    per-file resolutions.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';
import type { ProjectProfile } from '../../src/types/index.js';

const SNIPPET_A = 'public class A { public void a() {} }';
const SNIPPET_B = 'public class B { public void b() {} }';
const SNIPPET_C = 'public class C { public void c() {} }';

beforeAll(async () => {
  await initAnalyzer();
});

// ---------------------------------------------------------------------------
// analyze() — per-file meta.projectProfile
// ---------------------------------------------------------------------------

describe('analyze() — meta.projectProfile', () => {
  it('does not populate projectProfile when caller omits the option', async () => {
    const ir = await analyze(SNIPPET_A, '/src/A.java', 'java');
    expect(ir.meta.projectProfile).toBeUndefined();
  });

  it('populates projectProfile from a single-string option', async () => {
    const ir = await analyze(SNIPPET_A, '/src/A.java', 'java', {
      projectProfile: 'library/production',
    });
    expect(ir.meta.projectProfile).toBe('library/production');
  });

  it('populates projectProfile from a per-file Map', async () => {
    const map = new Map<string, ProjectProfile>([
      ['/src/A.java', 'application/production'],
    ]);
    const ir = await analyze(SNIPPET_A, '/src/A.java', 'java', {
      projectProfile: map,
    });
    expect(ir.meta.projectProfile).toBe('application/production');
  });

  it('falls back to unknown when Map misses this file', async () => {
    const map = new Map<string, ProjectProfile>([
      ['/src/Other.java', 'library/production'],
    ]);
    const ir = await analyze(SNIPPET_A, '/src/A.java', 'java', {
      projectProfile: map,
    });
    expect(ir.meta.projectProfile).toBe('unknown');
  });

  it('accepts the literal unknown profile without dropping the field', async () => {
    const ir = await analyze(SNIPPET_A, '/src/A.java', 'java', {
      projectProfile: 'unknown',
    });
    // Field is emitted so consumers can distinguish "caller asked, resolver
    // said unknown" from "caller did not ask".
    expect(ir.meta.projectProfile).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// analyzeProject() — meta.projectProfileSummary
// ---------------------------------------------------------------------------

describe('analyzeProject() — meta.projectProfileSummary', () => {
  it('omits projectProfileSummary when caller omits the option', async () => {
    const result = await analyzeProject([
      { code: SNIPPET_A, filePath: '/src/A.java', language: 'java' },
      { code: SNIPPET_B, filePath: '/src/B.java', language: 'java' },
    ]);
    expect(result.meta.projectProfileSummary).toBeUndefined();
  });

  it('rolls up a single-string profile into a uniform bucket', async () => {
    const result = await analyzeProject(
      [
        { code: SNIPPET_A, filePath: '/src/A.java', language: 'java' },
        { code: SNIPPET_B, filePath: '/src/B.java', language: 'java' },
        { code: SNIPPET_C, filePath: '/src/C.java', language: 'java' },
      ],
      { projectProfile: 'library/production' },
    );
    const summary = result.meta.projectProfileSummary;
    expect(summary).toBeDefined();
    expect(summary?.totalFiles).toBe(3);
    expect(summary?.byShape.library).toBe(3);
    expect(summary?.byShape.application).toBe(0);
    expect(summary?.byShape.unknown).toBe(0);
    expect(summary?.byEnv.production).toBe(3);
    expect(summary?.byEnv.dev).toBe(0);
    expect(summary?.byEnv.unknown).toBe(0);
  });

  it('rolls up a per-file Map with mixed shapes and envs', async () => {
    const map = new Map<string, ProjectProfile>([
      ['/src/A.java', 'library/production'],
      ['/src/B.java', 'application/dev'],
      ['/src/C.java', 'server/benchmark'],
    ]);
    const result = await analyzeProject(
      [
        { code: SNIPPET_A, filePath: '/src/A.java', language: 'java' },
        { code: SNIPPET_B, filePath: '/src/B.java', language: 'java' },
        { code: SNIPPET_C, filePath: '/src/C.java', language: 'java' },
      ],
      { projectProfile: map },
    );
    const summary = result.meta.projectProfileSummary!;
    expect(summary.totalFiles).toBe(3);
    expect(summary.byShape.library).toBe(1);
    expect(summary.byShape.application).toBe(1);
    expect(summary.byShape.server).toBe(1);
    expect(summary.byShape.cli).toBe(0);
    expect(summary.byShape.plugin).toBe(0);
    expect(summary.byShape.unknown).toBe(0);
    expect(summary.byEnv.production).toBe(1);
    expect(summary.byEnv.dev).toBe(1);
    expect(summary.byEnv.benchmark).toBe(1);
    expect(summary.byEnv.sample).toBe(0);
    expect(summary.byEnv.test).toBe(0);
    expect(summary.byEnv.unknown).toBe(0);
  });

  it('buckets files missing from the Map under unknown', async () => {
    const map = new Map<string, ProjectProfile>([
      ['/src/A.java', 'library/production'],
      // B and C intentionally omitted
    ]);
    const result = await analyzeProject(
      [
        { code: SNIPPET_A, filePath: '/src/A.java', language: 'java' },
        { code: SNIPPET_B, filePath: '/src/B.java', language: 'java' },
        { code: SNIPPET_C, filePath: '/src/C.java', language: 'java' },
      ],
      { projectProfile: map },
    );
    const summary = result.meta.projectProfileSummary!;
    expect(summary.totalFiles).toBe(3);
    expect(summary.byShape.library).toBe(1);
    expect(summary.byShape.unknown).toBe(2);
    expect(summary.byEnv.production).toBe(1);
    expect(summary.byEnv.unknown).toBe(2);
  });

  it('handles empty projects gracefully', async () => {
    const result = await analyzeProject([], {
      projectProfile: 'library/production',
    });
    const summary = result.meta.projectProfileSummary!;
    expect(summary.totalFiles).toBe(0);
    for (const shape of ['library', 'application', 'cli', 'server', 'plugin', 'unknown'] as const) {
      expect(summary.byShape[shape]).toBe(0);
    }
    for (const env of ['production', 'dev', 'sample', 'benchmark', 'test', 'unknown'] as const) {
      expect(summary.byEnv[env]).toBe(0);
    }
  });

  it('summary totals match per-file meta.projectProfile emissions', async () => {
    const map = new Map<string, ProjectProfile>([
      ['/src/A.java', 'library/production'],
      ['/src/B.java', 'library/production'],
      ['/src/C.java', 'application/production'],
    ]);
    const result = await analyzeProject(
      [
        { code: SNIPPET_A, filePath: '/src/A.java', language: 'java' },
        { code: SNIPPET_B, filePath: '/src/B.java', language: 'java' },
        { code: SNIPPET_C, filePath: '/src/C.java', language: 'java' },
      ],
      { projectProfile: map },
    );
    // Each per-file meta must also carry the resolved profile.
    const emitted = result.files.map(f => f.analysis.meta.projectProfile);
    expect(emitted).toEqual([
      'library/production',
      'library/production',
      'application/production',
    ]);
    const summary = result.meta.projectProfileSummary!;
    expect(summary.byShape.library).toBe(2);
    expect(summary.byShape.application).toBe(1);
    expect(summary.byEnv.production).toBe(3);
  });
});
