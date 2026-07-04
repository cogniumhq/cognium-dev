/**
 * Tests for library-profile-source-gate (cognium-dev #236).
 *
 * Verifies:
 *   - Under `library/*` profile, speculative `interprocedural_param`
 *     and `constructor_field` sources are dropped.
 *   - Concrete sources (`http_param`, `env_input`, `db_input`, …)
 *     are preserved unconditionally.
 *   - Non-library profiles (`application/*`, `cli/*`, `server/*`,
 *     `plugin/*`), `'unknown'`, and absent profiles leave the source
 *     list untouched.
 *   - The diagnostic result correctly records the applied profile,
 *     drop count, and per-type breakdown.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import {
  LibraryProfileSourceGatePass,
  type LibraryProfileSourceGateResult,
} from '../../../src/analysis/passes/library-profile-source-gate-pass.js';
import type {
  CircleIR,
  ProjectProfile,
  SastFinding,
  SourceType,
  TaintSource,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function makeIR(
  sources: TaintSource[],
  profile: ProjectProfile | undefined,
): CircleIR {
  const ir: CircleIR = {
    meta: {
      circle_ir: '3.0',
      file: 'src/Foo.java',
      language: 'java',
      loc: sources.length,
      hash: '',
    },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources, sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
  if (profile !== undefined) {
    ir.meta.projectProfile = profile;
  }
  return ir;
}

function runGate(
  sources: TaintSource[],
  profile: ProjectProfile | undefined,
): { result: LibraryProfileSourceGateResult; remaining: TaintSource[] } {
  const ir = makeIR(sources, profile);
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code: '',
    language: 'java',
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => {
      throw new Error('not used');
    },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
    getFindings: () => findings,
  };
  const result = new LibraryProfileSourceGatePass().run(ctx);
  return { result, remaining: graph.ir.taint.sources };
}

function src(type: SourceType, line: number): TaintSource {
  return {
    type,
    location: `${type}@${line}`,
    severity: 'high',
    line,
    confidence: 1.0,
  };
}

// ---------------------------------------------------------------------------
// Drop behaviour under library/* profile
// ---------------------------------------------------------------------------

describe('LibraryProfileSourceGatePass — library/* drops speculative sources', () => {
  it('TP-1: library/production drops interprocedural_param', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 5)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.profile).toBe('library/production');
    expect(result.dropped).toBe(1);
    expect(result.droppedByType.interprocedural_param).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-2: library/dev drops constructor_field', () => {
    const { result, remaining } = runGate(
      [src('constructor_field', 12)],
      'library/dev',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByType.constructor_field).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-3: library/production drops both speculative types together', () => {
    const { result, remaining } = runGate(
      [
        src('interprocedural_param', 1),
        src('interprocedural_param', 2),
        src('constructor_field', 3),
      ],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(3);
    expect(result.droppedByType.interprocedural_param).toBe(2);
    expect(result.droppedByType.constructor_field).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-4: library/benchmark still triggers gate', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 7)],
      'library/benchmark',
    );
    expect(result.applied).toBe(true);
    expect(remaining).toHaveLength(0);
  });

  it('TP-5: library/test still triggers gate', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 7)],
      'library/test',
    );
    expect(result.applied).toBe(true);
    expect(remaining).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Concrete-source preservation
// ---------------------------------------------------------------------------

describe('LibraryProfileSourceGatePass — concrete sources are preserved', () => {
  it('TN-1: http_param preserved even under library/production', () => {
    const { result, remaining } = runGate(
      [src('http_param', 1)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].type).toBe('http_param');
  });

  it('TN-2: env_input, db_input, file_input all preserved under library shape', () => {
    const sources = [
      src('env_input', 1),
      src('db_input', 2),
      src('file_input', 3),
    ];
    const { result, remaining } = runGate(sources, 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(3);
  });

  it('TN-3: mixed list — speculative dropped, concrete kept', () => {
    const sources = [
      src('http_param', 1),
      src('interprocedural_param', 2),
      src('db_input', 3),
      src('constructor_field', 4),
    ];
    const { result, remaining } = runGate(sources, 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(2);
    expect(remaining).toHaveLength(2);
    expect(remaining.map((s) => s.type).sort()).toEqual(['db_input', 'http_param']);
  });
});

// ---------------------------------------------------------------------------
// Non-library profiles are no-ops
// ---------------------------------------------------------------------------

describe('LibraryProfileSourceGatePass — non-library profiles are no-ops', () => {
  it('TN-4: application/production leaves interprocedural_param intact', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 1)],
      'application/production',
    );
    expect(result.applied).toBe(false);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
  });

  it('TN-5: cli/dev leaves interprocedural_param intact', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 1)],
      'cli/dev',
    );
    expect(result.applied).toBe(false);
    expect(remaining).toHaveLength(1);
  });

  it('TN-6: server/production leaves speculative sources intact', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 1), src('constructor_field', 2)],
      'server/production',
    );
    expect(result.applied).toBe(false);
    expect(remaining).toHaveLength(2);
  });

  it('TN-7: plugin/production leaves speculative sources intact', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 1)],
      'plugin/production',
    );
    expect(result.applied).toBe(false);
    expect(remaining).toHaveLength(1);
  });

  it("TN-8: 'unknown' profile is a no-op", () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 1)],
      'unknown',
    );
    expect(result.applied).toBe(false);
    expect(result.profile).toBe('unknown');
    expect(remaining).toHaveLength(1);
  });

  it('TN-9: absent profile is a no-op', () => {
    const { result, remaining } = runGate(
      [src('interprocedural_param', 1)],
      undefined,
    );
    expect(result.applied).toBe(false);
    expect(result.profile).toBeUndefined();
    expect(remaining).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Empty / degenerate inputs
// ---------------------------------------------------------------------------

describe('LibraryProfileSourceGatePass — empty inputs', () => {
  it('empty source list under library shape returns applied=true, dropped=0', () => {
    const { result, remaining } = runGate([], 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(0);
  });

  it('empty source list under absent profile returns applied=false', () => {
    const { result, remaining } = runGate([], undefined);
    expect(result.applied).toBe(false);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(0);
  });
});
