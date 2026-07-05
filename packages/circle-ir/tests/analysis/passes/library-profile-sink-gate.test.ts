/**
 * Tests for library-profile-sink-gate (cognium-dev #232).
 *
 * Verifies:
 *   - Under `library/*` profile, `log_injection` (CWE-117) sinks are
 *     dropped.
 *   - All other sink types (`sql_injection`, `command_injection`,
 *     `xss`, `path_traversal`, …) are preserved unconditionally.
 *   - Non-library profiles (`application/*`, `cli/*`, `server/*`,
 *     `plugin/*`), `'unknown'`, and absent profiles leave the sink
 *     list untouched.
 *   - The diagnostic result correctly records the applied profile,
 *     drop count, and per-type breakdown.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import {
  LibraryProfileSinkGatePass,
  type LibraryProfileSinkGateResult,
} from '../../../src/analysis/passes/library-profile-sink-gate-pass.js';
import type {
  CircleIR,
  ProjectProfile,
  SastFinding,
  SinkType,
  TaintSink,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function makeIR(
  sinks: TaintSink[],
  profile: ProjectProfile | undefined,
): CircleIR {
  const ir: CircleIR = {
    meta: {
      circle_ir: '3.0',
      file: 'src/Foo.java',
      language: 'java',
      loc: sinks.length,
      hash: '',
    },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks, sanitizers: [] },
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
  sinks: TaintSink[],
  profile: ProjectProfile | undefined,
): { result: LibraryProfileSinkGateResult; remaining: TaintSink[] } {
  const ir = makeIR(sinks, profile);
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
  const result = new LibraryProfileSinkGatePass().run(ctx);
  return { result, remaining: graph.ir.taint.sinks };
}

function sink(type: SinkType, line: number): TaintSink {
  return {
    type,
    cwe: 'CWE-000',
    location: `${type}@${line}`,
    line,
    confidence: 1.0,
  };
}

// ---------------------------------------------------------------------------
// Drop behaviour under library/* profile — TP-1 .. TP-5
// ---------------------------------------------------------------------------

describe('LibraryProfileSinkGatePass — library/* drops log_injection', () => {
  it('TP-1: library/production drops log_injection', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 5)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.profile).toBe('library/production');
    expect(result.dropped).toBe(1);
    expect(result.droppedByType.log_injection).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-2: library/dev drops log_injection', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 12)],
      'library/dev',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByType.log_injection).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-3: library/benchmark drops log_injection', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 3)],
      'library/benchmark',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-4: library/test drops log_injection', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 7)],
      'library/test',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-5: library/sample drops multiple log_injection sinks at once', () => {
    const { result, remaining } = runGate(
      [
        sink('log_injection', 1),
        sink('log_injection', 2),
        sink('log_injection', 3),
      ],
      'library/sample',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(3);
    expect(result.droppedByType.log_injection).toBe(3);
    expect(remaining).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Non-drop sink types preserved under library/* — TN-1 .. TN-5
// ---------------------------------------------------------------------------

describe('LibraryProfileSinkGatePass — non-drop sink types are preserved', () => {
  it('TN-1: sql_injection preserved under library/production', () => {
    const { result, remaining } = runGate(
      [sink('sql_injection', 1)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].type).toBe('sql_injection');
  });

  it('TN-2: command_injection preserved under library/production', () => {
    const { result, remaining } = runGate(
      [sink('command_injection', 1)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].type).toBe('command_injection');
  });

  it('TN-3: xss preserved under library/production', () => {
    const { result, remaining } = runGate(
      [sink('xss', 1)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].type).toBe('xss');
  });

  it('TN-4: path_traversal preserved under library/production', () => {
    const { result, remaining } = runGate(
      [sink('path_traversal', 1)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].type).toBe('path_traversal');
  });

  it('TN-5: mixed list — log_injection dropped, everything else kept', () => {
    const sinks = [
      sink('sql_injection', 1),
      sink('log_injection', 2),
      sink('command_injection', 3),
      sink('log_injection', 4),
      sink('xss', 5),
      sink('path_traversal', 6),
      sink('deserialization', 7),
    ];
    const { result, remaining } = runGate(sinks, 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(2);
    expect(result.droppedByType.log_injection).toBe(2);
    expect(remaining).toHaveLength(5);
    expect(remaining.map((s) => s.type).sort()).toEqual([
      'command_injection',
      'deserialization',
      'path_traversal',
      'sql_injection',
      'xss',
    ]);
  });
});

// ---------------------------------------------------------------------------
// Non-library profiles are no-ops — TN-6 .. TN-11
// ---------------------------------------------------------------------------

describe('LibraryProfileSinkGatePass — non-library profiles are no-ops', () => {
  it('TN-6: application/production leaves log_injection intact', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 1)],
      'application/production',
    );
    expect(result.applied).toBe(false);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
  });

  it('TN-7: cli/dev leaves log_injection intact', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 1)],
      'cli/dev',
    );
    expect(result.applied).toBe(false);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
  });

  it('TN-8: server/production leaves log_injection intact', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 1)],
      'server/production',
    );
    expect(result.applied).toBe(false);
    expect(remaining).toHaveLength(1);
  });

  it('TN-9: plugin/production leaves log_injection intact', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 1)],
      'plugin/production',
    );
    expect(result.applied).toBe(false);
    expect(remaining).toHaveLength(1);
  });

  it("TN-10: 'unknown' profile is a no-op", () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 1)],
      'unknown',
    );
    expect(result.applied).toBe(false);
    expect(result.profile).toBe('unknown');
    expect(remaining).toHaveLength(1);
  });

  it('TN-11: absent profile is a no-op', () => {
    const { result, remaining } = runGate(
      [sink('log_injection', 1)],
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

describe('LibraryProfileSinkGatePass — empty inputs', () => {
  it('empty sink list under library shape returns applied=true, dropped=0', () => {
    const { result, remaining } = runGate([], 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(0);
  });

  it('empty sink list under absent profile returns applied=false', () => {
    const { result, remaining } = runGate([], undefined);
    expect(result.applied).toBe(false);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(0);
  });
});
