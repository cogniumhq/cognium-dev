/**
 * Tests for library-profile-xss-gate (cognium-dev #244).
 *
 * Verifies:
 *   - Under `library/*` profile, `xss` (CWE-79) sinks whose simple-name
 *     receiver class is on `XSS_NON_HTML_OUTPUT_CLASSES` are dropped.
 *   - Genuine HTML-output receiver classes (`HttpServletResponse`,
 *     `JspWriter`, `PrintWriter`, template renderers) and unclassified
 *     receivers are preserved.
 *   - Non-`xss` sink types (`sql_injection`, `command_injection`, …)
 *     are preserved unconditionally regardless of receiver class.
 *   - Non-library profiles (`application/*`, `cli/*`, …), `'unknown'`,
 *     and absent profiles leave the sink list untouched.
 *   - The diagnostic result correctly records the applied profile,
 *     drop count, and per-class breakdown.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import {
  LibraryProfileXssGatePass,
  type LibraryProfileXssGateResult,
} from '../../../src/analysis/passes/library-profile-xss-gate-pass.js';
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
): { result: LibraryProfileXssGateResult; remaining: TaintSink[] } {
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
  const result = new LibraryProfileXssGatePass().run(ctx);
  return { result, remaining: graph.ir.taint.sinks };
}

function xssSink(cls: string | undefined, line: number, method = 'append'): TaintSink {
  return {
    type: 'xss',
    cwe: 'CWE-79',
    location: `${cls ?? 'unknown'}.${method}@${line}`,
    line,
    confidence: 1.0,
    method,
    class: cls,
  };
}

function nonXssSink(type: SinkType, cls: string, line: number): TaintSink {
  return {
    type,
    cwe: 'CWE-000',
    location: `${cls}@${line}`,
    line,
    confidence: 1.0,
    class: cls,
  };
}

// ---------------------------------------------------------------------------
// Drop behaviour — TP-1 .. TP-7 (7 denylist-class drops under library/*)
// ---------------------------------------------------------------------------

describe('LibraryProfileXssGatePass — library/* drops non-HTML-output xss sinks', () => {
  it('TP-1: library/production drops StringBuilder.append', () => {
    const { result, remaining } = runGate(
      [xssSink('StringBuilder', 5)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.profile).toBe('library/production');
    expect(result.dropped).toBe(1);
    expect(result.droppedByClass['StringBuilder']).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-2: library/production drops System.out.println (PrintStream / System)', () => {
    const { result, remaining } = runGate(
      [xssSink('PrintStream', 3, 'println'), xssSink('System', 4, 'out')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(2);
    expect(result.droppedByClass['PrintStream']).toBe(1);
    expect(result.droppedByClass['System']).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-3: library/production drops HttpSession.setAttribute', () => {
    const { result, remaining } = runGate(
      [xssSink('HttpSession', 12, 'setAttribute')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByClass['HttpSession']).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-4: library/production drops hutool HttpRequest.post', () => {
    const { result, remaining } = runGate(
      [xssSink('HttpRequest', 7, 'post')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByClass['HttpRequest']).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-5: library/production drops Logger.info', () => {
    const { result, remaining } = runGate(
      [xssSink('Logger', 9, 'info')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByClass['Logger']).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-6: library/production drops JSONUtil.parseObj', () => {
    const { result, remaining } = runGate(
      [xssSink('JSONUtil', 4, 'parseObj')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByClass['JSONUtil']).toBe(1);
    expect(remaining).toHaveLength(0);
  });

  it('TP-7: library/production drops RedisOutputStream.write (jedis wire-writer)', () => {
    const { result, remaining } = runGate(
      [xssSink('RedisOutputStream', 22, 'write')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(1);
    expect(result.droppedByClass['RedisOutputStream']).toBe(1);
    expect(remaining).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Preserve behaviour — TN-1 .. TN-4 (genuine XSS sinks + non-xss types)
// ---------------------------------------------------------------------------

describe('LibraryProfileXssGatePass — genuine XSS sinks preserved', () => {
  it('TN-1: HttpServletResponse.getWriter preserved under library/production', () => {
    const { result, remaining } = runGate(
      [xssSink('HttpServletResponse', 5, 'getWriter')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].class).toBe('HttpServletResponse');
  });

  it('TN-2: unclassified PrintWriter (no receiver class) preserved', () => {
    const { result, remaining } = runGate(
      [xssSink(undefined, 8, 'println')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
  });

  it('TN-3: JspWriter preserved (not on denylist)', () => {
    const { result, remaining } = runGate(
      [xssSink('JspWriter', 15, 'print')],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].class).toBe('JspWriter');
  });

  it('TN-4: non-xss sinks (sql_injection on StringBuilder) preserved unconditionally', () => {
    const { result, remaining } = runGate(
      [nonXssSink('sql_injection', 'StringBuilder', 3)],
      'library/production',
    );
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].type).toBe('sql_injection');
  });
});

// ---------------------------------------------------------------------------
// Non-library profiles are no-ops — TN-5 .. TN-7
// ---------------------------------------------------------------------------

describe('LibraryProfileXssGatePass — non-library profiles are no-ops', () => {
  it('TN-5: application/spring leaves StringBuilder.append xss intact', () => {
    const { result, remaining } = runGate(
      [xssSink('StringBuilder', 5)],
      'application/spring',
    );
    expect(result.applied).toBe(false);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(1);
  });

  it("TN-6: 'unknown' profile is a no-op", () => {
    const { result, remaining } = runGate(
      [xssSink('StringBuilder', 5)],
      'unknown',
    );
    expect(result.applied).toBe(false);
    expect(result.profile).toBe('unknown');
    expect(remaining).toHaveLength(1);
  });

  it('TN-7: absent profile is a no-op', () => {
    const { result, remaining } = runGate(
      [xssSink('StringBuilder', 5)],
      undefined,
    );
    expect(result.applied).toBe(false);
    expect(result.profile).toBeUndefined();
    expect(remaining).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Mixed lists + diagnostic breakdown
// ---------------------------------------------------------------------------

describe('LibraryProfileXssGatePass — mixed lists and diagnostics', () => {
  it('mixed sink list — denylisted xss dropped, others preserved', () => {
    const sinks = [
      xssSink('StringBuilder', 1),
      xssSink('HttpServletResponse', 2, 'getWriter'),
      xssSink('PrintStream', 3, 'println'),
      xssSink('Logger', 4, 'info'),
      nonXssSink('sql_injection', 'Connection', 5),
      xssSink(undefined, 6, 'println'),
      xssSink('JspWriter', 7, 'print'),
    ];
    const { result, remaining } = runGate(sinks, 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(3);
    expect(result.droppedByClass['StringBuilder']).toBe(1);
    expect(result.droppedByClass['PrintStream']).toBe(1);
    expect(result.droppedByClass['Logger']).toBe(1);
    expect(remaining).toHaveLength(4);
  });

  it('empty sink list under library shape returns applied=true, dropped=0', () => {
    const { result, remaining } = runGate([], 'library/production');
    expect(result.applied).toBe(true);
    expect(result.dropped).toBe(0);
    expect(remaining).toHaveLength(0);
    expect(result.droppedByClass).toEqual({});
  });
});
