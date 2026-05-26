/**
 * Tests for MissingGuardDomPass — CWE-285 authentication guard detection.
 *
 * Uses minimal IR fixtures (no WASM parsing).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext, SastFinding } from '../../../src/graph/analysis-pass.js';
import type { CircleIR } from '../../../src/types/index.js';
import { MissingGuardDomPass } from '../../../src/analysis/passes/missing-guard-dom-pass.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 30, hash: '' },
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

function makeCtx(ir: CircleIR, language?: string): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code: '',
    language: language ?? ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

// Minimal method type covering given line range
function makeMethod(name: string, start: number, end: number) {
  return {
    name,
    return_type: 'void' as const,
    parameters: [],
    annotations: [] as string[],
    modifiers: ['public'] as string[],
    start_line: start,
    end_line: end,
  };
}

function makeClass(name: string, methods: ReturnType<typeof makeMethod>[]) {
  return {
    name,
    kind: 'class' as const,
    package: null,
    extends: null,
    implements: [] as string[],
    annotations: [] as string[],
    methods,
    fields: [] as never[],
    start_line: 1,
    end_line: 30,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('MissingGuardDomPass', () => {
  it('positive: sensitive op with no dominating auth check → 1 finding', () => {
    // CFG: entry(0,l1) → body(1,l5-l10) [no branches]
    // delete() at line 7, no authenticate() anywhere
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 10 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'delete',
          receiver: 'repo',
          arguments: [],
          location: { line: 7, column: 0 },
          in_method: 'handleDelete',
        },
      ],
      types: [makeClass('MyController', [makeMethod('handleDelete', 5, 10)])],
    });

    const ctx = makeCtx(ir);
    new MissingGuardDomPass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('missing-guard-dom');
    expect(ctx.findings[0].cwe).toBe('CWE-285');
    expect(ctx.findings[0].line).toBe(7);
  });

  it('negative: auth check dominates sensitive op → 0 findings', () => {
    // CFG: entry(0) → auth-block(1,l4-l6) → delete-block(2,l7-l11)
    // authenticate() at line 5 (in block 1) dominates delete() at line 9 (in block 2)
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 4, end_line: 6 },
          { id: 2, type: 'normal', start_line: 7, end_line: 11 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' as const },
          { from: 1, to: 2, type: 'sequential' as const },
        ],
      },
      calls: [
        {
          method_name: 'authenticate',
          receiver: 'authService',
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'handleDelete',
        },
        {
          method_name: 'delete',
          receiver: 'repo',
          arguments: [],
          location: { line: 9, column: 0 },
          in_method: 'handleDelete',
        },
      ],
      types: [makeClass('MyController', [makeMethod('handleDelete', 4, 11)])],
    });

    const ctx = makeCtx(ir);
    new MissingGuardDomPass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('skips non-Java languages', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'app.py', language: 'python', loc: 10, hash: '' },
      calls: [
        {
          method_name: 'delete',
          receiver: 'repo',
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'view',
        },
      ],
    });

    const ctx = makeCtx(ir, 'python');
    new MissingGuardDomPass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('returns 0 findings when CFG has no edges', () => {
    const ir = makeIR({
      cfg: {
        blocks: [{ id: 0, type: 'normal', start_line: 1, end_line: 10 }],
        edges: [],
      },
      calls: [
        {
          method_name: 'delete',
          receiver: null,
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'run',
        },
      ],
    });

    const ctx = makeCtx(ir);
    new MissingGuardDomPass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('deduplicates: only one finding per method even with multiple sensitive ops', () => {
    // Two delete() calls in same method, one auth check outside method scope
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 15 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'delete',
          receiver: 'r',
          arguments: [],
          location: { line: 7, column: 0 },
          in_method: 'handle',
        },
        {
          method_name: 'deleteById',
          receiver: 'r',
          arguments: [],
          location: { line: 11, column: 0 },
          in_method: 'handle',
        },
      ],
      types: [makeClass('Ctrl', [makeMethod('handle', 5, 15)])],
    });

    const ctx = makeCtx(ir);
    new MissingGuardDomPass().run(ctx);

    // At most one finding per method (deduplication by method key)
    expect(ctx.findings.length).toBeLessThanOrEqual(1);
  });
});
