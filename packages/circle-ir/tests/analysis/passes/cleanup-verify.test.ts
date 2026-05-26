/**
 * Tests for CleanupVerifyPass — CWE-772 post-dominator-based cleanup detection.
 *
 * Uses minimal IR fixtures (no WASM parsing).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext, SastFinding } from '../../../src/graph/analysis-pass.js';
import type { CircleIR } from '../../../src/types/index.js';
import { CleanupVerifyPass } from '../../../src/analysis/passes/cleanup-verify-pass.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 20, hash: '' },
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

function makeMethod(name: string, start: number, end: number) {
  return {
    name,
    return_type: 'void' as const,
    parameters: [] as never[],
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
    end_line: 20,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CleanupVerifyPass', () => {
  it('positive: close() does not post-dominate the open — branching path skips cleanup', () => {
    // CFG (original):
    //   entry(0,l1) → open(1,l5) ─→ branch-a(2,l8)  → exit(4,l15)
    //                           └─→ close-branch(3,l12) → exit(4,l15)
    //
    // Post-dom from exit(4):
    //   idom[3]=4, idom[2]=4, idom[1]=4, idom[0]=1
    // → block 3 does NOT post-dominate block 1 (path 1→2→4 bypasses block 3)
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry',  start_line:  1, end_line:  1 },
          { id: 1, type: 'normal', start_line:  5, end_line:  5 }, // resource open
          { id: 2, type: 'normal', start_line:  8, end_line:  8 }, // early return
          { id: 3, type: 'normal', start_line: 12, end_line: 12 }, // close
          { id: 4, type: 'exit',   start_line: 15, end_line: 15 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' as const },
          { from: 1, to: 2, type: 'true'       as const },
          { from: 1, to: 3, type: 'false'      as const },
          { from: 2, to: 4, type: 'sequential' as const },
          { from: 3, to: 4, type: 'sequential' as const },
        ],
      },
      dfg: {
        defs: [{ id: 1, variable: 'stream', line: 5, kind: 'local' as const }],
        uses: [],
        chains: [],
      },
      calls: [
        {
          method_name: 'FileInputStream',
          receiver: null,
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'readData',
          is_constructor: true,
        },
        {
          method_name: 'close',
          receiver: 'stream',
          arguments: [],
          location: { line: 12, column: 0 },
          in_method: 'readData',
        },
      ],
      types: [makeClass('MyClass', [makeMethod('readData', 3, 14)])],
    });

    const ctx = makeCtx(ir);
    new CleanupVerifyPass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('cleanup-verify');
    expect(ctx.findings[0].cwe).toBe('CWE-772');
    expect(ctx.findings[0].line).toBe(5);
  });

  it('negative: close() post-dominates the open — all paths cleaned up', () => {
    // Linear CFG: entry(0) → open(1,l5) → close(2,l10) → exit(3,l15)
    // Post-dom: idom[2]=3, idom[1]=2 → block 2 post-dominates block 1
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry',  start_line:  1, end_line:  1 },
          { id: 1, type: 'normal', start_line:  5, end_line:  5 }, // open
          { id: 2, type: 'normal', start_line: 10, end_line: 10 }, // close
          { id: 3, type: 'exit',   start_line: 15, end_line: 15 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' as const },
          { from: 1, to: 2, type: 'sequential' as const },
          { from: 2, to: 3, type: 'sequential' as const },
        ],
      },
      dfg: {
        defs: [{ id: 1, variable: 'stream', line: 5, kind: 'local' as const }],
        uses: [],
        chains: [],
      },
      calls: [
        {
          method_name: 'FileInputStream',
          receiver: null,
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'readData',
          is_constructor: true,
        },
        {
          method_name: 'close',
          receiver: 'stream',
          arguments: [],
          location: { line: 10, column: 0 },
          in_method: 'readData',
        },
      ],
      types: [makeClass('MyClass', [makeMethod('readData', 3, 14)])],
    });

    const ctx = makeCtx(ir);
    new CleanupVerifyPass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('skips Rust (RAII guarantees cleanup)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'main.rs', language: 'rust', loc: 10, hash: '' },
    });
    const ctx = makeCtx(ir, 'rust');
    new CleanupVerifyPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips Bash (no structured resource model)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'script.sh', language: 'bash', loc: 10, hash: '' },
    });
    const ctx = makeCtx(ir, 'bash');
    new CleanupVerifyPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('no finding when resource has no close() call (ResourceLeakPass handles it)', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry',  start_line: 1, end_line:  1 },
          { id: 1, type: 'normal', start_line: 5, end_line:  5 },
          { id: 2, type: 'exit',   start_line: 10, end_line: 10 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' as const },
          { from: 1, to: 2, type: 'sequential' as const },
        ],
      },
      dfg: {
        defs: [{ id: 1, variable: 'stream', line: 5, kind: 'local' as const }],
        uses: [],
        chains: [],
      },
      calls: [
        {
          method_name: 'FileInputStream',
          receiver: null,
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'run',
          is_constructor: true,
        },
        // No close() call
      ],
      types: [makeClass('MyClass', [makeMethod('run', 3, 9)])],
    });

    const ctx = makeCtx(ir);
    new CleanupVerifyPass().run(ctx);
    // CleanupVerifyPass defers to ResourceLeakPass for missing close
    expect(ctx.findings).toHaveLength(0);
  });
});
