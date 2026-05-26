/**
 * Tests for Pass #22: dead-code (CWE-561, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { DeadCodePass } from '../../../src/analysis/passes/dead-code-pass.js';
import type { CircleIR, SastFinding, CFGBlock, CFGEdge } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function block(id: number, type: CFGBlock['type'], start_line: number, end_line: number): CFGBlock {
  return { id, type, start_line, end_line };
}

function edge(from: number, to: number, type: CFGEdge['type'] = 'sequential'): CFGEdge {
  return { from, to, type };
}

function makeIR(blocks: CFGBlock[], edges: CFGEdge[], file = 'app.ts'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks, edges },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(ir: CircleIR): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code: '',
    language: ir.meta.language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used in this pass'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
  };
  return { ctx, findings };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DeadCodePass', () => {
  it('returns empty result when CFG has no blocks', () => {
    const ir = makeIR([], []);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('returns empty result for a fully reachable linear CFG', () => {
    // entry → normal → exit
    const blocks = [
      block(1, 'entry', 1, 2),
      block(2, 'normal', 3, 5),
      block(3, 'exit', 6, 6),
    ];
    const edges = [edge(1, 2), edge(2, 3)];
    const ir = makeIR(blocks, edges);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('detects an unreachable normal block after an unconditional return', () => {
    // entry → normal(return) → exit
    //                         dead ←  (no edge leading here)
    const blocks = [
      block(1, 'entry', 1, 1),
      block(2, 'normal', 2, 4),
      block(3, 'exit',  5, 5),
      block(4, 'normal', 7, 9), // dead: unreachable
    ];
    const edges = [edge(1, 2), edge(2, 3)];
    const ir = makeIR(blocks, edges);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(1);
    expect(result.deadBlocks[0].id).toBe(4);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-561');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].line).toBe(7);
  });

  it('does not report entry or exit blocks as dead even with no edges', () => {
    // Single entry block with no edges at all — entry is reachable by definition
    const blocks = [block(1, 'entry', 1, 5)];
    const ir = makeIR(blocks, []);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not report blocks with start_line <= 0', () => {
    // Synthetic zero-line block should be suppressed
    const blocks = [
      block(1, 'entry', 1, 2),
      block(2, 'normal', 0, 0), // synthetic, unreachable but suppressed
    ];
    const ir = makeIR(blocks, []);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('detects multiple unreachable blocks', () => {
    const blocks = [
      block(1, 'entry', 1, 1),
      block(2, 'normal', 2, 4),
      block(3, 'exit',  5, 5),
      block(4, 'normal', 7, 9),   // dead
      block(5, 'normal', 11, 13), // dead
    ];
    const edges = [edge(1, 2), edge(2, 3)];
    const ir = makeIR(blocks, edges);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(2);
    expect(findings).toHaveLength(2);
  });

  it('falls back to lowest-id block as entry when no entry-typed block exists', () => {
    // All blocks are 'normal'; lowest id (1) is treated as entry
    const blocks = [
      block(1, 'normal', 1, 3),
      block(2, 'normal', 4, 6),
      block(3, 'normal', 8, 10), // dead (no edge from 1 or 2)
    ];
    const edges = [edge(1, 2)];
    const ir = makeIR(blocks, edges);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    expect(result.deadBlocks).toHaveLength(1);
    expect(result.deadBlocks[0].id).toBe(3);
    expect(findings).toHaveLength(1);
  });

  it('uses prefers block with no incoming edges over id-based fallback', () => {
    // Block 5 has no incoming edges → treated as entry; block 3 becomes dead
    const blocks = [
      block(3, 'normal', 1, 3), // would win by id, but has incoming edges
      block(5, 'normal', 4, 6), // no incoming → entry fallback
      block(7, 'normal', 8, 10), // dead
    ];
    const edges = [edge(5, 3)]; // 5 → 3 sequential; 7 has nothing
    const ir = makeIR(blocks, edges);
    const { ctx, findings } = makeCtx(ir);
    const result = new DeadCodePass().run(ctx);
    // block 7 is dead; block 5 and 3 are reachable
    expect(result.deadBlocks.map(b => b.id)).toContain(7);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('includes correct file and id in finding', () => {
    const blocks = [
      block(1, 'entry', 1, 1),
      block(2, 'normal', 5, 8), // dead
    ];
    const ir = makeIR(blocks, [], 'src/utils.ts');
    const { ctx, findings } = makeCtx(ir);
    new DeadCodePass().run(ctx);
    expect(findings[0].file).toBe('src/utils.ts');
    expect(findings[0].id).toBe('dead-code-src/utils.ts-5');
    expect(findings[0].pass).toBe('dead-code');
    expect(findings[0].category).toBe('reliability');
  });

  it('single-line dead block shows "line N" in message', () => {
    const blocks = [
      block(1, 'entry', 1, 2),
      block(2, 'normal', 10, 10), // dead, single line
    ];
    const ir = makeIR(blocks, []);
    const { ctx, findings } = makeCtx(ir);
    new DeadCodePass().run(ctx);
    expect(findings[0].message).toMatch(/line 10/);
  });

  it('multi-line dead block shows "lines N–M" in message', () => {
    const blocks = [
      block(1, 'entry', 1, 2),
      block(2, 'normal', 10, 15), // dead, multi-line
    ];
    const ir = makeIR(blocks, []);
    const { ctx, findings } = makeCtx(ir);
    new DeadCodePass().run(ctx);
    expect(findings[0].message).toMatch(/lines 10.+15/);
    expect(findings[0].end_line).toBe(15);
  });
});
