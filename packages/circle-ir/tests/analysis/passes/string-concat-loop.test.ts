/**
 * Tests for Pass #50: string-concat-loop (CWE-1046, category: performance)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { StringConcatLoopPass } from '../../../src/analysis/passes/string-concat-loop-pass.js';
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

/** CFG with a back-edge spanning lines 2–6. */
function loopCfg(): { blocks: CFGBlock[]; edges: CFGEdge[] } {
  return {
    blocks: [
      block(1, 'entry', 1, 1),
      block(2, 'loop',  2, 6),
      block(3, 'exit',  7, 7),
    ],
    edges: [
      edge(1, 2),
      edge(2, 3),
      edge(2, 2, 'back'),
    ],
  };
}

function makeIR(
  code: string,
  cfg: { blocks: CFGBlock[]; edges: CFGEdge[] },
  file = 'App.ts',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg,
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(ir: CircleIR, code: string): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code,
    language: ir.meta.language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
  };
  return { ctx, findings };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('StringConcatLoopPass', () => {
  it('returns empty result when there are no loops', () => {
    const code = 'result += item.name;\n';
    const cfg = {
      blocks: [block(1, 'entry', 1, 5)],
      edges: [],
    };
    const ir = makeIR(code, cfg);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new StringConcatLoopPass().run(ctx);
    expect(result.concatInLoops).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags string += inside a loop body', () => {
    const code = [
      'let html = "";',         // line 1 — before loop
      'for (const item of items) {', // line 2 — loop start
      '  html += item.name;',   // line 3 — should be flagged
      '  html += " ";',         // line 4 — should be flagged
      '}',                       // line 5
      '',                        // line 6 (still in block 2, end_line=6)
    ].join('\n');
    const ir = makeIR(code, loopCfg());
    const { ctx, findings } = makeCtx(ir, code);
    const result = new StringConcatLoopPass().run(ctx);
    expect(result.concatInLoops.length).toBeGreaterThanOrEqual(1);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].cwe).toBe('CWE-1046');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/html/);
    expect(findings[0].message).toMatch(/O\(n²\)/);
    expect(findings[0].fix).toMatch(/join/i);
  });

  it('does NOT flag numeric += (count += 1)', () => {
    const code = [
      '',                        // line 1
      'for (let i = 0; i < n; i++) {', // line 2
      '  count += 1;',           // line 3 — numeric var name
      '  sum += values[i];',     // line 4 — numeric var name
      '  i += 2;',               // line 5 — loop increment
      '',                        // line 6
    ].join('\n');
    const ir = makeIR(code, loopCfg());
    const { ctx, findings } = makeCtx(ir, code);
    new StringConcatLoopPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag a numeric RHS literal (total += 5)', () => {
    const code = [
      '',
      'for (const x of xs) {',
      '  total += 5;',           // line 3 — numeric RHS
      '  scoreCount += 1;',      // line 4 — numeric suffix
      '',
      '',
    ].join('\n');
    const ir = makeIR(code, loopCfg());
    const { ctx, findings } = makeCtx(ir, code);
    new StringConcatLoopPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags `result += item.name` inside a loop', () => {
    const code = [
      '',
      'for (const item of list) {',
      '  output += item.label;', // "output" is not in the numeric-names list
      '',
      '',
      '',
    ].join('\n');
    const ir = makeIR(code, loopCfg());
    const { ctx, findings } = makeCtx(ir, code);
    const r = new StringConcatLoopPass().run(ctx);
    expect(r.concatInLoops.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].evidence).toMatchObject({ loop_start: expect.any(Number) });
  });

  it('includes file metadata in finding', () => {
    const code = [
      '',
      'for (const x of xs) {',
      '  html += x;',
      '',
      '',
      '',
    ].join('\n');
    const ir = makeIR(code, loopCfg(), 'src/render.ts');
    const { ctx, findings } = makeCtx(ir, code);
    new StringConcatLoopPass().run(ctx);
    expect(findings[0].file).toBe('src/render.ts');
    expect(findings[0].pass).toBe('string-concat-loop');
    expect(findings[0].category).toBe('performance');
    expect(findings[0].id).toMatch(/^string-concat-loop-/);
  });

  it('emits at most one finding per line even with multiple loop ranges', () => {
    const code = [
      '',
      'for (const a of as) {',
      '  buf += a;',             // line 3 — inside loop
      '',
      '',
      '',
    ].join('\n');
    const ir = makeIR(code, loopCfg());
    const { ctx, findings } = makeCtx(ir, code);
    new StringConcatLoopPass().run(ctx);
    // Verify no duplicate findings for the same line
    const lines = findings.map(f => f.line);
    expect(lines).toHaveLength(new Set(lines).size);
  });
});
