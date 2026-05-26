/**
 * Tests for Pass #84: excessive-allocation (CWE-770, category: performance)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { ExcessiveAllocationPass } from '../../../src/analysis/passes/excessive-allocation-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

// CFG for a simple loop: entry → loop header → body → (back-edge to header)
const LOOP_CFG = {
  blocks: [
    { id: 0, type: 'entry' as const, start_line: 1, end_line: 1 },
    { id: 1, type: 'loop' as const, start_line: 2, end_line: 2 },
    { id: 2, type: 'normal' as const, start_line: 3, end_line: 7 },
  ],
  edges: [
    { from: 0, to: 1, type: 'sequential' as const },
    { from: 1, to: 2, type: 'true' as const },
    { from: 2, to: 1, type: 'back' as const },
  ],
};

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 20, hash: '' },
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

function makeCtx(ir: CircleIR, code: string): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code,
    language: ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

describe('ExcessiveAllocationPass', () => {
  it('flags new Map() inside a loop (TypeScript)', () => {
    const ir = makeIR({ cfg: LOOP_CFG });
    const code = `
const results = [];
for (let i = 0; i < n; i++) {
  const map = new Map();
  process(map);
}`;
    const ctx = makeCtx(ir, code);
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops.length).toBeGreaterThanOrEqual(1);
    expect(result.allocationsInLoops[0].pattern).toMatch(/new Map/);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].cwe).toBe('CWE-770');
    expect(ctx.findings[0].level).toBe('warning');
    expect(ctx.findings[0].message).toMatch(/new Map/);
  });

  it('flags new ArrayList<>() inside a loop (Java)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Processor.java', language: 'java', loc: 15, hash: '' },
      cfg: LOOP_CFG,
    });
    const code = `
void process() {
for (int i = 0; i < n; i++) {
  List<String> items = new ArrayList<>();
  items.add(getItem(i));
}
}`;
    const ctx = makeCtx(ir, code);
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops.some(a => a.pattern.includes('ArrayList'))).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'excessive-allocation')).toBe(true);
  });

  it('flags list() inside a loop (Python)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'proc.py', language: 'python', loc: 10, hash: '' },
      cfg: LOOP_CFG,
    });
    const code = `
items = []
for i in range(n):
  temp = list()
  temp.append(get(i))
`;
    const ctx = makeCtx(ir, code);
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops.some(a => a.pattern.includes('list'))).toBe(true);
  });

  it('flags Vec::new() inside a loop (Rust)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'main.rs', language: 'rust', loc: 10, hash: '' },
      cfg: LOOP_CFG,
    });
    const code = `
fn run() {
for i in 0..n {
  let v = Vec::new();
  process(&v);
}
}`;
    const ctx = makeCtx(ir, code);
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops.some(a => a.pattern.includes('Vec::new'))).toBe(true);
  });

  it('does NOT flag new Map() declared BEFORE the loop', () => {
    const ir = makeIR({ cfg: LOOP_CFG });
    // Map is created on line 1, loop starts on line 2 — line 1 is outside loop body
    const code = `const cache = new Map();
for (let i = 0; i < n; i++) {
  cache.set(i, compute(i));
}`;
    const ctx = makeCtx(ir, code);
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT flag when no loops exist in CFG', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 2, end_line: 6 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' }],
      },
    });
    const code = `
const a = 1;
const m = new Map();
m.set('x', 1);
`;
    const ctx = makeCtx(ir, code);
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips bash', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'script.sh', language: 'bash', loc: 5, hash: '' },
      cfg: LOOP_CFG,
    });
    const ctx = makeCtx(ir, 'while true; do\n  arr=()\ndone');
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops).toHaveLength(0);
  });

  it('skips lines that mention "pool" or "cache" (benign patterns)', () => {
    const ir = makeIR({ cfg: LOOP_CFG });
    const code = `
const x = 1;
for (let i = 0; i < n; i++) {
  const buf = pool.new Map(); // from pool
}`;
    const ctx = makeCtx(ir, code);
    // "pool" in the line should suppress the finding
    const result = new ExcessiveAllocationPass().run(ctx);
    expect(result.allocationsInLoops).toHaveLength(0);
  });

  it('includes correct metadata in findings', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'src/hot-path.ts', language: 'typescript', loc: 10, hash: '' },
      cfg: LOOP_CFG,
    });
    const code = `
const x = [];
for (const item of items) {
  const s = new Set();
  s.add(item);
}`;
    const ctx = makeCtx(ir, code);
    new ExcessiveAllocationPass().run(ctx);
    expect(ctx.findings[0].file).toBe('src/hot-path.ts');
    expect(ctx.findings[0].pass).toBe('excessive-allocation');
    expect(ctx.findings[0].category).toBe('performance');
    expect(ctx.findings[0].id).toMatch(/^excessive-allocation-/);
  });
});
