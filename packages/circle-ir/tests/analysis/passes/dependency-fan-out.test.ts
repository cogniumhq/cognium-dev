/**
 * Tests for Pass #72: dependency-fan-out (architecture smell)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { DependencyFanOutPass } from '../../../src/analysis/passes/dependency-fan-out-pass.js';
import type { CircleIR, SastFinding, ImportInfo } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeImport(from: string, idx: number): ImportInfo {
  return { imported_name: `Dep${idx}`, from_package: from, alias: null, is_wildcard: false, line_number: idx };
}

function makeIR(file: string, imports: ImportInfo[]): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports, exports: [], unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(ir: CircleIR): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph, code: '', language: 'typescript',
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

describe('DependencyFanOutPass', () => {
  it('flags a file with 25 imports', () => {
    const imports = Array.from({ length: 25 }, (_, i) => makeImport(`lib${i}`, i));
    const { ctx, findings } = makeCtx(makeIR('src/heavy.ts', imports));
    const result = new DependencyFanOutPass().run(ctx);

    expect(result.importCount).toBe(25);
    expect(result.exceeded).toBe(true);
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(1);
  });

  it('does NOT flag a file with 10 imports', () => {
    const imports = Array.from({ length: 10 }, (_, i) => makeImport(`lib${i}`, i));
    const { ctx, findings } = makeCtx(makeIR('src/light.ts', imports));
    const result = new DependencyFanOutPass().run(ctx);

    expect(result.importCount).toBe(10);
    expect(result.exceeded).toBe(false);
    expect(findings).toHaveLength(0);
  });

  it('flags a file with exactly 20 imports (at threshold)', () => {
    const imports = Array.from({ length: 20 }, (_, i) => makeImport(`lib${i}`, i));
    const { ctx, findings } = makeCtx(makeIR('src/borderline.ts', imports));
    const result = new DependencyFanOutPass().run(ctx);

    expect(result.exceeded).toBe(true);
    expect(findings).toHaveLength(1);
  });

  it('does NOT flag a file with 0 imports', () => {
    const { ctx, findings } = makeCtx(makeIR('src/simple.ts', []));
    const result = new DependencyFanOutPass().run(ctx);

    expect(result.importCount).toBe(0);
    expect(result.exceeded).toBe(false);
    expect(findings).toHaveLength(0);
  });

  it('includes correct pass metadata in findings', () => {
    const imports = Array.from({ length: 22 }, (_, i) => makeImport(`lib${i}`, i));
    const { ctx, findings } = makeCtx(makeIR('src/bloated.ts', imports));
    new DependencyFanOutPass().run(ctx);

    expect(findings[0].pass).toBe('dependency-fan-out');
    expect(findings[0].category).toBe('architecture');
    expect(findings[0].level).toBe('note');
    expect(findings[0].severity).toBe('low');
  });

  it('includes import count and threshold in the finding message', () => {
    const imports = Array.from({ length: 25 }, (_, i) => makeImport(`lib${i}`, i));
    const { ctx, findings } = makeCtx(makeIR('src/large.ts', imports));
    new DependencyFanOutPass().run(ctx);

    expect(findings[0].message).toMatch(/25/);
    expect(findings[0].message).toMatch(/20/); // threshold
  });

  it('does NOT flag a file with 19 imports (just under threshold)', () => {
    const imports = Array.from({ length: 19 }, (_, i) => makeImport(`lib${i}`, i));
    const { ctx, findings } = makeCtx(makeIR('src/almost.ts', imports));
    new DependencyFanOutPass().run(ctx);

    expect(findings).toHaveLength(0);
  });
});
