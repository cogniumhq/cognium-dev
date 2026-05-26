/**
 * Tests for MissingOverridePass — annotation coverage detection.
 *
 * Uses minimal IR fixtures (no WASM parsing).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext, SastFinding } from '../../../src/graph/analysis-pass.js';
import type { CircleIR } from '../../../src/types/index.js';
import { MissingOverridePass } from '../../../src/analysis/passes/missing-override-pass.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 40, hash: '' },
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

function makeMethod(
  name: string,
  opts: {
    annotations?: string[];
    modifiers?: string[];
    startLine?: number;
  } = {},
) {
  return {
    name,
    return_type: 'void' as const,
    parameters: [] as never[],
    annotations: opts.annotations ?? [],
    modifiers: opts.modifiers ?? ['public'],
    start_line: opts.startLine ?? 10,
    end_line: (opts.startLine ?? 10) + 5,
  };
}

function makeClass(
  name: string,
  methods: ReturnType<typeof makeMethod>[],
  opts: { extends?: string | null } = {},
) {
  return {
    name,
    kind: 'class' as const,
    package: null,
    extends: opts.extends ?? null,
    implements: [] as string[],
    annotations: [] as string[],
    methods,
    fields: [] as never[],
    start_line: 1,
    end_line: 40,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('MissingOverridePass', () => {
  it('positive: child method overrides parent method but lacks @Override', () => {
    // Parent has execute(); Child has execute() without @Override
    const parent = makeClass('Base', [
      makeMethod('execute', { startLine: 5 }),
    ]);
    const child = makeClass('Derived', [
      makeMethod('execute', { startLine: 20 }), // no @Override annotation
    ], { extends: 'Base' });

    const ir = makeIR({ types: [parent, child] });
    const ctx = makeCtx(ir);
    new MissingOverridePass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('missing-override');
    expect(ctx.findings[0].line).toBe(20);
    expect(ctx.findings[0].message).toContain('Derived');
    expect(ctx.findings[0].message).toContain('execute');
  });

  it('negative: @Override annotation present → no finding', () => {
    const parent = makeClass('Base', [
      makeMethod('execute', { startLine: 5 }),
    ]);
    const child = makeClass('Derived', [
      makeMethod('execute', {
        startLine: 20,
        annotations: ['Override'],
      }),
    ], { extends: 'Base' });

    const ir = makeIR({ types: [parent, child] });
    const ctx = makeCtx(ir);
    new MissingOverridePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('negative: private method is skipped', () => {
    const parent = makeClass('Base', [
      makeMethod('execute', { startLine: 5 }),
    ]);
    const child = makeClass('Derived', [
      makeMethod('execute', {
        startLine: 20,
        modifiers: ['private'], // private override doesn't use @Override in Java
      }),
    ], { extends: 'Base' });

    const ir = makeIR({ types: [parent, child] });
    const ctx = makeCtx(ir);
    new MissingOverridePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('negative: static method is skipped (cannot override in Java)', () => {
    const parent = makeClass('Base', [
      makeMethod('factory', { startLine: 5 }),
    ]);
    const child = makeClass('Derived', [
      makeMethod('factory', { startLine: 20, modifiers: ['public', 'static'] }),
    ], { extends: 'Base' });

    const ir = makeIR({ types: [parent, child] });
    const ctx = makeCtx(ir);
    new MissingOverridePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('negative: constructor is skipped (same name as class)', () => {
    const parent = makeClass('Base', [
      makeMethod('Base', { startLine: 5 }), // parent constructor
    ]);
    const child = makeClass('Derived', [
      makeMethod('Derived', { startLine: 20 }), // child constructor (same name as child class, not parent)
    ], { extends: 'Base' });

    const ir = makeIR({ types: [parent, child] });
    const ctx = makeCtx(ir);
    new MissingOverridePass().run(ctx);

    // 'Derived' != 'Base' so constructor check based on type.name works
    // The child constructor 'Derived' == child class name 'Derived' → skipped
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips non-Java languages', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'App.py', language: 'python', loc: 20, hash: '' },
    });
    const ctx = makeCtx(ir, 'python');
    new MissingOverridePass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('handles multi-level inheritance chain', () => {
    // GrandParent.execute() → Parent extends GrandParent → Child extends Parent
    // Child.execute() without @Override should still be flagged
    const grandParent = makeClass('GrandParent', [
      makeMethod('execute', { startLine: 5 }),
    ]);
    const parent = makeClass('Parent', [
      makeMethod('execute', { startLine: 15, annotations: ['Override'] }),
    ], { extends: 'GrandParent' });
    const child = makeClass('Child', [
      makeMethod('execute', { startLine: 25 }), // overrides but no @Override
    ], { extends: 'Parent' });

    const ir = makeIR({ types: [grandParent, parent, child] });
    const ctx = makeCtx(ir);
    new MissingOverridePass().run(ctx);

    // Child should be flagged (inherits execute from Parent/GrandParent)
    expect(ctx.findings.some(f => f.message.includes('Child'))).toBe(true);
  });
});
