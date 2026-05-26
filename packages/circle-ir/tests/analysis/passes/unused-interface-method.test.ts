/**
 * Tests for UnusedInterfaceMethodPass — dead interface method detection.
 *
 * Uses minimal IR fixtures (no WASM parsing).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext, SastFinding } from '../../../src/graph/analysis-pass.js';
import type { CircleIR } from '../../../src/types/index.js';
import { UnusedInterfaceMethodPass } from '../../../src/analysis/passes/unused-interface-method-pass.js';

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

function makeInterfaceType(name: string, methodNames: string[]) {
  return {
    name,
    kind: 'interface' as const,
    package: null,
    extends: null,
    implements: [] as string[],
    annotations: [] as string[],
    methods: methodNames.map((mName, i) => ({
      name: mName,
      return_type: 'void' as const,
      parameters: [] as never[],
      annotations: [] as string[],
      modifiers: [] as string[],
      start_line: 5 + i * 3,
      end_line: 5 + i * 3 + 1,
    })),
    fields: [] as never[],
    start_line: 1,
    end_line: 30,
  };
}

function makeCall(methodName: string) {
  return {
    method_name: methodName,
    receiver: 'obj' as string | null,
    arguments: [] as never[],
    location: { line: 20, column: 0 },
    in_method: 'main',
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('UnusedInterfaceMethodPass', () => {
  it('positive: interface method with no call in file → 1 finding', () => {
    const ir = makeIR({
      types: [makeInterfaceType('IProcessor', ['process'])],
      calls: [], // no calls at all
    });

    const ctx = makeCtx(ir);
    new UnusedInterfaceMethodPass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('unused-interface-method');
    expect(ctx.findings[0].message).toContain('process');
    expect(ctx.findings[0].message).toContain('IProcessor');
  });

  it('negative: interface method is called somewhere in the file → 0 findings', () => {
    const ir = makeIR({
      types: [makeInterfaceType('IProcessor', ['process'])],
      calls: [makeCall('process')],
    });

    const ctx = makeCtx(ir);
    new UnusedInterfaceMethodPass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('reports each unused method individually', () => {
    const ir = makeIR({
      types: [makeInterfaceType('IMulti', ['alpha', 'beta', 'gamma'])],
      calls: [makeCall('beta')], // only beta is called
    });

    const ctx = makeCtx(ir);
    new UnusedInterfaceMethodPass().run(ctx);

    // alpha and gamma are unused; beta is called
    expect(ctx.findings).toHaveLength(2);
    const ruleIds = ctx.findings.map(f => f.rule_id);
    expect(ruleIds.every(r => r === 'unused-interface-method')).toBe(true);
    const messages = ctx.findings.map(f => f.message);
    expect(messages.some(m => m.includes('alpha'))).toBe(true);
    expect(messages.some(m => m.includes('gamma'))).toBe(true);
    expect(messages.every(m => !m.includes('beta'))).toBe(true);
  });

  it('skips Python files', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'app.py', language: 'python', loc: 10, hash: '' },
      types: [makeInterfaceType('IFoo', ['doWork'])],
    });
    const ctx = makeCtx(ir, 'python');
    new UnusedInterfaceMethodPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('processes TypeScript files as well as Java', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'app.ts', language: 'typescript', loc: 20, hash: '' },
      types: [makeInterfaceType('IService', ['render'])],
      calls: [],
    });
    const ctx = makeCtx(ir, 'typescript');
    new UnusedInterfaceMethodPass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].message).toContain('render');
  });

  it('ignores class types — only checks interface types', () => {
    const ir = makeIR({
      types: [
        {
          name: 'MyClass',
          kind: 'class' as const,
          package: null,
          extends: null,
          implements: [] as string[],
          annotations: [] as string[],
          methods: [{
            name: 'notCalled',
            return_type: 'void' as const,
            parameters: [] as never[],
            annotations: [] as string[],
            modifiers: ['public'] as string[],
            start_line: 5,
            end_line: 8,
          }],
          fields: [] as never[],
          start_line: 1,
          end_line: 20,
        },
      ],
      calls: [],
    });

    const ctx = makeCtx(ir);
    new UnusedInterfaceMethodPass().run(ctx);

    // Class methods are not checked by this pass
    expect(ctx.findings).toHaveLength(0);
  });
});
