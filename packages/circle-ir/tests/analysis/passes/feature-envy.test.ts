/**
 * Tests for Pass #87: feature-envy (CWE-1060, category: architecture)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { FeatureEnvyPass } from '../../../src/analysis/passes/feature-envy-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'OrderService.java', language: 'java', loc: 50, hash: '' },
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

function makeCtx(ir: CircleIR): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code: '',
    language: ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

describe('FeatureEnvyPass', () => {
  it('flags a method with 5 external calls to PaymentService and 1 internal call', () => {
    const ir = makeIR({
      types: [{
        name: 'OrderService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'checkout',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 5,
          end_line: 20,
        }],
        fields: [],
        start_line: 1,
        end_line: 25,
      }],
      calls: [
        // 5 calls to PaymentService (external)
        { method_name: 'validate', receiver: 'payment', receiver_type: 'PaymentService', arguments: [], location: { line: 7, column: 4 } },
        { method_name: 'charge', receiver: 'payment', receiver_type: 'PaymentService', arguments: [], location: { line: 9, column: 4 } },
        { method_name: 'authorize', receiver: 'payment', receiver_type: 'PaymentService', arguments: [], location: { line: 11, column: 4 } },
        { method_name: 'capture', receiver: 'payment', receiver_type: 'PaymentService', arguments: [], location: { line: 13, column: 4 } },
        { method_name: 'confirm', receiver: 'payment', receiver_type: 'PaymentService', arguments: [], location: { line: 15, column: 4 } },
        // 1 internal call
        { method_name: 'updateStatus', receiver: 'this', receiver_type: null, arguments: [], location: { line: 17, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new FeatureEnvyPass().run(ctx);
    expect(result.envyMethods.some(e => e.methodName === 'checkout')).toBe(true);
    expect(result.envyMethods[0].enviedClass).toBe('PaymentService');
    expect(result.envyMethods[0].externalCalls).toBe(5);
    expect(result.envyMethods[0].internalCalls).toBe(1);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].cwe).toBe('CWE-1060');
    expect(ctx.findings[0].level).toBe('note');
    expect(ctx.findings[0].message).toMatch(/checkout/);
    expect(ctx.findings[0].message).toMatch(/PaymentService/);
  });

  it('does NOT flag when external calls are below the minimum threshold (< 4)', () => {
    const ir = makeIR({
      types: [{
        name: 'OrderService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'getPrice',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 10,
        }],
        fields: [],
        start_line: 1,
        end_line: 12,
      }],
      calls: [
        // Only 3 external calls — below MIN_EXTERNAL_CALLS of 4
        { method_name: 'tax', receiver: 'pricing', receiver_type: 'PricingService', arguments: [], location: { line: 3, column: 4 } },
        { method_name: 'discount', receiver: 'pricing', receiver_type: 'PricingService', arguments: [], location: { line: 5, column: 4 } },
        { method_name: 'final', receiver: 'pricing', receiver_type: 'PricingService', arguments: [], location: { line: 7, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new FeatureEnvyPass().run(ctx);
    expect(result.envyMethods).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT flag a balanced method (external calls not significantly > internal)', () => {
    const ir = makeIR({
      types: [{
        name: 'ReportService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'generateReport',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 20,
        }],
        fields: [],
        start_line: 1,
        end_line: 22,
      }],
      calls: [
        // 4 external calls to DataService
        { method_name: 'fetch', receiver: 'ds', receiver_type: 'DataService', arguments: [], location: { line: 3, column: 4 } },
        { method_name: 'query', receiver: 'ds', receiver_type: 'DataService', arguments: [], location: { line: 5, column: 4 } },
        { method_name: 'count', receiver: 'ds', receiver_type: 'DataService', arguments: [], location: { line: 7, column: 4 } },
        { method_name: 'filter', receiver: 'ds', receiver_type: 'DataService', arguments: [], location: { line: 9, column: 4 } },
        // 4 internal calls — envy margin is only 2, so 4 > 4+2 is false
        { method_name: 'format', receiver: 'this', receiver_type: null, arguments: [], location: { line: 11, column: 4 } },
        { method_name: 'validate', receiver: 'this', receiver_type: null, arguments: [], location: { line: 13, column: 4 } },
        { method_name: 'save', receiver: 'this', receiver_type: null, arguments: [], location: { line: 15, column: 4 } },
        { method_name: 'notify', receiver: 'this', receiver_type: null, arguments: [], location: { line: 17, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new FeatureEnvyPass().run(ctx);
    expect(result.envyMethods).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips non-class types', () => {
    const ir = makeIR({
      types: [{
        name: 'IOrderService',
        kind: 'interface',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'process',
          return_line: null,
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 3,
        }] as never,
        fields: [],
        start_line: 1,
        end_line: 5,
      }],
      calls: Array.from({ length: 5 }, (_, i) => ({
        method_name: `ext${i}`,
        receiver: 'other',
        receiver_type: 'OtherService',
        arguments: [],
        location: { line: 2, column: 4 },
      })),
    });
    const ctx = makeCtx(ir);
    const result = new FeatureEnvyPass().run(ctx);
    expect(result.envyMethods).toHaveLength(0);
  });

  it('skips bash and rust', () => {
    const irBash = makeIR({
      meta: { circle_ir: '3.0', file: 'script.sh', language: 'bash', loc: 5, hash: '' },
    });
    const ctxBash = makeCtx(irBash);
    expect(new FeatureEnvyPass().run(ctxBash).envyMethods).toHaveLength(0);
  });

  it('includes correct metadata in findings', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'src/domain/Order.java', language: 'java', loc: 40, hash: '' },
      types: [{
        name: 'Order',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'calculateShipping',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 10,
          end_line: 25,
        }],
        fields: [],
        start_line: 1,
        end_line: 30,
      }],
      calls: Array.from({ length: 5 }, (_, i) => ({
        method_name: `ship${i}`,
        receiver: 'logistics',
        receiver_type: 'LogisticsService',
        arguments: [],
        location: { line: 12 + i, column: 4 },
      })),
    });
    const ctx = makeCtx(ir);
    new FeatureEnvyPass().run(ctx);
    expect(ctx.findings[0].file).toBe('src/domain/Order.java');
    expect(ctx.findings[0].pass).toBe('feature-envy');
    expect(ctx.findings[0].category).toBe('architecture');
    expect(ctx.findings[0].line).toBe(10);
  });
});
