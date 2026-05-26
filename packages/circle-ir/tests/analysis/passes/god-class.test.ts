/**
 * Tests for Pass #86: god-class (CWE-1060, category: architecture)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { GodClassPass } from '../../../src/analysis/passes/god-class-pass.js';
import type { CircleIR, MethodInfo, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Service.java', language: 'java', loc: 200, hash: '' },
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

/** Generate N simple methods at consecutive lines. */
function makeMethods(count: number): MethodInfo[] {
  return Array.from({ length: count }, (_, i) => ({
    name: `method${i}`,
    return_type: null,
    parameters: [],
    annotations: [],
    modifiers: [],
    start_line: i + 1,
    end_line: i + 1,
  }));
}

describe('GodClassPass', () => {
  it('flags a class exceeding WMC and LCOM2 thresholds', () => {
    // 50 methods → WMC = 50 (fallback 1 each) > 47 ✓
    // 1 field accessed only by method0 → LCOM2 ≈ 1.0 > 0.8 ✓
    const methods = makeMethods(50);

    const ir = makeIR({
      types: [{
        name: 'GodService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods,
        fields: [{ name: 'data', type: 'String', modifiers: ['private'], annotations: [] }],
        start_line: 1,
        end_line: 60,
      }],
      dfg: {
        // Only method0 (line 1) accesses the field "data"
        defs: [{ id: 1, variable: 'data', line: 1, kind: 'field' }],
        uses: [],
        chains: [],
      },
    });
    const ctx = makeCtx(ir);
    const result = new GodClassPass().run(ctx);
    expect(result.godClasses.some(c => c.className === 'GodService')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'god-class')).toBe(true);
    expect(ctx.findings[0].cwe).toBe('CWE-1060');
    expect(ctx.findings[0].level).toBe('warning');
    expect(ctx.findings[0].message).toMatch(/GodService/);
    expect(ctx.findings[0].message).toMatch(/WMC=/);
  });

  it('flags a class exceeding WMC and CBO thresholds', () => {
    // 50 methods → WMC = 50 > 47 ✓
    // 15 external call receiver types → CBO = 15 > 14 ✓
    const methods = makeMethods(50);

    const externalTypes = [
      'OrderService', 'PaymentService', 'ShipmentService', 'InvoiceService',
      'CustomerService', 'ProductService', 'InventoryService', 'NotificationService',
      'AuditService', 'EmailService', 'LogService', 'MetricsService',
      'CacheService', 'AuthService', 'ReportService',
    ];
    const calls = externalTypes.map((t, i) => ({
      method_name: 'execute',
      receiver: 'svc',
      receiver_type: t,
      arguments: [],
      location: { line: i + 2, column: 4 },
    }));

    const ir = makeIR({
      types: [{
        name: 'BigOrchestrator',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods,
        fields: [],
        start_line: 1,
        end_line: 60,
      }],
      calls,
    });
    const ctx = makeCtx(ir);
    const result = new GodClassPass().run(ctx);
    expect(result.godClasses.some(c => c.className === 'BigOrchestrator')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'god-class')).toBe(true);
  });

  it('does NOT flag a small, cohesive class', () => {
    // 3 methods, all sharing the same field → LCOM2 = 0
    // WMC = 3 (well below 47)
    const ir = makeIR({
      types: [{
        name: 'UserRepository',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [
          { name: 'findById', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 1, end_line: 5 },
          { name: 'save', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 6, end_line: 10 },
          { name: 'delete', return_type: null, parameters: [], annotations: [], modifiers: [], start_line: 11, end_line: 15 },
        ],
        fields: [{ name: 'db', type: 'Database', modifiers: ['private'], annotations: [] }],
        start_line: 1,
        end_line: 20,
      }],
      dfg: {
        // All methods use 'db' → high cohesion (Q = 3)
        defs: [],
        uses: [
          { def_id: 1, variable: 'db', line: 2 },
          { def_id: 1, variable: 'db', line: 7 },
          { def_id: 1, variable: 'db', line: 12 },
        ],
        chains: [],
      },
    });
    const ctx = makeCtx(ir);
    const result = new GodClassPass().run(ctx);
    expect(result.godClasses).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips interfaces and enums', () => {
    const ir = makeIR({
      types: [{
        name: 'HugeInterface',
        kind: 'interface',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: makeMethods(50),
        fields: [],
        start_line: 1,
        end_line: 60,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new GodClassPass().run(ctx);
    expect(result.godClasses).toHaveLength(0);
  });

  it('skips bash and rust', () => {
    const irBash = makeIR({
      meta: { circle_ir: '3.0', file: 'script.sh', language: 'bash', loc: 5, hash: '' },
    });
    const ctxBash = makeCtx(irBash);
    expect(new GodClassPass().run(ctxBash).godClasses).toHaveLength(0);

    const irRust = makeIR({
      meta: { circle_ir: '3.0', file: 'main.rs', language: 'rust', loc: 5, hash: '' },
    });
    const ctxRust = makeCtx(irRust);
    expect(new GodClassPass().run(ctxRust).godClasses).toHaveLength(0);
  });

  it('includes correct metadata in findings', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'src/core/Orchestrator.java', language: 'java', loc: 200, hash: '' },
      types: [{
        name: 'Orchestrator',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: makeMethods(50),
        fields: [{ name: 'state', type: 'String', modifiers: ['private'], annotations: [] }],
        start_line: 5,
        end_line: 200,
      }],
      dfg: {
        defs: [{ id: 1, variable: 'state', line: 5, kind: 'field' }],
        uses: [],
        chains: [],
      },
    });
    const ctx = makeCtx(ir);
    new GodClassPass().run(ctx);
    expect(ctx.findings[0].file).toBe('src/core/Orchestrator.java');
    expect(ctx.findings[0].pass).toBe('god-class');
    expect(ctx.findings[0].category).toBe('architecture');
    expect(ctx.findings[0].line).toBe(5);
    expect(ctx.findings[0].evidence).toMatchObject({ wmc: 50 });
  });
});
