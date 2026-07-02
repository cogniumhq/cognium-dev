/**
 * Tests for Pass #109: sink-semantics (category: security, no CWE)
 *
 * Verifies the `<ClassName>#<methodName>` → `overrides` registry gate
 * that drops sinks whose emitted `SinkType` label disagrees with the
 * registry's real-behavior classification (cognium-dev #139 Tier A).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { SinkSemanticsPass } from '../../../src/analysis/passes/sink-semantics-pass.js';
import type { CircleIR, SastFinding, TaintSink } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig, SinkSemanticsEntry } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function makeIR(file: string, sinks: TaintSink[]): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'java', loc: sinks.length, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks, sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function runOn(
  sinks: TaintSink[],
  entries: SinkSemanticsEntry[],
): { kept: TaintSink[]; droppedCount: number; registrySize: number } {
  const ir = makeIR('T.java', sinks);
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code: '',
    language: 'java',
    config: {
      sources: [],
      sinks: [],
      sanitizers: [],
      sinkSemantics: entries,
    } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
    getFindings: () => findings,
  };
  const result = new SinkSemanticsPass().run(ctx);
  return {
    kept: graph.ir.taint.sinks,
    droppedCount: result.droppedCount,
    registrySize: result.registrySize,
  };
}

/** Minimal TaintSink factory. */
function sink(overrides: Partial<TaintSink>): TaintSink {
  return {
    type: 'command_injection',
    cwe: 'CWE-78',
    location: 'test',
    line: 1,
    confidence: 1.0,
    ...overrides,
  } as TaintSink;
}

// Canonical 8-entry seed registry (mirrors DEFAULT_SINK_SEMANTICS)
const SEED_REGISTRY: SinkSemanticsEntry[] = [
  { signature: 'Jedis#executeCommand', real_class: 'db_protocol', overrides: ['command_injection', 'code_injection'] },
  { signature: 'Connection#executeCommand', real_class: 'db_protocol', overrides: ['command_injection', 'code_injection'] },
  { signature: 'JedisCluster#executeCommand', real_class: 'db_protocol', overrides: ['command_injection', 'code_injection'] },
  { signature: 'Func1#exec', real_class: 'functional_dispatch', overrides: ['command_injection', 'code_injection'] },
  { signature: 'Action0#call', real_class: 'functional_dispatch', overrides: ['command_injection'] },
  { signature: 'Action1#call', real_class: 'functional_dispatch', overrides: ['command_injection'] },
  { signature: 'Unsafe#defineAnonymousClass', real_class: 'jdk_internal', overrides: ['code_injection'] },
  { signature: 'MethodHandle#invokeExact', real_class: 'jdk_internal', overrides: ['code_injection'] },
];

// ---------------------------------------------------------------------------
// TP: Sinks that MUST be dropped
// ---------------------------------------------------------------------------

describe('SinkSemanticsPass — true-positive drops', () => {
  it('TP-1: Jedis#executeCommand + command_injection → dropped', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Jedis', method: 'executeCommand', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-2: Connection#executeCommand + command_injection → dropped (Jedis base)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Connection', method: 'executeCommand', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-3: Func1#exec + command_injection → dropped (RxJava)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Func1', method: 'exec', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-4: Unsafe#defineAnonymousClass + code_injection → dropped', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Unsafe', method: 'defineAnonymousClass', type: 'code_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-5: MethodHandle#invokeExact + code_injection → dropped', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'MethodHandle', method: 'invokeExact', type: 'code_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-6: Jedis#executeCommand + code_injection → dropped (multi-override entry)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Jedis', method: 'executeCommand', type: 'code_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// TN: Sinks that MUST be kept (recall guards)
// ---------------------------------------------------------------------------

describe('SinkSemanticsPass — true-negative keeps (recall guards)', () => {
  it('TN-1: Runtime#exec + command_injection → kept (not in registry)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Runtime', method: 'exec', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });

  it('TN-2: Jedis#executeCommand + sql_injection → kept (label not in overrides)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Jedis', method: 'executeCommand', type: 'sql_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });

  it('TN-3: unresolved receiver (class = undefined) → kept (false-negative-safe)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: undefined, method: 'executeCommand', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });

  it('TN-4: MyCustomJedis#executeCommand → kept (class-scoped registry)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'MyCustomJedis', method: 'executeCommand', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });

  it('TN-5: Statement#execute + command_injection → kept (Statement not registered)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Statement', method: 'execute', type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });

  it('TN-6: Class#forName + code_injection → kept (JDK reflection stays flagged)', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Class', method: 'forName', type: 'code_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });

  it('TN-7: sink with missing method → kept', () => {
    const { kept, droppedCount } = runOn(
      [sink({ class: 'Jedis', method: undefined, type: 'command_injection' })],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Registry-lifecycle edge cases
// ---------------------------------------------------------------------------

describe('SinkSemanticsPass — registry lifecycle', () => {
  it('empty registry → no drops, registrySize 0', () => {
    const { kept, droppedCount, registrySize } = runOn(
      [sink({ class: 'Jedis', method: 'executeCommand', type: 'command_injection' })],
      [],
    );
    expect(kept).toHaveLength(1);
    expect(droppedCount).toBe(0);
    expect(registrySize).toBe(0);
  });

  it('registrySize reflects unique signatures', () => {
    const { registrySize } = runOn([], SEED_REGISTRY);
    expect(registrySize).toBe(SEED_REGISTRY.length);
  });

  it('duplicate signature entries union their overrides', () => {
    const entries: SinkSemanticsEntry[] = [
      { signature: 'X#y', real_class: 'db_protocol', overrides: ['command_injection'] },
      { signature: 'X#y', real_class: 'db_protocol', overrides: ['code_injection'] },
    ];
    // First sink hits the first override, second hits the second — both drop.
    const { droppedCount, registrySize } = runOn(
      [
        sink({ class: 'X', method: 'y', type: 'command_injection' }),
        sink({ class: 'X', method: 'y', type: 'code_injection' }),
      ],
      entries,
    );
    expect(droppedCount).toBe(2);
    expect(registrySize).toBe(1);
  });

  it('mixed batch: drops targeted sinks and preserves others', () => {
    const { kept, droppedCount } = runOn(
      [
        sink({ class: 'Jedis', method: 'executeCommand', type: 'command_injection' }),  // drop
        sink({ class: 'Runtime', method: 'exec', type: 'command_injection' }),          // keep
        sink({ class: 'Func1', method: 'exec', type: 'command_injection' }),            // drop
        sink({ class: 'Statement', method: 'execute', type: 'sql_injection' }),         // keep
        sink({ class: 'Unsafe', method: 'defineAnonymousClass', type: 'code_injection' }), // drop
      ],
      SEED_REGISTRY,
    );
    expect(kept).toHaveLength(2);
    expect(droppedCount).toBe(3);
    expect(kept.map((s) => s.class).sort()).toEqual(['Runtime', 'Statement']);
  });

  it('array identity preserved when droppedCount === 0', () => {
    const inputSinks: TaintSink[] = [
      sink({ class: 'Runtime', method: 'exec', type: 'command_injection' }),
    ];
    const ir = makeIR('T.java', inputSinks);
    const graph = new CodeGraph(ir);
    const beforeRef = graph.ir.taint.sinks;
    const findings: SastFinding[] = [];
    const ctx: PassContext = {
      graph,
      code: '',
      language: 'java',
      config: { sources: [], sinks: [], sanitizers: [], sinkSemantics: SEED_REGISTRY } as TaintConfig,
      getResult: () => { throw new Error('not used'); },
      hasResult: () => false,
      addFinding: (f) => findings.push(f),
      getFindings: () => findings,
    };
    new SinkSemanticsPass().run(ctx);
    expect(graph.ir.taint.sinks).toBe(beforeRef);
    expect(graph.ir.taint.sinks).toHaveLength(1);
  });

  it('array identity preserved when droppedCount > 0 (in-place mutation)', () => {
    const inputSinks: TaintSink[] = [
      sink({ class: 'Jedis', method: 'executeCommand', type: 'command_injection' }),
      sink({ class: 'Runtime', method: 'exec', type: 'command_injection' }),
    ];
    const ir = makeIR('T.java', inputSinks);
    const graph = new CodeGraph(ir);
    const beforeRef = graph.ir.taint.sinks;
    const findings: SastFinding[] = [];
    const ctx: PassContext = {
      graph,
      code: '',
      language: 'java',
      config: { sources: [], sinks: [], sanitizers: [], sinkSemantics: SEED_REGISTRY } as TaintConfig,
      getResult: () => { throw new Error('not used'); },
      hasResult: () => false,
      addFinding: (f) => findings.push(f),
      getFindings: () => findings,
    };
    new SinkSemanticsPass().run(ctx);
    expect(graph.ir.taint.sinks).toBe(beforeRef);
    expect(graph.ir.taint.sinks).toHaveLength(1);
    expect(graph.ir.taint.sinks[0]?.class).toBe('Runtime');
  });

  it('missing sinkSemantics on config → no-op (legacy caller)', () => {
    const ir = makeIR('T.java', [
      sink({ class: 'Jedis', method: 'executeCommand', type: 'command_injection' }),
    ]);
    const graph = new CodeGraph(ir);
    const findings: SastFinding[] = [];
    const ctx: PassContext = {
      graph,
      code: '',
      language: 'java',
      // No sinkSemantics field
      config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
      getResult: () => { throw new Error('not used'); },
      hasResult: () => false,
      addFinding: (f) => findings.push(f),
      getFindings: () => findings,
    };
    const result = new SinkSemanticsPass().run(ctx);
    expect(result.droppedCount).toBe(0);
    expect(result.registrySize).toBe(0);
    expect(graph.ir.taint.sinks).toHaveLength(1);
  });

  it('emits no findings (source-tagging-style gate)', () => {
    const ir = makeIR('T.java', [
      sink({ class: 'Jedis', method: 'executeCommand', type: 'command_injection' }),
    ]);
    const graph = new CodeGraph(ir);
    const findings: SastFinding[] = [];
    const ctx: PassContext = {
      graph,
      code: '',
      language: 'java',
      config: { sources: [], sinks: [], sanitizers: [], sinkSemantics: SEED_REGISTRY } as TaintConfig,
      getResult: () => { throw new Error('not used'); },
      hasResult: () => false,
      addFinding: (f) => findings.push(f),
      getFindings: () => findings,
    };
    new SinkSemanticsPass().run(ctx);
    expect(findings).toHaveLength(0);
  });
});
