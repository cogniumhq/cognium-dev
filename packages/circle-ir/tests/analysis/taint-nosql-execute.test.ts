/**
 * Tests for sink-semantics drops on NoSQL and JDK/Spring executor
 * `execute(...)` signatures. These callers dispatch to a driver's wire
 * protocol (Mongo BSON, Redis RESP, Cassandra CQL) or a Runnable queue —
 * they are NOT OS `exec` and NOT raw SQL. The `sink-semantics` pass
 * drops the aliased `command_injection` / `sql_injection` labels while
 * leaving legitimate SQL / command sinks (Statement, Runtime.exec)
 * untouched.
 *
 * Closes cognium-dev#233 (command_injection + sql_injection families,
 * NoSQL and executor callbacks).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../src/graph/code-graph.js';
import { SinkSemanticsPass } from '../../src/analysis/passes/sink-semantics-pass.js';
import type { CircleIR, SastFinding, TaintSink } from '../../src/types/index.js';
import type { PassContext } from '../../src/graph/analysis-pass.js';
import type { TaintConfig, SinkSemanticsEntry } from '../../src/types/config.js';

function makeIR(sinks: TaintSink[]): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'T.java', language: 'java', loc: sinks.length, hash: '' },
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

function runOn(sinks: TaintSink[], entries: SinkSemanticsEntry[]) {
  const ir = makeIR(sinks);
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
  return { kept: graph.ir.taint.sinks, droppedCount: result.droppedCount };
}

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

// The v3.153.0 registry entries added for #233
const REGISTRY_3_153_0: SinkSemanticsEntry[] = [
  { signature: 'MongoTemplate#execute',    real_class: 'nosql_protocol', overrides: ['sql_injection', 'command_injection'] },
  { signature: 'MongoOperations#execute',  real_class: 'nosql_protocol', overrides: ['sql_injection', 'command_injection'] },
  { signature: 'CqlSession#execute',       real_class: 'nosql_protocol', overrides: ['command_injection'] },
  { signature: 'RedisTemplate#execute',    real_class: 'nosql_protocol', overrides: ['sql_injection', 'command_injection'] },
  { signature: 'StringRedisTemplate#execute', real_class: 'nosql_protocol', overrides: ['sql_injection', 'command_injection'] },
  { signature: 'RedissonClient#execute',   real_class: 'nosql_protocol', overrides: ['sql_injection', 'command_injection'] },
  { signature: 'ExecutorService#execute',  real_class: 'framework_callback', overrides: ['command_injection', 'sql_injection'] },
  { signature: 'ThreadPoolExecutor#execute', real_class: 'framework_callback', overrides: ['command_injection', 'sql_injection'] },
  { signature: 'ForkJoinPool#execute',     real_class: 'framework_callback', overrides: ['command_injection', 'sql_injection'] },
  { signature: 'TaskExecutor#execute',     real_class: 'framework_callback', overrides: ['command_injection', 'sql_injection'] },
  { signature: 'TransactionTemplate#execute', real_class: 'framework_callback', overrides: ['sql_injection', 'command_injection'] },
];

describe('Sink-semantics: NoSQL execute drops (#233)', () => {
  it('MongoTemplate#execute + sql_injection → dropped', () => {
    const { kept } = runOn(
      [sink({ class: 'MongoTemplate', method: 'execute', type: 'sql_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(0);
  });

  it('RedisTemplate#execute + command_injection → dropped', () => {
    const { kept } = runOn(
      [sink({ class: 'RedisTemplate', method: 'execute', type: 'command_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(0);
  });

  it('CqlSession#execute + command_injection → dropped, sql_injection preserved', () => {
    // CqlSession only drops the command_injection alias; SQL injection is a
    // real CQL concern and stays flagged.
    const { kept, droppedCount } = runOn(
      [
        sink({ class: 'CqlSession', method: 'execute', type: 'command_injection' }),
        sink({ class: 'CqlSession', method: 'execute', type: 'sql_injection' }),
      ],
      REGISTRY_3_153_0,
    );
    expect(droppedCount).toBe(1);
    expect(kept.map((s) => s.type).sort()).toEqual(['sql_injection']);
  });

  it('RedissonClient#execute + sql_injection → dropped', () => {
    const { kept } = runOn(
      [sink({ class: 'RedissonClient', method: 'execute', type: 'sql_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(0);
  });
});

describe('Sink-semantics: executor callback drops (#233)', () => {
  it('ExecutorService#execute + command_injection → dropped', () => {
    const { kept } = runOn(
      [sink({ class: 'ExecutorService', method: 'execute', type: 'command_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(0);
  });

  it('ThreadPoolExecutor#execute + command_injection → dropped', () => {
    const { kept } = runOn(
      [sink({ class: 'ThreadPoolExecutor', method: 'execute', type: 'command_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(0);
  });

  it('TransactionTemplate#execute + sql_injection → dropped', () => {
    const { kept } = runOn(
      [sink({ class: 'TransactionTemplate', method: 'execute', type: 'sql_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(0);
  });

  it('Runtime#exec + command_injection → kept (real command exec)', () => {
    const { kept } = runOn(
      [sink({ class: 'Runtime', method: 'exec', type: 'command_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(1);
  });

  it('Statement#execute + sql_injection → kept (real SQL exec)', () => {
    const { kept } = runOn(
      [sink({ class: 'Statement', method: 'execute', type: 'sql_injection' })],
      REGISTRY_3_153_0,
    );
    expect(kept).toHaveLength(1);
  });
});
