/**
 * Tests for Pass #45: n-plus-one (CWE-1049, category: performance)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { NPlusOnePass } from '../../../src/analysis/passes/n-plus-one-pass.js';
import type { CircleIR, SastFinding, CallInfo, CFGBlock, CFGEdge } from '../../../src/types/index.js';
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

function makeCall(method_name: string, line: number, receiver: string | null = null): CallInfo {
  return {
    method_name,
    receiver,
    arguments: [],
    location: { line, column: 0 },
  };
}

function makeIR(
  calls: CallInfo[],
  cfg: { blocks: CFGBlock[]; edges: CFGEdge[] },
  file = 'app.ts',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 20, hash: '' },
    types: [],
    calls,
    cfg,
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

// A minimal CFG with a back-edge representing a loop over lines 2–5
// entry(1) → loop-header(2–5) → exit(6)
//                  ↑___________| (back-edge: 5→2)
function loopCfg(): { blocks: CFGBlock[]; edges: CFGEdge[] } {
  const blocks = [
    block(1, 'entry', 1, 1),
    block(2, 'loop',  2, 5),
    block(3, 'exit',  6, 6),
  ];
  const edges = [
    edge(1, 2),
    edge(2, 3),
    edge(2, 2, 'back'), // back-edge: tail=block2, header=block2 → loop body 2-5
  ];
  return { blocks, edges };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NPlusOnePass', () => {
  it('returns empty result when there are no loops', () => {
    const calls = [makeCall('findUnique', 3)];
    const cfg = {
      blocks: [block(1, 'entry', 1, 10)],
      edges: [],
    };
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags a high-confidence DB method called inside a loop', () => {
    // findUnique is in HIGH_CONFIDENCE_DB_METHODS
    const cfg = loopCfg();
    const calls = [makeCall('findUnique', 3)]; // line 3 is inside loop (2-5)
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-1049');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/findUnique/);
    expect(findings[0].message).toMatch(/batching/i);
  });

  it('flags a medium-confidence method with a DB-like receiver inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, 'prisma')]; // prisma is a DB receiver
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toMatchObject({
      loop_start: expect.any(Number),
      loop_end: expect.any(Number),
    });
  });

  it('does not flag a medium-confidence method with a non-DB receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, 'localHelper')]; // not a DB receiver
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag a medium-confidence method with null receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, null)];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag a high-confidence DB call outside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('findUnique', 10)]; // line 10 is outside loop (2-5)
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags `fetch()` (high-confidence) inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('fetch', 4)];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
    expect(findings[0].message).toMatch(/fetch/);
  });

  it('flags JDBC executeQuery inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('executeQuery', 3, 'stmt')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags Prisma findMany inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('findMany', 3)];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags `query` with a `db` receiver inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('query', 3, 'db')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags `get` with an `axios` receiver inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'axios')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('collects multiple DB calls inside a loop', () => {
    const cfg = loopCfg();
    const calls = [
      makeCall('findUnique', 2),
      makeCall('executeQuery', 4, 'conn'),
    ];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(2);
    expect(findings).toHaveLength(2);
  });

  it('includes file and pass metadata in finding', () => {
    const cfg = loopCfg();
    const calls = [makeCall('findUnique', 3)];
    const ir = makeIR(calls, cfg, 'src/service.ts');
    const { ctx, findings } = makeCtx(ir);
    new NPlusOnePass().run(ctx);
    expect(findings[0].file).toBe('src/service.ts');
    expect(findings[0].pass).toBe('n-plus-one');
    expect(findings[0].category).toBe('performance');
    expect(findings[0].id).toBe('n-plus-one-src/service.ts-3');
  });

  it('includes loop bounds in evidence', () => {
    const cfg = loopCfg();
    const calls = [makeCall('findUnique', 3)];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    new NPlusOnePass().run(ctx);
    expect(findings[0].evidence).toHaveProperty('loop_start');
    expect(findings[0].evidence).toHaveProperty('loop_end');
  });

  // ---------------------------------------------------------------------------
  // Tests for suffix-based receiver matching (userRepository, orderDao, etc.)
  // ---------------------------------------------------------------------------

  it('flags medium-confidence method with *Repository suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, 'userRepository')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/find/);
  });

  it('flags medium-confidence method with *Repo suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('save', 3, 'orderRepo')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
    expect(findings).toHaveLength(1);
  });

  it('flags medium-confidence method with *Dao suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('query', 3, 'productDao')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Service suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'paymentService')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Client suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('post', 3, 'apiClient')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *DataSource suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('execute', 3, 'mainDataSource')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Gateway suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('request', 3, 'paymentGateway')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Store suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('load', 3, 'sessionStore')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Cache suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'redisCache')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Collection suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, 'usersCollection')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with *Mapper suffix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('insert', 3, 'userMapper')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('still does not flag medium-confidence method with unrecognized receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, 'myHelper')]; // no matching suffix or prefix
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  // Test new prefix patterns added
  it('flags medium-confidence method with mongo prefix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('find', 3, 'mongoClient')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with redis prefix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'redisConnection')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  it('flags medium-confidence method with pg prefix receiver', () => {
    const cfg = loopCfg();
    const calls = [makeCall('query', 3, 'pgPool')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(1);
  });

  // ---------------------------------------------------------------------------
  // Regression: in-memory collection receivers must NOT be flagged.
  // JavaScript `Map.get()` / `Map.has()` inside loops is normal algorithm code,
  // not a DB query.
  // ---------------------------------------------------------------------------

  it('does not flag Map.get() with *Index receiver inside a loop', () => {
    // Regression: `rpoIndex.get(node)` in graph algorithms (e.g. dominator
    // computation) was being flagged because `Index` was in the DB suffix list.
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'rpoIndex')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag Map.get() with *Map receiver inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'nodeMap')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag Map.get() with *Lookup receiver inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'parentLookup')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
  });

  it('does not flag Map.get() with *ById receiver inside a loop', () => {
    const cfg = loopCfg();
    const calls = [makeCall('get', 3, 'usersById')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
  });

  it('does not flag bare-name in-memory collections (idom, seen, visited)', () => {
    const cfg = loopCfg();
    const calls = [
      makeCall('get', 2, 'idom'),
      makeCall('get', 3, 'seen'),
      makeCall('get', 4, 'visited'),
      makeCall('get', 5, 'memo'),
    ];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('in-memory exclusion takes precedence over DB prefix (dbIndex is ambiguous)', () => {
    // `dbIndex` could be a JS Map keyed by db name OR a DB index. The
    // in-memory exclusion takes precedence to favour fewer false positives
    // in algorithm code. Real DB code uses clearer names (`db`, `dbClient`).
    const cfg = loopCfg();
    const calls = [makeCall('query', 3, 'dbIndex')];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('still flags clean DB receivers after the in-memory exclusion is added', () => {
    // Sanity check: ordinary DB receivers without in-memory suffixes still
    // get flagged (regression check that we did not break the prefix path).
    const cfg = loopCfg();
    const calls = [
      makeCall('query', 2, 'db'),
      makeCall('get', 3, 'axios'),
      makeCall('find', 4, 'userRepository'),
    ];
    const ir = makeIR(calls, cfg);
    const { ctx, findings } = makeCtx(ir);
    const result = new NPlusOnePass().run(ctx);
    expect(result.loopDbCalls).toHaveLength(3);
    expect(findings).toHaveLength(3);
  });
});
