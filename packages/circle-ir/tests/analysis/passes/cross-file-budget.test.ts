/**
 * Tests for the cross-file budget circuit breaker introduced in 3.89.0
 * (issue #141 — langchain4j/Sa-Token cross-file phase hang).
 *
 * CrossFilePass.run() accepts `{ budgetMs }` and checks the wall-time
 * budget BETWEEN phases 1→2, 2→3, 3→4. On exceed:
 *   - the remaining phases are skipped
 *   - `result.budgetExceeded === true`
 *   - taintPaths produced by earlier phases are preserved
 *
 * Deterministic timing here uses a sync busy-wait inside the resolver
 * mocks, since the breaker only inspects `Date.now()` between phase calls.
 */

import { describe, it, expect } from 'vitest';
import { CrossFilePass } from '../../../src/analysis/passes/cross-file-pass.js';
import type { ProjectGraph } from '../../../src/graph/project-graph.js';
import type { CircleIR, TypeHierarchy } from '../../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Sync busy-wait for `ms` milliseconds — deterministic so breaker fires reliably. */
function sleepSync(ms: number): void {
  const end = Date.now() + ms;
  while (Date.now() < end) { /* spin */ }
}

interface MockFlow {
  sourceFile: string;
  sourceLine: number;
  sourceType: string;
  targetFile: string;
  targetLine: number;
  targetMethod: string;
}

interface ResolverHooks {
  flows?: MockFlow[];
  /** Wall time the phase 1 resolver call should consume. */
  phase1DelayMs?: number;
  phase2DelayMs?: number;
  phase3DelayMs?: number;
  /** Counters set by the mock so tests can assert which phases ran. */
  counters: { p1: number; p2: number; p3: number; p4: number };
}

function makeIRWithSink(file: string, sinkLine: number): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'java', loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: {
      sources: [],
      sinks: [{ type: 'sql_injection', cwe: 'CWE-89', line: sinkLine, location: `line ${sinkLine}`, confidence: 0.9 }],
      sanitizers: [],
    },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeProjectGraph(hooks: ResolverHooks, irMap?: Map<string, CircleIR>): ProjectGraph {
  const emptyTypeHierarchy: TypeHierarchy = { classes: {}, interfaces: {} };
  const filePaths = irMap ? Array.from(irMap.keys()) : [];
  return {
    get filePaths() { return filePaths; },
    getIR(path: string) { return irMap?.get(path); },
    get resolver() {
      return {
        findCrossFileTaintFlows: () => {
          hooks.counters.p1++;
          if (hooks.phase1DelayMs) sleepSync(hooks.phase1DelayMs);
          return hooks.flows ?? [];
        },
        findInterproceduralTaintPaths: () => {
          hooks.counters.p2++;
          if (hooks.phase2DelayMs) sleepSync(hooks.phase2DelayMs);
          return [];
        },
        findFieldBindingTaintPaths: () => {
          hooks.counters.p3++;
          if (hooks.phase3DelayMs) sleepSync(hooks.phase3DelayMs);
          return [];
        },
        getResolvedCallsFromFile: () => [],
        getMethodTaintInfo: () => undefined,
      };
    },
    get typeHierarchy() {
      return { toTypeHierarchyData: () => emptyTypeHierarchy };
    },
  } as unknown as ProjectGraph;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CrossFilePass — crossFileBudgetMs circuit breaker (3.89.0 #141)', () => {
  it('budget = 0 (default) → unlimited; all phases run; budgetExceeded absent', () => {
    const counters = { p1: 0, p2: 0, p3: 0, p4: 0 };
    const pg = makeProjectGraph({ counters, phase1DelayMs: 20 });

    const result = new CrossFilePass().run(pg, new Map());  // no options → budgetMs defaults to 0

    expect(counters.p1).toBe(1);
    expect(counters.p2).toBe(1);
    expect(counters.p3).toBe(1);
    // phase 4 runs as standalone helper — verified by absence of budgetExceeded
    expect(result.budgetExceeded).toBeUndefined();
  });

  it('budget unset on second call signature → still unlimited', () => {
    const counters = { p1: 0, p2: 0, p3: 0, p4: 0 };
    const pg = makeProjectGraph({ counters });

    const result = new CrossFilePass().run(pg, new Map(), {});

    expect(counters.p1).toBe(1);
    expect(counters.p2).toBe(1);
    expect(counters.p3).toBe(1);
    expect(result.budgetExceeded).toBeUndefined();
  });

  it('budget exceeded after phase 1 → phases 2/3 skipped; budgetExceeded=true; phase 1 paths preserved', () => {
    const counters = { p1: 0, p2: 0, p3: 0, p4: 0 };
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 5,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 10,
      targetMethod: 'executeQuery',
    };
    const irMap = new Map([['src/B.java', makeIRWithSink('src/B.java', 10)]]);
    const pg = makeProjectGraph(
      { counters, flows: [flow], phase1DelayMs: 60 },  // burn 60ms in phase 1
      irMap,
    );

    const result = new CrossFilePass().run(
      pg,
      new Map([
        ['src/A.java', ['', '', '', '', 'String id = req.getParameter("id");']],
        ['src/B.java', ['', '', '', '', '', '', '', '', '', 'stmt.executeQuery(id);']],
      ]),
      { budgetMs: 10 },  // budget 10ms — phase 1 alone blows it
    );

    expect(counters.p1).toBe(1);
    expect(counters.p2).toBe(0);  // skipped
    expect(counters.p3).toBe(0);  // skipped
    expect(result.budgetExceeded).toBe(true);
    // Phase 1 result preserved.
    expect(result.taintPaths).toHaveLength(1);
    expect(result.taintPaths[0].source.file).toBe('src/A.java');
  });

  it('budget exceeded after phase 2 → phase 3 skipped; budgetExceeded=true', () => {
    const counters = { p1: 0, p2: 0, p3: 0, p4: 0 };
    const pg = makeProjectGraph({ counters, phase2DelayMs: 60 });

    const result = new CrossFilePass().run(
      pg,
      new Map(),
      { budgetMs: 30 },  // phase 1 fast, phase 2 burns 60ms → check after p2 trips
    );

    expect(counters.p1).toBe(1);
    expect(counters.p2).toBe(1);  // p2 ran (breaker fires AFTER it)
    expect(counters.p3).toBe(0);  // p3 skipped
    expect(result.budgetExceeded).toBe(true);
  });

  it('budget not exceeded → all phases run; budgetExceeded absent', () => {
    const counters = { p1: 0, p2: 0, p3: 0, p4: 0 };
    const pg = makeProjectGraph({ counters });

    const result = new CrossFilePass().run(
      pg,
      new Map(),
      { budgetMs: 60_000 },  // plenty of headroom
    );

    expect(counters.p1).toBe(1);
    expect(counters.p2).toBe(1);
    expect(counters.p3).toBe(1);
    expect(result.budgetExceeded).toBeUndefined();
  });

  it('result schema: when budgetExceeded set, taintPaths/typeHierarchy/crossFileCalls still defined', () => {
    const counters = { p1: 0, p2: 0, p3: 0, p4: 0 };
    const pg = makeProjectGraph({ counters, phase1DelayMs: 50 });

    const result = new CrossFilePass().run(pg, new Map(), { budgetMs: 5 });

    expect(result.budgetExceeded).toBe(true);
    expect(Array.isArray(result.taintPaths)).toBe(true);
    expect(Array.isArray(result.crossFileCalls)).toBe(true);
    expect(result.typeHierarchy).toBeDefined();
  });
});
