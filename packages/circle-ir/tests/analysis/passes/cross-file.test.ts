/**
 * Tests for CrossFilePass
 *
 * Uses a mock ProjectGraph to test all code paths including:
 *  - Empty project
 *  - Cross-file taint flows
 *  - Missing sourceLines (fallback to empty array)
 *  - Missing target IR (defaults for type/CWE)
 *  - Same-file calls skipped
 *  - exact vs. fuzzy resolution
 */

import { describe, it, expect } from 'vitest';
import { CrossFilePass } from '../../../src/analysis/passes/cross-file-pass.js';
import type { ProjectGraph } from '../../../src/graph/project-graph.js';
import type { CircleIR, TypeHierarchy } from '../../../src/types/index.js';
import { CodeGraph } from '../../../src/graph/code-graph.js';

// ---------------------------------------------------------------------------
// Helpers — mock types that CrossFilePass reads
// ---------------------------------------------------------------------------

interface MockFlow {
  sourceFile: string;
  sourceLine: number;
  sourceType: string;
  targetFile: string;
  targetLine: number;
  targetMethod: string;
  variable?: string;
}

interface MockResolvedCall {
  sourceFile: string;
  targetFile: string;
  targetMethod: string;
  resolution: 'exact' | 'fuzzy' | 'unresolved';
  call: {
    method_name: string;
    in_method?: string;
    location: { line: number; column: number };
    arguments?: Array<{ expression?: string }>;
  };
}

function makeEmptyIR(file: string, language = 'java'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeIRWithSink(file: string, sinkLine: number, type = 'sql_injection', cwe = 'CWE-89'): CircleIR {
  const ir = makeEmptyIR(file);
  ir.taint.sinks.push({ type: type as CircleIR['taint']['sinks'][0]['type'], cwe, line: sinkLine, location: `line ${sinkLine}`, confidence: 0.9 });
  return ir;
}

function makeProjectGraph(opts: {
  filePaths?: string[];
  flows?: MockFlow[];
  resolvedCallsMap?: Map<string, MockResolvedCall[]>;
  irMap?: Map<string, CircleIR>;
  typeHierarchyData?: TypeHierarchy;
}): ProjectGraph {
  const emptyTypeHierarchy: TypeHierarchy = { classes: {}, interfaces: {} };
  return {
    get filePaths() { return opts.filePaths ?? []; },
    getIR(path: string) { return opts.irMap?.get(path); },
    get resolver() {
      return {
        findCrossFileTaintFlows: () => opts.flows ?? [],
        findInterproceduralTaintPaths: () => [],
        findFieldBindingTaintPaths: () => [],
        getResolvedCallsFromFile: (path: string) => opts.resolvedCallsMap?.get(path) ?? [],
        getMethodTaintInfo: () => undefined,
      };
    },
    get typeHierarchy() {
      return {
        toTypeHierarchyData: () => opts.typeHierarchyData ?? emptyTypeHierarchy,
      };
    },
  } as unknown as ProjectGraph;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CrossFilePass — empty/minimal project', () => {
  it('returns empty arrays for empty project', () => {
    const pg = makeProjectGraph({});
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls).toHaveLength(0);
    expect(result.taintPaths).toHaveLength(0);
  });

  it('returns empty arrays for single file with no flows', () => {
    const pg = makeProjectGraph({ filePaths: ['src/A.java'] });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls).toHaveLength(0);
    expect(result.taintPaths).toHaveLength(0);
  });

  it('populates typeHierarchy from projectGraph.typeHierarchy', () => {
    const hierarchy: TypeHierarchy = { classes: { 'Foo': { extends: 'Bar', implements: [] } }, interfaces: {} };
    const pg = makeProjectGraph({ typeHierarchyData: hierarchy });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.typeHierarchy.classes['Foo']).toBeDefined();
    expect(result.typeHierarchy.classes['Foo'].extends).toBe('Bar');
  });
});

describe('CrossFilePass — cross-file taint flows', () => {
  it('maps one cross-file flow to a TaintPath', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 5,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 10,
      targetMethod: 'executeQuery',
    };
    const irB = makeIRWithSink('src/B.java', 10, 'sql_injection', 'CWE-89');
    const pg = makeProjectGraph({
      flows: [flow],
      irMap: new Map([['src/B.java', irB]]),
    });
    const sourceLines = new Map([
      ['src/A.java', ['', '', '', '', 'String id = req.getParam("id");']],
      ['src/B.java', ['', '', '', '', '', '', '', '', '', 'stmt.executeQuery(id);']],
    ]);
    const result = new CrossFilePass().run(pg, sourceLines);
    expect(result.taintPaths).toHaveLength(1);
    const path = result.taintPaths[0];
    expect(path.id).toBe('cf-0');
    expect(path.source.file).toBe('src/A.java');
    expect(path.source.line).toBe(5);
    expect(path.source.type).toBe('http_param');
    expect(path.sink.file).toBe('src/B.java');
    expect(path.sink.line).toBe(10);
    expect(path.sink.type).toBe('sql_injection');
    expect(path.sink.cwe).toBe('CWE-89');
    expect(path.hops).toHaveLength(2);
    expect(path.path_exists).toBe(true);
    expect(path.confidence).toBe(0.7);
  });

  it('skips flow when target IR not found (no sql_injection default)', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 3,
      sourceType: 'http_param',
      targetFile: 'src/Missing.java',
      targetLine: 7,
      targetMethod: 'processInput',
    };
    const pg = makeProjectGraph({
      flows: [flow],
      irMap: new Map(),  // no IR for Missing.java
    });
    const result = new CrossFilePass().run(pg, new Map());
    // Flow is skipped — no default sql_injection fabrication
    expect(result.taintPaths).toHaveLength(0);
  });

  it('skips flow when no matched sink at target line', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 3,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 99,  // no sink at line 99
      targetMethod: 'foo',
    };
    const irB = makeIRWithSink('src/B.java', 10);  // sink at 10, not 99
    const pg = makeProjectGraph({
      flows: [flow],
      irMap: new Map([['src/B.java', irB]]),
    });
    const result = new CrossFilePass().run(pg, new Map());
    // Mismatched line: flow is skipped rather than defaulting to sql_injection
    expect(result.taintPaths).toHaveLength(0);
  });

  it('falls back to empty string for code when sourceLines key missing', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 1,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 1,
      targetMethod: 'foo',
    };
    const irB = makeIRWithSink('src/B.java', 1);  // sink at line 1 so flow is kept
    const pg = makeProjectGraph({
      flows: [flow],
      irMap: new Map([['src/B.java', irB]]),
    });
    // No sourceLines at all — code fields should fall back to ''
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.taintPaths).toHaveLength(1);
    expect(result.taintPaths[0].source.code).toBe('');
    expect(result.taintPaths[0].sink.code).toBe('');
  });

  it('uses source code from sourceLines when present', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 1,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 1,
      targetMethod: 'foo',
    };
    const irB = makeIRWithSink('src/B.java', 1);  // sink at line 1 so flow is kept
    const pg = makeProjectGraph({
      flows: [flow],
      irMap: new Map([['src/B.java', irB]]),
    });
    const sourceLines = new Map([
      ['src/A.java', ['String id = req.getParam("id");']],
      ['src/B.java', ['stmt.execute(id);']],
    ]);
    const result = new CrossFilePass().run(pg, sourceLines);
    expect(result.taintPaths[0].source.code).toBe('String id = req.getParam("id");');
    expect(result.taintPaths[0].sink.code).toBe('stmt.execute(id);');
  });

  it('indexes multiple flows with sequential ids cf-0, cf-1, cf-2', () => {
    const flows: MockFlow[] = [
      { sourceFile: 'A.java', sourceLine: 1, sourceType: 'http_param', targetFile: 'B.java', targetLine: 2, targetMethod: 'm1' },
      { sourceFile: 'A.java', sourceLine: 3, sourceType: 'http_param', targetFile: 'C.java', targetLine: 4, targetMethod: 'm2' },
      { sourceFile: 'D.java', sourceLine: 5, sourceType: 'http_param', targetFile: 'E.java', targetLine: 6, targetMethod: 'm3' },
    ];
    // Provide target IRs with sinks at the expected lines so all three flows are kept
    const irMap = new Map([
      ['B.java', makeIRWithSink('B.java', 2)],
      ['C.java', makeIRWithSink('C.java', 4)],
      ['E.java', makeIRWithSink('E.java', 6)],
    ]);
    const pg = makeProjectGraph({ flows, irMap });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.taintPaths.map(p => p.id)).toEqual(['cf-0', 'cf-1', 'cf-2']);
  });
});

describe('CrossFilePass — resolved inter-file calls', () => {
  it('skips same-file calls', () => {
    const rc: MockResolvedCall = {
      sourceFile: 'src/A.java',
      targetFile: 'src/A.java',  // same file
      targetMethod: 'helper',
      resolution: 'exact',
      call: { method_name: 'helper', in_method: 'main', location: { line: 5, column: 0 }, arguments: [] },
    };
    const pg = makeProjectGraph({
      filePaths: ['src/A.java'],
      resolvedCallsMap: new Map([['src/A.java', [rc]]]),
    });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls).toHaveLength(0);
  });

  it('maps exact cross-file call with resolved=true', () => {
    const rc: MockResolvedCall = {
      sourceFile: 'src/A.java',
      targetFile: 'src/B.java',
      targetMethod: 'process',
      resolution: 'exact',
      call: {
        method_name: 'process',
        in_method: 'handle',
        location: { line: 10, column: 4 },
        arguments: [{ expression: 'id' }],
      },
    };
    const pg = makeProjectGraph({
      filePaths: ['src/A.java'],
      resolvedCallsMap: new Map([['src/A.java', [rc]]]),
    });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls).toHaveLength(1);
    const call = result.crossFileCalls[0];
    expect(call.resolved).toBe(true);
    expect(call.from.file).toBe('src/A.java');
    expect(call.from.method).toBe('handle');
    expect(call.from.line).toBe(10);
    expect(call.to.file).toBe('src/B.java');
    expect(call.to.method).toBe('process');
    expect(call.args_mapping).toHaveLength(1);
    expect(call.args_mapping[0].caller_arg).toBe(0);
  });

  it('maps fuzzy cross-file call with resolved=false', () => {
    const rc: MockResolvedCall = {
      sourceFile: 'src/A.java',
      targetFile: 'src/B.java',
      targetMethod: 'compute',
      resolution: 'fuzzy',
      call: { method_name: 'compute', location: { line: 3, column: 0 } },
    };
    const pg = makeProjectGraph({
      filePaths: ['src/A.java'],
      resolvedCallsMap: new Map([['src/A.java', [rc]]]),
    });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls[0].resolved).toBe(false);
  });

  it('handles call with no arguments (empty args_mapping)', () => {
    const rc: MockResolvedCall = {
      sourceFile: 'src/A.java',
      targetFile: 'src/B.java',
      targetMethod: 'doWork',
      resolution: 'exact',
      call: { method_name: 'doWork', location: { line: 1, column: 0 } },
    };
    const pg = makeProjectGraph({
      filePaths: ['src/A.java'],
      resolvedCallsMap: new Map([['src/A.java', [rc]]]),
    });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls[0].args_mapping).toHaveLength(0);
  });

  it('generates correct call id format sourceFile:line:method', () => {
    const rc: MockResolvedCall = {
      sourceFile: 'src/A.java',
      targetFile: 'src/B.java',
      targetMethod: 'execute',
      resolution: 'exact',
      call: { method_name: 'execute', location: { line: 15, column: 0 } },
    };
    const pg = makeProjectGraph({
      filePaths: ['src/A.java'],
      resolvedCallsMap: new Map([['src/A.java', [rc]]]),
    });
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.crossFileCalls[0].id).toBe('src/A.java:15:execute');
  });
});

// ---------------------------------------------------------------------------
// Type-axis dedup (cognium-dev#143 / PR A)
// ---------------------------------------------------------------------------
//
// Direct cross-file flows and field-binding / interprocedural flows can both
// land at the same source/sink coordinates but with different vuln classes
// (e.g. a Jenkins field-binding flow into `execute()` produces a
// command_injection sink while a direct flow into the same `execute()`
// produces a code_injection sink because the matched sink at that line came
// from a different sink-entry).  Prior to the fix the IP-path dedup keyed
// only on `(source.file, source.line, sink.file, sink.line)` and would
// silently drop the second finding.  The fix adds `sink.type` to the dedup
// key.
describe('CrossFilePass — dedup by type (PR A)', () => {
  /**
   * Build a ProjectGraph where the IR returned by `getIR(file)` flips its
   * sink entry between calls.  The first call (used by the direct-flow
   * branch at line ~53) returns an IR whose sink at the target line is type
   * T1; the second call (used by the IP-path branch at line ~113) returns
   * an IR whose sink at the same line is type T2.  This is the only way
   * the test can drive `matchedSink.type` to differ between the two
   * branches given the current code.
   */
  function makeFlippingProjectGraph(
    targetFile: string,
    targetLine: number,
    typeFirst: string,
    cweFirst: string,
    typeSecond: string,
    cweSecond: string,
    flows: MockFlow[],
    ipPaths: ReturnType<typeof makeIpPath>[],
  ): ProjectGraph {
    const irFirst  = makeIRWithSink(targetFile, targetLine, typeFirst,  cweFirst);
    const irSecond = makeIRWithSink(targetFile, targetLine, typeSecond, cweSecond);
    let calls = 0;
    return {
      get filePaths() { return []; },
      getIR(_path: string) {
        const ir = calls === 0 ? irFirst : irSecond;
        calls += 1;
        return ir;
      },
      get resolver() {
        return {
          findCrossFileTaintFlows: () => flows,
          findInterproceduralTaintPaths: () => [],
          findFieldBindingTaintPaths: () => ipPaths,
          getResolvedCallsFromFile: () => [],
          getMethodTaintInfo: () => undefined,
        };
      },
      get typeHierarchy() {
        return { toTypeHierarchyData: () => ({ classes: {}, interfaces: {} } as TypeHierarchy) };
      },
    } as unknown as ProjectGraph;
  }

  /** Mirrors the InterproceduralTaintPath shape consumed by cross-file-pass. */
  function makeIpPath(
    sourceFile: string,
    sourceLine: number,
    sourceType: string,
    sinkFile: string,
    sinkLine: number,
  ) {
    return {
      source: { file: sourceFile, line: sourceLine, type: sourceType },
      sink:   { file: sinkFile,   line: sinkLine,   type: 'placeholder', cwe: 'CWE-0' },
      hops:   [
        { file: sourceFile, line: sourceLine, method: '', kind: 'source' as const },
        { file: sinkFile,   line: sinkLine,   method: '', kind: 'sink'   as const },
      ],
      confidence: 0.7,
    };
  }

  it('emits both findings when direct + IP land at same coords with different sink.type', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 5,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 10,
      targetMethod: 'execute',
    };
    const ipPath = makeIpPath('src/A.java', 5, 'http_param', 'src/B.java', 10);
    const pg = makeFlippingProjectGraph(
      'src/B.java', 10,
      'command_injection', 'CWE-77',  // direct-flow branch sees this
      'code_injection',    'CWE-94',  // IP-path branch sees this
      [flow], [ipPath],
    );
    const result = new CrossFilePass().run(pg, new Map());
    // Both must be emitted — they describe different vuln classes at the
    // same call site.
    expect(result.taintPaths).toHaveLength(2);
    const types = result.taintPaths.map(p => p.sink.type).sort();
    expect(types).toEqual(['code_injection', 'command_injection']);
  });

  it('still dedups when direct + IP land at same coords with same sink.type', () => {
    const flow: MockFlow = {
      sourceFile: 'src/A.java',
      sourceLine: 5,
      sourceType: 'http_param',
      targetFile: 'src/B.java',
      targetLine: 10,
      targetMethod: 'execute',
    };
    const ipPath = makeIpPath('src/A.java', 5, 'http_param', 'src/B.java', 10);
    // Both branches see the SAME sink type — IP must be deduped.
    const pg = makeFlippingProjectGraph(
      'src/B.java', 10,
      'command_injection', 'CWE-77',
      'command_injection', 'CWE-77',
      [flow], [ipPath],
    );
    const result = new CrossFilePass().run(pg, new Map());
    expect(result.taintPaths).toHaveLength(1);
    expect(result.taintPaths[0].sink.type).toBe('command_injection');
  });
});
