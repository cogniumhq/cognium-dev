/**
 * Tests for TaintPropagationPass
 *
 * Focuses on the three supplementary flow-detection strategies that the pass
 * adds on top of the DFG-based propagation:
 *   - Array element flows
 *   - Collection / iterator flows
 *   - Direct parameter-to-sink (interprocedural) flows
 *
 * Also covers the early-exit guard (empty sources / sinks) and the dead-code
 * FP filter that discards flows whose sink line is unreachable.
 */

import { describe, it, expect } from 'vitest';
import { TaintPropagationPass } from '../../../src/analysis/passes/taint-propagation-pass.js';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import type { CircleIR, TaintSink, TaintSource, CallInfo } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';
import type { ConstantPropagatorResult } from '../../../src/analysis/passes/constant-propagation-pass.js';
import type { SinkFilterResult } from '../../../src/analysis/passes/sink-filter-pass.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(calls: CallInfo[] = [], language = 'java'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language, loc: 100, hash: '' },
    types: [],
    calls,
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeSink(line: number, type = 'sql_injection', cwe = 'CWE-89'): TaintSink {
  return { type: type as TaintSink['type'], cwe, line, location: `line ${line}`, confidence: 0.9 };
}

function makeSource(line: number, type: TaintSource['type'] = 'http_param'): TaintSource {
  return { type, location: `line ${line}`, severity: 'high', line, confidence: 0.9 };
}

function makeInterproceduralSource(line: number, paramName: string, methodName: string): TaintSource {
  return {
    type: 'interprocedural_param',
    location: `String ${paramName} in ${methodName}`,
    severity: 'high',
    line,
    confidence: 0.9,
  };
}

const emptyConfig: TaintConfig = { sources: [], sinks: [], sanitizers: [] };

function makeConstProp(overrides: Partial<ConstantPropagatorResult> = {}): ConstantPropagatorResult {
  return {
    unreachableLines:     overrides.unreachableLines     ?? new Set(),
    tainted:              overrides.tainted              ?? new Set(),
    taintedArrayElements: overrides.taintedArrayElements ?? new Map(),
    symbols:              overrides.symbols              ?? new Map(),
    sanitizedVars:        overrides.sanitizedVars        ?? new Set(),
    synchronizedLines:    overrides.synchronizedLines    ?? new Set(),
    instanceFieldTaint:   overrides.instanceFieldTaint   ?? new Map(),
    conditionalTaints:    overrides.conditionalTaints    ?? new Map(),
    lineConditions:       overrides.lineConditions       ?? new Map(),
    taintedCollections:   overrides.taintedCollections   ?? new Map(),
  };
}

function makeCtx(opts: {
  language?:  string;
  ir?:        CircleIR;
  sources?:   TaintSource[];
  sinks?:     TaintSink[];
  constProp?: ConstantPropagatorResult;
}): PassContext {
  const lang   = opts.language ?? 'java';
  const ir     = opts.ir ?? makeIR();
  const graph  = new CodeGraph(ir);

  const sinkFilter: SinkFilterResult = {
    sources:    opts.sources    ?? [],
    sinks:      opts.sinks      ?? [],
    sanitizers: [],
  };

  const constProp = opts.constProp ?? makeConstProp();

  const resultMap = new Map<string, unknown>([
    ['sink-filter',          sinkFilter],
    ['constant-propagation', constProp],
  ]);

  return {
    graph,
    code:       '',
    language:   lang,
    config:     emptyConfig,
    getResult:  <T>(name: string) => resultMap.get(name) as T,
    hasResult:  (name: string)    => resultMap.has(name),
    addFinding: () => {},
  };
}

// ---------------------------------------------------------------------------
// Tests: early-exit guard
// ---------------------------------------------------------------------------

describe('TaintPropagationPass — early-exit guard', () => {
  it('returns empty flows when sources list is empty', () => {
    const ctx    = makeCtx({ sources: [], sinks: [makeSink(10)] });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows).toHaveLength(0);
  });

  it('returns empty flows when sinks list is empty', () => {
    const ctx    = makeCtx({ sources: [makeSource(5)], sinks: [] });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows).toHaveLength(0);
  });

  it('returns empty flows when both sources and sinks are empty', () => {
    const ctx    = makeCtx({ sources: [], sinks: [] });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: array element flows
// ---------------------------------------------------------------------------

describe('TaintPropagationPass — array element flows', () => {
  it('detects a flow for a tainted array element used at a sink', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      receiver:    'stmt',
      arguments:   [{ position: 0, expression: 'params[0]', variable: undefined, literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'processRequest',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(10)],
      constProp: makeConstProp({ taintedArrayElements: new Map([['params', new Set(['0'])]]) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 10)).toBe(true);
  });

  it('detects a flow for a wildcard-tainted array (index *)', () => {
    const calls: CallInfo[] = [{
      method_name: 'exec',
      arguments:   [{ position: 0, expression: 'args[2]', variable: undefined, literal: null }],
      location:    { line: 15, column: 0 },
      in_method:   'run',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(15, 'command_injection', 'CWE-78')],
      constProp: makeConstProp({ taintedArrayElements: new Map([['args', new Set(['*'])]]) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 15)).toBe(true);
  });

  it('does NOT emit a flow when the accessed array index is not tainted', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, expression: 'params[1]', variable: undefined, literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'test',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(10)],
      // only index '0' is tainted; index '1' is not
      constProp: makeConstProp({ taintedArrayElements: new Map([['params', new Set(['0'])]]) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    // No array flow for params[1]
    expect(result.flows.filter(f => f.source_line === 5 && f.sink_line === 10)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: collection / iterator flows
// ---------------------------------------------------------------------------

describe('TaintPropagationPass — collection flows', () => {
  it('detects flow when a tainted variable is directly passed to a sink call', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, variable: 'userInput', expression: 'userInput', literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'process',
    }];
    const ir  = makeIR(calls);
    // 'userInput' must be in constProp.tainted (unscoped) so the FP check doesn't discard it
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(10)],
      constProp: makeConstProp({ tainted: new Set(['userInput']) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 10)).toBe(true);
  });

  it('detects flow via collection .get() expression', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, expression: 'params.get(0)', variable: undefined, literal: null }],
      location:    { line: 20, column: 0 },
      in_method:   'query',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(20)],
      constProp: makeConstProp({ tainted: new Set(['params']) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 20)).toBe(true);
  });

  it('detects flow via .poll() iterator method', () => {
    const calls: CallInfo[] = [{
      method_name: 'exec',
      arguments:   [{ position: 0, expression: 'queue.poll()', variable: undefined, literal: null }],
      location:    { line: 30, column: 0 },
      in_method:   'consume',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(30, 'command_injection', 'CWE-78')],
      constProp: makeConstProp({ tainted: new Set(['queue']) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 30)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tests: interprocedural parameter-to-sink flows
// ---------------------------------------------------------------------------

describe('TaintPropagationPass — interprocedural parameter flows', () => {
  it('detects flow from interprocedural param source to sink call', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, variable: 'userId', expression: 'userId', literal: null }],
      location:    { line: 25, column: 0 },
      in_method:   'handleRequest',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources: [makeInterproceduralSource(3, 'userId', 'handleRequest')],
      sinks:   [makeSink(25)],
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 25)).toBe(true);
  });

  it('does NOT emit flow when param name does not match call argument', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, variable: 'otherVar', expression: 'otherVar', literal: null }],
      location:    { line: 25, column: 0 },
      in_method:   'handleRequest',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources: [makeInterproceduralSource(3, 'userId', 'handleRequest')],
      sinks:   [makeSink(25)],
    });
    const result = new TaintPropagationPass().run(ctx);
    // 'userId' not in call arguments → no param flow
    expect(result.flows.filter(f => f.source_line === 3 && f.sink_line === 25)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: dead-code FP filter
// ---------------------------------------------------------------------------

describe('TaintPropagationPass — dead-code FP filter', () => {
  it('suppresses array element flow when sink line is unreachable', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, expression: 'params[0]', variable: undefined, literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'test',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(10)],
      constProp: makeConstProp({
        taintedArrayElements: new Map([['params', new Set(['0'])]]),
        unreachableLines:     new Set([10]),  // sink line is dead code
      }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.filter(f => f.sink_line === 10)).toHaveLength(0);
  });

  it('suppresses collection flow when sink line is unreachable', () => {
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, variable: 'userInput', expression: 'userInput', literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'test',
    }];
    const ir  = makeIR(calls);
    const ctx = makeCtx({
      ir,
      sources:   [makeSource(5)],
      sinks:     [makeSink(10)],
      constProp: makeConstProp({
        tainted:          new Set(['userInput']),
        unreachableLines: new Set([10]),
      }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.filter(f => f.sink_line === 10)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: expression-scan flows (issue #18)
//
// These tests validate the language-agnostic fallback added to bridge two
// gaps that previously suppressed Python flows for every non-XSS category:
//   1. Languages without a per-language DFG builder produce empty DFGs, so
//      the def-use-chain propagator can never emit a flow.
//   2. Call-argument extraction may leave `arg.variable` null when the
//      argument is a compound expression (e.g. concatenation), defeating
//      the equality check used by the DFG-based propagator.
//
// The expression-scan supplement keys off the explicit `source.variable`
// set by `findPythonAssignmentSources` and word-boundary-matches it against
// each sink call argument's expression text. Language-agnostic by design.
// ---------------------------------------------------------------------------

function makeSourceWithVar(line: number, variable: string, type: TaintSource['type'] = 'http_param'): TaintSource {
  return { type, location: `line ${line}`, severity: 'high', line, confidence: 0.9, variable };
}

describe('TaintPropagationPass — expression-scan flows (#18)', () => {
  it('emits a sql_injection flow when a tainted variable appears in a concatenation expression at the sink', () => {
    // Simulates Python `cur.execute("SELECT ... " + uid)` where Python's call-
    // arg extractor leaves arg.variable null because the arg is a binary_operator.
    const calls: CallInfo[] = [{
      method_name: 'execute',
      receiver:    'cur',
      arguments:   [{ position: 0, expression: '"SELECT * FROM users WHERE id = " + uid', variable: undefined, literal: null }],
      location:    { line: 8, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(5, 'uid', 'http_body')],
      sinks:    [makeSink(8, 'sql_injection', 'CWE-89')],
    });
    const result = new TaintPropagationPass().run(ctx);
    const flow = result.flows.find(f => f.source_line === 5 && f.sink_line === 8);
    expect(flow).toBeDefined();
    expect(flow?.sink_type).toBe('sql_injection');
  });

  it('emits a command_injection flow for `os.system(cmd)` where cmd is a tainted assignment variable', () => {
    const calls: CallInfo[] = [{
      method_name: 'system',
      receiver:    'os',
      arguments:   [{ position: 0, expression: 'cmd', variable: undefined, literal: null }],
      location:    { line: 5, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(4, 'cmd', 'http_param')],
      sinks:    [makeSink(5, 'command_injection', 'CWE-78')],
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 5 && f.sink_type === 'command_injection')).toBe(true);
  });

  it('emits a path_traversal flow for `open(fname, "rb")` where fname is a tainted assignment variable', () => {
    const calls: CallInfo[] = [{
      method_name: 'open',
      arguments:   [{ position: 0, expression: 'fname', variable: undefined, literal: null }],
      location:    { line: 4, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(3, 'fname', 'http_param')],
      sinks:    [makeSink(4, 'path_traversal', 'CWE-22')],
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.some(f => f.sink_line === 4 && f.sink_type === 'path_traversal')).toBe(true);
  });

  it('emits TWO distinct flows when two sinks of different types coexist at the same line', () => {
    // Probe-confirmed: cur.execute("SELECT..." + uid) registers both xss
    // (heuristic) and sql_injection sinks at the same line. Both must emit.
    const calls: CallInfo[] = [{
      method_name: 'execute',
      receiver:    'cur',
      arguments:   [{ position: 0, expression: '"SELECT * FROM users WHERE id = " + uid', variable: undefined, literal: null }],
      location:    { line: 8, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(5, 'uid', 'http_body')],
      sinks:    [
        makeSink(8, 'xss',           'CWE-79'),
        makeSink(8, 'sql_injection', 'CWE-89'),
      ],
    });
    const result = new TaintPropagationPass().run(ctx);
    const types = result.flows.filter(f => f.sink_line === 8).map(f => f.sink_type).sort();
    expect(types).toEqual(['sql_injection', 'xss']);
  });

  it('respects sink argPositions — does NOT emit when matching variable is in a non-tainted argument position', () => {
    const calls: CallInfo[] = [{
      method_name: 'execute',
      receiver:    'cur',
      arguments:   [
        { position: 0, expression: '"SELECT * FROM users WHERE id = ?"', variable: undefined, literal: null },
        { position: 1, expression: 'uid',                                  variable: undefined, literal: null },
      ],
      location:    { line: 8, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(5, 'uid', 'http_body')],
      // sink declares only position 0 is tainted (parameterised query)
      sinks:    [{ type: 'sql_injection', cwe: 'CWE-89', line: 8, location: 'line 8', confidence: 0.9, argPositions: [0] }],
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.filter(f => f.source_line === 5 && f.sink_line === 8)).toHaveLength(0);
  });

  it('does NOT match substrings (word-boundary required)', () => {
    // Source variable 'id' must NOT match identifiers like 'fid' or 'user_id'.
    const calls: CallInfo[] = [{
      method_name: 'execute',
      arguments:   [{ position: 0, expression: '"SELECT * FROM t WHERE k = " + fid', variable: undefined, literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(5, 'id', 'http_param')],
      sinks:    [makeSink(10, 'sql_injection', 'CWE-89')],
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.filter(f => f.source_line === 5 && f.sink_line === 10)).toHaveLength(0);
  });

  it('does NOT emit when sink line is in unreachable (dead) code', () => {
    const calls: CallInfo[] = [{
      method_name: 'execute',
      arguments:   [{ position: 0, expression: '"x = " + uid', variable: undefined, literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(5, 'uid', 'http_param')],
      sinks:    [makeSink(10, 'sql_injection', 'CWE-89')],
      constProp: makeConstProp({ unreachableLines: new Set([10]) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.filter(f => f.sink_line === 10)).toHaveLength(0);
  });

  it('does NOT emit when source has no `variable` field (Java-style sources are unaffected)', () => {
    const calls: CallInfo[] = [{
      method_name: 'execute',
      arguments:   [{ position: 0, expression: 'something + uid', variable: undefined, literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'java');
    const ctx = makeCtx({
      language: 'java',
      ir,
      // makeSource() does NOT set .variable — typical for Java HTTP sources.
      sources:  [makeSource(5, 'http_param')],
      sinks:    [makeSink(10, 'sql_injection', 'CWE-89')],
    });
    const result = new TaintPropagationPass().run(ctx);
    // Expression-scan supplement must NOT fire — there's no variable to scan for.
    expect(result.flows.filter(f => f.source_line === 5 && f.sink_line === 10)).toHaveLength(0);
  });

  it('does NOT emit when source line is at or after sink line', () => {
    const calls: CallInfo[] = [{
      method_name: 'execute',
      arguments:   [{ position: 0, expression: '"x = " + uid', variable: undefined, literal: null }],
      location:    { line: 5, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      // source line >= sink line: assignment-after-use is impossible flow.
      sources:  [makeSourceWithVar(5, 'uid', 'http_param')],
      sinks:    [makeSink(5, 'sql_injection', 'CWE-89')],
    });
    const result = new TaintPropagationPass().run(ctx);
    expect(result.flows.filter(f => f.source_line === 5 && f.sink_line === 5)).toHaveLength(0);
  });

  it('deduplicates flows when invoked alongside DFG-based propagator producing the same (source,sink,type) triple', () => {
    // Simulate the case where both propagators reach the same flow: the
    // expression-scan supplement must skip if an identical triple already
    // exists in the flows list.
    const calls: CallInfo[] = [{
      method_name: 'executeQuery',
      arguments:   [{ position: 0, variable: 'uid', expression: 'uid', literal: null }],
      location:    { line: 10, column: 0 },
      in_method:   'handler',
    }];
    const ir  = makeIR(calls, 'python');
    const ctx = makeCtx({
      language: 'python',
      ir,
      sources:  [makeSourceWithVar(5, 'uid', 'http_param')],
      sinks:    [makeSink(10, 'sql_injection', 'CWE-89')],
      constProp: makeConstProp({ tainted: new Set(['uid']) }),
    });
    const result = new TaintPropagationPass().run(ctx);
    const sqli = result.flows.filter(f => f.source_line === 5 && f.sink_line === 10 && f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(1);
  });
});
