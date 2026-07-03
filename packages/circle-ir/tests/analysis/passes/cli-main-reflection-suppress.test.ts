/**
 * Tests for Pass #110: cli-main-reflection-suppress (category: security)
 *
 * Verifies the per-file Java heuristic that drops reflection
 * `code_injection` sinks in fat-jar CLI tool files (cognium-dev #162
 * Option B).
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { CliMainReflectionSuppressPass } from '../../../src/analysis/passes/cli-main-reflection-suppress-pass.js';
import type {
  CircleIR,
  MethodInfo,
  ParameterInfo,
  SastFinding,
  SinkType,
  TaintSink,
  TypeInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function makeParam(name: string, type: string): ParameterInfo {
  return { name, type, annotations: [] };
}

function makeMethod(
  name: string,
  params: ParameterInfo[] = [],
  annotations: string[] = [],
  modifiers: string[] = [],
): MethodInfo {
  return {
    name,
    return_type: null,
    parameters: params,
    annotations,
    modifiers,
    start_line: 1,
    end_line: 1,
  };
}

function makeType(opts: {
  name: string;
  annotations?: string[];
  extends?: string | null;
  implements?: string[];
  methods?: MethodInfo[];
}): TypeInfo {
  return {
    name: opts.name,
    kind: 'class',
    package: null,
    extends: opts.extends ?? null,
    implements: opts.implements ?? [],
    annotations: opts.annotations ?? [],
    methods: opts.methods ?? [],
    fields: [],
    start_line: 1,
    end_line: 100,
  };
}

function makeIR(opts: {
  language?: string;
  types: TypeInfo[];
  sinks: TaintSink[];
}): CircleIR {
  return {
    meta: {
      circle_ir: '3.0',
      file: 'T.java',
      language: opts.language ?? 'java',
      loc: 1,
      hash: '',
    },
    types: opts.types,
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: opts.sinks, sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function runOn(opts: {
  language?: string;
  types: TypeInfo[];
  sinks: TaintSink[];
}): { kept: TaintSink[]; cliMainSignal: boolean; droppedCount: number } {
  const ir = makeIR(opts);
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code: '',
    language: opts.language ?? 'java',
    config: {
      sources: [],
      sinks: [],
      sanitizers: [],
    } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
    getFindings: () => findings,
  };
  const result = new CliMainReflectionSuppressPass().run(ctx);
  return {
    kept: graph.ir.taint.sinks,
    cliMainSignal: result.cliMainSignal,
    droppedCount: result.droppedCount,
  };
}

function reflSink(method: string, type: SinkType = 'code_injection'): TaintSink {
  return {
    type,
    cwe: 'CWE-094',
    location: 'test',
    line: 42,
    confidence: 1.0,
    method,
  };
}

const MAIN_METHOD = makeMethod(
  'main',
  [makeParam('args', 'String[]')],
  [],
  ['public', 'static'],
);

// ---------------------------------------------------------------------------
// TP: Sinks that MUST be dropped
// ---------------------------------------------------------------------------

describe('CliMainReflectionSuppressPass — true-positive drops', () => {
  it('TP-1: main + loadClass sink → dropped', () => {
    const { kept, cliMainSignal, droppedCount } = runOn({
      types: [makeType({ name: 'TestRig', methods: [MAIN_METHOD] })],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(true);
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-2: main + Class.forName + Constructor.newInstance + Method.invoke → all dropped', () => {
    const { kept, droppedCount } = runOn({
      types: [makeType({ name: 'TestRig', methods: [MAIN_METHOD] })],
      sinks: [
        reflSink('forName'),
        reflSink('newInstance'),
        reflSink('invoke'),
        reflSink('getConstructor'),
        reflSink('getMethod'),
      ],
    });
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(5);
  });

  it('TP-3: fully-qualified String[] parameter type still matches', () => {
    const method = makeMethod(
      'main',
      [makeParam('args', 'java.lang.String[]')],
      [],
      ['public', 'static'],
    );
    const { kept, droppedCount } = runOn({
      types: [makeType({ name: 'CLI', methods: [method] })],
      sinks: [reflSink('loadClass')],
    });
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });

  it('TP-4: main + defineClass → dropped', () => {
    const { kept, droppedCount } = runOn({
      types: [makeType({ name: 'CLI', methods: [MAIN_METHOD] })],
      sinks: [reflSink('defineClass')],
    });
    expect(kept).toHaveLength(0);
    expect(droppedCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// TN: Sinks that MUST be preserved (recall guards)
// ---------------------------------------------------------------------------

describe('CliMainReflectionSuppressPass — recall guards', () => {
  it('TN-1: @RestController with same reflection sinks → all preserved', () => {
    const { kept, cliMainSignal, droppedCount } = runOn({
      types: [
        makeType({
          name: 'ApiController',
          annotations: ['RestController'],
          methods: [MAIN_METHOD], // main also present
        }),
      ],
      sinks: [reflSink('loadClass'), reflSink('forName')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(2);
    expect(droppedCount).toBe(0);
  });

  it('TN-2: HttpServlet subclass with reflection → preserved', () => {
    const { kept, cliMainSignal } = runOn({
      types: [
        makeType({
          name: 'MyServlet',
          extends: 'HttpServlet',
          methods: [MAIN_METHOD],
        }),
      ],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(1);
  });

  it('TN-3: no main method → gate inactive, sinks preserved', () => {
    const { kept, cliMainSignal } = runOn({
      types: [makeType({ name: 'PlainClass', methods: [] })],
      sinks: [reflSink('loadClass'), reflSink('forName')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(2);
  });

  it('TN-4: main + ScriptEngine.eval → preserved (not in reflection set)', () => {
    const { kept, droppedCount } = runOn({
      types: [makeType({ name: 'CLI', methods: [MAIN_METHOD] })],
      sinks: [reflSink('eval'), reflSink('evaluate'), reflSink('parseExpression')],
    });
    expect(kept).toHaveLength(3);
    expect(droppedCount).toBe(0);
  });

  it('TN-5: main + reflection but sink.type !== code_injection → preserved', () => {
    // e.g. hypothetical sink where invoke is used as command_injection tag
    const { kept } = runOn({
      types: [makeType({ name: 'CLI', methods: [MAIN_METHOD] })],
      sinks: [reflSink('invoke', 'command_injection')],
    });
    expect(kept).toHaveLength(1);
  });

  it('TN-6: main + reflection but no sink.method → preserved', () => {
    const sinkNoMethod: TaintSink = {
      type: 'code_injection',
      cwe: 'CWE-094',
      location: 'test',
      line: 5,
      confidence: 1.0,
    };
    const { kept } = runOn({
      types: [makeType({ name: 'CLI', methods: [MAIN_METHOD] })],
      sinks: [sinkNoMethod],
    });
    expect(kept).toHaveLength(1);
  });

  it('TN-7: language !== java → gate inactive (Python main)', () => {
    const { kept, cliMainSignal } = runOn({
      language: 'python',
      types: [makeType({ name: 'CLI', methods: [MAIN_METHOD] })],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(1);
  });

  it('TN-8: @Service stereotype disables gate', () => {
    const { cliMainSignal, kept } = runOn({
      types: [
        makeType({
          name: 'MyService',
          annotations: ['Service'],
          methods: [MAIN_METHOD],
        }),
      ],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(1);
  });

  it('TN-9: @GetMapping method disables gate', () => {
    const controller = makeType({
      name: 'ApiController',
      methods: [
        MAIN_METHOD,
        makeMethod('get', [], ['GetMapping']),
      ],
    });
    const { cliMainSignal, kept } = runOn({
      types: [controller],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(1);
  });

  it('TN-10: annotation with @ prefix and args normalized correctly', () => {
    const { cliMainSignal } = runOn({
      types: [
        makeType({
          name: 'Ctrl',
          annotations: ['@RestController("v1")'],
          methods: [MAIN_METHOD],
        }),
      ],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
  });

  it('TN-11: qualified annotation (org.springframework.web.bind.annotation.RestController) normalized', () => {
    const { cliMainSignal } = runOn({
      types: [
        makeType({
          name: 'Ctrl',
          annotations: ['org.springframework.web.bind.annotation.RestController'],
          methods: [MAIN_METHOD],
        }),
      ],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
  });

  it('TN-12: main with String args (not String[]) → not main', () => {
    const notMain = makeMethod('main', [makeParam('s', 'String')]);
    const { cliMainSignal, kept } = runOn({
      types: [makeType({ name: 'X', methods: [notMain] })],
      sinks: [reflSink('loadClass')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(1);
  });

  it('TN-13: CommandLineRunner implementer disables gate (Spring Boot CLI)', () => {
    const { cliMainSignal, kept } = runOn({
      types: [
        makeType({
          name: 'Boot',
          implements: ['CommandLineRunner'],
          methods: [MAIN_METHOD],
        }),
      ],
      sinks: [reflSink('forName')],
    });
    expect(cliMainSignal).toBe(false);
    expect(kept).toHaveLength(1);
  });

  it('TN-14: mixed drop set — reflection dropped, script eval kept', () => {
    const { kept, droppedCount } = runOn({
      types: [makeType({ name: 'CLI', methods: [MAIN_METHOD] })],
      sinks: [
        reflSink('loadClass'),
        reflSink('eval'),
        reflSink('newInstance'),
      ],
    });
    expect(droppedCount).toBe(2);
    expect(kept).toHaveLength(1);
    expect(kept[0].method).toBe('eval');
  });
});
