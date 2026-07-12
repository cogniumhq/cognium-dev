/**
 * Tests for SinkFilterPass
 *
 * Covers the six-stage filtering pipeline:
 *   1. Dead code (unreachable lines)
 *   2. Clean array elements
 *   3. Clean variables
 *   4. Sanitized sinks
 *   5. Python XPath FP reduction
 *   6. JavaScript XSS FP reduction
 * Plus source merging and additional-sink deduplication.
 */

import { describe, it, expect } from 'vitest';
import { SinkFilterPass } from '../../../src/analysis/passes/sink-filter-pass.js';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import type { CircleIR, TaintSink, TaintSource, TaintSanitizer } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';
import type { TaintMatcherResult } from '../../../src/analysis/passes/taint-matcher-pass.js';
import type { ConstantPropagatorResult } from '../../../src/analysis/passes/constant-propagation-pass.js';
import type { LanguageSourcesResult } from '../../../src/analysis/passes/language-sources-pass.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(language = 'java', file = 'Test.java'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 100, hash: '' },
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

function makeSink(line: number, type = 'sql_injection', cwe = 'CWE-89'): TaintSink {
  return { type: type as TaintSink['type'], cwe, line, location: `line ${line}`, confidence: 0.9 };
}

function makeSource(line: number): TaintSource {
  return { type: 'http_param', location: `line ${line}`, severity: 'high', line, confidence: 0.9 };
}

const emptyConfig: TaintConfig = { sources: [], sinks: [], sanitizers: [] };

function makeConstProp(overrides: Partial<ConstantPropagatorResult> = {}): ConstantPropagatorResult {
  return {
    unreachableLines:    overrides.unreachableLines    ?? new Set(),
    tainted:             overrides.tainted             ?? new Set(),
    taintedArrayElements:overrides.taintedArrayElements ?? new Map(),
    symbols:             overrides.symbols             ?? new Map(),
    sanitizedVars:       overrides.sanitizedVars       ?? new Set(),
    synchronizedLines:   overrides.synchronizedLines   ?? new Set(),
    instanceFieldTaint:  overrides.instanceFieldTaint  ?? new Map(),
    conditionalTaints:   overrides.conditionalTaints   ?? new Map(),
    lineConditions:      overrides.lineConditions      ?? new Map(),
    taintedCollections:  overrides.taintedCollections  ?? new Map(),
  };
}

function makeCtx(opts: {
  language?: string;
  code?: string;
  ir?: CircleIR;
  sources?: TaintSource[];
  sinks?: TaintSink[];
  taintSanitizers?: TaintSanitizer[];
  additionalSources?: TaintSource[];
  additionalSinks?: TaintSink[];
  constProp?: ConstantPropagatorResult;
  pyTaintedVars?: Map<string, number>;
  pySanitizedVars?: Set<string>;
  jsTaintedVars?: Map<string, number>;
}): PassContext {
  const lang = opts.language ?? 'java';
  const ir   = opts.ir ?? makeIR(lang);
  const graph = new CodeGraph(ir);

  const taintMatcher: TaintMatcherResult = {
    sources:          opts.sources         ?? [],
    sinks:            opts.sinks           ?? [],
    sanitizers:       opts.taintSanitizers ?? [],
    sanitizerMethods: [],
    config:           emptyConfig,
  };

  const langSources: LanguageSourcesResult = {
    additionalSources: opts.additionalSources ?? [],
    additionalSinks:   opts.additionalSinks   ?? [],
    pyTaintedVars:     opts.pyTaintedVars     ?? new Map(),
    pySanitizedVars:   opts.pySanitizedVars   ?? new Set(),
    jsTaintedVars:     opts.jsTaintedVars     ?? new Map(),
  };

  const constProp = opts.constProp ?? makeConstProp();

  const resultMap = new Map<string, unknown>([
    ['taint-matcher',         taintMatcher],
    ['constant-propagation',  constProp],
    ['language-sources',      langSources],
  ]);

  return {
    graph,
    code:     opts.code ?? '',
    language: lang,
    config:   emptyConfig,
    getResult:  <T>(name: string) => resultMap.get(name) as T,
    hasResult:  (name: string)    => resultMap.has(name),
    addFinding: () => {},
  };
}

// ---------------------------------------------------------------------------
// Tests: pass-through and source/sink merging
// ---------------------------------------------------------------------------

describe('SinkFilterPass — pass-through and merging', () => {
  it('returns empty sinks for empty taint-matcher input', () => {
    const ctx = makeCtx({});
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
    expect(result.sources).toHaveLength(0);
  });

  it('passes sinks through unchanged when no filtering criteria match', () => {
    const sink = makeSink(10);
    const ctx  = makeCtx({ sinks: [sink] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
    expect(result.sinks[0].line).toBe(10);
  });

  it('merges additionalSources from language-sources into result.sources', () => {
    const s1 = makeSource(5);
    const s2 = makeSource(8);
    const ctx = makeCtx({ sources: [s1], additionalSources: [s2] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(2);
    expect(result.sources.map(s => s.line)).toContain(5);
    expect(result.sources.map(s => s.line)).toContain(8);
  });

  it('includes non-duplicate additionalSinks in result.sinks', () => {
    const s1 = makeSink(10);
    const s2 = makeSink(15, 'xss', 'CWE-79');
    const ctx = makeCtx({ sinks: [s1], additionalSinks: [s2] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(2);
  });

  it('deduplicates additionalSinks with same line/cwe/type', () => {
    const s1 = makeSink(10);  // sql_injection / CWE-89 / line 10
    const s2 = makeSink(10);  // exact duplicate
    const ctx = makeCtx({ sinks: [s1], additionalSinks: [s2] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('returns sanitizers from taint-matcher unchanged', () => {
    const ctx = makeCtx({});
    const result = new SinkFilterPass().run(ctx);
    expect(Array.isArray(result.sanitizers)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tests: Stage 1 — dead code filter
// ---------------------------------------------------------------------------

describe('SinkFilterPass — Stage 1: dead code filter', () => {
  it('removes sink on an unreachable line', () => {
    const sink = makeSink(5);
    const ctx  = makeCtx({
      sinks:     [sink],
      constProp: makeConstProp({ unreachableLines: new Set([5]) }),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('keeps sinks on reachable lines', () => {
    const sink = makeSink(5);
    const ctx  = makeCtx({
      sinks:     [sink],
      constProp: makeConstProp({ unreachableLines: new Set([99]) }),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('removes only the unreachable sink when multiple sinks present', () => {
    const s1 = makeSink(5);
    const s2 = makeSink(10);
    const ctx = makeCtx({
      sinks:     [s1, s2],
      constProp: makeConstProp({ unreachableLines: new Set([5]) }),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
    expect(result.sinks[0].line).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// Tests: Stage 5 — Python XPath FP reduction
// ---------------------------------------------------------------------------

describe('SinkFilterPass — Stage 5: Python XPath FP reduction', () => {
  // Code lines (1-indexed): line 1='', 2=xpath with query, 3=xpath with key=safe, 4=xpath other_query
  const code = [
    '',
    'result = tree.xpath(query)',
    'result2 = tree.xpath(key=safe)',
    'result3 = tree.xpath(other_query)',
  ].join('\n');

  it('keeps xpath_injection sink when tainted var is present on the sink line', () => {
    const sink = makeSink(2, 'xpath_injection', 'CWE-643');
    const ctx  = makeCtx({
      language:      'python',
      code,
      sinks:         [sink],
      pyTaintedVars: new Map([['query', 1]]),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('removes xpath_injection sink when no tainted var appears on sink line', () => {
    const sink = makeSink(2, 'xpath_injection', 'CWE-643');
    const ctx  = makeCtx({
      language:      'python',
      code,
      sinks:         [sink],
      pyTaintedVars: new Map([['other', 1]]),  // 'other' not on line 2
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xpath_injection sink when tainted var is in pySanitizedVars', () => {
    const sink = makeSink(2, 'xpath_injection', 'CWE-643');
    const ctx  = makeCtx({
      language:       'python',
      code,
      sinks:          [sink],
      pyTaintedVars:  new Map([['query', 1]]),
      pySanitizedVars: new Set(['query']),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xpath_injection when var matches .xpath(key=var) named-arg pattern', () => {
    const sink = makeSink(3, 'xpath_injection', 'CWE-643');
    const ctx  = makeCtx({
      language:      'python',
      code,
      sinks:         [sink],
      pyTaintedVars: new Map([['safe', 1]]),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('does NOT filter non-xpath sinks in Python (e.g. sql_injection)', () => {
    const sink = makeSink(2, 'sql_injection', 'CWE-89');
    const ctx  = makeCtx({
      language:      'python',
      code,
      sinks:         [sink],
      pyTaintedVars: new Map([['other', 1]]),  // no tainted var on line 2
    });
    const result = new SinkFilterPass().run(ctx);
    // sql_injection not touched by stage 5 → still present
    expect(result.sinks).toHaveLength(1);
  });

  it('does not apply Python XPath filtering to non-python languages', () => {
    const sink = makeSink(2, 'xpath_injection', 'CWE-643');
    const ctx  = makeCtx({
      language:      'java',  // not python
      code,
      sinks:         [sink],
      pyTaintedVars: new Map([['other', 1]]),
    });
    const result = new SinkFilterPass().run(ctx);
    // Stage 5 not triggered for Java → sink is kept
    expect(result.sinks).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: Stage 6 — JavaScript XSS FP reduction
// ---------------------------------------------------------------------------

describe('SinkFilterPass — Stage 6: JavaScript XSS FP reduction', () => {
  const code = [
    '',
    'element.innerHTML = id;',
    'document.write("safe text");',
    'element.innerHTML = req.query.id;',
  ].join('\n');

  it('does NOT filter xss sinks when jsTaintedVars is empty', () => {
    const sink = makeSink(3, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language:     'javascript',
      code,
      sinks:        [sink],
      jsTaintedVars: new Map(),  // empty — stage 6 skipped
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('keeps xss sink when a tainted var appears on the sink line', () => {
    const sink = makeSink(2, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language:     'javascript',
      code,
      sinks:        [sink],
      jsTaintedVars: new Map([['id', 1]]),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('removes xss sink when jsTaintedVars populated but no var appears on sink line', () => {
    const sink = makeSink(3, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language:     'javascript',
      code,
      sinks:        [sink],
      jsTaintedVars: new Map([['id', 1]]),  // 'id' not on line 3
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('keeps xss sink matching req.query JS_TAINTED_PATTERN even without explicit var', () => {
    const sink = makeSink(4, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language:     'javascript',
      code,
      sinks:        [sink],
      jsTaintedVars: new Map([['other', 1]]),  // 'other' not on line 4, but pattern matches
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('does not filter non-xss sinks in JavaScript', () => {
    const sink = makeSink(3, 'sql_injection', 'CWE-89');
    const ctx  = makeCtx({
      language:     'javascript',
      code,
      sinks:        [sink],
      jsTaintedVars: new Map([['id', 1]]),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('applies same filtering to TypeScript language', () => {
    const sink = makeSink(3, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language:     'typescript',
      code,
      sinks:        [sink],
      jsTaintedVars: new Map([['id', 1]]),  // 'id' not on line 3
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: Stage 6 — JavaScript XSS FP reduction (sanitizers and string literals)
// ---------------------------------------------------------------------------

describe('SinkFilterPass — Stage 6: XSS sanitizer and string literal filtering', () => {
  it('removes xss sink when DOMPurify.sanitize() is used on the line', () => {
    const code = 'element.innerHTML = DOMPurify.sanitize(userInput);';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when sanitizeHtml() is used on the line', () => {
    const code = 'element.innerHTML = sanitizeHtml(content);';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when escapeHtml() is used on the line', () => {
    const code = 'element.innerHTML = escapeHtml(userInput);';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when validator.escape() is used on the line', () => {
    const code = 'element.innerHTML = validator.escape(input);';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when encodeURIComponent() is used on the line', () => {
    const code = 'element.innerHTML = encodeURIComponent(query);';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when innerHTML is assigned a double-quoted string literal', () => {
    const code = 'element.innerHTML = "<div>Hello World</div>";';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when innerHTML is assigned a single-quoted string literal', () => {
    const code = "element.innerHTML = '<span>Safe</span>';";
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when innerHTML is assigned an empty string', () => {
    const code = 'element.innerHTML = "";';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when outerHTML is assigned a string literal', () => {
    const code = 'element.outerHTML = "<div>Replacement</div>";';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('removes xss sink when innerHTML is assigned a template literal without interpolation', () => {
    const code = 'element.innerHTML = `<div>Static content</div>`;';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('keeps xss sink when innerHTML is assigned a template literal WITH interpolation', () => {
    const code = 'element.innerHTML = `<div>${userInput}</div>`;';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
      jsTaintedVars: new Map([['userInput', 1]]),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('keeps xss sink when innerHTML is assigned a variable (not a literal)', () => {
    const code = 'element.innerHTML = content;';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('removes xss sink when innerHTML RHS is a known string constant from constProp', () => {
    const code = 'element.innerHTML = staticContent;';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const symbols = new Map([
      ['staticContent', { value: '<div>Safe</div>', type: 'string', sourceLine: 1 }],
    ]);
    const ctx = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
      constProp: makeConstProp({ symbols }),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('keeps xss sink when variable is not a known constant', () => {
    const code = 'element.innerHTML = dynamicContent;';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const symbols = new Map([
      ['dynamicContent', { value: null, type: 'unknown', sourceLine: 1 }],
    ]);
    const ctx = makeCtx({
      language: 'javascript',
      code,
      sinks: [sink],
      constProp: makeConstProp({ symbols }),
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('removes xss sink when Angular bypassSecurityTrust is used', () => {
    const code = 'this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(content);';
    const sink = makeSink(1, 'xss', 'CWE-79');
    const ctx  = makeCtx({
      language: 'typescript',
      code,
      sinks: [sink],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: Stage 3 — clean variable filter (nested inner-call false positive)
// ---------------------------------------------------------------------------
// Regression for: Runtime.exec() not recognized as command_injection sink when
// nested inner calls at the same source line (e.g. System.getProperty("user.dir")
// inside r.exec(args, argsEnv, new File(System.getProperty("user.dir")))) have only
// literal arguments, incorrectly causing the outer exec() sink to be filtered out.

describe('SinkFilterPass — Stage 3: nested inner-call does not suppress outer sink', () => {
  it('keeps exec() sink when a nested inner call on the same line has only literal args', () => {
    // Simulates: r.exec(args, argsEnv, new java.io.File(System.getProperty("user.dir")))
    // Before fix: System.getProperty("user.dir") at same line had all-literal args, which
    // caused filterCleanVariableSinks to return false for the exec() sink.
    const execSink: TaintSink = {
      type: 'command_injection',
      cwe:  'CWE-78',
      line: 10,
      location: 'r.exec() in doPost',
      method:   'exec',
      confidence: 0.9,
    };
    const ir = makeIR();
    // Outer call: r.exec(args, argsEnv, <complex expression>)
    ir.calls.push({
      method_name: 'exec',
      receiver:    'r',
      arguments: [
        { position: 0, expression: 'args',    variable: 'args',    literal: null },
        { position: 1, expression: 'argsEnv', variable: 'argsEnv', literal: null },
        { position: 2, expression: 'new java.io.File(System.getProperty("user.dir"))', variable: 'File', literal: null },
      ],
      location: { line: 10, column: 4 },
      in_method: 'doPost',
    });
    // Inner call: System.getProperty("user.dir") — all-literal argument on the same line
    ir.calls.push({
      method_name: 'getProperty',
      receiver:    'System',
      arguments: [
        { position: 0, expression: '"user.dir"', variable: null, literal: 'user.dir' },
      ],
      location: { line: 10, column: 0 },
      in_method: 'doPost',
    });
    const ctx = makeCtx({ ir, sinks: [execSink] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
    expect(result.sinks[0].type).toBe('command_injection');
  });

  it('still filters exec() sink when its OWN args are all string literals (no taint possible)', () => {
    // r.exec("ls -la") — hardcoded command, no user input
    const execSink: TaintSink = {
      type: 'command_injection',
      cwe:  'CWE-78',
      line: 10,
      location: 'r.exec() in doPost',
      method:   'exec',
      confidence: 0.9,
    };
    const ir = makeIR();
    ir.calls.push({
      method_name: 'exec',
      receiver:    'r',
      arguments: [
        { position: 0, expression: '"ls -la"', variable: null, literal: 'ls -la' },
      ],
      location: { line: 10, column: 4 },
      in_method: 'doPost',
    });
    const ctx = makeCtx({ ir, sinks: [execSink] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('keeps exec() sink when it has a variable arg and no inner calls', () => {
    // r.exec(cmd) — cmd is user-controlled (unknown variable)
    const execSink: TaintSink = {
      type: 'command_injection',
      cwe:  'CWE-78',
      line: 10,
      location: 'r.exec() in doPost',
      method:   'exec',
      confidence: 0.9,
    };
    const ir = makeIR();
    ir.calls.push({
      method_name: 'exec',
      receiver:    'r',
      arguments: [
        { position: 0, expression: 'cmd', variable: 'cmd', literal: null },
      ],
      location: { line: 10, column: 4 },
      in_method: 'doPost',
    });
    const ctx = makeCtx({ ir, sinks: [execSink] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('keeps exec() sink for the exec(cmd+bar, argsEnv, new File(...)) overload with inner literal call', () => {
    // r.exec(cmd + bar, argsEnv, new java.io.File(System.getProperty("user.dir")))
    const execSink: TaintSink = {
      type: 'command_injection',
      cwe:  'CWE-78',
      line: 10,
      location: 'r.exec() in doPost',
      method:   'exec',
      confidence: 0.9,
    };
    const ir = makeIR();
    ir.calls.push({
      method_name: 'exec',
      receiver:    'r',
      arguments: [
        { position: 0, expression: 'cmd + bar', variable: 'cmd',    literal: null },
        { position: 1, expression: 'argsEnv',   variable: 'argsEnv', literal: null },
        { position: 2, expression: 'new java.io.File(System.getProperty("user.dir"))', variable: 'File', literal: null },
      ],
      location: { line: 10, column: 4 },
      in_method: 'doPost',
    });
    ir.calls.push({
      method_name: 'getProperty',
      receiver:    'System',
      arguments: [
        { position: 0, expression: '"user.dir"', variable: null, literal: 'user.dir' },
      ],
      location: { line: 10, column: 0 },
      in_method: 'doPost',
    });
    const ctx = makeCtx({ ir, sinks: [execSink] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: Stage 4 — sanitized sinks filter
// ---------------------------------------------------------------------------

describe('SinkFilterPass — Stage 4: sanitized sinks filter', () => {
  it('filters a sql_injection sink when a class-qualified sanitizer call wraps the argument', () => {
    // executeQuery(ESAPI.encodeForSQL(input)) → ESAPI.encodeForSQL is a class-qualified sanitizer
    const sink = makeSink(10, 'sql_injection', 'CWE-89');
    const ir = makeIR();
    ir.calls.push({
      method_name: 'executeQuery',
      receiver:    'stmt',
      arguments: [
        { position: 0, expression: 'ESAPI.encodeForSQL(input)', variable: 'input', literal: null },
      ],
      location: { line: 10, column: 0 },
      in_method: 'doGet',
    });
    const sanitizer: TaintSanitizer = {
      type:      'sql_injection',
      method:    'ESAPI.encodeForSQL()',
      line:      10,
      sanitizes: ['sql_injection'],
    };
    const ctx = makeCtx({ ir, sinks: [sink], taintSanitizers: [sanitizer] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(0);
  });

  it('keeps sink when sanitizer class name does not appear in the call argument', () => {
    // executeQuery(input) — ESAPI sanitizer declared but not used in the expression
    const sink = makeSink(10, 'sql_injection', 'CWE-89');
    const ir = makeIR();
    ir.calls.push({
      method_name: 'executeQuery',
      receiver:    'stmt',
      arguments: [
        { position: 0, expression: 'input', variable: 'input', literal: null },
      ],
      location: { line: 10, column: 0 },
      in_method: 'doGet',
    });
    const sanitizer: TaintSanitizer = {
      type:      'sql_injection',
      method:    'ESAPI.encodeForSQL()',
      line:      10,
      sanitizes: ['sql_injection'],
    };
    const ctx = makeCtx({ ir, sinks: [sink], taintSanitizers: [sanitizer] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });

  it('does not filter sink when sanitizer targets a different sink type', () => {
    // Sanitizer sanitizes xss but the sink is sql_injection
    const sink = makeSink(10, 'sql_injection', 'CWE-89');
    const ir = makeIR();
    ir.calls.push({
      method_name: 'executeQuery',
      receiver:    'stmt',
      arguments: [
        { position: 0, expression: 'escapeHtml(input)', variable: 'input', literal: null },
      ],
      location: { line: 10, column: 0 },
      in_method: 'doGet',
    });
    const sanitizer: TaintSanitizer = {
      type:      'xss',
      method:    'escapeHtml()',
      line:      10,
      sanitizes: ['xss'],
    };
    const ctx = makeCtx({ ir, sinks: [sink], taintSanitizers: [sanitizer] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sinks).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: non-executable source-line gate (cognium-dev #250, 3.168.0)
//
// Locks in the hoist of the `isNonExecutableSourceLine` gate from
// `generateFindings()` (per-file legacy) into `SinkFilterPass.run()`
// (Circle-IR 3.0 pipeline). Sources whose `line` points at an import,
// package, `use`, `#include`, block-comment continuation, line-comment,
// standalone annotation/decorator, blank line, or `const NAME = <literal>`
// declaration are dropped BEFORE `TaintPropagationPass` and
// `InterproceduralPass` run, so no downstream flow generator emits a
// `taint.flows[]` entry with a fabricated `source_line`.
//
// Real-world evidence: openapi-generator (~3.166.0) reported 256/317
// C+H `taint.flows[]` entries with `source.line=10` (Apache-2.0
// license comment continuation). Every downstream flow generator keys
// off `source.line`, so this choke-point gate collapses the entire
// residual at once.
// ---------------------------------------------------------------------------

describe('SinkFilterPass — non-executable source-line gate (#250)', () => {
  // Line-number-annotated fixture mirroring the openapi-generator
  // CodegenConfigurator.java repro (block-comment header + package +
  // imports + real method body).
  const javaCode = [
    '/*',                                                 // 1  block-comment open
    ' * Copyright 2018 OpenAPI-Generator Contributors',   // 2  interior star
    ' *',                                                 // 3  interior star (blank)
    ' * Licensed under the Apache License, Version 2.0',  // 4  interior star
    ' */',                                                // 5  block-comment close
    '',                                                   // 6  blank
    'package org.openapitools.codegen.config;',           // 7  package
    '',                                                   // 8  blank
    'import java.util.List;',                             // 9  import
    'import java.util.Map;',                              // 10 import  <-- #250 telltale
    '',                                                   // 11 blank
    '@Deprecated',                                        // 12 standalone annotation
    'public class Foo {',                                 // 13 class body — executable
    '    public String handle(String x) {',               // 14 executable
    '        return x + " sink";',                        // 15 executable
    '    }',                                              // 16 executable
    '}',                                                  // 17
  ].join('\n');

  it('drops a source on a block-comment line (Java, line 1)', () => {
    const bad = makeSource(1);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(0);
  });

  it('drops a source on a block-comment interior-star line (Java, line 3)', () => {
    const bad = makeSource(3);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(0);
  });

  it('drops a source on a package declaration (Java, line 7)', () => {
    const bad = makeSource(7);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(0);
  });

  it('drops a source on an import line (Java, line 10 — openapi-generator repro)', () => {
    const bad = makeSource(10);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(0);
  });

  it('drops a source on a standalone annotation line (Java, line 12)', () => {
    const bad = makeSource(12);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(0);
  });

  it('drops a source on a blank line (Java, line 6)', () => {
    const bad = makeSource(6);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(0);
  });

  it('preserves a source on an executable statement line (Java, line 15)', () => {
    const good = makeSource(15);
    const ctx = makeCtx({ language: 'java', code: javaCode, sources: [good] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(15);
  });

  it('drops only the fabricated source when both are present (Java)', () => {
    const bad  = makeSource(10);   // import line
    const good = makeSource(15);   // real method body
    const ctx  = makeCtx({
      language: 'java',
      code:     javaCode,
      sources:  [bad, good],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(15);
  });

  it('drops fabricated sources from additionalSources too (Java)', () => {
    // Same as above but the fabricated source comes from
    // langSources.additionalSources instead of taintMatcher.sources.
    const bad  = makeSource(10);
    const good = makeSource(15);
    const ctx  = makeCtx({
      language: 'java',
      code:     javaCode,
      sources:  [good],
      additionalSources: [bad],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(15);
  });

  it('is a full no-op when ctx.code is empty (legacy caller)', () => {
    // Preserves pre-3.168 behaviour for callers that don't pass file
    // text. This guarantees external harnesses / tests that build a
    // PassContext without source text keep observing every source.
    const bad = makeSource(10);
    const ctx = makeCtx({ language: 'java', code: '', sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(10);
  });

  it('is a full no-op on an unknown language (Cobol / etc.)', () => {
    // `isNonExecutableSourceLine` returns false on unrecognised
    // languages, so the gate degrades safely for languages the
    // detector doesn't yet cover.
    const bad = makeSource(10);
    const ctx = makeCtx({ language: 'cobol', code: javaCode, sources: [bad] });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
  });

  it('drops a source on a Python `import` line (line 3)', () => {
    const pyCode = [
      '# Copyright header',                    // 1  py line comment
      '"""Module docstring."""',               // 2  docstring
      'import os',                             // 3  import  <-- fabricated source
      'from flask import Flask, request',      // 4  from-import
      '',                                      // 5  blank
      '@app.route("/x")',                      // 6  standalone decorator
      'def handle():',                         // 7  executable
      '    return request.args.get("x")',      // 8  executable — legit source
    ].join('\n');
    const bad  = makeSource(3);
    const good = makeSource(8);
    const ctx  = makeCtx({
      language: 'python',
      code:     pyCode,
      sources:  [bad, good],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(8);
  });

  it('drops a source on a JavaScript `import` line (line 4)', () => {
    const jsCode = [
      '/**',                                   // 1  jsdoc open
      ' * Foo controller.',                    // 2  jsdoc interior
      ' */',                                   // 3  jsdoc close
      "import express from 'express';",        // 4  import  <-- fabricated source
      "import { readFile } from 'fs/promises';", // 5  import
      '',                                      // 6  blank
      'const app = express();',                // 7  executable
      "app.get('/x', (req, res) => {",         // 8  executable
      '  res.send(req.query.q);',              // 9  executable — legit source
      '});',                                   // 10
    ].join('\n');
    const bad  = makeSource(4);
    const good = makeSource(9);
    const ctx  = makeCtx({
      language: 'javascript',
      code:     jsCode,
      sources:  [bad, good],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(9);
  });

  it('drops a source on a Go `package` line and preserves a body-line source', () => {
    const goCode = [
      '// Copyright header',                   // 1  line comment
      'package foo',                           // 2  package
      '',                                      // 3  blank
      'import (',                              // 4  import block open
      '    "net/http"',                        // 5  import member
      ')',                                     // 6  import block close
      '',                                      // 7  blank
      'func handle(w http.ResponseWriter, r *http.Request) {', // 8  executable
      '    q := r.URL.Query().Get("q")',       // 9  executable — legit source
      '    w.Write([]byte(q))',                // 10 executable
      '}',                                     // 11
    ].join('\n');
    const bad  = makeSource(2);
    const good = makeSource(9);
    const ctx  = makeCtx({
      language: 'go',
      code:     goCode,
      sources:  [bad, good],
    });
    const result = new SinkFilterPass().run(ctx);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].line).toBe(9);
  });
});
