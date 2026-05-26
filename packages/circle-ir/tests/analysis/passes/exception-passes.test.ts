/**
 * Tests for the five Phase-4 exception/reliability passes:
 *   - SwallowedExceptionPass
 *   - BroadCatchPass
 *   - UnhandledExceptionPass
 *   - DoubleClosePass
 *   - UseAfterClosePass
 *
 * Each pass has a positive case (should detect) and a negative case (should not detect).
 * Uses minimal IR fixtures — no WASM parsing required.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';

import { SwallowedExceptionPass } from '../../../src/analysis/passes/swallowed-exception-pass.js';
import { BroadCatchPass } from '../../../src/analysis/passes/broad-catch-pass.js';
import { UnhandledExceptionPass } from '../../../src/analysis/passes/unhandled-exception-pass.js';
import { DoubleClosePass } from '../../../src/analysis/passes/double-close-pass.js';
import { UseAfterClosePass } from '../../../src/analysis/passes/use-after-close-pass.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.java', language: 'java', loc: 20, hash: '' },
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

function makeCtx(ir: CircleIR, code: string, language?: string): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();

  return {
    graph,
    code,
    language: language ?? ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

// ---------------------------------------------------------------------------
// SwallowedExceptionPass
// ---------------------------------------------------------------------------

describe('SwallowedExceptionPass', () => {
  it('detects an empty catch block', () => {
    // Line 1: try {
    // Line 2:   doSomething();
    // Line 3: } catch (IOException e) {
    // Line 4: }
    const code = 'try {\n  doSomething();\n} catch (IOException e) {\n}';
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 4 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'java');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('swallowed-exception');
    expect(ctx.findings[0].line).toBe(3);
  });

  it('does not flag a catch block that logs the exception', () => {
    // Line 1: try {
    // Line 2:   doSomething();
    // Line 3: } catch (IOException e) {
    // Line 4:   logger.error(e);
    // Line 5: }
    const code = 'try {\n  doSomething();\n} catch (IOException e) {\n  logger.error(e);\n}';
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'java');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag catch block that forwards error via callback', () => {
    // Express pattern: try { view.render(opts, cb); } catch (err) { cb(err); }
    const code = 'try {\n  view.render(opts, cb);\n} catch (err) {\n  cb(err);\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag catch block that calls next(err) (Express middleware)', () => {
    const code = 'try {\n  doSomething();\n} catch (e) {\n  next(e);\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag catch block that calls reject(err) (Promise)', () => {
    const code = 'try {\n  doSomething();\n} catch (err) {\n  reject(err);\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('still flags catch block where error is not referenced', () => {
    const code = 'try {\n  doSomething();\n} catch (err) {\n  doOtherThing();\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
  });

  it('skips Rust', () => {
    const code = 'fn foo() {}';
    const ir = makeIR({ meta: { circle_ir: '3.0', file: 'test.rs', language: 'rust', loc: 1, hash: '' } });
    const ctx = makeCtx(ir, code, 'rust');
    new SwallowedExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// BroadCatchPass
// ---------------------------------------------------------------------------

describe('BroadCatchPass', () => {
  it('detects catch(Exception e) in Java', () => {
    // Line 1: try {
    // Line 2:   doSomething();
    // Line 3: } catch (Exception e) {
    // Line 4:   handle(e);
    // Line 5: }
    const code = 'try {\n  doSomething();\n} catch (Exception e) {\n  handle(e);\n}';
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'java');
    new BroadCatchPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('broad-catch');
    expect(ctx.findings[0].line).toBe(3);
  });

  it('does not flag catch(IOException e) in Java', () => {
    const code = 'try {\n  doSomething();\n} catch (IOException e) {\n  handle(e);\n}';
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'java');
    new BroadCatchPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('detects bare except: in Python', () => {
    // Line 1: try:
    // Line 2:   do_something()
    // Line 3: except:
    // Line 4:   pass
    const code = 'try:\n  do_something()\nexcept:\n  pass';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.py', language: 'python', loc: 4, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 4 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'python');
    new BroadCatchPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('broad-catch');
  });

  it('skips JavaScript (no typed catch)', () => {
    const code = 'try {\n  doSomething();\n} catch (e) {\n  handle(e);\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 },
          { id: 1, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new BroadCatchPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// UnhandledExceptionPass
// ---------------------------------------------------------------------------

describe('UnhandledExceptionPass', () => {
  it('detects throw with no try/catch in JS', () => {
    // Line 1: function validate(x) {
    // Line 2:   throw new Error("bad");
    // Line 3: }
    const code = 'function validate(x) {\n  throw new Error("bad");\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 3, hash: '' },
      types: [
        {
          name: 'module',
          kind: 'class',
          start_line: 1,
          end_line: 3,
          methods: [{ name: 'validate', start_line: 1, end_line: 3, parameters: [], is_public: true }],
          fields: [],
          implements: [],
        },
      ],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('unhandled-exception');
    expect(ctx.findings[0].line).toBe(2);
  });

  it('does not flag throw inside a try body (covered range)', () => {
    // Line 1: try {
    // Line 2:   throw new Error("bad");
    // Line 3: } catch (e) {
    // Line 4:   handle(e);
    // Line 5: }
    const code = 'try {\n  throw new Error("bad");\n} catch (e) {\n  handle(e);\n}';
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'normal', start_line: 1, end_line: 2 }, // try body
          { id: 1, type: 'normal', start_line: 3, end_line: 5 }, // catch body
        ],
        edges: [{ from: 0, to: 1, type: 'exception' }],
      },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: TypeError after typeof check', () => {
    const code = [
      'function use(fn) {',                                  // line 1
      '  if (typeof fn !== "function") {',                    // line 2
      '    throw new TypeError("requires a function");',      // line 3
      '  }',                                                  // line 4
      '  fn();',                                              // line 5
      '}',                                                    // line 6
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 6, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 6,
        methods: [{ name: 'use', start_line: 1, end_line: 6, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: RangeError after range check', () => {
    const code = [
      'function setStatus(code) {',                           // line 1
      '  if (code < 100 || code > 999) {',                   // line 2
      '    throw new RangeError("Invalid status code");',     // line 3
      '  }',                                                  // line 4
      '}',                                                    // line 5
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 5,
        methods: [{ name: 'setStatus', start_line: 1, end_line: 5, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: TypeError after negation check', () => {
    const code = [
      'function process(x) {',        // line 1
      '  if (!x) {',                   // line 2
      '    throw new TypeError("x required");', // line 3
      '  }',                           // line 4
      '}',                             // line 5
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 5,
        methods: [{ name: 'process', start_line: 1, end_line: 5, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: Error after guard check', () => {
    // Express pattern: throw new Error("callback function required") after typeof check
    const code = [
      'function process(x) {',               // line 1
      '  if (!x) {',                          // line 2
      '    throw new Error("critical");',     // line 3
      '  }',                                  // line 4
      '}',                                    // line 5
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 5,
        methods: [{ name: 'process', start_line: 1, end_line: 5, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: Error after typeof check (Express pattern)', () => {
    const code = [
      'function use(fn) {',                                         // line 1
      '  if (typeof fn !== "function") {',                           // line 2
      '    throw new Error("callback function required");',          // line 3
      '  }',                                                         // line 4
      '}',                                                           // line 5
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 5,
        methods: [{ name: 'use', start_line: 1, end_line: 5, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: Error after === check (Express cookie pattern)', () => {
    const code = [
      'function setCookie(signed, secret) {',            // line 1
      '  if (signed && !secret) {',                       // line 2
      '    throw new Error("cookieParser required");',    // line 3
      '  }',                                              // line 4
      '}',                                                // line 5
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 5,
        methods: [{ name: 'setCookie', start_line: 1, end_line: 5, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: TypeError in switch default arm', () => {
    const code = [
      'function convert(type, value) {',                               // line 1
      '  switch (type) {',                                             // line 2
      '    case "string": return String(value);',                      // line 3
      '    case "number": return Number(value);',                      // line 4
      '    default:',                                                  // line 5
      '      throw new TypeError("unknown value for " + type);',      // line 6
      '  }',                                                           // line 7
      '}',                                                             // line 8
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 8, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 8,
        methods: [{ name: 'convert', start_line: 1, end_line: 8, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag validation throw: TypeError after Array.isArray guard', () => {
    const code = [
      'function setContentType(value) {',                                  // line 1
      '  if (Array.isArray(value)) {',                                     // line 2
      '    throw new TypeError("Content-Type cannot be set to an Array");', // line 3
      '  }',                                                               // line 4
      '}',                                                                 // line 5
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 5, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 5,
        methods: [{ name: 'setContentType', start_line: 1, end_line: 5, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('still flags TypeError with no preceding guard', () => {
    const code = [
      'function broken() {',                        // line 1
      '  throw new TypeError("always throws");',    // line 2
      '}',                                           // line 3
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 3, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 3,
        methods: [{ name: 'broken', start_line: 1, end_line: 3, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
  });

  it('still flags Error with no preceding guard', () => {
    const code = [
      'function broken() {',                          // line 1
      '  throw new Error("unconditional throw");',    // line 2
      '}',                                             // line 3
    ].join('\n');
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 3, hash: '' },
      types: [{
        name: 'module', kind: 'class', start_line: 1, end_line: 3,
        methods: [{ name: 'broken', start_line: 1, end_line: 3, parameters: [], is_public: true }],
        fields: [], implements: [],
      }],
      cfg: { blocks: [], edges: [] },
    });
    const ctx = makeCtx(ir, code, 'javascript');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
  });

  it('skips Java', () => {
    const code = 'void foo() { throw new RuntimeException(); }';
    const ir = makeIR();
    const ctx = makeCtx(ir, code, 'java');
    new UnhandledExceptionPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DoubleClosePass
// ---------------------------------------------------------------------------

describe('DoubleClosePass', () => {
  it('detects two close() calls on the same resource', () => {
    const code = [
      'FileInputStream fis = new FileInputStream("f.txt");', // line 1
      'process(fis);',                                        // line 2
      'fis.close();',                                         // line 3
      'otherStuff();',                                        // line 4
      'fis.close();',                                         // line 5
    ].join('\n');

    const ir = makeIR({
      types: [
        {
          name: 'Test',
          kind: 'class',
          start_line: 1,
          end_line: 5,
          methods: [{ name: 'test', start_line: 1, end_line: 5, parameters: [], is_public: true }],
          fields: [],
          implements: [],
        },
      ],
      calls: [
        { method_name: 'FileInputStream', is_constructor: true, receiver: null, location: { line: 1, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'close', is_constructor: false, receiver: 'fis', location: { line: 3, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'close', is_constructor: false, receiver: 'fis', location: { line: 5, column: 0 }, arguments: [], resolution: 'unknown' },
      ],
      dfg: {
        defs: [{ id: 1, variable: 'fis', line: 1, expression: 'new FileInputStream("f.txt")' }],
        uses: [],
        chains: [],
      },
    });

    const ctx = makeCtx(ir, code, 'java');
    new DoubleClosePass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('double-close');
    expect(ctx.findings[0].line).toBe(1);
  });

  it('does not flag a resource closed only once', () => {
    const code = [
      'FileInputStream fis = new FileInputStream("f.txt");',
      'process(fis);',
      'fis.close();',
    ].join('\n');

    const ir = makeIR({
      types: [
        {
          name: 'Test',
          kind: 'class',
          start_line: 1,
          end_line: 3,
          methods: [{ name: 'test', start_line: 1, end_line: 3, parameters: [], is_public: true }],
          fields: [],
          implements: [],
        },
      ],
      calls: [
        { method_name: 'FileInputStream', is_constructor: true, receiver: null, location: { line: 1, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'close', is_constructor: false, receiver: 'fis', location: { line: 3, column: 0 }, arguments: [], resolution: 'unknown' },
      ],
      dfg: {
        defs: [{ id: 1, variable: 'fis', line: 1, expression: 'new FileInputStream("f.txt")' }],
        uses: [],
        chains: [],
      },
    });

    const ctx = makeCtx(ir, code, 'java');
    new DoubleClosePass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// UseAfterClosePass
// ---------------------------------------------------------------------------

describe('UseAfterClosePass', () => {
  it('detects a method call on a resource after close()', () => {
    const code = [
      'FileInputStream fis = new FileInputStream("f.txt");', // line 1
      'fis.close();',                                         // line 2
      'int b = fis.read();',                                  // line 3
    ].join('\n');

    const ir = makeIR({
      types: [
        {
          name: 'Test',
          kind: 'class',
          start_line: 1,
          end_line: 3,
          methods: [{ name: 'test', start_line: 1, end_line: 3, parameters: [], is_public: true }],
          fields: [],
          implements: [],
        },
      ],
      calls: [
        { method_name: 'FileInputStream', is_constructor: true, receiver: null, location: { line: 1, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'close', is_constructor: false, receiver: 'fis', location: { line: 2, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'read', is_constructor: false, receiver: 'fis', location: { line: 3, column: 0 }, arguments: [], resolution: 'unknown' },
      ],
      dfg: {
        defs: [{ id: 1, variable: 'fis', line: 1, expression: 'new FileInputStream("f.txt")' }],
        uses: [],
        chains: [],
      },
    });

    const ctx = makeCtx(ir, code, 'java');
    new UseAfterClosePass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('use-after-close');
    expect(ctx.findings[0].line).toBe(3);
  });

  it('does not flag calls that precede close()', () => {
    const code = [
      'FileInputStream fis = new FileInputStream("f.txt");', // line 1
      'int b = fis.read();',                                  // line 2
      'fis.close();',                                         // line 3
    ].join('\n');

    const ir = makeIR({
      types: [
        {
          name: 'Test',
          kind: 'class',
          start_line: 1,
          end_line: 3,
          methods: [{ name: 'test', start_line: 1, end_line: 3, parameters: [], is_public: true }],
          fields: [],
          implements: [],
        },
      ],
      calls: [
        { method_name: 'FileInputStream', is_constructor: true, receiver: null, location: { line: 1, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'read', is_constructor: false, receiver: 'fis', location: { line: 2, column: 0 }, arguments: [], resolution: 'unknown' },
        { method_name: 'close', is_constructor: false, receiver: 'fis', location: { line: 3, column: 0 }, arguments: [], resolution: 'unknown' },
      ],
      dfg: {
        defs: [{ id: 1, variable: 'fis', line: 1, expression: 'new FileInputStream("f.txt")' }],
        uses: [],
        chains: [],
      },
    });

    const ctx = makeCtx(ir, code, 'java');
    new UseAfterClosePass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});
