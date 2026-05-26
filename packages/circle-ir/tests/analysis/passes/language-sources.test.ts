/**
 * Tests for LanguageSourcesPass and its exported helper functions.
 *
 * Covers:
 *  - buildPythonTaintedVars()
 *  - buildPythonSanitizedVars()
 *  - findPythonTrustBoundaryViolations()
 *  - buildJavaScriptTaintedVars()
 *  - LanguageSourcesPass.run() — Java getter sources, Python/JS assignment sources, DOM sinks
 */

import { describe, it, expect } from 'vitest';
import {
  LanguageSourcesPass,
  buildPythonTaintedVars,
  buildPythonSanitizedVars,
  findPythonTrustBoundaryViolations,
  buildJavaScriptTaintedVars,
} from '../../../src/analysis/passes/language-sources-pass.js';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import type { CircleIR, TypeInfo, MethodInfo } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(types: TypeInfo[] = [], language = 'java', file = 'App.java'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 50, hash: '' },
    types,
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

function makeMethod(name: string, startLine: number, params: string[] = []): MethodInfo {
  return {
    name,
    return_type: null,
    parameters: params.map(p => ({ name: p, type: 'String', annotations: [] })),
    annotations: [],
    modifiers: ['public'],
    start_line: startLine,
    end_line: startLine + 3,
    fields_accessed: [],
  };
}

function makeCtx(
  ir: CircleIR,
  code: string,
  language: string,
  instanceFieldTaint: Map<string, { className: string; sourceParam: string; sourceLine: number }> = new Map(),
): PassContext {
  const graph = new CodeGraph(ir);
  const results = new Map<string, unknown>([
    [
      'constant-propagation',
      {
        instanceFieldTaint,
        unreachableLines: new Set<number>(),
        taintedArrayElements: new Map(),
        symbols: new Map(),
        tainted: new Set<string>(),
        sanitizedVars: new Set<string>(),
        synchronizedLines: new Set<number>(),
        knownValues: new Map(),
        deadLines: new Set<number>(),
      },
    ],
    ['taint-matcher', { sources: [], sinks: [], sanitizers: [], sanitizerMethods: new Set() }],
  ]);
  return {
    graph,
    code,
    language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: () => {},
  };
}

// ---------------------------------------------------------------------------
// buildPythonTaintedVars
// ---------------------------------------------------------------------------

describe('buildPythonTaintedVars()', () => {
  it('returns empty map for empty code', () => {
    expect(buildPythonTaintedVars('').size).toBe(0);
  });

  it('detects request.args assignment', () => {
    const code = 'name = request.args.get("user")';
    const result = buildPythonTaintedVars(code);
    expect(result.has('name')).toBe(true);
    expect(result.get('name')).toBe(1);
  });

  it('detects request.form assignment', () => {
    const code = 'data = request.form["key"]';
    const result = buildPythonTaintedVars(code);
    expect(result.has('data')).toBe(true);
  });

  it('detects Django request.GET assignment', () => {
    const code = 'q = request.GET.get("q")';
    const result = buildPythonTaintedVars(code);
    expect(result.has('q')).toBe(true);
  });

  it('detects Django request.POST assignment', () => {
    const code = 'val = request.POST["val"]';
    const result = buildPythonTaintedVars(code);
    expect(result.has('val')).toBe(true);
  });

  it('propagates taint through variable assignment', () => {
    const code = 'user = request.args.get("user")\nquery = user';
    const result = buildPythonTaintedVars(code);
    expect(result.has('user')).toBe(true);
    expect(result.has('query')).toBe(true);
  });

  it('propagates taint through augmented assignment +=', () => {
    const code = [
      'base = request.args.get("id")',
      'result += base',
    ].join('\n');
    const result = buildPythonTaintedVars(code);
    expect(result.has('result')).toBe(true);
  });

  it('propagates taint to loop variable via for-in', () => {
    const code = [
      'items = request.args.getlist("ids")',
      'for item in items:',
      '    pass',
    ].join('\n');
    const result = buildPythonTaintedVars(code);
    expect(result.has('item')).toBe(true);
  });

  it('handles for-in over direct source', () => {
    const code = 'for val in request.args.values():';
    const result = buildPythonTaintedVars(code);
    expect(result.has('val')).toBe(true);
  });

  it('skips comment lines', () => {
    const code = '# user = request.args.get("user")';
    expect(buildPythonTaintedVars(code).size).toBe(0);
  });

  it('does NOT treat os.environ.get as tainted (safe env read)', () => {
    const code = 'key = os.environ.get("SECRET")';
    const result = buildPythonTaintedVars(code);
    expect(result.has('key')).toBe(false);
  });

  it('does NOT treat os.getenv as tainted (safe env read)', () => {
    const code = 'key = os.getenv("SECRET")';
    expect(buildPythonTaintedVars(code).has('key')).toBe(false);
  });

  it('removes variable from taint when re-assigned to clean value', () => {
    const code = [
      'user = request.args.get("id")',
      'user = "safe_value"',
    ].join('\n');
    const result = buildPythonTaintedVars(code);
    expect(result.has('user')).toBe(false);
  });

  it('propagates container subscript taint', () => {
    const code = [
      'tainted = request.args.get("x")',
      'data["key"] = tainted',
      'val = data["key"]',
    ].join('\n');
    const result = buildPythonTaintedVars(code);
    expect(result.has('val')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildPythonSanitizedVars
// ---------------------------------------------------------------------------

describe('buildPythonSanitizedVars()', () => {
  it('returns empty set for empty code', () => {
    expect(buildPythonSanitizedVars('', new Map()).size).toBe(0);
  });

  it('detects apostrophe-guard with return', () => {
    const code = [
      "if \"'\" in user_input:",
      '    return',
    ].join('\n');
    const result = buildPythonSanitizedVars(code, new Map([['user_input', 1]]));
    expect(result.has('user_input')).toBe(true);
  });

  it('detects apostrophe-guard with raise', () => {
    const code = [
      "if \"'\" in param:",
      '    raise ValueError("invalid")',
    ].join('\n');
    const result = buildPythonSanitizedVars(code, new Map([['param', 1]]));
    expect(result.has('param')).toBe(true);
  });

  it('detects apostrophe-guard with abort', () => {
    const code = [
      "if \"'\" in user:",
      '    abort(400)',
    ].join('\n');
    const result = buildPythonSanitizedVars(code, new Map([['user', 1]]));
    expect(result.has('user')).toBe(true);
  });

  it('does NOT sanitize if block body does not exit', () => {
    const code = [
      "if \"'\" in param:",
      '    x = 1',
    ].join('\n');
    const result = buildPythonSanitizedVars(code, new Map([['param', 1]]));
    expect(result.has('param')).toBe(false);
  });

  it('detects .replace() sanitizer', () => {
    const tainted = new Map([['raw', 1]]);
    const code = "clean = raw.replace(\"'\", \"&apos;\")";
    const result = buildPythonSanitizedVars(code, tainted);
    expect(result.has('clean')).toBe(true);
  });

  it('propagates sanitization through assignment when sanitized before propagation pass', () => {
    // The apostrophe-guard pass runs first; propagation then picks up already-sanitized vars.
    // For a guard-based sanitized var 'safe', 'query = safe' propagates.
    const code = [
      "if \"'\" in raw:",
      '    return',
      'safe = raw',
      'query = safe',
    ].join('\n');
    const tainted = new Map([['raw', 1]]);
    const result = buildPythonSanitizedVars(code, tainted);
    expect(result.has('raw')).toBe(true);
    expect(result.has('safe')).toBe(true);
    expect(result.has('query')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// findPythonTrustBoundaryViolations
// ---------------------------------------------------------------------------

describe('findPythonTrustBoundaryViolations()', () => {
  it('returns empty array for empty tainted vars', () => {
    expect(findPythonTrustBoundaryViolations('session["k"] = x', new Map()).length).toBe(0);
  });

  it('detects session write with tainted value', () => {
    const code = [
      'user = request.args.get("user")',
      'session["user"] = user',
    ].join('\n');
    const tainted = new Map([['user', 1]]);
    const violations = findPythonTrustBoundaryViolations(code, tainted);
    expect(violations.length).toBe(1);
    expect(violations[0].sinkLine).toBe(2);
  });

  it('detects flask.session write with tainted value', () => {
    const code = 'flask.session["key"] = tainted_val';
    const tainted = new Map([['tainted_val', 1]]);
    const violations = findPythonTrustBoundaryViolations(code, tainted);
    expect(violations.length).toBe(1);
  });

  it('detects session write with tainted key', () => {
    const code = 'session[tainted_key] = "safe"';
    const tainted = new Map([['tainted_key', 1]]);
    const violations = findPythonTrustBoundaryViolations(code, tainted);
    expect(violations.length).toBe(1);
  });

  it('skips comment lines', () => {
    const code = '# session["key"] = tainted';
    const tainted = new Map([['tainted', 1]]);
    expect(findPythonTrustBoundaryViolations(code, tainted).length).toBe(0);
  });

  it('does not flag session write with clean value', () => {
    const code = 'session["role"] = "admin"';
    const tainted = new Map([['user', 1]]);
    expect(findPythonTrustBoundaryViolations(code, tainted).length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// buildJavaScriptTaintedVars
// ---------------------------------------------------------------------------

describe('buildJavaScriptTaintedVars()', () => {
  it('returns empty map for non-JS/TS language', () => {
    expect(buildJavaScriptTaintedVars('const id = req.query.id', 'java').size).toBe(0);
  });

  it('detects req.query assignment', () => {
    const code = 'const id = req.query.id';
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('id')).toBe(true);
  });

  it('detects req.body assignment', () => {
    const code = 'const body = req.body';
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('body')).toBe(true);
  });

  it('detects req.params assignment', () => {
    const code = 'const p = req.params.id';
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('p')).toBe(true);
  });

  it('detects process.env assignment', () => {
    const code = 'const key = process.env.API_KEY';
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('key')).toBe(true);
  });

  it('detects process.argv assignment', () => {
    const code = 'const args = process.argv';
    const result = buildJavaScriptTaintedVars(code, 'typescript');
    expect(result.has('args')).toBe(true);
  });

  it('propagates taint to derived variable', () => {
    const code = [
      'const id = req.query.id',
      'const query = id + " suffix"',
    ].join('\n');
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('query')).toBe(true);
  });

  it('skips comment lines (//)', () => {
    const code = '// const id = req.query.id';
    expect(buildJavaScriptTaintedVars(code, 'javascript').size).toBe(0);
  });

  it('skips reserved words (if, while, for, etc.)', () => {
    const code = 'if = req.query.id';  // pathological, but should be skipped
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('if')).toBe(false);
  });

  it('detects ctx.query assignment (Koa)', () => {
    const code = 'const q = ctx.query.page';
    const result = buildJavaScriptTaintedVars(code, 'javascript');
    expect(result.has('q')).toBe(true);
  });

  it('detects request.body assignment', () => {
    const code = 'const data = request.body';
    const result = buildJavaScriptTaintedVars(code, 'typescript');
    expect(result.has('data')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// LanguageSourcesPass.run() — Java getter sources
// ---------------------------------------------------------------------------

describe('LanguageSourcesPass — Java getter sources', () => {
  it('detects getX() returning tainted constructor field', () => {
    const types: TypeInfo[] = [
      {
        name: 'UserService',
        kind: 'class',
        start_line: 1,
        end_line: 20,
        methods: [makeMethod('getName', 5)],
        fields: [],
        annotations: [],
        modifiers: [],
        extends: null,
        implements: [],
      },
    ];
    const fieldTaint = new Map([
      ['name', { className: 'UserService', sourceParam: 'nameParam', sourceLine: 2 }],
    ]);
    const ir = makeIR(types, 'java');
    const ctx = makeCtx(ir, '', 'java', fieldTaint);
    const result = new LanguageSourcesPass().run(ctx);
    const getterSource = result.additionalSources.find(s => s.type === 'constructor_field');
    expect(getterSource).toBeDefined();
    expect(getterSource!.location).toContain('getName');
    expect(getterSource!.confidence).toBe(0.95);
  });

  it('detects isActive() returning tainted boolean field (is* pattern)', () => {
    const types: TypeInfo[] = [
      {
        name: 'Session',
        kind: 'class',
        start_line: 1,
        end_line: 20,
        methods: [makeMethod('isActive', 8)],
        fields: [],
        annotations: [],
        modifiers: [],
        extends: null,
        implements: [],
      },
    ];
    const fieldTaint = new Map([
      ['active', { className: 'Session', sourceParam: 'activeParam', sourceLine: 2 }],
    ]);
    const ctx = makeCtx(makeIR(types, 'java'), '', 'java', fieldTaint);
    const result = new LanguageSourcesPass().run(ctx);
    const s = result.additionalSources.find(s => s.location?.includes('isActive'));
    expect(s).toBeDefined();
  });

  it('skips getter with parameters', () => {
    const types: TypeInfo[] = [
      {
        name: 'Repo',
        kind: 'class',
        start_line: 1,
        end_line: 20,
        methods: [makeMethod('getName', 5, ['prefix'])],
        fields: [],
        annotations: [],
        modifiers: [],
        extends: null,
        implements: [],
      },
    ];
    const fieldTaint = new Map([
      ['name', { className: 'Repo', sourceParam: 'n', sourceLine: 2 }],
    ]);
    const ctx = makeCtx(makeIR(types, 'java'), '', 'java', fieldTaint);
    const result = new LanguageSourcesPass().run(ctx);
    // Method has a parameter → should not be detected as getter
    const getterSource = result.additionalSources.find(s => s.type === 'constructor_field');
    expect(getterSource).toBeUndefined();
  });

  it('returns empty sources when instanceFieldTaint is empty', () => {
    const types: TypeInfo[] = [
      {
        name: 'Foo',
        kind: 'class',
        start_line: 1,
        end_line: 10,
        methods: [makeMethod('getBar', 5)],
        fields: [],
        annotations: [],
        modifiers: [],
        extends: null,
        implements: [],
      },
    ];
    const ctx = makeCtx(makeIR(types, 'java'), '', 'java', new Map());
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.additionalSources.filter(s => s.type === 'constructor_field').length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// LanguageSourcesPass.run() — Python assignment sources
// ---------------------------------------------------------------------------

describe('LanguageSourcesPass — Python assignment sources', () => {
  it('detects request.args assignment source', () => {
    const code = 'user = request.args.get("id")';
    const ctx = makeCtx(makeIR([], 'python', 'app.py'), code, 'python');
    const result = new LanguageSourcesPass().run(ctx);
    const src = result.additionalSources.find(s => s.type === 'http_param');
    expect(src).toBeDefined();
    expect(src!.line).toBe(1);
    expect(src!.variable).toBe('user');
  });

  it('detects request.POST (Django) assignment source', () => {
    const code = 'data = request.POST.get("data")';
    const ctx = makeCtx(makeIR([], 'python', 'views.py'), code, 'python');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.additionalSources.some(s => s.type === 'http_body')).toBe(true);
  });

  it('populates pyTaintedVars for python language', () => {
    const code = 'name = request.args.get("name")';
    const ctx = makeCtx(makeIR([], 'python', 'app.py'), code, 'python');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.pyTaintedVars.has('name')).toBe(true);
  });

  it('returns empty pyTaintedVars for non-python language', () => {
    const code = 'const id = req.query.id';
    const ctx = makeCtx(makeIR([], 'javascript', 'app.js'), code, 'javascript');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.pyTaintedVars.size).toBe(0);
  });

  it('adds trust boundary violation sink when session written with tainted var', () => {
    const code = [
      'user = request.args.get("u")',
      'session["user"] = user',
    ].join('\n');
    const ctx = makeCtx(makeIR([], 'python', 'app.py'), code, 'python');
    const result = new LanguageSourcesPass().run(ctx);
    const tbSink = result.additionalSinks.find(s => s.type === 'trust_boundary');
    expect(tbSink).toBeDefined();
    expect(tbSink!.cwe).toBe('CWE-501');
  });

  it('adds XSS sink when a tainted var is returned inside an HTML f-string', () => {
    const code = [
      'data = request.args.get("q")',
      'return f"<html>{data}</html>"',
    ].join('\n');
    const ctx = makeCtx(makeIR([], 'python', 'app.py'), code, 'python');
    const result = new LanguageSourcesPass().run(ctx);
    const xssSink = result.additionalSinks.find(s => s.type === 'xss');
    expect(xssSink).toBeDefined();
    expect(xssSink!.cwe).toBe('CWE-79');
    expect(xssSink!.line).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// LanguageSourcesPass.run() — JavaScript DOM sinks
// ---------------------------------------------------------------------------

describe('LanguageSourcesPass — JavaScript DOM sinks', () => {
  it('detects innerHTML DOM XSS sink', () => {
    const code = 'element.innerHTML = userInput;';
    const ctx = makeCtx(makeIR([], 'javascript', 'app.js'), code, 'javascript');
    const result = new LanguageSourcesPass().run(ctx);
    const sink = result.additionalSinks.find(s => s.type === 'xss');
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-79');
    expect(sink!.line).toBe(1);
  });

  it('detects document.write() DOM XSS sink', () => {
    const code = 'document.write(userInput);';
    const ctx = makeCtx(makeIR([], 'javascript', 'app.js'), code, 'javascript');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.additionalSinks.some(s => s.type === 'xss')).toBe(true);
  });

  it('detects outerHTML DOM XSS sink', () => {
    const code = 'el.outerHTML = x;';
    const ctx = makeCtx(makeIR([], 'typescript', 'app.ts'), code, 'typescript');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.additionalSinks.some(s => s.type === 'xss' && s.line === 1)).toBe(true);
  });

  it('does NOT add DOM sinks for Python code', () => {
    const code = 'element.innerHTML = x';
    const ctx = makeCtx(makeIR([], 'python', 'app.py'), code, 'python');
    const result = new LanguageSourcesPass().run(ctx);
    // DOM sinks only apply to JS/TS
    expect(result.additionalSinks.filter(s => s.cwe === 'CWE-79').length).toBe(0);
  });

  it('detects req.query assignment source', () => {
    const code = 'const id = req.query.id';
    const ctx = makeCtx(makeIR([], 'javascript', 'app.js'), code, 'javascript');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.additionalSources.some(s => s.type === 'http_param')).toBe(true);
  });

  it('populates jsTaintedVars for javascript language', () => {
    const code = 'const id = req.query.id';
    const ctx = makeCtx(makeIR([], 'javascript', 'app.js'), code, 'javascript');
    const result = new LanguageSourcesPass().run(ctx);
    expect(result.jsTaintedVars.has('id')).toBe(true);
  });
});
