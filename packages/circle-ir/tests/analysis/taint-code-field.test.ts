/**
 * Tests for the `code` field on TaintSource / TaintSink.
 *
 * Verifies that analyzeTaint() populates the trimmed source-line text on every
 * emitted source and sink when `code` is provided, that the field stays
 * undefined when `code` is omitted (backward compatible), and that the
 * exported `attachSourceLineCode()` helper is idempotent.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import {
  analyzeTaint,
  attachSourceLineCode,
} from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';
import { LanguageSourcesPass } from '../../src/analysis/passes/language-sources-pass.js';
import { CodeGraph } from '../../src/graph/code-graph.js';
import type {
  CircleIR,
  TaintSource,
  TaintSink,
} from '../../src/types/index.js';
import type { PassContext } from '../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../src/types/config.js';

describe('TaintSource/TaintSink — code field', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('analyzeTaint() populates code on each emitted source when code is provided', async () => {
    const code = `
public class Controller {
    public void handleRequest(HttpServletRequest request) {
        String id = request.getParameter("id");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java', code);

    expect(taint.sources.length).toBeGreaterThan(0);
    for (const s of taint.sources) {
      expect(s.code).toBeDefined();
      expect(typeof s.code).toBe('string');
    }
    const httpSource = taint.sources.find(s => s.type === 'http_param');
    expect(httpSource).toBeDefined();
    expect(httpSource!.code).toContain('request.getParameter');
    // Must be trimmed (no leading whitespace).
    expect(httpSource!.code!.startsWith(' ')).toBe(false);
  });

  it('analyzeTaint() populates code on each emitted sink when code is provided', async () => {
    const code = `
public class Repository {
    public void query(Statement stmt, String sql) {
        stmt.executeQuery(sql);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java', code);

    const sqlSink = taint.sinks.find(s => s.type === 'sql_injection');
    expect(sqlSink).toBeDefined();
    expect(sqlSink!.code).toBeDefined();
    expect(sqlSink!.code).toContain('executeQuery');
    expect(sqlSink!.code!.startsWith(' ')).toBe(false);
  });

  it('analyzeTaint() leaves code undefined when no code arg is provided', async () => {
    const code = `
public class Controller {
    public void handleRequest(HttpServletRequest request) {
        String id = request.getParameter("id");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    // No `code` arg → backward-compatible: emitted sources keep code === undefined.
    const taint = analyzeTaint(calls, types);
    expect(taint.sources.length).toBeGreaterThan(0);
    for (const s of taint.sources) {
      expect(s.code).toBeUndefined();
    }
    for (const s of taint.sinks) {
      expect(s.code).toBeUndefined();
    }
  });

  it('attachSourceLineCode() populates missing code on sources and sinks', () => {
    const code = [
      'line one',
      '  taint source here',
      '  sink here',
    ].join('\n');
    const sources: TaintSource[] = [
      {
        type: 'http_param',
        location: 'X.foo()',
        severity: 'high',
        line: 2,
        confidence: 1.0,
      },
    ];
    const sinks: TaintSink[] = [
      {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'X.bar()',
        line: 3,
        confidence: 1.0,
      },
    ];
    attachSourceLineCode(sources, sinks, code);
    expect(sources[0].code).toBe('taint source here');
    expect(sinks[0].code).toBe('sink here');
  });

  it('attachSourceLineCode() is idempotent — preserves pre-existing code values', () => {
    const code = 'a\nb\nc';
    const sources: TaintSource[] = [
      {
        type: 'http_param',
        location: 'X',
        severity: 'high',
        line: 2,
        confidence: 1.0,
        code: 'PRE_EXISTING',
      },
    ];
    const sinks: TaintSink[] = [
      {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'X',
        line: 3,
        confidence: 1.0,
      },
    ];
    attachSourceLineCode(sources, sinks, code);
    // Pre-existing value preserved.
    expect(sources[0].code).toBe('PRE_EXISTING');
    // Missing value filled in.
    expect(sinks[0].code).toBe('c');
  });

  it('attachSourceLineCode() handles out-of-range lines gracefully', () => {
    const code = 'only one line';
    const sources: TaintSource[] = [
      {
        type: 'http_param',
        location: 'X',
        severity: 'high',
        line: 99,
        confidence: 1.0,
      },
    ];
    attachSourceLineCode(sources, [], code);
    // Out-of-range → undefined?.trim() → undefined.
    expect(sources[0].code).toBeUndefined();
  });

  it('LanguageSourcesPass emits sources with code populated', () => {
    const code = 'user = request.args.get("id")';
    const ir: CircleIR = {
      meta: { circle_ir: '3.0', file: 'app.py', language: 'python', loc: 1, hash: '' },
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
    const graph = new CodeGraph(ir);
    const results = new Map<string, unknown>([
      [
        'constant-propagation',
        {
          instanceFieldTaint: new Map(),
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
    const ctx: PassContext = {
      graph,
      code,
      language: 'python',
      config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
      getResult: <T>(name: string) => results.get(name) as T,
      hasResult: (name: string) => results.has(name),
      addFinding: () => {},
    };
    const result = new LanguageSourcesPass().run(ctx);
    const src = result.additionalSources.find(s => s.type === 'http_param');
    expect(src).toBeDefined();
    expect(src!.code).toBe('user = request.args.get("id")');
  });
});
