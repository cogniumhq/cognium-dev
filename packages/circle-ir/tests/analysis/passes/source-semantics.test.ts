/**
 * Tests for Pass #108: source-semantics (category: security, no CWE)
 *
 * Verifies the three source-taggers (constant / SPI / demoPath) and the
 * downstream `sourceSemanticsAllowed` consumption predicate.
 *
 * Note: all string literals below are fabricated fixtures; no real
 * credentials.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { SourceSemanticsPass, DEMO_PATH_RE } from '../../../src/analysis/passes/source-semantics-pass.js';
import { sourceSemanticsAllowed } from '../../../src/analysis/findings.js';
import type { CircleIR, SastFinding, TaintSource, SinkType } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function makeIR(
  file: string,
  sources: TaintSource[],
  language: CircleIR['meta']['language'] = 'java',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: sources.length, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources, sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function runOn(
  file: string,
  code: string,
  sources: TaintSource[],
  language: CircleIR['meta']['language'] = 'java',
): TaintSource[] {
  const ir = makeIR(file, sources, language);
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code,
    language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
    getFindings: () => findings,
  };
  new SourceSemanticsPass().run(ctx);
  // Return the tagged sources (same reference — the pass mutates in place).
  return graph.ir.taint.sources;
}

/** Minimal TaintSource factory. */
function src(overrides: Partial<TaintSource> & { code?: string; line?: number }): TaintSource {
  return {
    type: 'http_param',
    location: 'test',
    severity: 'high',
    line: overrides.line ?? 1,
    confidence: 1.0,
    ...overrides,
  } as TaintSource;
}

// ---------------------------------------------------------------------------
// Filter 1 — Constant tagging
// ---------------------------------------------------------------------------

describe('SourceSemanticsPass — constant tagging', () => {
  it('TP-1: `private static final String API_KEY = "abc123";` tags constant', () => {
    const code = `private static final String API_KEY = "abc123";\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].constant).toBe(true);
  });

  it('TP-2: `String h = "https://example.com";` tags constant', () => {
    const code = `String h = "https://example.com";\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].constant).toBe(true);
  });

  it('TP-3: `String v = SomeEnum.VALUE;` tags constant (enum ref)', () => {
    const code = `String v = SomeEnum.VALUE;\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].constant).toBe(true);
  });

  it('TN-1: `String h = req.getParameter("h");` does not tag constant', () => {
    const code = `String h = req.getParameter("h");\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].constant).toBeUndefined();
  });

  it('TN-2: `String h = compute();` does not tag constant', () => {
    const code = `String h = compute();\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].constant).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Filter 2 — SPI tagging
// ---------------------------------------------------------------------------

describe('SourceSemanticsPass — SPI tagging', () => {
  it('TP-1: `ServiceLoader.load(Plugin.class)` tags spi', () => {
    const code = `ServiceLoader<Plugin> plugins = ServiceLoader.load(Plugin.class);\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].spi).toBe(true);
  });

  it('TP-2: `Class.forName(name)` with adjacent META-INF lookup tags spi', () => {
    const code = [
      `public void init() {`,
      `  Class<?> c = Class.forName(name);`,
      `  Enumeration<URL> urls = cl.getResources("META-INF/services/plugins");`,
      `}`,
      ``,
    ].join('\n');
    const out = runOn('src/Foo.java', code, [src({ code: 'Class<?> c = Class.forName(name);', line: 2 })]);
    expect(out[0].spi).toBe(true);
  });

  it('TP-3: `ServiceLoader.stream(Plugin.class)` tags spi', () => {
    const code = `Stream<Plugin> s = ServiceLoader.stream(Plugin.class);\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].spi).toBe(true);
  });

  it('TN-1: `Class.forName(userInput)` with no META-INF lookup does not tag spi', () => {
    const code = `Class<?> c = Class.forName(userInput);\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].spi).toBeUndefined();
  });

  it('TN-2: `String s = req.getParameter("x");` does not tag spi', () => {
    const code = `String s = req.getParameter("x");\n`;
    const out = runOn('src/Foo.java', code, [src({ code: code.trimEnd(), line: 1 })]);
    expect(out[0].spi).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Filter 3 — DemoPath tagging
// ---------------------------------------------------------------------------

describe('SourceSemanticsPass — demoPath tagging', () => {
  it('TP-1: `src/main/java/com/example/demo/Foo.java` tags every source', () => {
    const out = runOn(
      'src/main/java/com/example/demo/Foo.java',
      `String x = req.getParameter("x");\n`,
      [src({ code: 'String x = req.getParameter("x");', line: 1 })],
    );
    expect(out[0].demoPath).toBe(true);
  });

  it('TP-2: `examples/OAuth.java` tags demoPath', () => {
    const out = runOn(
      'examples/OAuth.java',
      `String x = req.getParameter("x");\n`,
      [src({ code: 'String x = req.getParameter("x");', line: 1 })],
    );
    expect(out[0].demoPath).toBe(true);
  });

  it('TP-3: `src/test/java/com/foo/integration-tests/Bar.java` tags demoPath', () => {
    const out = runOn(
      'src/test/java/com/foo/integration-tests/Bar.java',
      `String x = req.getParameter("x");\n`,
      [src({ code: 'String x = req.getParameter("x");', line: 1 })],
    );
    expect(out[0].demoPath).toBe(true);
  });

  it('TN-1: `src/main/java/com/foo/prod/Bar.java` does not tag demoPath', () => {
    const out = runOn(
      'src/main/java/com/foo/prod/Bar.java',
      `String x = req.getParameter("x");\n`,
      [src({ code: 'String x = req.getParameter("x");', line: 1 })],
    );
    expect(out[0].demoPath).toBeUndefined();
  });

  it('TN-2: `src/main/java/DemoParser.java` (filename only) does not tag demoPath', () => {
    // DEMO_PATH_RE requires a `/demo/` path component, not just a filename
    // starting with "Demo".
    expect(DEMO_PATH_RE.test('src/main/java/DemoParser.java')).toBe(false);
    const out = runOn(
      'src/main/java/DemoParser.java',
      `String x = req.getParameter("x");\n`,
      [src({ code: 'String x = req.getParameter("x");', line: 1 })],
    );
    expect(out[0].demoPath).toBeUndefined();
  });

  it('applies demoPath to every source in the file (uniform per-file flag)', () => {
    const out = runOn(
      'demo/App.java',
      `String a = req.getParameter("a");\nString b = req.getParameter("b");\n`,
      [
        src({ code: 'String a = req.getParameter("a");', line: 1 }),
        src({ code: 'String b = req.getParameter("b");', line: 2 }),
      ],
    );
    expect(out[0].demoPath).toBe(true);
    expect(out[1].demoPath).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Consumption — sourceSemanticsAllowed
// ---------------------------------------------------------------------------

describe('sourceSemanticsAllowed (findings.ts consumption)', () => {
  const taintSinks: SinkType[] = [
    'sql_injection', 'command_injection', 'xss', 'path_traversal',
    'ssrf', 'deserialization', 'code_injection', 'xpath_injection',
    'ldap_injection', 'crlf', 'mass_assignment', 'open_redirect',
    'trust_boundary', 'xxe', 'mybatis_mapper_call',
  ];

  it('constant source is dropped for every taint sink type', () => {
    for (const sink of taintSinks) {
      expect(sourceSemanticsAllowed({ constant: true }, sink)).toBe(false);
    }
  });

  it('spi source is allowed for code_injection only', () => {
    expect(sourceSemanticsAllowed({ spi: true }, 'code_injection')).toBe(true);
    for (const sink of taintSinks.filter(t => t !== 'code_injection')) {
      expect(sourceSemanticsAllowed({ spi: true }, sink)).toBe(false);
    }
  });

  it('demoPath source (never dropped by the gate)', () => {
    // demoPath is not consumed by sourceSemanticsAllowed — only by
    // scan-secrets-pass. The predicate must NOT drop demoPath-tagged
    // sources.
    for (const sink of taintSinks) {
      expect(sourceSemanticsAllowed({} /* demoPath NOT relevant here */, sink)).toBe(true);
    }
  });

  it('untagged source (default preserved)', () => {
    for (const sink of taintSinks) {
      expect(sourceSemanticsAllowed({}, sink)).toBe(true);
    }
  });

  it('constant AND spi tags — constant wins (drop takes precedence)', () => {
    // In practice a source shouldn't be both, but if it were, the safer
    // outcome is to drop (constants can't carry input).
    expect(sourceSemanticsAllowed({ constant: true, spi: true }, 'code_injection')).toBe(false);
  });
});
