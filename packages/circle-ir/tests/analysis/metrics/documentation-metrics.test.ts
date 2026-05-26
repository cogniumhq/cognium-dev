import { describe, it, expect } from 'vitest';
import { DocumentationMetricsPass } from '../../../src/analysis/metrics/passes/documentation-metrics-pass.js';
import type { MetricContext } from '../../../src/analysis/metrics/metric-pass.js';
import type { CircleIR, TypeInfo } from '../../../src/types/index.js';

function makeMethod(name: string, start: number, end: number): TypeInfo['methods'][0] {
  return { name, return_type: null, parameters: [], annotations: [], modifiers: [], start_line: start, end_line: end };
}

function makeType(name: string, start: number, methods: TypeInfo['methods']): TypeInfo {
  const end = methods.length > 0 ? methods[methods.length - 1].end_line + 1 : start + 5;
  return {
    name, kind: 'class', package: null, extends: null, implements: [], annotations: [],
    fields: [], methods, start_line: start, end_line: end,
  };
}

function makeCtx(code: string, types: TypeInfo[]): MetricContext {
  const ir: CircleIR = {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 0, hash: '' },
    types, calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [] },
    taint: { sources: [], sinks: [] },
    imports: [], exports: [], unresolved: [], enriched: {},
  };
  return { ir, code, language: 'typescript', accumulated: [] };
}

describe('DocumentationMetricsPass', () => {
  it('returns 0 for no documentable items', () => {
    const results = new DocumentationMetricsPass().run(makeCtx('', []));
    expect(results[0].value).toBe(0);
    expect(results[0].name).toBe('doc_coverage');
  });

  it('computes 1.0 when all types and methods have doc blocks', () => {
    // line 1: /**
    // line 2:  * Foo class
    // line 3:  */
    // line 4: class Foo {
    // line 5:   /**
    // line 6:    * method bar
    // line 7:    */
    // line 8:   bar() {}
    // line 9: }
    const code = `/**\n * Foo class\n */\nclass Foo {\n  /**\n   * method bar\n   */\n  bar() {}\n}`;
    const type = makeType('Foo', 4, [makeMethod('bar', 8, 8)]);
    const results = new DocumentationMetricsPass().run(makeCtx(code, [type]));
    expect(results[0].value).toBe(1);
  });

  it('computes 0.5 when half of items are documented', () => {
    // Type at line 2 (line 1 is doc), method at line 4 (line 3 is NOT doc)
    const code = `/**\n * doc\n */\nclass Foo {\n  bar() {}\n}`;
    // Type starts at line 4 → doc block ends at line 3 ✓
    // Method starts at line 5 → line 4 is "class Foo {" → not a doc block end
    const type = makeType('Foo', 4, [makeMethod('bar', 5, 5)]);
    const results = new DocumentationMetricsPass().run(makeCtx(code, [type]));
    // 1 documented (type), 1 undocumented (method) → 0.5
    expect(results[0].value).toBeCloseTo(0.5);
  });

  it('returns 0 when no doc blocks exist', () => {
    const code = `class Foo {\n  bar() {}\n}`;
    const type = makeType('Foo', 1, [makeMethod('bar', 2, 2)]);
    const results = new DocumentationMetricsPass().run(makeCtx(code, [type]));
    expect(results[0].value).toBe(0);
  });

  it('has category documentation', () => {
    const results = new DocumentationMetricsPass().run(makeCtx('', []));
    expect(results[0].category).toBe('documentation');
  });
});
