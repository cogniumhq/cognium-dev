/**
 * Tests for Pass #79: variable-shadowing (CWE-1109, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { VariableShadowingPass } from '../../../src/analysis/passes/variable-shadowing-pass.js';
import type {
  CircleIR, SastFinding, DFGDef, TypeInfo, MethodInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDef(id: number, variable: string, line: number, kind: DFGDef['kind']): DFGDef {
  return { id, variable, line, kind };
}

function makeMethod(name: string, startLine: number, endLine: number): MethodInfo {
  return {
    name, return_type: null, parameters: [], annotations: [], modifiers: ['public'],
    start_line: startLine, end_line: endLine,
  };
}

function makeType(name: string, methods: MethodInfo[]): TypeInfo {
  return {
    name, kind: 'class', methods, fields: [], annotations: [], modifiers: [],
    start_line: 1, end_line: 20,
  };
}

function makeIR(
  code: string,
  defs: DFGDef[],
  types: TypeInfo[],
  language = 'java',
  file = 'App.java',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 20, hash: '' },
    types,
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs, uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [], exports: [], unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(ir: CircleIR, code: string): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph, code, language: ir.meta.language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
  };
  return { ctx, findings };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('VariableShadowingPass', () => {
  it('flags Java param shadowed by inner local declaration', () => {
    // Line 1: void method(int x) {
    // Line 5:   int x = 2;  ← shadows param
    const code = [
      'void method(int x) {',  // 1 — param x
      '  int y = 1;',           // 2
      '  {',                    // 3
      '    // nested block',    // 4
      '    int x = 2;',         // 5 — shadows param
      '  }',                    // 6
      '}',                      // 7
    ].join('\n');

    const defs = [
      makeDef(1, 'x', 1, 'param'),   // parameter
      makeDef(2, 'x', 5, 'local'),   // shadowing local
    ];
    const types = [makeType('App', [makeMethod('method', 1, 7)])];
    const ir = makeIR(code, defs, types, 'java');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new VariableShadowingPass().run(ctx);

    expect(result.shadows).toHaveLength(1);
    expect(result.shadows[0].kind).toBe('param');
    expect(result.shadows[0].variable).toBe('x');
    expect(result.shadows[0].line).toBe(5);
    expect(result.shadows[0].shadowedAt).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-1109');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/x/);
    expect(findings[0].message).toMatch(/shadows/);
  });

  it('flags JS param shadowed by let declaration', () => {
    const code = [
      'function process(value) {',  // 1 — param value
      '  if (true) {',              // 2
      '    let value = 0;',         // 3 — shadows param
      '  }',                        // 4
      '}',                          // 5
    ].join('\n');

    const defs = [
      makeDef(1, 'value', 1, 'param'),
      makeDef(2, 'value', 3, 'local'),
    ];
    const types = [makeType('Svc', [makeMethod('process', 1, 5)])];
    const ir = makeIR(code, defs, types, 'javascript', 'service.js');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new VariableShadowingPass().run(ctx);

    expect(result.shadows).toHaveLength(1);
    expect(result.shadows[0].kind).toBe('param');
    expect(findings).toHaveLength(1);
  });

  it('flags JS outer-local shadowed by inner let declaration', () => {
    const code = [
      'function build() {',    // 1
      '  let x = 1;',          // 2 — outer local
      '  for (;;) {',          // 3
      '    let x = 2;',        // 4 — inner shadow
      '  }',                   // 5
      '}',                     // 6
    ].join('\n');

    const defs = [
      makeDef(1, 'x', 2, 'local'),  // outer let x
      makeDef(2, 'x', 4, 'local'),  // inner let x — shadow
    ];
    const types = [makeType('Builder', [makeMethod('build', 1, 6)])];
    const ir = makeIR(code, defs, types, 'javascript', 'builder.js');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new VariableShadowingPass().run(ctx);

    expect(result.shadows).toHaveLength(1);
    expect(result.shadows[0].kind).toBe('outer-local');
    expect(result.shadows[0].line).toBe(4);
    expect(findings[0].cwe).toBe('CWE-1109');
  });

  it('does NOT flag JS reassignment (no let/const/var on second def line)', () => {
    // x = 1 then x = 2 — reassignment, not a re-declaration
    const code = [
      'function f() {',   // 1
      '  let x = 1;',     // 2 — declaration
      '  x = 2;',         // 3 — bare reassignment (no decl keyword)
      '}',                // 4
    ].join('\n');

    const defs = [
      makeDef(1, 'x', 2, 'local'),  // let x = 1
      makeDef(2, 'x', 3, 'local'),  // x = 2 (reassignment)
    ];
    const types = [makeType('Foo', [makeMethod('f', 1, 4)])];
    const ir = makeIR(code, defs, types, 'javascript', 'foo.js');
    const { ctx, findings } = makeCtx(ir, code);
    new VariableShadowingPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag a single def (no shadow possible)', () => {
    const code = 'void m(int x) { int y = 1; }\n';
    const defs = [
      makeDef(1, 'x', 1, 'param'),
      makeDef(2, 'y', 1, 'local'),
    ];
    const types = [makeType('App', [makeMethod('m', 1, 1)])];
    const ir = makeIR(code, defs, types, 'java');
    const { ctx, findings } = makeCtx(ir, code);
    new VariableShadowingPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag two different variable names', () => {
    const code = 'function f(a) { let b = 1; }\n';
    const defs = [
      makeDef(1, 'a', 1, 'param'),
      makeDef(2, 'b', 1, 'local'),
    ];
    const types = [makeType('F', [makeMethod('f', 1, 1)])];
    const ir = makeIR(code, defs, types, 'javascript', 'f.js');
    const { ctx, findings } = makeCtx(ir, code);
    new VariableShadowingPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('returns empty result when there are no types/methods', () => {
    const code = 'let x = 1;\n';
    const defs = [makeDef(1, 'x', 1, 'local')];
    const ir = makeIR(code, defs, [], 'javascript', 'script.js');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new VariableShadowingPass().run(ctx);
    expect(result.shadows).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('includes file and pass metadata in findings', () => {
    const code = [
      'void m(int n) {',  // 1
      '  int n = 0;',     // 2 — shadows param
      '}',                // 3
    ].join('\n');
    const defs = [
      makeDef(1, 'n', 1, 'param'),
      makeDef(2, 'n', 2, 'local'),
    ];
    const types = [makeType('App', [makeMethod('m', 1, 3)])];
    const ir = makeIR(code, defs, types, 'java', 'src/App.java');
    const { ctx, findings } = makeCtx(ir, code);
    new VariableShadowingPass().run(ctx);
    expect(findings[0].file).toBe('src/App.java');
    expect(findings[0].pass).toBe('variable-shadowing');
    expect(findings[0].category).toBe('reliability');
    expect(findings[0].id).toMatch(/^variable-shadowing-/);
  });
});
