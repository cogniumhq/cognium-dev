/**
 * Tests for Pass #81: leaked-global (CWE-1109, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { LeakedGlobalPass } from '../../../src/analysis/passes/leaked-global-pass.js';
import type {
  CircleIR, SastFinding, DFGDef, TypeInfo, MethodInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDef(id: number, variable: string, line: number): DFGDef {
  return { id, variable, line, kind: 'local' };
}

function makeMethod(name: string, startLine: number, endLine: number): MethodInfo {
  return {
    name, return_type: null, parameters: [], annotations: [], modifiers: [],
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
  language = 'javascript',
  file = 'app.js',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 10, hash: '' },
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

describe('LeakedGlobalPass', () => {
  it('flags bare assignment inside a JS function with no prior declaration', () => {
    // function f() { x = 5; }  — x has no let/const/var anywhere in f
    const code = [
      'function f() {',   // 1
      '  x = 5;',         // 2 — bare assignment, no declaration
      '}',                // 3
    ].join('\n');

    const defs = [makeDef(1, 'x', 2)];
    const types = [makeType('Module', [makeMethod('f', 1, 3)])];
    const ir = makeIR(code, defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new LeakedGlobalPass().run(ctx);

    expect(result.leaks).toHaveLength(1);
    expect(result.leaks[0].variable).toBe('x');
    expect(result.leaks[0].line).toBe(2);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-1109');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/x/);
    expect(findings[0].message).toMatch(/accidental global/);
  });

  it('does NOT flag when variable is declared with let elsewhere in the function', () => {
    // function f() { let x = 5; x = 10; }
    const code = [
      'function f() {',   // 1
      '  let x = 5;',     // 2 — declaration
      '  x = 10;',        // 3 — reassignment (no decl keyword, but x IS declared)
      '}',                // 4
    ].join('\n');

    const defs = [
      makeDef(1, 'x', 2),  // let x = 5 — has decl keyword
      makeDef(2, 'x', 3),  // x = 10   — no decl keyword, but x is declared above
    ];
    const types = [makeType('M', [makeMethod('f', 1, 4)])];
    const ir = makeIR(code, defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    new LeakedGlobalPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag variable declared with var', () => {
    const code = [
      'function g() {',   // 1
      '  var x = 5;',     // 2 — var is a declaration keyword
      '}',                // 3
    ].join('\n');

    const defs = [makeDef(1, 'x', 2)];
    const types = [makeType('M', [makeMethod('g', 1, 3)])];
    const ir = makeIR(code, defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    new LeakedGlobalPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag variable starting with underscore', () => {
    const code = [
      'function h() {',   // 1
      '  _temp = 5;',     // 2 — _ prefix → intentional
      '}',                // 3
    ].join('\n');

    const defs = [makeDef(1, '_temp', 2)];
    const types = [makeType('M', [makeMethod('h', 1, 3)])];
    const ir = makeIR(code, defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    new LeakedGlobalPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag Python code (language filter)', () => {
    const code = [
      'def f():',   // 1
      '    x = 5',  // 2
    ].join('\n');

    const defs = [makeDef(1, 'x', 2)];
    const types = [makeType('M', [makeMethod('f', 1, 2)])];
    const ir = makeIR(code, defs, types, 'python', 'app.py');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new LeakedGlobalPass().run(ctx);
    expect(result.leaks).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag skip-listed variable names (err, e, i, etc.)', () => {
    const code = [
      'function f() {',   // 1
      '  err = new Error();',  // 2 — skip-listed name
      '}',                     // 3
    ].join('\n');

    const defs = [makeDef(1, 'err', 2)];
    const types = [makeType('M', [makeMethod('f', 1, 3)])];
    const ir = makeIR(code, defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    new LeakedGlobalPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag TypeScript const declaration', () => {
    const code = [
      'function ts() {',  // 1
      '  const x = 5;',   // 2 — const is a declaration keyword
      '}',                // 3
    ].join('\n');

    const defs = [makeDef(1, 'x', 2)];
    const types = [makeType('M', [makeMethod('ts', 1, 3)])];
    const ir = makeIR(code, defs, types, 'typescript', 'app.ts');
    const { ctx, findings } = makeCtx(ir, code);
    new LeakedGlobalPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('includes file and pass metadata in findings', () => {
    const code = [
      'function run() {',  // 1
      '  result = 42;',    // 2 — bare assignment, no declaration
      '}',                 // 3
    ].join('\n');

    const defs = [makeDef(1, 'result', 2)];
    const types = [makeType('M', [makeMethod('run', 1, 3)])];
    const ir = makeIR(code, defs, types, 'javascript', 'src/runner.js');
    const { ctx, findings } = makeCtx(ir, code);
    new LeakedGlobalPass().run(ctx);
    expect(findings[0].file).toBe('src/runner.js');
    expect(findings[0].pass).toBe('leaked-global');
    expect(findings[0].category).toBe('reliability');
    expect(findings[0].id).toMatch(/^leaked-global-/);
  });
});
