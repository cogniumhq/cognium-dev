/**
 * Tests for Pass #82: unused-variable (CWE-561, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { UnusedVariablePass } from '../../../src/analysis/passes/unused-variable-pass.js';
import type {
  CircleIR, SastFinding, DFGDef, DFGUse,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDef(id: number, variable: string, line: number): DFGDef {
  return { id, variable, line, kind: 'local' };
}

function makeUse(id: number, variable: string, line: number, defId: number): DFGUse {
  return { id, variable, line, def_id: defId };
}

function makeIR(
  code: string,
  defs: DFGDef[],
  uses: DFGUse[],
  file = 'App.ts',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs, uses, chains: [] },
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

describe('UnusedVariablePass', () => {
  it('flags a local variable with no uses', () => {
    const code = 'const x = 5;\n'; // x is declared but never read
    const defs = [makeDef(1, 'x', 1)];
    const uses: DFGUse[] = []; // no uses at all
    const ir = makeIR(code, defs, uses);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new UnusedVariablePass().run(ctx);

    expect(result.unusedVars).toHaveLength(1);
    expect(result.unusedVars[0].variable).toBe('x');
    expect(result.unusedVars[0].line).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-561');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].level).toBe('note');
    expect(findings[0].message).toMatch(/x/);
    expect(findings[0].message).toMatch(/never read/);
  });

  it('does NOT flag a variable that has uses', () => {
    const code = 'const x = 5;\nconsole.log(x);\n';
    const defs = [makeDef(1, 'x', 1)];
    const uses = [makeUse(1, 'x', 2, 1)]; // use at line 2 reaches def 1
    const ir = makeIR(code, defs, uses);
    const { ctx, findings } = makeCtx(ir, code);
    new UnusedVariablePass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag variables starting with underscore', () => {
    const code = 'const _x = 5;\n';
    const defs = [makeDef(1, '_x', 1)];
    const ir = makeIR(code, defs, []);
    const { ctx, findings } = makeCtx(ir, code);
    new UnusedVariablePass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag catch-block variables', () => {
    const code = 'try {} catch (err) { /* ignored */ }\n';
    const defs = [makeDef(1, 'err', 1)];
    const ir = makeIR(code, defs, []);
    const { ctx, findings } = makeCtx(ir, code);
    new UnusedVariablePass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags the first def (overwritten before read) but not the second', () => {
    // let x = 1;   (line 1) — value overwritten without read → unused
    // x = 2;       (line 2) — creates second def
    // use(x);      (line 3) — uses second def
    const code = [
      'let x = 1;',  // line 1
      'x = 2;',      // line 2
      'use(x);',     // line 3
    ].join('\n');

    const def1 = makeDef(1, 'x', 1);
    const def2 = makeDef(2, 'x', 2);
    // Only use at line 3 reaches def2 (second def)
    const uses = [makeUse(1, 'x', 3, 2)];
    const ir = makeIR(code, [def1, def2], uses);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new UnusedVariablePass().run(ctx);

    // def1 (x=1) has no uses → flagged
    // def2 (x=2) has a use → not flagged
    expect(result.unusedVars).toHaveLength(1);
    expect(result.unusedVars[0].line).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(1);
  });

  it('does NOT flag skip-listed variable names (err, e, i, etc.)', () => {
    const code = 'const err = new Error();\nconst e = 1;\nconst i = 0;\n';
    const defs = [
      makeDef(1, 'err', 1),
      makeDef(2, 'e', 2),
      makeDef(3, 'i', 3),
    ];
    const ir = makeIR(code, defs, []);
    const { ctx, findings } = makeCtx(ir, code);
    new UnusedVariablePass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('skips test files and emits no findings', () => {
    const code = 'const x = 5;\n'; // x is unused, but this is a test file
    const defs = [makeDef(1, 'x', 1)];
    const ir = makeIR(code, defs, [], 'src/utils.test.ts');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new UnusedVariablePass().run(ctx);
    expect(result.unusedVars).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('includes file and pass metadata in findings', () => {
    const code = 'const result = compute();\n';
    const defs = [makeDef(1, 'result', 1)];
    const ir = makeIR(code, defs, [], 'src/helpers.ts');
    const { ctx, findings } = makeCtx(ir, code);
    new UnusedVariablePass().run(ctx);
    expect(findings[0].file).toBe('src/helpers.ts');
    expect(findings[0].pass).toBe('unused-variable');
    expect(findings[0].category).toBe('reliability');
    expect(findings[0].id).toMatch(/^unused-variable-/);
  });
});
