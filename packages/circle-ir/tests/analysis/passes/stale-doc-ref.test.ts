/**
 * Tests for Pass #33: stale-doc-ref (maintainability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { StaleDocRefPass } from '../../../src/analysis/passes/stale-doc-ref-pass.js';
import type { CircleIR, SastFinding, TypeInfo, ImportInfo } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeType(name: string): TypeInfo {
  return {
    name, kind: 'class', start_line: 1, end_line: 10,
    methods: [], fields: [], annotations: [], modifiers: [], superclass: null, interfaces: [],
  };
}

function makeImport(name: string): ImportInfo {
  return { imported_name: name, from_package: './somewhere', alias: null, is_wildcard: false, line_number: 1 };
}

function makeIR(code: string, types: TypeInfo[], imports: ImportInfo[], file = 'src/App.ts'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 20, hash: '' },
    types, calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports, exports: [], unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(ir: CircleIR, code: string): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph, code, language: 'typescript',
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

describe('StaleDocRefPass', () => {
  it('does NOT flag {@link} where the type exists in ir.types', () => {
    const code = `
/** See {@link FooClass} for details. */
function doSomething() {}
`;
    const { ctx, findings } = makeCtx(makeIR(code, [makeType('FooClass')], []), code);
    new StaleDocRefPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags {@link} when the type is unknown', () => {
    const code = `
/** See {@link BarUtil} for details. */
function doSomething() {}
`;
    const { ctx, findings } = makeCtx(makeIR(code, [], []), code);
    new StaleDocRefPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('BarUtil');
  });

  it('does NOT flag @see when the symbol is in imports', () => {
    const code = `
/** @see MyInterface */
function doSomething() {}
`;
    const { ctx, findings } = makeCtx(makeIR(code, [], [makeImport('MyInterface')]), code);
    new StaleDocRefPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags @see when the symbol is unknown', () => {
    const code = `
/** @see GhostClass */
function doSomething() {}
`;
    const { ctx, findings } = makeCtx(makeIR(code, [], []), code);
    new StaleDocRefPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('GhostClass');
  });

  it('does NOT flag doc comments with no link refs', () => {
    const code = `
/** This function does stuff. No refs here. */
function doSomething() {}
`;
    const { ctx, findings } = makeCtx(makeIR(code, [], []), code);
    const result = new StaleDocRefPass().run(ctx);
    expect(result.staleRefs).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('produces no findings when there are no doc comments at all', () => {
    const code = `
// regular comment
function doSomething() {}
`;
    const { ctx, findings } = makeCtx(makeIR(code, [], []), code);
    const result = new StaleDocRefPass().run(ctx);
    expect(result.staleRefs).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('includes correct pass metadata in findings', () => {
    const code = `/** @see Unknown */\nfunction f() {}`;
    const { ctx, findings } = makeCtx(makeIR(code, [], [], 'src/helpers.ts'), code);
    new StaleDocRefPass().run(ctx);

    expect(findings[0].pass).toBe('stale-doc-ref');
    expect(findings[0].category).toBe('maintainability');
    expect(findings[0].level).toBe('note');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].file).toBe('src/helpers.ts');
  });

  it('handles qualified {@link java.util.List} by taking the last segment', () => {
    const code = `/** Uses {@link java.util.List} internally. */\nfunction f() {}`;
    // 'List' is not in types/imports → should flag
    const { ctx, findings } = makeCtx(makeIR(code, [], []), code);
    new StaleDocRefPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('List');
  });
});
