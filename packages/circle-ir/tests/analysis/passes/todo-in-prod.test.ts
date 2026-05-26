/**
 * Tests for Pass #36: todo-in-prod (category: maintainability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { TodoInProdPass } from '../../../src/analysis/passes/todo-in-prod-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(file = 'app.ts'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'typescript', loc: 10, hash: '' },
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

function makeCtx(ir: CircleIR, code: string): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code,
    language: ir.meta.language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used in this pass'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
  };
  return { ctx, findings };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TodoInProdPass', () => {
  it('returns empty result for test file paths', () => {
    const code = '// TODO: fix this later\n';
    const ir = makeIR('src/__tests__/utils.test.ts');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new TodoInProdPass().run(ctx);
    expect(result.markerLines).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('returns empty result for spec file paths', () => {
    const code = '// FIXME: broken\n';
    const ir = makeIR('tests/service.spec.ts');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new TodoInProdPass().run(ctx);
    expect(result.markerLines).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('returns empty result when no markers are present', () => {
    const code = [
      'function processUser(id: string) {',
      '  const user = db.findById(id);',
      '  return user;',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(makeIR(), code);
    const result = new TodoInProdPass().run(ctx);
    expect(result.markerLines).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags a TODO in a // comment with low severity', () => {
    const code = 'function go() {\n  // TODO: handle edge case\n  return 1;\n}\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    const result = new TodoInProdPass().run(ctx);
    expect(result.markerLines).toHaveLength(1);
    expect(result.markerLines[0].marker).toBe('TODO');
    expect(result.markerLines[0].line).toBe(2);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].level).toBe('note');
    expect(findings[0].category).toBe('maintainability');
  });

  it('flags FIXME with medium severity', () => {
    const code = 'function go() {\n  // FIXME: this is broken\n  return 1;\n}\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].evidence).toEqual({ marker: 'FIXME' });
  });

  it('flags HACK with medium severity', () => {
    const code = 'const x = 1; // HACK: workaround for bug\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].evidence).toEqual({ marker: 'HACK' });
  });

  it('flags XXX with low severity', () => {
    const code = '// XXX: unclear logic here\nconst a = 1;\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].evidence).toEqual({ marker: 'XXX' });
  });

  it('is case-insensitive (todo, fixme, hack, xxx in lowercase)', () => {
    const code = '// todo: lower case\n// fixme: also lower\n// hack: and this\n// xxx: and this too\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(4);
  });

  it('detects markers inside a block comment line (* prefix)', () => {
    const code = [
      '/**',
      ' * TODO: improve this',
      ' */',
      'function foo() {}',
    ].join('\n');
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(2);
  });

  it('detects markers after # prefix (Python-style comment)', () => {
    const code = '# TODO: refactor\ndef foo(): pass\n';
    const ir = makeIR('app.py');
    const { ctx, findings } = makeCtx(ir, code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toEqual({ marker: 'TODO' });
  });

  it('detects markers after -- prefix (SQL-style comment)', () => {
    const code = '-- TODO: optimize this query\nSELECT * FROM users;\n';
    const ir = makeIR('query.sql');
    const { ctx, findings } = makeCtx(ir, code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('does not flag TODO inside a string literal', () => {
    // The MARKER_RE requires a comment prefix (// # -- *) before the marker
    const code = 'const msg = "TODO: this is just a string";\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('detects multiple markers on different lines', () => {
    const code = [
      'function init() {',
      '  // TODO: add logging',
      '  setup();',
      '  // FIXME: null check missing',
      '  run();',
      '  // HACK: skip validation for now',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(makeIR(), code);
    const result = new TodoInProdPass().run(ctx);
    expect(result.markerLines).toHaveLength(3);
    expect(findings).toHaveLength(3);
    const markers = findings.map(f => (f.evidence as { marker: string }).marker);
    expect(markers).toContain('TODO');
    expect(markers).toContain('FIXME');
    expect(markers).toContain('HACK');
  });

  it('records correct line number for each marker', () => {
    const code = [
      '// line 1 — no marker',
      '// TODO: line 2',
      '// line 3 — no marker',
      '// FIXME: line 4',
    ].join('\n');
    const { ctx } = makeCtx(makeIR(), code);
    const result = new TodoInProdPass().run(ctx);
    const lines = result.markerLines.map(m => m.line);
    expect(lines).toContain(2);
    expect(lines).toContain(4);
  });

  it('includes correct file path and unique id in finding', () => {
    const code = '// TODO: fix auth logic\n';
    const ir = makeIR('src/auth/service.ts');
    const { ctx, findings } = makeCtx(ir, code);
    new TodoInProdPass().run(ctx);
    expect(findings[0].file).toBe('src/auth/service.ts');
    expect(findings[0].id).toBe('todo-in-prod-src/auth/service.ts-1');
    expect(findings[0].pass).toBe('todo-in-prod');
  });

  it('includes the trimmed line text as snippet', () => {
    const code = '  // TODO: cache results here\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings[0].snippet).toBe('// TODO: cache results here');
  });

  it('includes marker text in message', () => {
    const code = '// FIXME: rewrite this\n';
    const { ctx, findings } = makeCtx(makeIR(), code);
    new TodoInProdPass().run(ctx);
    expect(findings[0].message).toMatch(/FIXME/);
    expect(findings[0].message).toMatch(/line 1/);
  });
});
