/**
 * Tests for Pass #24: missing-await (CWE-252, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { MissingAwaitPass } from '../../../src/analysis/passes/missing-await-pass.js';
import type { CircleIR, SastFinding, CallInfo, DFGDef } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCall(method_name: string, line: number): CallInfo {
  return {
    method_name,
    receiver: null,
    arguments: [],
    location: { line, column: 0 },
  };
}

function makeDef(id: number, variable: string, line: number): DFGDef {
  return { id, variable, line, kind: 'local' };
}

function makeIR(
  language: CircleIR['meta']['language'],
  calls: CallInfo[],
  defs: DFGDef[] = [],
  file = 'app.ts',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 20, hash: '' },
    types: [],
    calls,
    cfg: { blocks: [], edges: [] },
    dfg: { defs, uses: [], chains: [] },
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

describe('MissingAwaitPass', () => {
  it('returns empty result for non-JS/TS languages', () => {
    const calls = [makeCall('findOne', 5)];
    const ir = makeIR('java', calls);
    const code = 'findOne(id);\n';
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags a call to an async method with no await and no DFG def', () => {
    // line 3: "  findOne(userId);"
    const code = 'function handler() {\n  setup();\n  findOne(userId);\n}\n';
    const calls = [makeCall('findOne', 3)];
    const ir = makeIR('javascript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-252');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].line).toBe(3);
  });

  it('does not flag when `await` is present on the same line', () => {
    const code = 'async function go() {\n  const u = await findOne(id);\n}\n';
    const calls = [makeCall('findOne', 2)];
    const defs = [makeDef(1, 'u', 2)];
    const ir = makeIR('typescript', calls, defs);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag when result is captured in a variable (DFG def present)', () => {
    // No await on the line, but result is assigned → DFG def at line 2
    const code = 'function go() {\n  const p = findOne(id);\n}\n';
    const calls = [makeCall('findOne', 2)];
    const defs = [makeDef(1, 'p', 2)]; // result captured
    const ir = makeIR('typescript', calls, defs);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag `return asyncOp()` (intentional Promise pass-through)', () => {
    const code = 'function go() {\n  return findOne(id);\n}\n';
    const calls = [makeCall('findOne', 2)];
    const ir = makeIR('typescript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does not flag a method not in ASYNC_METHODS', () => {
    const code = 'function go() {\n  processItem(x);\n}\n';
    const calls = [makeCall('processItem', 2)];
    const ir = makeIR('typescript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags `fetch()` call without await in TypeScript', () => {
    const code = 'function load() {\n  fetch("/api/data");\n}\n';
    const calls = [makeCall('fetch', 2)];
    const ir = makeIR('typescript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(1);
    expect(findings[0].message).toMatch(/fetch/);
  });

  it('flags `writeFile()` without await', () => {
    const code = 'function save() {\n  writeFile(path, data);\n}\n';
    const calls = [makeCall('writeFile', 2)];
    const ir = makeIR('javascript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    new MissingAwaitPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/writeFile/);
  });

  it('flags `connect()` without await', () => {
    const code = 'function init() {\n  connect();\n}\n';
    const calls = [makeCall('connect', 2)];
    const ir = makeIR('typescript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    new MissingAwaitPass().run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('collects multiple missing-await findings', () => {
    const code = [
      'async function handler() {',
      '  findOne(id);',        // line 2
      '  writeFile(p, d);',    // line 3
      '  fetch("/api");',      // line 4
      '}',
    ].join('\n');
    const calls = [
      makeCall('findOne', 2),
      makeCall('writeFile', 3),
      makeCall('fetch', 4),
    ];
    const ir = makeIR('typescript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingAwaitPass().run(ctx);
    expect(result.missingAwaitCalls).toHaveLength(3);
    expect(findings).toHaveLength(3);
  });

  it('includes file path and pass name in finding', () => {
    const code = 'function go() {\n  findOne(id);\n}\n';
    const calls = [makeCall('findOne', 2)];
    const ir = makeIR('typescript', calls, [], 'src/repo.ts');
    const { ctx, findings } = makeCtx(ir, code);
    new MissingAwaitPass().run(ctx);
    expect(findings[0].file).toBe('src/repo.ts');
    expect(findings[0].pass).toBe('missing-await');
    expect(findings[0].category).toBe('reliability');
    expect(findings[0].id).toBe('missing-await-src/repo.ts-2');
  });

  it('includes snippet in finding', () => {
    const code = 'async function go() {\n  findOne(userId);\n}\n';
    const calls = [makeCall('findOne', 2)];
    const ir = makeIR('typescript', calls);
    const { ctx, findings } = makeCtx(ir, code);
    new MissingAwaitPass().run(ctx);
    expect(findings[0].snippet).toBe('findOne(userId);');
  });
});
