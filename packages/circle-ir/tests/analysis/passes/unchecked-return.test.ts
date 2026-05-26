/**
 * Tests for Pass #28: unchecked-return (CWE-252, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { UncheckedReturnPass } from '../../../src/analysis/passes/unchecked-return-pass.js';
import type { CircleIR, SastFinding, CallInfo, DFGDef } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCall(
  method_name: string,
  line: number,
  receiver: string | null = null,
): CallInfo {
  return {
    method_name,
    receiver,
    arguments: [],
    location: { line, column: 0 },
  };
}

function makeDef(variable: string, line: number): DFGDef {
  return { id: line, variable, line, kind: 'local' };
}

function makeIR(
  code: string,
  calls: CallInfo[],
  defs: DFGDef[] = [],
  file = 'App.java',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'java', loc: 20, hash: '' },
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
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
  };
  return { ctx, findings };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('UncheckedReturnPass', () => {
  it('flags file.delete() when return value is discarded', () => {
    const code = 'file.delete();\n';
    const calls = [makeCall('delete', 1, 'file')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new UncheckedReturnPass().run(ctx);
    expect(result.uncheckedCalls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-252');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/delete/);
    expect(findings[0].message).toMatch(/silently discarded/);
  });

  it('does NOT flag when result is captured in a variable', () => {
    const code = 'boolean ok = file.delete();\n';
    const calls = [makeCall('delete', 1, 'file')];
    const defs = [makeDef('ok', 1)]; // def at line 1 → result captured
    const ir = makeIR(code, calls, defs);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag when result is checked in an if statement', () => {
    const code = 'if (file.delete()) { ... }\n';
    const calls = [makeCall('delete', 1, 'file')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags file.createNewFile() when result is discarded', () => {
    const code = 'file.createNewFile();\n';
    const calls = [makeCall('createNewFile', 1, 'file')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/createNewFile/);
  });

  it('flags matcher.find() when result is discarded', () => {
    const code = 'matcher.find();\n';
    const calls = [makeCall('find', 1, 'matcher')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('does NOT flag list.add() — not in the must-check list', () => {
    const code = 'list.add(item);\n';
    const calls = [makeCall('add', 1, 'list')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags mkdir() — high-confidence regardless of receiver', () => {
    const code = 'tmpDir.mkdir();\n';
    const calls = [makeCall('mkdir', 1, 'tmpDir')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/mkdir/);
  });

  it('flags tryLock() — concurrent high-confidence', () => {
    const code = 'lock.tryLock();\n';
    const calls = [makeCall('tryLock', 1, 'lock')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('flags medium-confidence renameTo when receiver looks like a file', () => {
    const code = 'file.renameTo(dest);\n';
    const calls = [makeCall('renameTo', 1, 'file')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(1);
  });

  it('does NOT flag medium-confidence renameTo with non-file receiver', () => {
    const code = 'conn.renameTo(dest);\n'; // conn is not a file receiver
    const calls = [makeCall('renameTo', 1, 'conn')];
    const ir = makeIR(code, calls);
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('includes file and pass metadata in findings', () => {
    const code = 'file.delete();\n';
    const calls = [makeCall('delete', 1, 'file')];
    const ir = makeIR(code, calls, [], 'src/Cleaner.java');
    const { ctx, findings } = makeCtx(ir, code);
    new UncheckedReturnPass().run(ctx);
    expect(findings[0].file).toBe('src/Cleaner.java');
    expect(findings[0].pass).toBe('unchecked-return');
    expect(findings[0].category).toBe('reliability');
    expect(findings[0].id).toMatch(/^unchecked-return-/);
  });
});
