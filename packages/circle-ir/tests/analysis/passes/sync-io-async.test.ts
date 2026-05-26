/**
 * Tests for Pass #48: sync-io-async (CWE-1050, category: performance)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { SyncIoAsyncPass } from '../../../src/analysis/passes/sync-io-async-pass.js';
import type {
  CircleIR, SastFinding, CallInfo, TypeInfo, MethodInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCall(method_name: string, line: number, receiver: string | null = null): CallInfo {
  return {
    method_name,
    receiver,
    arguments: [],
    location: { line, column: 0 },
  };
}

function makeMethod(
  name: string,
  startLine: number,
  endLine: number,
  modifiers: string[] = [],
): MethodInfo {
  return {
    name,
    return_type: null,
    parameters: [],
    annotations: [],
    modifiers,
    start_line: startLine,
    end_line: endLine,
  };
}

function makeType(name: string, methods: MethodInfo[]): TypeInfo {
  return {
    name,
    kind: 'class',
    methods,
    fields: [],
    annotations: [],
    modifiers: [],
    start_line: 1,
    end_line: 50,
  };
}

function makeIR(
  calls: CallInfo[],
  types: TypeInfo[],
  language: string = 'typescript',
  file = 'server.ts',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 50, hash: '' },
    types,
    calls,
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(ir: CircleIR): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code: '',
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

describe('SyncIoAsyncPass', () => {
  it('flags readFileSync inside an async method', () => {
    // async loadConfig() { ... readFileSync() ... } — lines 5–15
    const asyncMethod = makeMethod('loadConfig', 5, 15, ['async', 'public']);
    const types = [makeType('FileService', [asyncMethod])];
    const calls = [makeCall('readFileSync', 10)]; // inside async method
    const ir = makeIR(calls, types);
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-1050');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/readFileSync/);
    expect(findings[0].message).toMatch(/loadConfig/);
  });

  it('flags execSync inside an async method', () => {
    const asyncMethod = makeMethod('runScript', 1, 20, ['async']);
    const types = [makeType('Runner', [asyncMethod])];
    const calls = [makeCall('execSync', 10)];
    const ir = makeIR(calls, types);
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(1);
    expect(findings[0].evidence).toMatchObject({
      blocking_method: 'execSync',
      async_method: 'runScript',
    });
  });

  it('flags any *Sync method inside an async function', () => {
    const asyncMethod = makeMethod('process', 1, 20, ['async']);
    const types = [makeType('Handler', [asyncMethod])];
    // Custom *Sync method not in any hardcoded list
    const calls = [makeCall('customOperationSync', 10)];
    const ir = makeIR(calls, types);
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(1);
  });

  it('does NOT flag readFileSync in a non-async method', () => {
    const syncMethod = makeMethod('loadConfig', 5, 15, ['public']); // no 'async'
    const types = [makeType('FileService', [syncMethod])];
    const calls = [makeCall('readFileSync', 10)];
    const ir = makeIR(calls, types);
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag readFile (async variant) inside an async method', () => {
    const asyncMethod = makeMethod('loadConfig', 5, 15, ['async']);
    const types = [makeType('FileService', [asyncMethod])];
    const calls = [makeCall('readFile', 10)]; // async variant — no Sync suffix
    const ir = makeIR(calls, types);
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('is a no-op for Java', () => {
    const asyncMethod = makeMethod('loadConfig', 5, 15, ['async']);
    const types = [makeType('Service', [asyncMethod])];
    const calls = [makeCall('readFileSync', 10)];
    const ir = makeIR(calls, types, 'java', 'Service.java');
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('returns empty result when there are no async methods', () => {
    const types = [makeType('Service', [makeMethod('doWork', 1, 10, ['public'])])];
    const calls = [makeCall('readFileSync', 5)];
    const ir = makeIR(calls, types);
    const { ctx, findings } = makeCtx(ir);
    const result = new SyncIoAsyncPass().run(ctx);
    expect(result.blockingInAsyncFns).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('includes file and pass metadata in findings', () => {
    const asyncMethod = makeMethod('handle', 1, 20, ['async']);
    const types = [makeType('Handler', [asyncMethod])];
    const calls = [makeCall('statSync', 10)];
    const ir = makeIR(calls, types, 'typescript', 'src/handler.ts');
    const { ctx, findings } = makeCtx(ir);
    new SyncIoAsyncPass().run(ctx);
    expect(findings[0].file).toBe('src/handler.ts');
    expect(findings[0].pass).toBe('sync-io-async');
    expect(findings[0].category).toBe('performance');
    expect(findings[0].id).toMatch(/^sync-io-async-/);
  });
});
