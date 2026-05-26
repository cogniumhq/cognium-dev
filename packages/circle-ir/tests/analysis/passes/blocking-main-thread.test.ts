/**
 * Tests for Pass #83: blocking-main-thread (CWE-1050, category: performance)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { BlockingMainThreadPass } from '../../../src/analysis/passes/blocking-main-thread-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'handler.ts', language: 'typescript', loc: 30, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {},
    ...overrides,
  };
}

function makeCtx(ir: CircleIR): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code: '',
    language: ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

describe('BlockingMainThreadPass', () => {
  it('flags pbkdf2Sync inside a NestJS @Post decorated handler', () => {
    const ir = makeIR({
      types: [{
        name: 'AuthController',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'login',
          return_type: null,
          parameters: [],
          annotations: ['Post', 'HttpCode'],
          modifiers: [],
          start_line: 5,
          end_line: 15,
        }],
        fields: [],
        start_line: 1,
        end_line: 20,
      }],
      calls: [
        { method_name: 'pbkdf2Sync', receiver: 'crypto', arguments: [], location: { line: 10, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new BlockingMainThreadPass().run(ctx);
    expect(result.blockingInHandlers).toHaveLength(1);
    expect(result.blockingInHandlers[0].reason).toBe('crypto');
    expect(result.blockingInHandlers[0].handler).toBe('login');
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].cwe).toBe('CWE-1050');
    expect(ctx.findings[0].level).toBe('warning');
    expect(ctx.findings[0].message).toMatch(/pbkdf2Sync/);
    expect(ctx.findings[0].message).toMatch(/login/);
  });

  it('flags createHash inside a handler identified by (req, res) parameters', () => {
    const ir = makeIR({
      types: [{
        name: 'UserController',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'getUser',
          return_type: null,
          parameters: [
            { name: 'req', type: 'Request', annotations: [] },
            { name: 'res', type: 'Response', annotations: [] },
          ],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 10,
        }],
        fields: [],
        start_line: 1,
        end_line: 12,
      }],
      calls: [
        { method_name: 'createHash', receiver: 'crypto', arguments: [], location: { line: 5, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new BlockingMainThreadPass().run(ctx);
    expect(result.blockingInHandlers).toHaveLength(1);
    expect(result.blockingInHandlers[0].reason).toBe('crypto');
    expect(ctx.findings[0].message).toMatch(/createHash/);
  });

  it('flags readFileSync inside a handler named "handle"', () => {
    const ir = makeIR({
      types: [{
        name: 'RequestHandler',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'handle',
          return_type: null,
          parameters: [{ name: 'context', type: 'Context', annotations: [] }],
          annotations: [],
          modifiers: [],
          start_line: 2,
          end_line: 12,
        }],
        fields: [],
        start_line: 1,
        end_line: 14,
      }],
      calls: [
        { method_name: 'readFileSync', receiver: 'fs', arguments: [], location: { line: 6, column: 8 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new BlockingMainThreadPass().run(ctx);
    expect(result.blockingInHandlers).toHaveLength(1);
    expect(result.blockingInHandlers[0].reason).toBe('sync-suffix');
  });

  it('does NOT flag readFileSync in a non-handler method', () => {
    const ir = makeIR({
      types: [{
        name: 'FileUtils',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'loadConfig',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: ['private'],
          start_line: 1,
          end_line: 10,
        }],
        fields: [],
        start_line: 1,
        end_line: 12,
      }],
      calls: [
        { method_name: 'readFileSync', receiver: 'fs', arguments: [], location: { line: 5, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new BlockingMainThreadPass().run(ctx);
    expect(result.blockingInHandlers).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT flag non-blocking methods inside a handler', () => {
    const ir = makeIR({
      types: [{
        name: 'Controller',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'getData',
          return_type: null,
          parameters: [{ name: 'req', type: 'Request', annotations: [] }],
          annotations: ['Get'],
          modifiers: [],
          start_line: 1,
          end_line: 10,
        }],
        fields: [],
        start_line: 1,
        end_line: 12,
      }],
      calls: [
        { method_name: 'findAll', receiver: 'repo', arguments: [], location: { line: 5, column: 4 } },
        { method_name: 'readFile', receiver: 'fs', arguments: [], location: { line: 6, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new BlockingMainThreadPass().run(ctx);
    expect(result.blockingInHandlers).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('is a no-op for Java', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Controller.java', language: 'java', loc: 20, hash: '' },
      types: [{
        name: 'Controller',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'handle',
          return_type: null,
          parameters: [],
          annotations: ['GetMapping'],
          modifiers: [],
          start_line: 1,
          end_line: 10,
        }],
        fields: [],
        start_line: 1,
        end_line: 12,
      }],
      calls: [
        { method_name: 'readFileSync', receiver: null, arguments: [], location: { line: 5, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    const result = new BlockingMainThreadPass().run(ctx);
    expect(result.blockingInHandlers).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('includes correct metadata in findings', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'src/api/auth.ts', language: 'typescript', loc: 25, hash: '' },
      types: [{
        name: 'AuthController',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'register',
          return_type: null,
          parameters: [],
          annotations: ['Post'],
          modifiers: [],
          start_line: 3,
          end_line: 18,
        }],
        fields: [],
        start_line: 1,
        end_line: 20,
      }],
      calls: [
        { method_name: 'scryptSync', receiver: 'crypto', arguments: [], location: { line: 10, column: 4 } },
      ],
    });
    const ctx = makeCtx(ir);
    new BlockingMainThreadPass().run(ctx);
    expect(ctx.findings[0].file).toBe('src/api/auth.ts');
    expect(ctx.findings[0].pass).toBe('blocking-main-thread');
    expect(ctx.findings[0].category).toBe('performance');
    expect(ctx.findings[0].id).toMatch(/^blocking-main-thread-/);
  });
});
