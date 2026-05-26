/**
 * Tests for Pass #88: naming-convention (category: maintainability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { NamingConventionPass } from '../../../src/analysis/passes/naming-convention-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 30, hash: '' },
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

describe('NamingConventionPass', () => {
  // -------------------------------------------------------------------------
  // Java / TypeScript: class names
  // -------------------------------------------------------------------------

  it('flags a TypeScript class not in PascalCase (starts with lowercase)', () => {
    const ir = makeIR({
      types: [{
        name: 'userService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 1,
        end_line: 5,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.some(v => v.name === 'userService' && v.entity === 'class')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'naming-convention')).toBe(true);
    expect(ctx.findings[0].level).toBe('note');
  });

  it('does NOT flag a TypeScript class in PascalCase', () => {
    const ir = makeIR({
      types: [{
        name: 'UserService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 1,
        end_line: 5,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.entity === 'class')).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Java / TypeScript: interface naming (I-prefix)
  // -------------------------------------------------------------------------

  it('flags an interface using the I-prefix anti-pattern when enforceIPrefix is enabled', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'IFoo.ts', language: 'typescript', loc: 5, hash: '' },
      types: [{
        name: 'IUserRepository',
        kind: 'interface',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 1,
        end_line: 3,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass({ enforceIPrefix: true }).run(ctx);
    expect(result.violations.some(v => v.name === 'IUserRepository' && v.entity === 'interface')).toBe(true);
  });

  it('does NOT flag an I-prefix interface by default (enforceIPrefix is opt-in)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'IFoo.ts', language: 'typescript', loc: 5, hash: '' },
      types: [{
        name: 'IUserRepository',
        kind: 'interface',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 1,
        end_line: 3,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx); // default: enforceIPrefix = false
    expect(result.violations.filter(v => v.entity === 'interface')).toHaveLength(0);
  });

  it('does NOT flag a properly named interface', () => {
    const ir = makeIR({
      types: [{
        name: 'UserRepository',
        kind: 'interface',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 1,
        end_line: 5,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.entity === 'interface')).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Java / TypeScript: method names
  // -------------------------------------------------------------------------

  it('flags a TypeScript method not in camelCase (starts with uppercase)', () => {
    const ir = makeIR({
      types: [{
        name: 'OrderController',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'ProcessOrder',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 3,
          end_line: 8,
        }],
        fields: [],
        start_line: 1,
        end_line: 10,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.some(v => v.name === 'ProcessOrder' && v.entity === 'method')).toBe(true);
  });

  it('does NOT flag a properly named camelCase method', () => {
    const ir = makeIR({
      types: [{
        name: 'OrderController',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'processOrder',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 3,
          end_line: 8,
        }],
        fields: [],
        start_line: 1,
        end_line: 10,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.entity === 'method')).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Python: snake_case methods
  // -------------------------------------------------------------------------

  it('flags a Python method using camelCase instead of snake_case', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'service.py', language: 'python', loc: 20, hash: '' },
      types: [{
        name: 'UserService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'getUser',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 3,
          end_line: 8,
        }],
        fields: [],
        start_line: 1,
        end_line: 10,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.some(v => v.name === 'getUser' && v.entity === 'method')).toBe(true);
    expect(ctx.findings[0].message).toMatch(/snake_case/);
  });

  it('does NOT flag a properly named Python snake_case method', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'service.py', language: 'python', loc: 10, hash: '' },
      types: [{
        name: 'UserService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'get_user',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 3,
          end_line: 8,
        }],
        fields: [],
        start_line: 1,
        end_line: 10,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.entity === 'method')).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Python: dunder methods are exempt
  // -------------------------------------------------------------------------

  it('does NOT flag Python dunder methods like __init__', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'model.py', language: 'python', loc: 10, hash: '' },
      types: [{
        name: 'User',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: '__init__',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 2,
          end_line: 5,
        }],
        fields: [],
        start_line: 1,
        end_line: 6,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.entity === 'method')).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Java: constant naming
  // -------------------------------------------------------------------------

  it('flags a Java static final field not in UPPER_SNAKE_CASE', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Config.java', language: 'java', loc: 10, hash: '' },
      types: [{
        name: 'Config',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [
          { name: 'maxRetries', type: 'int', modifiers: ['final', 'static', 'public'], annotations: [] },
        ],
        start_line: 1,
        end_line: 8,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.some(v => v.name === 'maxRetries' && v.entity === 'field')).toBe(true);
    expect(ctx.findings[0].message).toMatch(/UPPER_SNAKE_CASE/);
  });

  it('does NOT flag a Java static final field already in UPPER_SNAKE_CASE', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Config.java', language: 'java', loc: 10, hash: '' },
      types: [{
        name: 'Config',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [
          { name: 'MAX_RETRIES', type: 'int', modifiers: ['final', 'static', 'public'], annotations: [] },
        ],
        start_line: 1,
        end_line: 8,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.entity === 'field')).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Skip rules
  // -------------------------------------------------------------------------

  it('skips names with _ prefix (private convention)', () => {
    const ir = makeIR({
      types: [{
        name: 'Service',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: '_internalHelper',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: ['private'],
          start_line: 5,
          end_line: 10,
        }],
        fields: [],
        start_line: 1,
        end_line: 12,
      }],
    });
    const ctx = makeCtx(ir);
    const result = new NamingConventionPass().run(ctx);
    expect(result.violations.filter(v => v.name === '_internalHelper')).toHaveLength(0);
  });

  it('caps findings at 20 per file', () => {
    // Create 30 mis-named methods
    const methods = Array.from({ length: 30 }, (_, i) => ({
      name: `BadName${i}`,
      return_type: null as null,
      parameters: [] as never[],
      annotations: [] as string[],
      modifiers: [] as string[],
      start_line: i + 1,
      end_line: i + 1,
    }));

    const ir = makeIR({
      types: [{
        name: 'BigClass',
        kind: 'class' as const,
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods,
        fields: [],
        start_line: 1,
        end_line: 35,
      }],
    });
    const ctx = makeCtx(ir);
    new NamingConventionPass().run(ctx);
    expect(ctx.findings.length).toBeLessThanOrEqual(20);
  });

  it('includes correct metadata in findings', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'src/api/auth_controller.ts', language: 'typescript', loc: 20, hash: '' },
      types: [{
        name: 'auth_controller',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 1,
        end_line: 5,
      }],
    });
    const ctx = makeCtx(ir);
    new NamingConventionPass().run(ctx);
    expect(ctx.findings[0].file).toBe('src/api/auth_controller.ts');
    expect(ctx.findings[0].pass).toBe('naming-convention');
    expect(ctx.findings[0].category).toBe('maintainability');
  });
});
