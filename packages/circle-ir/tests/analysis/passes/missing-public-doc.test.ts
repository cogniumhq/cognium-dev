/**
 * Tests for Pass #35: missing-public-doc (category: maintainability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { MissingPublicDocPass } from '../../../src/analysis/passes/missing-public-doc-pass.js';
import type {
  CircleIR, SastFinding, TypeInfo, MethodInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMethod(
  name: string,
  start_line: number,
  end_line: number,
  modifiers: string[] = [],
): MethodInfo {
  return { name, return_type: null, parameters: [], annotations: [], modifiers, start_line, end_line };
}

function makeType(
  name: string,
  start_line: number,
  end_line: number,
  methods: MethodInfo[] = [],
): TypeInfo {
  return {
    name, kind: 'class', package: null, extends: null, implements: [],
    annotations: [], methods, fields: [], start_line, end_line,
  };
}

function makeIR(
  language: CircleIR['meta']['language'],
  types: TypeInfo[],
  file = 'app.ts',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 50, hash: '' },
    types,
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

describe('MissingPublicDocPass', () => {
  it('returns empty result for test file paths', () => {
    const types = [makeType('MyClass', 3, 10, [makeMethod('doWork', 5, 8, ['public'])])];
    const ir = makeIR('typescript', types, 'src/__tests__/utils.test.ts');
    const code = 'class MyClass {\n  doWork() {}\n}\n';
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
    expect(result.missingDocTypes).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('returns empty result for unsupported languages (rust)', () => {
    const types = [makeType('MyStruct', 1, 5)];
    const ir = makeIR('rust', types);
    const { ctx, findings } = makeCtx(ir, 'struct MyStruct {}');
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
    expect(result.missingDocTypes).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('flags a TypeScript class with no doc comment', () => {
    // Class starts at line 1 — no /** above it
    const types = [makeType('UserService', 1, 10)];
    const ir = makeIR('typescript', types);
    const code = 'class UserService {\n}\n';
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocTypes).toHaveLength(1);
    expect(result.missingDocTypes[0].name).toBe('UserService');
    expect(findings.some(f => f.message.includes('UserService'))).toBe(true);
  });

  it('does not flag a TypeScript class with a JSDoc comment', () => {
    const types = [makeType('UserService', 3, 12)];
    const ir = makeIR('typescript', types);
    const code = [
      '/**',
      ' * Manages users.',
      ' */',
      'class UserService {',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocTypes).toHaveLength(0);
    expect(findings.filter(f => f.message.includes('class'))).toHaveLength(0);
  });

  it('flags a public TypeScript method with no doc comment', () => {
    const method = makeMethod('getUser', 5, 7, []); // no 'private' → public in TS
    const types = [makeType('UserService', 1, 10, [method])];
    const ir = makeIR('typescript', types);
    const code = [
      '/**',
      ' * Manages users.',
      ' */',
      'class UserService {',
      '  getUser(id: string) {',
      '    return null;',
      '  }',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(1);
    expect(result.missingDocMethods[0].method.name).toBe('getUser');
    const methodFinding = findings.find(f => f.message.includes('getUser'));
    expect(methodFinding).toBeDefined();
    expect(methodFinding!.category).toBe('maintainability');
    expect(methodFinding!.level).toBe('note');
  });

  it('does not flag a private TypeScript method', () => {
    const method = makeMethod('_internal', 5, 7, ['private']);
    const types = [makeType('MyClass', 1, 10, [method])];
    const ir = makeIR('typescript', types);
    const code = '/**\n * A class.\n */\nclass MyClass {\n  private _internal() {}\n}\n';
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });

  it('does not flag a protected TypeScript method', () => {
    const method = makeMethod('validate', 5, 7, ['protected']);
    const types = [makeType('Base', 1, 10, [method])];
    const ir = makeIR('typescript', types);
    const code = '/**\n * A class.\n */\nclass Base {\n  protected validate() {}\n}\n';
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });

  it('does not flag a TypeScript method preceded by a JSDoc comment', () => {
    const method = makeMethod('getUser', 6, 8, []);
    const types = [makeType('Service', 1, 10, [method])];
    const ir = makeIR('typescript', types);
    const code = [
      '/**',
      ' * Service class.',
      ' */',
      'class Service {',
      '  /** Get the user. */',
      '  getUser(id: string) {',
      '    return null;',
      '  }',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });

  it('flags a Java public method with no doc comment', () => {
    const method = makeMethod('processRequest', 5, 8, ['public']);
    const types = [makeType('Controller', 1, 12, [method])];
    const ir = makeIR('java', types, 'Controller.java');
    // Class has doc, method does not
    const code = [
      '/**',
      ' * Controller class.',
      ' */',
      'public class Controller {',
      '    public void processRequest() {',
      '        // logic',
      '        return;',
      '    }',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(1);
    expect(result.missingDocMethods[0].method.name).toBe('processRequest');
  });

  it('does not flag a Java private method', () => {
    const method = makeMethod('helper', 5, 7, ['private']);
    const types = [makeType('Service', 1, 10, [method])];
    const ir = makeIR('java', types, 'Service.java');
    const code = '/**\n * Service.\n */\npublic class Service {\n    private void helper() {}\n}\n';
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });

  it('does not flag a Python method starting with underscore', () => {
    const method = makeMethod('_helper', 5, 7);
    const types = [makeType('MyClass', 1, 10, [method])];
    const ir = makeIR('python', types, 'app.py');
    const code = [
      '"""',
      'My module.',
      '"""',
      'class MyClass:',
      '    def _helper(self):',
      '        pass',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });

  it('does not flag a Python method with a docstring', () => {
    const method = makeMethod('process', 5, 9);
    const types = [makeType('Processor', 1, 12, [method])];
    const ir = makeIR('python', types, 'app.py');
    const code = [
      '"""Module doc."""',
      'class Processor:',
      '    pass',
      '',
      '    def process(self, data):',
      '        """Process the data."""',
      '        return data',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });

  it('flags a Python method without a docstring', () => {
    const method = makeMethod('run', 3, 5);
    const types = [makeType('Runner', 1, 7, [method])];
    const ir = makeIR('python', types, 'runner.py');
    const code = [
      'class Runner:',
      '    pass',
      '    def run(self):',
      '        return True',
      '',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods.some(m => m.method.name === 'run')).toBe(true);
    expect(findings.some(f => f.message.includes('run'))).toBe(true);
  });

  it('includes fix suggestion in type finding', () => {
    const types = [makeType('MyClass', 1, 5)];
    const ir = makeIR('typescript', types);
    const code = 'class MyClass {\n}\n';
    const { ctx, findings } = makeCtx(ir, code);
    new MissingPublicDocPass().run(ctx);
    const typeFinding = findings.find(f => f.message.includes('MyClass'));
    expect(typeFinding?.fix).toMatch(/MyClass/);
  });

  it('detects doc comment with multi-line annotation above method', () => {
    // Annotation between doc comment and method should not break detection
    const method = makeMethod('handle', 7, 9, []);
    const types = [makeType('Handler', 1, 12, [method])];
    const ir = makeIR('java', types, 'Handler.java');
    const code = [
      '/**',
      ' * Handler.',
      ' */',
      'public class Handler {',
      '    /**',
      '     * Handle the request.',
      '     */',
      '    public void handle() {',
      '        // body',
      '    }',
      '}',
    ].join('\n');
    const { ctx, findings } = makeCtx(ir, code);
    const result = new MissingPublicDocPass().run(ctx);
    expect(result.missingDocMethods).toHaveLength(0);
  });
});
