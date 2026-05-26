/**
 * Tests for Pass #21: resource-leak (CWE-772, category: reliability)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { ResourceLeakPass } from '../../../src/analysis/passes/resource-leak-pass.js';
import type {
  CircleIR, SastFinding, CallInfo, DFGDef, TypeInfo, MethodInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConstructorCall(
  method_name: string,
  line: number,
): CallInfo {
  return {
    method_name,
    receiver: null,
    is_constructor: true,
    arguments: [],
    location: { line, column: 0 },
  };
}

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

function makeDef(id: number, variable: string, line: number): DFGDef {
  return { id, variable, line, kind: 'local' };
}

function makeMethod(name: string, startLine: number, endLine: number): MethodInfo {
  return {
    name,
    return_type: null,
    parameters: [],
    annotations: [],
    modifiers: ['public'],
    start_line: startLine,
    end_line: endLine,
  };
}

function makeIR(
  code: string,
  calls: CallInfo[],
  defs: DFGDef[],
  types: TypeInfo[] = [],
  file = 'App.java',
): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'java', loc: 30, hash: '' },
    types,
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

// Enclosing method spanning lines 1–20
const ENCLOSING_TYPE: TypeInfo = {
  name: 'App',
  kind: 'class',
  methods: [makeMethod('readData', 1, 20)],
  fields: [],
  annotations: [],
  modifiers: [],
  start_line: 1,
  end_line: 20,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ResourceLeakPass', () => {
  it('flags FileInputStream with no close() call — definite leak', () => {
    const code = [
      'FileInputStream fis = new FileInputStream(file);', // line 1
      'byte[] data = fis.read();',                        // line 2
      '// method ends — fis never closed',               // line 3
    ].join('\n');
    const openCall = makeConstructorCall('FileInputStream', 1);
    const defs = [makeDef(1, 'fis', 1)];
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall], defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new ResourceLeakPass().run(ctx);
    expect(result.leaks).toHaveLength(1);
    expect(result.leaks[0].kind).toBe('definite');
    expect(findings).toHaveLength(1);
    expect(findings[0].cwe).toBe('CWE-772');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].level).toBe('error');
    expect(findings[0].message).toMatch(/fis/);
    expect(findings[0].message).toMatch(/never closed/);
  });

  it('does NOT flag when close() is called inside a finally block', () => {
    const code = [
      'FileInputStream fis = new FileInputStream(file);', // line 1
      'try {',                                            // line 2
      '  fis.read();',                                   // line 3
      '} finally {',                                     // line 4 — finally present
      '  fis.close();',                                  // line 5
      '}',                                               // line 6
    ].join('\n');
    const openCall = makeConstructorCall('FileInputStream', 1);
    const closeCall = makeCall('close', 5, 'fis');
    const defs = [makeDef(1, 'fis', 1)];
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall, closeCall], defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    new ResourceLeakPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags potential leak when close() exists but no finally block', () => {
    const code = [
      'FileOutputStream fos = new FileOutputStream(path);', // line 1
      'fos.write(data);',                                   // line 2
      'fos.close();',                                       // line 3 — close but no finally
    ].join('\n');
    const openCall = makeConstructorCall('FileOutputStream', 1);
    const closeCall = makeCall('close', 3, 'fos');
    const defs = [makeDef(1, 'fos', 1)];
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall, closeCall], defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new ResourceLeakPass().run(ctx);
    expect(result.leaks).toHaveLength(1);
    expect(result.leaks[0].kind).toBe('potential');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].message).toMatch(/fos/);
    expect(findings[0].message).toMatch(/finally/);
  });

  it('does NOT flag a non-resource constructor', () => {
    const code = 'MyService svc = new MyService();\n';
    const openCall = makeConstructorCall('MyService', 1);
    const defs = [makeDef(1, 'svc', 1)];
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall], defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    new ResourceLeakPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag when resource is not captured in a variable', () => {
    const code = 'new FileInputStream(file).read();\n';
    const openCall = makeConstructorCall('FileInputStream', 1);
    // No def at line 1 — resource not bound to variable
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall], [], types);
    const { ctx, findings } = makeCtx(ir, code);
    new ResourceLeakPass().run(ctx);
    expect(findings).toHaveLength(0);
  });

  it('flags Socket with no close — definite leak', () => {
    const code = [
      'Socket socket = new Socket(host, port);', // line 1
      'socket.getOutputStream().write(data);',   // line 2
    ].join('\n');
    const openCall = makeConstructorCall('Socket', 1);
    const defs = [makeDef(1, 'socket', 1)];
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall], defs, types);
    const { ctx, findings } = makeCtx(ir, code);
    const result = new ResourceLeakPass().run(ctx);
    expect(result.leaks).toHaveLength(1);
    expect(result.leaks[0].resource).toBe('Socket');
    expect(result.leaks[0].variable).toBe('socket');
  });

  it('includes file and pass metadata in findings', () => {
    const code = 'BufferedReader br = new BufferedReader(r);\n';
    const openCall = makeConstructorCall('BufferedReader', 1);
    const defs = [makeDef(1, 'br', 1)];
    const types = [ENCLOSING_TYPE];
    const ir = makeIR(code, [openCall], defs, types, 'src/Parser.java');
    const { ctx, findings } = makeCtx(ir, code);
    new ResourceLeakPass().run(ctx);
    expect(findings[0].file).toBe('src/Parser.java');
    expect(findings[0].pass).toBe('resource-leak');
    expect(findings[0].category).toBe('reliability');
    expect(findings[0].id).toMatch(/^resource-leak-/);
  });
});
