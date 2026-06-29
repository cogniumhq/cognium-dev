import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 56 — #183: Python reflection-based code-injection sinks.
 *
 * `importlib.import_module(taint)` and `importlib.__import__(taint)`
 * are currently missed because DEFAULT_SINKS only registers the bare
 * classless `__import__` form (line 1676). The namespaced forms are
 * the common pattern (`import importlib; importlib.import_module(x)`).
 *
 * Asserts on flows for inline source→sink shapes (e.g. `f(input())`),
 * which exercise the engine's co-located source/sink path. The bare
 * `__import__` form already produces flows in this shape; we add the
 * `importlib.*` shapes.
 *
 * Deferred (skipped): `getattr(obj, taint)()` two-call shape requires
 * alias tracking from getattr's return value through the next call's
 * receiver — tracked in #183 itself.
 */
describe('Sprint 56 — #183 Python reflection code_injection', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  const sinkMethods = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.sinks ?? []).filter(s => s.type === 'code_injection').map(s => s.method);

  it('FN — importlib.import_module(taint) is detected as code_injection sink', async () => {
    const code = `import importlib
def handler():
    importlib.import_module(input())
`;
    const r = await analyze(code, 'a.py', 'python');
    expect(sinkMethods(r)).toContain('import_module');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — importlib.__import__(taint) is detected as code_injection sink', async () => {
    const code = `import importlib
def handler():
    importlib.__import__(input())
`;
    const r = await analyze(code, 'b.py', 'python');
    expect(sinkMethods(r)).toContain('__import__');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — bare __import__(taint) still fires', async () => {
    const code = `def handler():
    __import__(input())
`;
    const r = await analyze(code, 'c.py', 'python');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — Java Class.forName(taint) still fires', async () => {
    const code = `public class Loader {
    public void load(javax.servlet.http.HttpServletRequest req) throws Exception {
        Class.forName(req.getParameter("cls"));
    }
}`;
    const r = await analyze(code, 'D.java', 'java');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — JS require(taint) still fires', async () => {
    const code = `function handler(req) {
    require(req.query.mod);
}`;
    const r = await analyze(code, 'e.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('Sprint 72 (#183 residual) — getattr(obj, taint)() with input() source fires', async () => {
    const code = `def handler(obj):
    name = input()
    fn = getattr(obj, name)
    fn()
`;
    const r = await analyze(code, 'f.py', 'python');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });
});

/**
 * Sprint 68 — #183 follow-up: Python CWE-470 reflection-invocation
 * (`getattr(obj, taint)()`).
 *
 * Sprint 56 (3.113.0) closed the `importlib.import_module(taint)` /
 * `importlib.__import__(taint)` sub-cases of #183 but explicitly deferred
 * the `getattr(obj, taint)()` two-call shape because it requires tracking
 * the alias returned by `getattr` through to the subsequent invocation.
 *
 * This sprint closes the remaining shape:
 *   1. DIRECT:  `getattr(obj, taint)()` on a single line
 *   2. ALIASED: `fn = getattr(obj, taint); fn()` across two lines
 *
 * Detection lives in `language-sources-pass.ts` (regex-driven, mirrors
 * `findPythonReturnXSSSinks`) and emits `code_injection`/CWE-94 sinks at
 * the invocation site. The taint connection relies on `pyTaintedVars`,
 * so the demo uses a Flask `request.args.get` source (which IS tracked
 * in `PYTHON_TAINTED_PATTERNS`). The `input()` shape stays deferred —
 * `input()` is registered as a source in `configs/sources/python.json`
 * but not in `PYTHON_TAINTED_PATTERNS`, which is a separate broader
 * concern.
 *
 * Conservative gates:
 *   - 3-arg `getattr(obj, name, default)` is NOT a sink (data-access
 *     pattern; default proves caller treats result as a value, not a
 *     callable target). TP-control case below.
 *   - Bare `value = getattr(obj, name)` with NO subsequent invocation
 *     is NOT a sink (covered by absence; no test needed).
 */
describe('Sprint 68 — #183 Python getattr(...)() reflection invocation', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  const codeInjSinks = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.sinks ?? []).filter(s => s.type === 'code_injection');

  it('FN — aliased: fn = getattr(obj, taint); fn() emits code_injection', async () => {
    const code = `from flask import request
def handler(obj):
    name = request.args.get("fn")
    fn = getattr(obj, name)
    return fn()
`;
    const r = await analyze(code, 'aliased.py', 'python');
    expect(codeInjSinks(r).length).toBeGreaterThanOrEqual(1);
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — direct: getattr(obj, taint)() (single line) emits code_injection', async () => {
    const code = `from flask import request
def handler(obj):
    name = request.args.get("fn")
    return getattr(obj, name)()
`;
    const r = await analyze(code, 'direct.py', 'python');
    expect(codeInjSinks(r).length).toBeGreaterThanOrEqual(1);
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('TP-control — 3-arg getattr(obj, name, default) data-access does NOT fire', async () => {
    const code = `from flask import request
def handler(obj):
    name = request.args.get("attr")
    value = getattr(obj, name, None)
    return value
`;
    const r = await analyze(code, 'default.py', 'python');
    expect(codeInjSinks(r).length).toBe(0);
  });

  it('TP-control — bare getattr without invocation does NOT fire code_injection', async () => {
    const code = `from flask import request
def handler(obj):
    name = request.args.get("attr")
    value = getattr(obj, name)
    return value
`;
    const r = await analyze(code, 'bare.py', 'python');
    expect(codeInjSinks(r).length).toBe(0);
  });
});
