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

  it.skip('deferred — getattr(obj, taint)() two-call shape (alias tracking required)', async () => {
    const code = `def handler(obj):
    name = input()
    fn = getattr(obj, name)
    fn()
`;
    const r = await analyze(code, 'f.py', 'python');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });
});
