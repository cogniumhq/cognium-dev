/**
 * cognium-dev #239 C.1 — Class.forName literal-argument guard.
 *
 * `Class.forName("com.foo.Bar")` with a string-literal argument is safe:
 * the class name is compile-time constant. Only `Class.forName(userInput)`
 * qualifies as CWE-094 / CWE-470. The `safe_if_string_literal_at: 0`
 * primitive (added in 3.153.0) is now applied to the `Class.forName`
 * sink entry in `configs/sinks/code_injection.yaml`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const codeInjectionSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter((s) => s.type === 'code_injection');

describe('cognium-dev #239 C.1 — Class.forName literal guard', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops sink when Class.forName arg is a string literal', async () => {
    const code = `public class A {
  public Class<?> load() throws Exception {
    return Class.forName("com.foo.Bar");
  }
}
`;
    const r = await analyze(code, 'src/main/java/A.java', 'java');
    expect(codeInjectionSinks(r.taint?.sinks)).toHaveLength(0);
  });

  it('preserves sink when Class.forName arg is tainted (Servlet request param)', async () => {
    const code = `import javax.servlet.http.*;
public class B extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String name = req.getParameter("cls");
    Class<?> c = Class.forName(name);
    c.newInstance();
  }
}
`;
    const r = await analyze(code, 'src/main/java/B.java', 'java');
    expect(codeInjectionSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });
});
