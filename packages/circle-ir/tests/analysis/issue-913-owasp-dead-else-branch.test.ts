/**
 * cognium-dev #913 — OWASP BenchmarkTest00999 shape: param is dead on the else branch
 * when `(7 * 42) - num > 200` is always true; bar must stay the safe literal.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#913 OWASP dead else branch (BenchmarkTest00999)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag sqli when only the dead else would assign param to bar', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = new Helper().pick(param);
    java.sql.Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    c.prepareCall("{call " + bar + "}");
  }
  class Helper {
    String pick(String param) {
      int num = 86;
      String bar;
      if ((7 * 42) - num > 200) bar = "This_should_always_happen";
      else bar = param;
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(0);
  });
});
