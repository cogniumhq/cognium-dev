/**
 * cognium-dev #913 — OWASP BenchmarkTest00999: param is dead on the else branch
 * when `(7 * 42) - num > 200` is always true; bar must stay the safe literal.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#913 OWASP dead else branch (BenchmarkTest00999)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not emit sql_injection when only the dead else assigns param to bar', async () => {
    const path =
      '/home/coder/corpus/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00999.java';
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest00999.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(0);
  });

  it('does not flag sqli for the inlined OWASP if/else shape without the corpus file', async () => {
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
