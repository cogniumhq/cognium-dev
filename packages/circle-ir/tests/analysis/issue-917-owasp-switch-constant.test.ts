/**
 * cognium-dev #917 — OWASP BenchmarkTest00992 shape: switch on a constant char
 * only takes case 'B' (bar = "bob"); param assignments on other cases are dead.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#917 OWASP constant switch target (BenchmarkTest00992)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag trust_boundary when bar is a safe literal from the live case', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = "x";
    String bar = new Helper().pick(param);
    request.getSession().putValue(bar, "10340");
  }
  class Helper {
    String pick(String param) throws Exception {
      String bar;
      String guess = "ABC";
      char switchTarget = guess.charAt(1);
      switch (switchTarget) {
        case 'A':
          bar = param;
          break;
        case 'B':
          bar = "bob";
          break;
        case 'C':
        case 'D':
          bar = param;
          break;
        default:
          bar = "bob's your uncle";
          break;
      }
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const tb = (r.taint?.flows ?? []).filter(f => f.sink_type === 'trust_boundary');
    expect(tb).toHaveLength(0);
  });

  it('still flags trust_boundary when charAt(2) takes a shared C/D case (BenchmarkTest01548)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = new Helper().pick(param);
    request.getSession().putValue("userid", bar);
  }
  class Helper {
    String pick(String param) throws Exception {
      String bar;
      String guess = "ABC";
      char switchTarget = guess.charAt(2);
      switch (switchTarget) {
        case 'A':
          bar = param;
          break;
        case 'B':
          bar = "safe";
          break;
        case 'C':
        case 'D':
          bar = param;
          break;
        default:
          bar = "safe";
          break;
      }
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const tb = (r.taint?.flows ?? []).filter(f => f.sink_type === 'trust_boundary');
    expect(tb.length).toBeGreaterThan(0);
  });
});
