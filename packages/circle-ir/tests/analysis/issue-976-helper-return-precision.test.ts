/**
 * cognium-dev#976 — with Java `try` locals now defined, a sink inside a `try`
 * is reached by the #590 callee-source → caller-sink link. That link must only
 * fire when the callee's source reaches what the callee returns:
 *  - a map read the callee overwrites before `return` does not;
 *  - `new java.util.HashMap<>()` is a locally constructed map (qualified form);
 *  - when constant propagation saw tainted data go into the call and holds the
 *    assignee untainted, the helper dropped it (constant branch, safe key).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const servlet = (helperBody: string) => `import javax.servlet.http.*;
import java.sql.*;
public class Lookup extends HttpServlet {
  private Connection conn;
  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    String bar = new Test().doSomething(request, param);
    try {
      String sql = "SELECT * FROM t WHERE k = '" + bar + "'";
      conn.createStatement().executeQuery(sql);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
${helperBody}
    }
  }
}`;

const sqlFlows = async (code: string) =>
  (await analyze(code, 'Lookup.java', 'java')).taint.flows.filter(f => f.sink_type === 'sql_injection');

describe('#976 helper-return precision for sinks inside try', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops a map read the helper overwrites with a safe key before returning', async () => {
    const flows = await sqlFlows(servlet(`      String bar = "safe!";
      java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
      m.put("keyA", "a_Value");
      m.put("keyB", param);
      bar = (String) m.get("keyB");
      bar = (String) m.get("keyA");
      return bar;`));
    expect(flows).toHaveLength(0);
  });

  it('keeps the flow when the tainted key is what the helper returns', async () => {
    const flows = await sqlFlows(servlet(`      String bar = "safe!";
      java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
      m.put("keyA", "a_Value");
      m.put("keyB", param);
      bar = (String) m.get("keyA");
      bar = (String) m.get("keyB");
      return bar;`));
    expect(flows.length).toBeGreaterThan(0);
  });

  it('drops a constant-true branch that assigns a literal', async () => {
    const flows = await sqlFlows(servlet(`      String bar;
      int num = 86;
      if ((7 * 42) - num > 200) bar = "This_should_always_happen";
      else bar = param;
      return bar;`));
    expect(flows).toHaveLength(0);
  });

  it('keeps the plain pass-through helper', async () => {
    const flows = await sqlFlows(servlet(`      String bar = param;
      return bar;`));
    expect(flows.length).toBeGreaterThan(0);
  });
});
