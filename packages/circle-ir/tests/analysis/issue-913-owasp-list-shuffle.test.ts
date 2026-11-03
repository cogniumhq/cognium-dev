/**
 * cognium-dev #913 S2 — OWASP BenchmarkTest01012: after add/remove shuffle,
 * `valuesList.get(1)` is the literal `moresafe`, not `param`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#913 OWASP list shuffle (BenchmarkTest01012)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag sqli on the real BenchmarkTest01012 fixture', async () => {
    const corpus =
      process.env.CORPUS_ROOT ??
      (process.env.HOME ? `${process.env.HOME}/corpus` : '/home/coder/corpus');
    const path = `${corpus}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01012.java`;
    if (!existsSync(path)) return;
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest01012.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(0);
  });

  it('inline servlet shape stays clean on sql_injection', async () => {
    const code = `import javax.servlet.http.*;
import java.util.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    java.sql.Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    String sql = "SELECT * FROM u WHERE p='" + bar + "'";
    c.prepareStatement(sql).executeQuery();
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      String bar = "alsosafe";
      if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(1);
      }
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(0);
  });

  it('inline servlet shape still flags sqli when get(0) returns param after remove(0)', async () => {
    const code = `import javax.servlet.http.*;
import java.util.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    java.sql.Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    String sql = "SELECT * FROM u WHERE p='" + bar + "'";
    c.prepareStatement(sql).executeQuery();
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      String bar = "";
      if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(0);
      }
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli.length).toBeGreaterThan(0);
  });

  it('still flags sqli when remove(0) has a trailing line comment (BenchmarkTest01554 shape)', async () => {
    const code = `import javax.servlet.http.*;
import java.util.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    java.sql.Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    String sql = "SELECT * FROM u WHERE p='" + bar + "'";
    c.prepareStatement(sql).executeQuery();
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      String bar = "";
      if (param != null) {
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0); // remove the 1st safe value
        bar = valuesList.get(0);
      }
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli.length).toBeGreaterThan(0);
  });
});
