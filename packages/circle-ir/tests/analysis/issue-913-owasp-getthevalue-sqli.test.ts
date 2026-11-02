/**
 * cognium-dev #913 S4/S5 — OWASP SeparateClassRequest.getTheValue callers (#976 gate).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#913 OWASP getTheValue sqli pass-through (BenchmarkTest01803)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag sqli on the real BenchmarkTest01803 fixture', async () => {
    const corpus =
      process.env.CORPUS_ROOT ??
      (process.env.HOME ? `${process.env.HOME}/corpus` : '/home/coder/corpus');
    const path = `${corpus}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01803.java`;
    if (!existsSync(path)) return;
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest01803.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(0);
  });

  it('does not flag sqli on BenchmarkTest02728 (static helper, getTheValue caller)', async () => {
    const corpus =
      process.env.CORPUS_ROOT ??
      (process.env.HOME ? `${process.env.HOME}/corpus` : '/home/coder/corpus');
    for (const name of ['BenchmarkTest02728', 'BenchmarkTest02729']) {
      const path = `${corpus}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/${name}.java`;
      if (!existsSync(path)) continue;
      const code = readFileSync(path, 'utf8');
      const r = await analyze(code, `${name}.java`, 'java');
      const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
      expect(sqli, name).toHaveLength(0);
    }
  });

  it('still flags sqli on BenchmarkTest02625 (query-string taint into static helper)', async () => {
    const corpus =
      process.env.CORPUS_ROOT ??
      (process.env.HOME ? `${process.env.HOME}/corpus` : '/home/coder/corpus');
    const path = `${corpus}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02625.java`;
    if (!existsSync(path)) return;
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest02625.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli.length).toBeGreaterThan(0);
  });

  it('still flags sqli when the caller uses getTheParameter', async () => {
    const code = `import javax.servlet.http.*;
import java.sql.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheParameter("x");
    String bar = new Test().doSomething(request, param);
    Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    c.prepareStatement("{call " + bar + "}").executeQuery();
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      return param;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli.length).toBeGreaterThan(0);
  });
});
