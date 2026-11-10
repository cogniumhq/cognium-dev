/**
 * cognium-dev #1197 — OWASP ldapi false positives on getTheValue-fed instance inner helpers.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#1197 OWASP ldapi getTheValue pass-through (#914 S4 extension)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag ldap_injection on getTheValue-fed instance inner helper (BenchmarkTest01743)', async () => {
    const root =
      process.env.CORPUS_ROOT ??
      process.env.HOME + '/corpora';
    const path = join(
      root,
      '.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01743.java',
    );
    if (!existsSync(path)) return;
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest01743.java', 'java');
    const ldap = (r.taint?.flows ?? []).filter(f => f.sink_type === 'ldap_injection');
    expect(ldap).toHaveLength(0);
  });

  it('does not flag ldap_injection on getTheValue-fed pass-through helper', async () => {
    const code = `import javax.servlet.http.*;
import javax.naming.directory.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheValue("BenchmarkTest01743");
    String bar = new Test().doSomething(request, param);
    DirContext ctx = null;
    ctx.search("ou=users", "uid=" + bar, new SearchControls());
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      return param;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const ldap = (r.taint?.flows ?? []).filter(f => f.sink_type === 'ldap_injection');
    expect(ldap).toHaveLength(0);
  });

  it('still flags ldap_injection on static helper with HTTP param', async () => {
    const code = `import javax.servlet.http.*;
import javax.naming.directory.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = doSomething(request, param);
    DirContext ctx = null;
    ctx.search("ou=users", "uid=" + bar, new SearchControls());
  }
  private static String doSomething(HttpServletRequest request, String param) {
    return param;
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const ldap = (r.taint?.flows ?? []).filter(f => f.sink_type === 'ldap_injection');
    expect(ldap.length).toBeGreaterThan(0);
  });
});
