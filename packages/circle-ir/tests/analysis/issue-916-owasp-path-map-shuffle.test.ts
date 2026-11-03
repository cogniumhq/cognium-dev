/**
 * cognium-dev #916 — OWASP BenchmarkTest00954: safe-key HashMap shuffle in a helper
 * must not produce path_traversal when bar returned to the caller is the safe value.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const owaspFile = (name: string): string | null => {
  const root = process.env.CORPUS_ROOT;
  if (!root) return null;
  const path = `${root}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/${name}.java`;
  return existsSync(path) ? readFileSync(path, 'utf8') : null;
};

const pathFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).filter(f => f.sink_type === 'path_traversal');

describe('#916 OWASP map shuffle path_traversal (BenchmarkTest00954)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag path_traversal when helper returns safe map key value', async () => {
    const code = `import javax.servlet.http.*;
import java.io.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = new Test().doSomething(request, param);
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    new FileOutputStream(new FileInputStream(fileName).getFD());
  }
  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar = "safe!";
      java.util.HashMap<String, Object> map9749 = new java.util.HashMap<String, Object>();
      map9749.put("keyA-9749", "a_Value");
      map9749.put("keyB-9749", param);
      map9749.put("keyC", "another_Value");
      bar = (String) map9749.get("keyB-9749");
      bar = (String) map9749.get("keyA-9749");
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    expect(pathFlows(r)).toEqual([]);
  });

  it('OWASP corpus file stays clean when CORPUS_ROOT is set', async () => {
    const code = owaspFile('BenchmarkTest00954');
    if (!code) return;
    const r = await analyze(code, 'BenchmarkTest00954.java', 'java');
    expect(pathFlows(r)).toEqual([]);
  });
});
