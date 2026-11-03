/**
 * cognium-dev #1107 — OWASP SeparateClassRequest.getTheParameter through ThingInterface helper (BenchmarkTest02433).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { analyze, initAnalyzer } from '../../dist/analyzer.js';

describe('#1107 getTheParameter cmdi via ThingFactory helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const inlineBench = `import javax.servlet.http.*;
import java.io.IOException;
public class BenchmarkTest02433 extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheParameter("BenchmarkTest02433");
    if (param == null) param = "";
    String bar = doSomething(request, param);
    String osName = System.getProperty("os.name");
    String[] args;
    if (osName.indexOf("Windows") != -1) {
      args = new String[] {"cmd.exe", "/c", "echo ", bar};
    } else {
      args = new String[] {"sh", "-c", org.owasp.benchmark.helpers.Utils.getOSCommandString("ls ") + bar};
    }
    Runtime.getRuntime().exec(args, new String[] {"foo=bar"}, new java.io.File(System.getProperty("user.dir")));
  }
  private static String doSomething(HttpServletRequest request, String param) throws Exception {
    org.owasp.benchmark.helpers.ThingInterface thing =
        org.owasp.benchmark.helpers.ThingFactory.createThing();
    return thing.doSomething(param);
  }
}`;

  it('flags command_injection on inline BenchmarkTest02433 shape', async () => {
    const r = await analyze(inlineBench, 'BenchmarkTest02433.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi.length).toBeGreaterThan(0);
  });

  it('OWASP BenchmarkTest02433 corpus when CORPUS_ROOT is set', async () => {
    const root = process.env.CORPUS_ROOT;
    if (!root) return;
    const path = `${root}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02433.java`;
    if (!existsSync(path)) return;
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest02433.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi.length).toBeGreaterThan(0);
  });
});
