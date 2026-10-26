/**
 * cognium-dev #914 S1 — OWASP safe command-injection helpers that return a constant
 * while param is unused on live paths.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#914 OWASP constant helper return (command_injection)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag command_injection when helper returns only a safe literal', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("BenchmarkTest00177");
    String bar = new Helper().pick(param);
    Runtime.getRuntime().exec(bar);
  }
  class Helper {
    String pick(String param) {
      return "safe!";
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi).toHaveLength(0);
  });

  it('still flags command_injection when helper returns param on live paths', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("x");
    String bar = new Helper().pick(param);
    Runtime.getRuntime().exec(bar);
  }
  class Helper {
    String pick(String param) {
      return param;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi.length).toBeGreaterThan(0);
  });

  it('does not flag when only a dead else would assign param (constant branch)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("x");
    String bar = new Helper().pick(param);
    Runtime.getRuntime().exec(bar);
  }
  class Helper {
    String pick(String param) {
      int num = 86;
      String bar;
      if ((7 * 42) - num > 200) bar = "safe!";
      else bar = param;
      return bar;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi).toHaveLength(0);
  });
});
