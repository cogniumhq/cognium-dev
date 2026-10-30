/**
 * cognium-dev#913 / #914 / #916 / #917 — the helper-return gate in
 * InterproceduralPass must only drop a caller-side flow when the helper cannot
 * return its parameter. Each case below is a live flow that an earlier version
 * of the gate dropped (OWASP TP loss), written by hand in the same shape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

/** A servlet whose doPost passes `param` through `helper` into `sinkLine`. */
function servlet(helper: string, sinkLine: string, call = 'new Test().doSomething(request, param)'): string {
  return `import javax.servlet.http.*;
import java.io.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = ${call};
    ${sinkLine}
  }
${helper}
}`;
}

const CMD = 'Runtime.getRuntime().exec("echo " + bar);';
const FLOWS = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
  (r.taint?.flows ?? []).filter(f => f.sink_type === type);

describe('helper-return gate keeps live flows', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a value assigned over several lines is still the returned taint', async () => {
    const helper = `  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar = "";
      if (param != null) {
        bar =
            new String(
                java.util.Base64.getDecoder().decode(
                    java.util.Base64.getEncoder().encode(param.getBytes())));
      }
      return bar;
    }
  }`;
    const r = await analyze(servlet(helper, CMD), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('a one-line `if (live) bar = param;` branch is still the returned taint', async () => {
    const helper = `  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar;
      int num = 196;
      if ((500 / 42) + num > 200) bar = param;
      else bar = "This should never happen";
      return bar;
    }
  }`;
    const r = await analyze(servlet(helper, CMD), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('a helper taking (request, param) is judged on param, not on request', async () => {
    const helper = `  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar = "safe!";
      java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
      map.put("keyA", "a-Value");
      map.put("keyB", param);
      bar = (String) map.get("keyB");
      return bar;
    }
  }`;
    const r = await analyze(servlet(helper, CMD), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('a static helper returning the tainted map slot keeps the flow', async () => {
    const helper = `  private static String doSomething(HttpServletRequest request, String param) throws Exception {
    String bar = "safe!";
    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
    map.put("keyA", "a-Value"); // put some stuff in the collection
    map.put("keyB", param); // put it in a collection
    bar = (String) map.get("keyB"); // get it back out
    return bar;
  }`;
    const r = await analyze(servlet(helper, CMD, 'doSomething(request, param)'), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('a receiver mutated with the parameter carries it to the return', async () => {
    const helper = `  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      StringBuilder sb = new StringBuilder();
      sb.append(param);
      String bar = sb.toString();
      return bar;
    }
  }`;
    const r = await analyze(servlet(helper, CMD), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('both branches live: `if (c) bar = param; else bar = "x";` keeps the flow', async () => {
    const helper = `  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar;
      if (param.length() > 3) bar = param;
      else bar = "short";
      return bar;
    }
  }`;
    const r = await analyze(servlet(helper, CMD), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('still drops the constant-slot shuffle (safe key returned)', async () => {
    const helper = `  class Test {
    String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar = "safe!";
      java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
      map.put("keyA", "a-Value");
      map.put("keyB", param);
      bar = (String) map.get("keyB");
      bar = (String) map.get("keyA");
      return bar;
    }
  }`;
    const r = await analyze(servlet(helper, CMD), 'Bench.java', 'java');
    expect(FLOWS(r, 'command_injection')).toEqual([]);
  });
});
