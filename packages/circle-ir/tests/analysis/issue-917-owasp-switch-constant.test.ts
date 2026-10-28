/**
 * cognium-dev #917 — OWASP BenchmarkTest00992 shape: switch on a constant char
 * only takes case 'B' (bar = "bob"); param assignments on other cases are dead.
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

  it('matches OWASP BenchmarkTest00992 charAt selector with a trailing comment', async () => {
    const code = `import javax.servlet.http.*;
public class BenchmarkTest00992 extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = "x";
    String bar = new Test().doSomething(request, param);
    request.getSession().putValue(bar, "10340");
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) throws Exception {
      String bar;
      String guess = "ABC";
      char switchTarget = guess.charAt(1); // condition 'B', which is safe
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
    const r = await analyze(code, 'BenchmarkTest00992.java', 'java');
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

  it('does not flag trust_boundary after safe-key map shuffle (BenchmarkTest00322)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = "safe!";
    java.util.HashMap<String, Object> map53101 = new java.util.HashMap<String, Object>();
    map53101.put("keyA-53101", "a_Value");
    map53101.put("keyB-53101", param);
    map53101.put("keyC", "another_Value");
    bar = (String) map53101.get("keyB-53101");
    bar = (String) map53101.get("keyA-53101");
    request.getSession().putValue("userid", bar);
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const tb = (r.taint?.flows ?? []).filter(f => f.sink_type === 'trust_boundary');
    expect(tb).toEqual([]);
  });

  it('does not flag trust_boundary when safe literal is the session key (BenchmarkTest00586)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = "safe!";
    java.util.HashMap<String, Object> map58886 = new java.util.HashMap<String, Object>();
    map58886.put("keyA-58886", "a_Value");
    map58886.put("keyB-58886", param);
    map58886.put("keyC", "another_Value");
    bar = (String) map58886.get("keyB-58886");
    bar = (String) map58886.get("keyA-58886");
    request.getSession().putValue(bar, "10340");
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const tb = (r.taint?.flows ?? []).filter(f => f.sink_type === 'trust_boundary');
    expect(tb).toEqual([]);
  });

  it('OWASP corpus files stay clean when CORPUS_ROOT is set', async () => {
    for (const name of ['BenchmarkTest00322', 'BenchmarkTest00586', 'BenchmarkTest00992']) {
      const code = owaspFile(name);
      if (!code) return;
      const r = await analyze(code, `${name}.java`, 'java');
      const tb = (r.taint?.flows ?? []).filter(f => f.sink_type === 'trust_boundary');
      expect(tb, name).toEqual([]);
    }
  });
});
