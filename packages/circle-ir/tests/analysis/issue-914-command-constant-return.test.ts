/**
 * cognium-dev #914 S1 — OWASP safe command-injection helpers that return a constant
 * while param is unused on live paths.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
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

  it('does not flag command_injection for exec cwd File(System.getProperty) on safe args (BenchmarkTest00171)', async () => {
    const code = `import javax.servlet.http.*;
import java.io.IOException;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = "";
    if (request.getHeader("BenchmarkTest00171") != null) {
      param = request.getHeader("BenchmarkTest00171");
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");
    String bar = "safe!";
    java.util.HashMap<String, Object> map40534 = new java.util.HashMap<String, Object>();
    map40534.put("keyA-40534", "a_Value");
    map40534.put("keyB-40534", param);
    map40534.put("keyC", "another_Value");
    bar = (String) map40534.get("keyB-40534");
    bar = (String) map40534.get("keyA-40534");
    String[] args;
    String osName = System.getProperty("os.name");
    if (osName.indexOf("Windows") != -1) {
      args = new String[] {"cmd.exe", "/c", "echo ", bar};
    } else {
      args = new String[] {"sh", "-c", "ls ", bar};
    }
    String[] argsEnv = {"foo=bar"};
    Runtime r = Runtime.getRuntime();
    r.exec(args, argsEnv, new java.io.File(System.getProperty("user.dir")));
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi).toHaveLength(0);
  });

  it('does not flag command_injection on getTheValue-fed instance inner helper (#914 S4)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheValue("BenchmarkTest01778");
    String bar = new Test().doSomething(request, param);
    String a1 = "sh";
    String a2 = "-c";
    String[] args = {a1, a2, "echo " + bar};
    new ProcessBuilder(args).start();
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      return param;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi).toHaveLength(0);
  });

  it('still flags command_injection on static helper with HTTP param (#914 S4 guard)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("x");
    String bar = doSomething(request, param);
    String[] args = {"sh", "-c", "echo " + bar};
    new ProcessBuilder(args).start();
  }
  private static String doSomething(HttpServletRequest request, String param) {
    return param;
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi.length).toBeGreaterThan(0);
  });

  it('does not flag path_traversal on getTheValue-fed instance inner helper (#914 S4)', async () => {
    const code = `import javax.servlet.http.*;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheValue("BenchmarkTest01745");
    String bar = new Test().doSomething(request, param);
    new java.io.File(bar, "/Test.txt");
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      return param;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const pt = (r.taint?.flows ?? []).filter(f => f.sink_type === 'path_traversal');
    expect(pt).toHaveLength(0);
  });

  it('does not flag command_injection on getTheValue helper with os.name prefix exec (#914 S5, BenchmarkTest01791)', async () => {
    const code = `import javax.servlet.http.*;
import java.io.IOException;
public class Bench extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheValue("BenchmarkTest01791");
    String bar = new Test().doSomething(request, param);
    String cmd = "";
    String osName = System.getProperty("os.name");
    if (osName.indexOf("Windows") != -1) {
      cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
    }
    Runtime r = Runtime.getRuntime();
    r.exec(cmd + bar);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) throws IOException {
      int num = 106;
      return (7 * 42) - num > 200 ? "This should never happen" : param;
    }
  }
}`;
    const r = await analyze(code, 'Bench.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi).toHaveLength(0);
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

  it('OWASP BenchmarkTest01791 corpus stays clean when CORPUS_ROOT is set (#914 S6)', async () => {
    const root = process.env.CORPUS_ROOT;
    if (!root) return;
    const path = `${root}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01791.java`;
    if (!existsSync(path)) return;
    const code = readFileSync(path, 'utf8');
    const r = await analyze(code, 'BenchmarkTest01791.java', 'java');
    const cmdi = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmdi).toHaveLength(0);
  });
});
