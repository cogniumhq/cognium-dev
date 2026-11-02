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
