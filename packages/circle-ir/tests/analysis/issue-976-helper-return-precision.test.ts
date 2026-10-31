/**
 * cognium-dev#976 — with Java `try` locals now defined, a sink inside a `try`
 * is reached by the #590 callee-source → caller-sink link. That link must only
 * fire when the callee's source reaches what the callee returns:
 *  - a map read the callee overwrites before `return` does not;
 *  - `new java.util.HashMap<>()` is a locally constructed map (qualified form);
 *  - when constant propagation saw tainted data go into the call and holds the
 *    assignee untainted, the helper dropped it (constant branch, safe key).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const servlet = (helperBody: string) => `import javax.servlet.http.*;
import java.sql.*;
public class Lookup extends HttpServlet {
  private Connection conn;
  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    String bar = new Test().doSomething(request, param);
    try {
      String sql = "SELECT * FROM t WHERE k = '" + bar + "'";
      conn.createStatement().executeQuery(sql);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
${helperBody}
    }
  }
}`;

const sqlFlows = async (code: string) =>
  (await analyze(code, 'Lookup.java', 'java')).taint.flows.filter(f => f.sink_type === 'sql_injection');

describe('#976 helper-return precision for sinks inside try', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops a map read the helper overwrites with a safe key before returning', async () => {
    const flows = await sqlFlows(servlet(`      String bar = "safe!";
      java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
      m.put("keyA", "a_Value");
      m.put("keyB", param);
      bar = (String) m.get("keyB");
      bar = (String) m.get("keyA");
      return bar;`));
    expect(flows).toHaveLength(0);
  });

  it('keeps the flow when the tainted key is what the helper returns', async () => {
    const flows = await sqlFlows(servlet(`      String bar = "safe!";
      java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
      m.put("keyA", "a_Value");
      m.put("keyB", param);
      bar = (String) m.get("keyA");
      bar = (String) m.get("keyB");
      return bar;`));
    expect(flows.length).toBeGreaterThan(0);
  });

  it('drops a constant-true branch that assigns a literal', async () => {
    const flows = await sqlFlows(servlet(`      String bar;
      int num = 86;
      if ((7 * 42) - num > 200) bar = "This_should_always_happen";
      else bar = param;
      return bar;`));
    expect(flows).toHaveLength(0);
  });

  it('keeps the plain pass-through helper', async () => {
    const flows = await sqlFlows(servlet(`      String bar = param;
      return bar;`));
    expect(flows.length).toBeGreaterThan(0);
  });
});

// CWE-Bench-Java plexus-utils CVE-2017-1000487 (req-012): the callee's source
// reaches its return through an array element store, and the sink sits in a try.
const commandline = (fill: string) => `import java.io.*;
import java.util.*;
public class Commandline {
  private Map envVars = new HashMap();
  public String[] getEnvironmentVariables() {
    String[] environmentVars = new String[envVars.size()];
    int i = 0;
    for (Iterator it = envVars.keySet().iterator(); it.hasNext(); ) {
      String name = (String) it.next();
      String value = System.getenv(name);
${fill}
      i++;
    }
    return environmentVars;
  }
  public Process execute(String[] cmd) throws Exception {
    Process process;
    String[] environment = getEnvironmentVariables();
    try {
      process = Runtime.getRuntime().exec(cmd, environment);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
    return process;
  }
}`;

/** command_injection flows whose source is the callee's `System.getenv` (not `execute`'s own parameter). */
const envCmdFlows = async (code: string) => {
  const envLine = code.split('\n').findIndex(l => l.includes('System.getenv')) + 1;
  return (await analyze(code, 'Commandline.java', 'java')).taint.flows.filter(
    f => f.sink_type === 'command_injection' && f.source_line === envLine,
  );
};

describe('#976 callee source returned through an element store (plexus-utils CWE-78)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('keeps the flow when the source is stored into the returned array', async () => {
    const flows = await envCmdFlows(commandline(`      environmentVars[i] = name + "=" + value;`));
    expect(flows.length).toBeGreaterThan(0);
  });

  it('drops it when the stored array is not what the callee returns', async () => {
    const flows = await envCmdFlows(commandline(`      String[] scratch = new String[1];
      scratch[0] = value;`));
    expect(flows).toHaveLength(0);
  });
});

describe('#976 const-prop: an anti-sanitizer over an inline sanitizer is a round trip', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('keeps Base64 decode(encode(param)) in a branch as the returned taint', async () => {
    const flows = await sqlFlows(servlet(`      String bar = "";
      if (param != null) bar = new String(java.util.Base64.getDecoder().decode(java.util.Base64.getEncoder().encode(param.getBytes())));
      return bar;`));
    expect(flows.length).toBeGreaterThan(0);
  });

  it('the constant-dead branch veto still drops the flow', async () => {
    const flows = await sqlFlows(servlet(`      String bar = "";
      if ((7 * 42) - 86 > 200) bar = "safe"; else bar = param;
      return bar;`));
    expect(flows).toHaveLength(0);
  });
});

describe('#976 veto: a helper returning an array it stored the input into', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('keeps the flow (const-prop holds the element tainted, not the call result)', async () => {
    const code = `import javax.servlet.http.*;
public class Arr extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String[] bar = new Test().doSomething(request, param);
    try {
      Runtime.getRuntime().exec(bar);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
  class Test {
    String[] doSomething(HttpServletRequest request, String param) {
      String[] vars = new String[1];
      vars[0] = "X=" + param;
      return vars;
    }
  }
}`;
    const flows = (await analyze(code, 'Arr.java', 'java')).taint.flows.filter(f => f.sink_type === 'command_injection');
    expect(flows.length).toBeGreaterThan(0);
  });
});
