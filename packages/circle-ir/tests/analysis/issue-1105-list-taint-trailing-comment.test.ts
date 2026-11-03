/**
 * cognium-dev#1105 — Java taint carried through a `java.util.List` was lost
 * when the statement that reads it back had a trailing line comment:
 *
 *   valuesList.add(param);
 *   bar = valuesList.get(0); // get the param value
 *
 * `buildJavaTaintedVars` anchors its assignment patterns at `;` + end of line,
 * so `// …` hid the assignment and `bar` was never derived. The DFG does not
 * model `list.add(x)` as a write of the list, so nothing else carried the
 * taint. OWASP BenchmarkTest00575 had been found only through the
 * `System.getProperty` pairing that #1081 removed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowTypes = async (code: string) => {
  const r = await analyze(code, 'T.java', 'java');
  return r.taint.flows.map(f => f.sink_type);
};

const servlet = (body: string) => `
import java.io.*;
import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
${body}
  }
}
`;

describe('#1105 — List-carried taint survives a trailing line comment', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('List add/get inside an if block, commented read, reaches exec', async () => {
    const flows = await flowTypes(servlet(`
    String param = request.getParameter("x");
    String bar = "";
    if (param != null) {
      java.util.List<String> valuesList = new java.util.ArrayList<String>();
      valuesList.add(param); // keep it
      bar = valuesList.get(0); // get the param value
    }
    String cmd = "";
    Runtime r = Runtime.getRuntime();
    Process p = r.exec(cmd + bar);
`));
    expect(flows).toContain('command_injection');
  });

  it('a List that only ever receives literals does not fire', async () => {
    const flows = await flowTypes(servlet(`
    String param = request.getParameter("x");
    String bar = "";
    if (param != null) {
      java.util.List<String> valuesList = new java.util.ArrayList<String>();
      valuesList.add("safe"); // literal
      valuesList.add("moresafe"); // literal
      bar = valuesList.get(0); // get a safe value
    }
    String cmd = "";
    Runtime r = Runtime.getRuntime();
    Process p = r.exec(cmd + bar);
`));
    expect(flows).not.toContain('command_injection');
  });

  it('a commented read of a safe slot stays clean (const-prop slot veto)', async () => {
    const flows = await flowTypes(servlet(`
    String param = request.getParameter("x");
    String bar = "";
    if (param != null) {
      java.util.List<String> valuesList = new java.util.ArrayList<String>();
      valuesList.add("safe");
      valuesList.add(param);
      valuesList.add("moresafe");
      valuesList.remove(0); // remove the 1st safe value
      bar = valuesList.get(1); // get the last 'safe' value
    }
    String cmd = "";
    Runtime r = Runtime.getRuntime();
    Process p = r.exec(cmd + bar);
`));
    expect(flows).not.toContain('command_injection');
  });

  it('BenchmarkTest00575 shape: getParameterNames loop -> List in if -> exec with getProperty', async () => {
    const flows = await flowTypes(servlet(`
    String param = "";
    boolean flag = true;
    java.util.Enumeration<String> names = request.getParameterNames();
    while (names.hasMoreElements() && flag) {
      String name = (String) names.nextElement();
      String[] values = request.getParameterValues(name);
      if (values != null) {
        for (int i = 0; i < values.length && flag; i++) {
          String value = values[i];
          if (value.equals("BenchmarkTest00575")) {
            param = name;
            flag = false;
          }
        }
      }
    }

    String bar = "";
    if (param != null) {
      java.util.List<String> valuesList = new java.util.ArrayList<String>();
      valuesList.add("safe");
      valuesList.add(param);
      valuesList.add("moresafe");

      valuesList.remove(0); // remove the 1st safe value

      bar = valuesList.get(0); // get the param value
    }

    String cmd = "";
    String osName = System.getProperty("os.name");
    String[] argsEnv = {"Foo=bar"};
    Runtime r = Runtime.getRuntime();
    try {
      Process p = r.exec(cmd + bar, argsEnv, new java.io.File(System.getProperty("user.dir")));
    } catch (IOException e) {
      return;
    }
`));
    expect(flows).toContain('command_injection');
  });
});
