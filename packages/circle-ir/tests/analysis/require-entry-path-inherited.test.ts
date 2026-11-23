/**
 * require-entry-path: servlet handlers reached through in-project base classes.
 *
 * `Handler extends BaseServlet` where `BaseServlet extends HttpServlet` makes
 * `Handler.doGet` a servlet entry point. The per-type classifier sees only the
 * direct parent, so the gate treated every such handler as unreachable and
 * dropped its findings: SecuriBench Micro (`Basic1 extends BasicTestCase extends
 * HttpServlet`) went from 88.0% to 7.4% TPR under the default CLI.
 *
 * Each scan includes a `main()` elsewhere so Java has a Tier-1 entry point and
 * the zero-entry-point safety guard cannot mask the gate's decision.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const MAIN = `
public class App {
  public static void main(String[] args) { System.out.println("up"); }
}
`;

const BASE = `
import javax.servlet.http.HttpServlet;
public abstract class BaseServlet extends HttpServlet {
  protected String banner() { return "hi"; }
}
`;

const MID = `
public abstract class MidServlet extends BaseServlet {
}
`;

const handler = (name: string, parent: string, method: string) => `
import java.sql.*;
import javax.servlet.http.*;
public class ${name} extends ${parent} {
  protected void ${method}(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String id = req.getParameter("id");
    Statement st = DriverManager.getConnection("jdbc:x").createStatement();
    st.executeQuery("SELECT * FROM t WHERE id=" + id);
  }
}
`;

const sqliFlows = async (files: Array<[string, string]>, target: string) => {
  const result = await analyzeProject(
    files.map(([filePath, code]) => ({ filePath, code, language: 'java' as const })),
  );
  const fa = result.files.find(f => f.file === target);
  return (fa?.analysis.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
};

describe('require-entry-path: inherited servlet lifecycle methods', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('keeps doGet behind one in-project base servlet', async () => {
    const flows = await sqliFlows(
      [['App.java', MAIN], ['BaseServlet.java', BASE], ['Handler.java', handler('Handler', 'BaseServlet', 'doGet')]],
      'Handler.java',
    );
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('keeps doPost behind two in-project base servlets', async () => {
    const flows = await sqliFlows(
      [
        ['App.java', MAIN],
        ['BaseServlet.java', BASE],
        ['MidServlet.java', MID],
        ['Handler.java', handler('Handler', 'MidServlet', 'doPost')],
      ],
      'Handler.java',
    );
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('keeps doGet when HttpServlet is named with its package', async () => {
    const flows = await sqliFlows(
      [['App.java', MAIN], ['Handler.java', handler('Handler', 'javax.servlet.http.HttpServlet', 'doGet')]],
      'Handler.java',
    );
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('still drops a non-lifecycle method nothing calls', async () => {
    const flows = await sqliFlows(
      [['App.java', MAIN], ['BaseServlet.java', BASE], ['Handler.java', handler('Handler', 'BaseServlet', 'lookup')]],
      'Handler.java',
    );
    expect(flows).toHaveLength(0);
  });
});

describe('require-entry-path: the drop is counted on ProjectAnalysis', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const project = (method: string, disabledPasses?: string[]) => analyzeProject(
    [['App.java', MAIN], ['Handler.java', handler('Handler', 'javax.servlet.http.HttpServlet', method)]]
      .map(([filePath, code]) => ({ filePath, code, language: 'java' as const })),
    disabledPasses ? { disabledPasses } : {},
  );

  it('sets entry_path_dropped when the gate removes a flow', async () => {
    const result = await project('lookup');
    expect(result.entry_path_dropped).toBeGreaterThanOrEqual(1);
  });

  it('omits it when nothing was removed', async () => {
    const result = await project('doGet');
    expect(result.entry_path_dropped).toBeUndefined();
  });

  it('omits it when the gate is disabled, and the flow is kept', async () => {
    const result = await project('lookup', ['require-entry-path']);
    expect(result.entry_path_dropped).toBeUndefined();
    const flows = result.files.find(f => f.file === 'Handler.java')?.analysis.taint.flows ?? [];
    expect(flows.some(f => f.sink_type === 'sql_injection')).toBe(true);
  });
});
