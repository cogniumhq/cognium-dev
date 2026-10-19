/**
 * cognium-dev#590 — OWASP BenchmarkJava uses `new File(new File(dir), bar)`; the
 * outer File's child argument must register as path_traversal even when an inner
 * File constructor on the same line is also a sink candidate.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const VULN = `import java.io.File;
import javax.servlet.http.*;
public class PathServlet extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("x");
    String bar = "";
    java.util.List<String> valuesList = new java.util.ArrayList<>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.remove(0);
    bar = valuesList.get(0);
    File fileTarget = new File(new File("/var/data"), bar);
  }
}`;

const SAFE = `import java.io.File;
import javax.servlet.http.*;
public class PathServlet extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String bar = "reports.csv";
    File fileTarget = new File(new File("/var/data"), bar);
  }
}`;

describe('#590 nested File(parent, child) path_traversal', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports path_traversal on the outer File child argument', async () => {
    const result = await analyze(VULN, 'PathServlet.java', 'java');
    const sinkLine =
      VULN.split('\n').findIndex(l => l.includes('new File(new File')) + 1;
    const flows = result.taint?.flows ?? [];
    expect(
      flows.some(
        f =>
          f.sink_type === 'path_traversal' &&
          f.sink_line === sinkLine &&
          f.source_type === 'http_param',
      ),
    ).toBe(true);
  });

  it('stays clean when the child name is a literal', async () => {
    const result = await analyze(SAFE, 'PathServlet.java', 'java');
    expect((result.taint?.flows ?? []).filter(f => f.sink_type === 'path_traversal')).toEqual(
      [],
    );
  });
});
