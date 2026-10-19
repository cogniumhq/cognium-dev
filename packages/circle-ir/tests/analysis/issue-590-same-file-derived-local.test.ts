/**
 * cognium-dev#590 — helper return taint must reach caller sinks that consume a
 * DFG-derived local (`sql = "…" + bar`), not only sinks that mention `bar` directly.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const FIXTURE = `import javax.servlet.http.*;
import java.sql.*;
public class InvoiceLookupServlet extends HttpServlet {
  private Connection conn;

  private String fetchInvoice(HttpServletRequest request) {
    return request.getParameter("invoice");
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String invoice = fetchInvoice(request);
    String sql = "SELECT * FROM invoices WHERE ref = '" + invoice + "'";
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;

const SAFE_FIXTURE = `import javax.servlet.http.*;
import java.sql.*;
public class InvoiceLookupServlet extends HttpServlet {
  private Connection conn;

  private String fixedToken() {
    return "bar";
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String invoice = fixedToken();
    String sql = "SELECT * FROM invoices WHERE ref = '" + invoice + "'";
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;

describe('#590 same-file derived local after helper return', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports sql_injection when the sink uses a derived sql local', async () => {
    const result = await analyze(FIXTURE, 'InvoiceLookupServlet.java', 'java');
    const sinkLine =
      FIXTURE.split('\n').findIndex(l => l.includes('executeQuery(sql)')) + 1;
    const flows = result.taint?.flows ?? [];
    expect(
      flows.some(
        f =>
          f.sink_type === 'sql_injection' &&
          f.sink_line === sinkLine &&
          f.source_type === 'http_param',
      ),
    ).toBe(true);
  });

  it('stays clean when the helper returns a literal', async () => {
    const result = await analyze(SAFE_FIXTURE, 'InvoiceLookupServlet.java', 'java');
    const flows = result.taint?.flows ?? [];
    expect(flows.filter(f => f.sink_type === 'sql_injection')).toEqual([]);
  });
});
