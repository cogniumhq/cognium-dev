/**
 * cognium-dev #915 — OWASP BenchmarkTest01585 shape: inner class returns
 * org.apache.commons.lang.StringEscapeUtils.escapeHtml(param); PrintWriter.format stays clean.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const ESCAPE_INNER_FORMAT = `import java.io.IOException;
import javax.servlet.http.*;
import org.apache.commons.lang.StringEscapeUtils;
public class AcmeXss1585Servlet extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String[] values = request.getParameterValues("token");
    String param = (values != null && values.length > 0) ? values[0] : "";
    String bar = new EncodeStep().doSomething(request, param);
    response.setHeader("X-XSS-Protection", "0");
    Object[] obj = {"a", "b"};
    response.getWriter().format(bar, obj);
  }
  private class EncodeStep {
    public String doSomething(HttpServletRequest request, String param) throws IOException {
      return org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
    }
  }
}
`;

const RAW_FORMAT = `import javax.servlet.http.*;
public class RawFormatOnly extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("token");
    Object[] obj = {"a", "b"};
    response.getWriter().format(param, obj);
  }
}
`;

describe('#915 commons StringEscapeUtils inner helper + format', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('inner helper with FQN escapeHtml: format stays clean', async () => {
    const r = await analyze(ESCAPE_INNER_FORMAT, 'AcmeXss1585Servlet.java', 'java');
    expect(flows(r, 'xss')).toHaveLength(0);
  });

  it('negative: raw parameter in format still fires xss', async () => {
    const r = await analyze(RAW_FORMAT, 'RawFormatOnly.java', 'java');
    expect(flows(r, 'xss').length).toBeGreaterThan(0);
  });
});
