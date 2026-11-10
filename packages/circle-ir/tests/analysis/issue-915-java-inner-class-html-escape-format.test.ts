/**
 * cognium-dev #915 S1 — OWASP BenchmarkTest01048 shape: inner-class helper returns
 * HtmlUtils.htmlEscape(param); PrintWriter.format must stay clean; raw format still fires.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

/** Mirrors OWASP BenchmarkTest01048 (inner `Test`, htmlEscape, format sink). */
const OWASP_01048_SHAPE = `import java.io.IOException;
import org.springframework.web.util.HtmlUtils;
import javax.servlet.http.*;
public class BenchmarkTest01048 extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String param = "";
    if (request.getHeader("Referer") != null) {
      param = request.getHeader("Referer");
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");
  String bar = new Test().doSomething(request, param);
    response.setHeader("X-XSS-Protection", "0");
    Object[] obj = {"a", "b"};
    response.getWriter().format(java.util.Locale.US, bar, obj);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      return HtmlUtils.htmlEscape(param);
    }
  }
}
`;

const INNER_CLASS_SAFE = `import org.springframework.web.util.HtmlUtils;
import javax.servlet.http.*;
public class BenchServlet extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("Referer");
    String bar = new Test().doSomething(request, param);
    Object[] obj = {"a", "b"};
    response.getWriter().format(java.util.Locale.US, bar, obj);
  }
  private class Test {
    String doSomething(HttpServletRequest request, String param) {
      return HtmlUtils.htmlEscape(param);
    }
  }
}
`;

const RAW_FORMAT = `import javax.servlet.http.*;
public class RawFormatServlet extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getHeader("Referer");
    Object[] obj = {"a", "b"};
    response.getWriter().format(java.util.Locale.US, param, obj);
  }
}
`;

describe('#915 Java inner-class HtmlUtils.htmlEscape + format', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('BenchmarkTest01048 shape: no xss flow after htmlEscape helper', async () => {
    const r = await analyze(OWASP_01048_SHAPE, 'BenchmarkTest01048.java', 'java');
    expect(flows(r, 'xss')).toHaveLength(0);
  });

  it('inner-class helper servlet: format stays clean', async () => {
    const r = await analyze(INNER_CLASS_SAFE, 'BenchServlet.java', 'java');
    expect(flows(r, 'xss')).toHaveLength(0);
  });

  it('negative: format with raw header still fires', async () => {
    const r = await analyze(RAW_FORMAT, 'RawFormatServlet.java', 'java');
    expect(flows(r, 'xss').length).toBeGreaterThan(0);
  });
});
