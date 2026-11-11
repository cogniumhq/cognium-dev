/**
 * cognium-dev #915 — OWASP BenchmarkTest00942 shape: tainted bytes flow into
 * `encodeForHTML(new String(input))` inside a string concat passed to println;
 * the only dynamic fragment is encoder-wrapped.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const xssFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'xss');

const BENCHMARK_00942_SHAPE = `import java.io.IOException;
import javax.servlet.http.*;
public class BenchmarkTest00942 extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String param = request.getParameter("p");
    String bar = new Test().doSomething(request, param);
    byte[] input = ((String) bar).getBytes();
    response.getWriter()
        .println(
            "Sensitive value: '"
                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(new String(input))
                + "' stored");
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      return org.apache.commons.codec.binary.Base64.encodeBase64String(param.getBytes());
    }
  }
}`;

describe('#915 ESAPI encodeForHTML inside println concat', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('encodeForHTML-wrapped concat stays clean (BenchmarkTest00942 shape)', async () => {
    const r = await analyze(BENCHMARK_00942_SHAPE, 'BenchmarkTest00942.java', 'java');
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('negative: raw variable in concat still fires', async () => {
    const r = await analyze(
      [
        'import javax.servlet.http.*;',
        'public class RawConcat extends HttpServlet {',
        '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {',
        '    String bar = request.getParameter("p");',
        '    response.getWriter().println("x" + bar);',
        '  }',
        '}',
      ].join('\n'),
      'RawConcat.java',
      'java',
    );
    expect(xssFlows(r).length).toBeGreaterThan(0);
  });
});
