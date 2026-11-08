/**
 * cognium-dev#589 S4: inner-class / multi-line helpers that assign an HTML encoder
 * to a local then return it (OWASP BenchmarkTest01546 shape) must keep
 * trust_boundary on session writes, like direct encoder calls.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const flowTypes = (r: IR, sinkLine: number) =>
  [...new Set((r.taint.flows ?? []).filter((f) => f.sink_line === sinkLine).map((f) => f.sink_type))].sort();

const INNER_ENCODER_SERVLET = `import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class SessionPutServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("nickname");
        String bar = new Test().doSomething(request, param);
        request.getSession().putValue(bar, "10340");
    }

    private class Test {
        public String doSomething(HttpServletRequest request, String param) throws ServletException, IOException {
            String bar = StringEscapeUtils.escapeHtml(param);
            return bar;
        }
    }
}
`;

const STATIC_INNER_ENCODER = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

public class SessionValueServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("BenchmarkTest02526");
        String bar = doSomething(request, param);
        request.getSession().putValue("userid", bar);
    }

    private static String doSomething(HttpServletRequest request, String param) throws IOException {
        String bar = HtmlUtils.htmlEscape(param);
        return bar;
    }
}
`;

describe('cognium-dev#589 inner-class encoder helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('inner class helper: putValue(bar) keeps trust_boundary', async () => {
    const r = await analyze(INNER_ENCODER_SERVLET, 'SessionPutServlet.java', 'java');
    expect(flowTypes(r, 13)).toContain('trust_boundary');
  });

  it('static helper: putValue second arg keeps trust_boundary', async () => {
    const r = await analyze(STATIC_INNER_ENCODER, 'SessionValueServlet.java', 'java');
    expect(flowTypes(r, 12)).toContain('trust_boundary');
  });
});
