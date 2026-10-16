/**
 * cognium-dev#589 (slice): trust_boundary through a two-hop helper chain
 * wrapEncode → encodeForPage → escapeHtml.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const flowTypes = (r: IR, sinkLine: number) =>
  [...new Set((r.taint.flows ?? []).filter((f) => f.sink_line === sinkLine).map((f) => f.sink_type))].sort();

const HEAD = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;
`;

const servlet = (cls: string, body: string, helpers: string) => `${HEAD}public class ${cls} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
${body}
    }
${helpers}
}
`;

describe('cognium-dev#589 indirect encoder helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('SessionWriteServlet: setAttribute after wrapEncode keeps trust_boundary', async () => {
    const helpers = `    private String wrapEncode(String value) {
        return encodeForPage(value);
    }
    private String encodeForPage(String value) {
        return StringEscapeUtils.escapeHtml(value);
    }`;
    const code = servlet(
      'SessionWriteServlet',
      `        String nick = request.getParameter("nickname");
        String shown = wrapEncode(nick);
        request.getSession().setAttribute("displayName", shown);`,
      helpers,
    );
    const r = await analyze(code, 'SessionWriteServlet.java', 'java');
    expect(flowTypes(r, 11)).toEqual(['trust_boundary']);
  });

  it('negative: HTML print stays free of xss', async () => {
    const helpers = `    private String wrapEncode(String value) {
        return encodeForPage(value);
    }
    private String encodeForPage(String value) {
        return StringEscapeUtils.escapeHtml(value);
    }`;
    const code = servlet(
      'SessionShowServlet',
      `        String nick = request.getParameter("nickname");
        String shown = wrapEncode(nick);
        response.getWriter().print("<p>" + shown + "</p>");`,
      helpers,
    );
    const r = await analyze(code, 'SessionShowServlet.java', 'java');
    expect(flowTypes(r, 11)).not.toContain('xss');
  });
});
