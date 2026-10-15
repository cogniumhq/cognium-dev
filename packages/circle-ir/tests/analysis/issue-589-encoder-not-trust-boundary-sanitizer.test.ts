/**
 * #589 (slice) — an HTML/markup encoder neutralises the XSS context only.
 *
 * A local assigned from any registered sanitizer call entered
 * `constProp.sanitizedVars`, which carries no sink-type information, so
 * `filterCleanVariableSinks` treated the argument as clean for EVERY sink type:
 * `session.setAttribute("n", escapeHtml(x))` lost its `trust_boundary` sink.
 * Variables produced by a context-specific encoder now remember that scope and
 * only drop sinks of the types the encoder covers (xss, and the bare-helper
 * `external_taint_escape` credit that its config row also carries). Other
 * sanitizer families keep their existing behaviour.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { DEFAULT_SANITIZERS } from '../../src/analysis/config-loader.js';
import { HTML_CONTEXT_ENCODER_METHODS, SANITIZER_METHODS } from '../../src/analysis/constant-propagation/patterns.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const sinksAt = (r: IR, line: number) => (r.taint.sinks ?? []).filter(s => s.line === line).map(s => s.type);
const flowTypesFrom = (r: IR, srcLine: number, sinkLine: number) =>
  (r.taint.flows ?? []).filter(f => f.source_line === srcLine && f.sink_line === sinkLine).map(f => f.sink_type);

const save = (encoderImport: string, encode: string) => `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
${encoderImport}

public class ProfileSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick = request.getParameter("nickname");
        String shown = ${encode};
        request.getSession().setAttribute("displayName", shown);
        String raw = request.getParameter("theme");
        request.getSession().setAttribute("theme", raw);
    }
}
`;

describe('#589 an HTML encoder does not clear trust_boundary', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const variants: Array<[string, string, string]> = [
    ['Commons escapeHtml', 'import org.apache.commons.lang.StringEscapeUtils;', 'StringEscapeUtils.escapeHtml(nick)'],
    ['ESAPI encodeForHTML', 'import org.owasp.esapi.ESAPI;', 'ESAPI.encoder().encodeForHTML(nick)'],
    ['Spring htmlEscape', 'import org.springframework.web.util.HtmlUtils;', 'HtmlUtils.htmlEscape(nick)'],
  ];

  for (const [name, imp, enc] of variants) {
    it(`${name}: line 12 keeps trust_boundary with a flow from line 10, and no xss`, async () => {
      const r = await analyze(save(imp, enc), 'ProfileSaveServlet.java', 'java');
      expect(sinksAt(r, 12)).toContain('trust_boundary');
      expect(sinksAt(r, 12)).not.toContain('xss');
      expect(flowTypesFrom(r, 10, 12)).toContain('trust_boundary');
      expect(flowTypesFrom(r, 10, 12)).not.toContain('xss');
    });
    it(`${name}: the unencoded control on line 14 still reports trust_boundary`, async () => {
      const r = await analyze(save(imp, enc), 'ProfileSaveServlet.java', 'java');
      expect(sinksAt(r, 14)).toContain('trust_boundary');
    });
  }

  it('ProfileShowServlet: the same encoder written to HTML stays clean of xss', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ProfileShowServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String shown = StringEscapeUtils.escapeHtml(request.getParameter("nickname"));
        response.getWriter().print("<p>" + shown + "</p>");
    }
}
`, 'ProfileShowServlet.java', 'java');
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'xss')).toHaveLength(0);
  });

  it('other sanitizer families keep their scope: parseInt still clears an sql sink', async () => {
    const r = await analyze(`import java.io.IOException;
import java.sql.Connection;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IdServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Connection conn = null;
        int id = Integer.parseInt(request.getParameter("id"));
        conn.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id);
    }
}
`, 'IdServlet.java', 'java');
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection')).toHaveLength(0);
  });
});

describe('#589 the HTML-encoder list stays in step with the sanitizer config', () => {
  it('every listed method is a registered const-prop sanitizer', () => {
    for (const m of HTML_CONTEXT_ENCODER_METHODS) expect(SANITIZER_METHODS.has(m), m).toBe(true);
  });

  it('no listed method clears a sink type other than xss / external_taint_escape in the config', () => {
    for (const row of DEFAULT_SANITIZERS as Array<{ method?: string; removes?: string[] }>) {
      if (!row.method || !HTML_CONTEXT_ENCODER_METHODS.has(row.method)) continue;
      for (const t of row.removes ?? []) {
        expect(['xss', 'external_taint_escape'], `${row.method} removes ${t}`).toContain(t);
      }
    }
  });
});
