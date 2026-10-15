/**
 * A class-less sanitizer row (`sanitize`, `escape`, `htmlEscape`, ...) no longer
 * credits a same-file helper whose body is a no-op shape (#581, Java slice).
 *
 * A private helper that only trims, concatenates literals or passes its
 * parameter through does no escaping. Crediting it by name silenced real
 * sql_injection / xss findings. A helper that really escapes, and calls that
 * carry a class receiver, keep their credit.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowsAt = async (code: string, file: string, type: string) => {
  const ir = await analyze(code, file, 'java');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line);
};

const HEAD = `
import java.io.IOException;
import java.sql.Connection;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;
import org.apache.commons.text.StringEscapeUtils;
`;

const noop = `${HEAD}
public class LookupPageServlet extends HttpServlet {
    private Connection conn;

    private String sanitize(String raw) { return raw.trim(); }
    private String escape(String raw) { return raw; }
    private String htmlEscape(String raw) { return "[" + raw.trim() + "]"; }
    private String tidy(String raw) { return raw.trim(); }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        conn.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + sanitize(term) + "'");
        conn.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + tidy(term) + "'");
        resp.getWriter().write("<p>" + escape(term) + "</p>");
        resp.getWriter().write("<p>" + htmlEscape(term) + "</p>");
    }
}
`;

const lineOf = (code: string, needle: string) =>
  code.split('\n').findIndex(l => l.includes(needle)) + 1;

describe('Java no-op helper named like a sanitizer (#581)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports sql_injection through a trim-only sanitize() and through the renamed control', async () => {
    const lines = await flowsAt(noop, 'LookupPageServlet.java', 'sql_injection');
    expect(lines).toContain(lineOf(noop, `sanitize(term)`));
    expect(lines).toContain(lineOf(noop, `tidy(term)`));
  });

  it('reports xss through a pass-through escape() and a literal-wrapping htmlEscape()', async () => {
    const lines = await flowsAt(noop, 'LookupPageServlet.java', 'xss');
    expect(lines).toContain(lineOf(noop, `escape(term)`));
    expect(lines).toContain(lineOf(noop, `htmlEscape(term)`));
  });

  it('a helper that really escapes keeps its credit', async () => {
    const code = `${HEAD}
public class LookupSafeServlet extends HttpServlet {
    private String escape(String raw) { return raw.replace("<", "&lt;").replace(">", "&gt;"); }
    private String sanitize(String raw) { return StringEscapeUtils.escapeHtml4(raw); }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        resp.getWriter().write("<p>" + escape(term) + "</p>");
        resp.getWriter().write("<p>" + sanitize(term) + "</p>");
    }
}
`;
    expect(await flowsAt(code, 'LookupSafeServlet.java', 'xss')).toHaveLength(0);
  });

  it('class-qualified library calls stay clean in a file that defines a no-op helper of the same name', async () => {
    const code = `${HEAD}
public class LookupMixedServlet extends HttpServlet {
    private String htmlEscape(String raw) { return raw; }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        resp.getWriter().write("<p>" + HtmlUtils.htmlEscape(term) + "</p>");
        resp.getWriter().write("<p>" + StringEscapeUtils.escapeHtml4(term) + "</p>");
    }
}
`;
    expect(await flowsAt(code, 'LookupMixedServlet.java', 'xss')).toHaveLength(0);
  });

  it('inline replace chain credit is unchanged', async () => {
    const code = `${HEAD}
public class LookupInlineServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        String safe = term.replace("<", "&lt;").replace(">", "&gt;");
        resp.getWriter().write("<p>" + safe + "</p>");
    }
}
`;
    expect(await flowsAt(code, 'LookupInlineServlet.java', 'xss')).toHaveLength(0);
  });

  it('a no-op overload does not hide a real-escaping overload of the same name', async () => {
    const code = `${HEAD}
public class LookupOverloadServlet extends HttpServlet {
    private String escape(String raw) { return raw; }
    private String escape(String raw, int mode) { return raw.replace("<", "&lt;").replace(">", "&gt;"); }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        resp.getWriter().write("<p>" + escape(term, 1) + "</p>");
    }
}
`;
    expect(await flowsAt(code, 'LookupOverloadServlet.java', 'xss')).toHaveLength(0);
  });
});
