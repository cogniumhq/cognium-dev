/**
 * cognium-dev#517 (minimal slice): credit a private Java helper whose body is a
 * chained `replace` / `replaceAll` sequence when it entity-escapes `<` and `>`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function xssSinkLines(code: string, file: string) {
  const r = await analyze(code, file, 'java');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))].sort(
    (a, b) => a - b,
  );
}

const servletImports = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
`;

const echoPage = `${servletImports}
public class EchoPageServlet extends HttpServlet {
    private String tidy(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private String decorate(String value) {
        return "[" + value.trim() + "]";
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        response.getWriter().write("<p>" + tidy(q) + "</p>");
        response.getWriter().write("<p>" + decorate(q) + "</p>");
        String inline = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        response.getWriter().write("<p>" + inline + "</p>");
    }
}
`;

const echoHelperPartial = `${servletImports}
public class EchoHelperPartialServlet extends HttpServlet {
    private String squash(String value) {
        return value.replace("&", "&amp;").replace("\\n", "").replace("\\r", "");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        response.getWriter().write("<p>" + squash(q) + "</p>");
    }
}
`;

const echoHelperSql = `${servletImports}
import java.sql.Connection;
import java.sql.DriverManager;

public class EchoHelperSqlServlet extends HttpServlet {
    private String tidy(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        conn.createStatement().executeQuery("SELECT * FROM t WHERE x = '" + tidy(q) + "'");
    }
}
`;

const echoPartial = `${servletImports}
public class EchoPartialServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        String amp = q.replace("&", "&amp;");
        response.getWriter().write(amp);
        String nl = q.replace("\\n", "").replace("\\r", "");
        response.getWriter().write(nl);
    }
}
`;

describe('#517 Java replace-chain helper xss credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('credits tidy() chain: only decorate write reports xss', async () => {
    const lines = await xssSinkLines(echoPage, 'EchoPageServlet.java');
    expect(lines).toEqual([19]);
  });

  it('partial entity chain helper still reports xss', async () => {
    const lines = await xssSinkLines(echoHelperPartial, 'EchoHelperPartialServlet.java');
    expect(lines).toEqual([14]);
  });

  it('entity chain helper does not clear sql_injection', async () => {
    const r = await analyze(echoHelperSql, 'EchoHelperSqlServlet.java', 'java');
    const sqlLines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))];
    expect(sqlLines).toContain(18);
  });

  it('inline partial escapes on EchoPartialServlet still report xss', async () => {
    const lines = await xssSinkLines(echoPartial, 'EchoPartialServlet.java');
    expect(lines).toContain(11);
    expect(lines).toContain(13);
  });
});
