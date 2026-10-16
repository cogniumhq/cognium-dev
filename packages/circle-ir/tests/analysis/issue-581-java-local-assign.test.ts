/**
 * #581 Java slice: a trim-only same-file `sanitize()` must not credit
 * `String cleaned = sanitize(term)` when the sink uses `cleaned`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const HEAD = `
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
`;

const vuln = `${HEAD}
public class ItemSearchServlet extends HttpServlet {
    private Connection conn;

    private String sanitize(String raw) { return raw.trim(); }
    private String tidy(String raw) { return raw.trim(); }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        String cleaned = sanitize(term);
        String tidied = tidy(term);
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM items WHERE name = '" + cleaned + "'");
        st.executeQuery("SELECT * FROM items WHERE name = '" + tidied + "'");
    }
}
`;

const safe = `${HEAD}
public class ItemSearchEscapedServlet extends HttpServlet {
    private Connection conn;

    private String sanitize(String raw) { return raw.replace("'", "''"); }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String term = req.getParameter("term");
        String cleaned = sanitize(term);
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM items WHERE name = '" + cleaned + "'");
    }
}
`;

const lineOf = (code: string, needle: string) =>
  code.split('\n').findIndex(l => l.includes(needle)) + 1;

const sqlLines = async (code: string, file: string) => {
  const ir = await analyze(code, file, 'java');
  return (ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'sql_injection')
    .map(f => f.sink_line);
};

describe('Java local-assigned noop sanitize (#581)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports sql_injection through cleaned and the tidy control', async () => {
    const lines = await sqlLines(vuln, 'ItemSearchServlet.java');
    expect(lines).toContain(lineOf(vuln, `cleaned + "'`));
    expect(lines).toContain(lineOf(vuln, `tidied + "'`));
  });

  it('keeps a real-escaping sanitize() clean', async () => {
    expect(await sqlLines(safe, 'ItemSearchEscapedServlet.java')).toEqual([]);
  });
});
