/**
 * cognium-dev#348 — Java CR/LF strip credit, and a strip on one value must
 * not clear a different, unstripped value logged in the same statement.
 *
 *     String clean = one.replaceAll("[\r\n]", "");
 *     String msg = "one=" + clean + " two=" + two;   // `two` never stripped
 *     LOG.info(msg);
 *
 * The flow filter walked every contributor of `msg` backward and credited
 * the strip on `clean` to the flow from `two` too. The credit now applies only
 * to a sanitized def on the flow itself: a variable on its path, or one whose
 * own reaching defs lead back to the flow's source.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const code = `import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;

public class GatewayAudit {
    private static final Logger LOG = Logger.getLogger("gateway");

    public void strippedAssign(HttpServletRequest req) {
        String agent = req.getHeader("X-Client").replaceAll("[\\r\\n]", "");
        LOG.info("client=" + agent);
    }

    public void strippedTernary(HttpServletRequest req) {
        String agent = req.getHeader("X-Client");
        String flat = agent == null ? "" : agent.replaceAll("[\\r\\n]", "");
        LOG.info("client=" + flat);
    }

    public void mixedViaMessage(HttpServletRequest req) {
        String region = req.getHeader("X-Region");
        String tenant = req.getHeader("X-Tenant");
        String flat = region.replaceAll("[\\r\\n]", "");
        String msg = "region=" + flat + " tenant=" + tenant;
        LOG.info(msg);
    }

    public void bothStripped(HttpServletRequest req) {
        String region = req.getHeader("X-Region");
        String tenant = req.getHeader("X-Tenant");
        String a = region.replaceAll("[\\r\\n]", "");
        String b = tenant.replaceAll("[\\r\\n]", "");
        String msg = a + " " + b;
        LOG.info(msg);
    }

    public void twoHops(HttpServletRequest req) {
        String region = req.getHeader("X-Region");
        String flat = region.replaceAll("[\\r\\n]", "");
        String msg = "region=" + flat;
        LOG.info(msg);
    }

    public void numericMixed(HttpServletRequest req, Connection conn) throws SQLException {
        String page = req.getParameter("page");
        String owner = req.getParameter("owner");
        int n = Integer.parseInt(page);
        String q = "select * from docs where page=" + n + " and owner='" + owner + "'";
        conn.createStatement().executeQuery(q);
    }

    public void numericOnly(HttpServletRequest req, Connection conn) throws SQLException {
        String page = req.getParameter("page");
        int n = Integer.parseInt(page);
        String q = "select * from docs where page=" + n;
        conn.createStatement().executeQuery(q);
    }
}
`;

const lines = code.split('\n');
const lineOf = (text: string, after = 0) => lines.findIndex((l, i) => i >= after && l.includes(text)) + 1;
const methodLine = (name: string) => lineOf(`void ${name}(`);

describe('#348 sanitizer credit is limited to the flow it sanitizes', () => {
  let flows: Array<{ sink_type: string; source_line: number; sink_line: number }> = [];
  beforeAll(async () => {
    await initAnalyzer();
    const r = await analyze(code, 'GatewayAudit.java', 'java');
    flows = (r.taint.flows ?? []).filter(f => !f.sanitized);
  });

  const at = (type: string, sinkText: string, method: string) => {
    const sink = lineOf(sinkText, methodLine(method));
    return flows.filter(f => f.sink_type === type && f.sink_line === sink);
  };

  it('a CR/LF strip on assignment clears log_injection (inline and ternary)', () => {
    expect(at('log_injection', 'LOG.info', 'strippedAssign')).toHaveLength(0);
    expect(at('log_injection', 'LOG.info', 'strippedTernary')).toHaveLength(0);
  });

  it('the unstripped value beside a stripped one still fires, only from its own source', () => {
    const f = at('log_injection', 'LOG.info', 'mixedViaMessage');
    const tenantLine = lineOf('X-Tenant', methodLine('mixedViaMessage'));
    const regionLine = lineOf('X-Region', methodLine('mixedViaMessage'));
    expect(f.some(x => x.source_line === tenantLine)).toBe(true);
    expect(f.some(x => x.source_line === regionLine)).toBe(false);
  });

  it('stays clean when every contributor is stripped, and through two hops', () => {
    expect(at('log_injection', 'LOG.info', 'bothStripped')).toHaveLength(0);
    expect(at('log_injection', 'LOG.info', 'twoHops')).toHaveLength(0);
  });

  it('the same holds for other sanitizers: a numeric parse does not clear a raw sibling', () => {
    expect(at('sql_injection', 'executeQuery', 'numericMixed').length).toBeGreaterThan(0);
    expect(at('sql_injection', 'executeQuery', 'numericOnly')).toHaveLength(0);
  });
});
