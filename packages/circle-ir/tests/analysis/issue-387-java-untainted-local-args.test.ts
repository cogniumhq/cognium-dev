/**
 * cognium-dev#387 (slice) — proximity-only findings drop when every sink
 * argument is a local whose reaching defs are untainted (literals, UUID, etc.).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const run = async (code: string, file: string) => {
  const ir = await analyze(code, file, 'java');
  const t = ir.taint ?? ({} as NonNullable<typeof ir.taint>);
  const findings = generateFindings(
    t.sources ?? [], t.sinks ?? [], ir.dfg, file, code, 'java',
    t.sanitizers ?? [], ir.types ?? [], t.flows ?? [],
  );
  return { flows: t.flows ?? [], findings };
};

const PREF = `import java.io.IOException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PrefCookieServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String prefName = "theme";
        String prefValue = java.util.UUID.randomUUID().toString();
        Cookie pref = new Cookie(prefName, prefValue);
        pref.setHttpOnly(true);
        pref.setPath(request.getRequestURI());
        request.getSession().setAttribute(prefName, prefValue);
        response.addCookie(pref);
    }
}
`;

const VISIT_MARKER = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VisitMarkerServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String agent = request.getHeader("User-Agent");
        request.getSession().setAttribute("visited", "yes");
    }
}
`;

const VISIT_AGENT = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VisitAgentServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String agent = request.getHeader("User-Agent");
        String shown = decorate(agent);
        request.getSession().setAttribute("agent", shown);
    }

    private String decorate(String value) {
        return "[" + value + "]";
    }
}
`;

describe('#387 Java: untainted-local sink arguments drop proximity-only pairings', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('PrefCookieServlet: no finding at setAttribute(prefName, prefValue)', async () => {
    const { flows, findings } = await run(PREF, 'PrefCookieServlet.java');
    expect(flows).toHaveLength(0);
    const atSink = findings.filter((f) => f.sink.line === 15);
    expect(atSink).toHaveLength(0);
  });

  it('VisitMarkerServlet: literal setAttribute arguments stay clean', async () => {
    const { findings } = await run(VISIT_MARKER, 'VisitMarkerServlet.java');
    expect(findings.filter((f) => f.sink.line === 10)).toHaveLength(0);
  });

  it('VisitAgentServlet: helper-derived argument keeps proximity pairing', async () => {
    const { findings } = await run(VISIT_AGENT, 'VisitAgentServlet.java');
    expect(findings.some((f) => f.sink.line === 11)).toBe(true);
  });
});
