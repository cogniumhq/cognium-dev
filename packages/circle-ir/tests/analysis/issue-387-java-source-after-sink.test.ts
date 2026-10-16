/**
 * #387 (slice) — the source-after-sink direction gate, extended to Java.
 *
 * `generateFindings` drops a pairing whose source line is AFTER its sink line
 * when nothing in `taint.flows` backs that sink (previously C# only). A value
 * read on line N+2 cannot be what reached a sink on line N unless a loop or a
 * field carries it, and both of those are flow-backed (or `interprocedural_param`
 * / field sources), which the gate leaves untouched.
 *
 * For Java the gate covers request-derived (`http_*`) sources only: pairings
 * whose source is a `file_input` / `db_input` read after the sink stand in for
 * flows the taint layer does not yet prove (#590) and are left alone.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const run = async (code: string, file: string, withFlows = true) => {
  const ir = await analyze(code, file, 'java');
  const t = ir.taint ?? ({} as NonNullable<typeof ir.taint>);
  const findings = withFlows
    ? generateFindings(
        t.sources ?? [], t.sinks ?? [], ir.dfg, file, code, 'java',
        t.sanitizers ?? [], ir.types ?? [], t.flows ?? [],
      )
    : generateFindings(
        t.sources ?? [], t.sinks ?? [], ir.dfg, file, code, 'java',
        t.sanitizers ?? [], ir.types ?? [],
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

const LOOP = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoopCarry extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String saved = request.getParameter("seed");
        request.getSession().setAttribute("seed", saved);
        String last = "";
        for (int i = 0; i < 2; i++) {
            request.getSession().setAttribute("prev", last);
            last = request.getParameter("p" + i);
        }
    }
}
`;

const STATIC = `import java.io.IOException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StaticCookieServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie pref = new Cookie("theme", "dark");
        pref.setPath("/");
        request.getSession().setAttribute("theme", "dark");
        response.addCookie(pref);
    }
}
`;

describe('#387 Java: a source read after the sink does not pair with it when no flow backs the sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops the sink-before-source pairing (source line 14 -> sink line 12)', async () => {
    const { flows, findings } = await run(PREF, 'PrefCookieServlet.java');
    expect(flows).toHaveLength(0);
    const backwards = findings.filter(f => f.source.line > f.sink.line);
    expect(backwards.map(f => `${f.type}@${f.source.line}->${f.sink.line}`)).toEqual([]);
  });

  it('drops proximity-only pairings at setAttribute when every argument is an untainted local', async () => {
    const { findings } = await run(PREF, 'PrefCookieServlet.java');
    const forward = findings.filter(f => f.source.line === 14 && f.sink.line === 15);
    expect(forward).toHaveLength(0);
  });

  it('keeps every loop-carried, flow-backed finding including the backwards pair', async () => {
    const { flows, findings } = await run(LOOP, 'LoopCarry.java');
    expect(flows.length).toBeGreaterThan(0);
    expect(findings).toHaveLength(4);
    expect(findings.some(f => f.source.line === 14 && f.sink.line === 13)).toBe(true);
  });

  it('keeps a constant-only servlet at zero findings', async () => {
    const { findings } = await run(STATIC, 'StaticCookieServlet.java');
    expect(findings).toHaveLength(0);
  });

  it('keeps the legacy 8-argument signature unchanged (no flows supplied)', async () => {
    const legacy = await run(PREF, 'PrefCookieServlet.java', false);
    expect(legacy.findings.some(f => f.source.line > f.sink.line)).toBe(true);
  });

  it('leaves a file_input read after the sink it opened unchanged (stands in for an unproven flow)', async () => {
    const code = `import java.io.*;
import javax.servlet.http.HttpServletRequest;

public class Reader {
    public int run(HttpServletRequest request) throws IOException {
        String param = new org.example.helpers.RequestWrapper(request).getTheParameter("n");
        String fileName = "/srv/files/" + param;
        InputStream is = new FileInputStream(fileName);
        byte[] b = new byte[100];
        int size = is.read(b);
        return size;
    }
}
`;
    const { findings } = await run(code, 'Reader.java');
    const legacy = await run(code, 'Reader.java', false);
    expect(legacy.findings.some(f => f.source.line > f.sink.line)).toBe(true);
    expect(findings.map(f => `${f.type}@${f.source.line}->${f.sink.line}`).sort())
      .toEqual(legacy.findings.map(f => `${f.type}@${f.source.line}->${f.sink.line}`).sort());
  });
});
