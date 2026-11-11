/**
 * cognium-dev#476 — SecuriBench Collections8 shape: add literal then addAll(tainted list).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const COLLECTIONS8_STYLE = `import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedList;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VaultMergeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String s1 = req.getParameter("name");
        LinkedList c1 = new LinkedList();
        c1.addLast(s1);
        ArrayList c2 = new ArrayList();
        c2.add("abc");
        c2.addAll(c1);
        String s2 = (String) c2.get(1);
        PrintWriter writer = resp.getWriter();
        writer.println(s2);
    }
}
`;

const COLLECTIONS8_SAFE = `import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedList;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VaultMergeSafeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        LinkedList c1 = new LinkedList();
        c1.addLast("safe");
        ArrayList c2 = new ArrayList();
        c2.add("abc");
        c2.addAll(c1);
        String s2 = (String) c2.get(0);
        PrintWriter writer = resp.getWriter();
        writer.println(s2);
    }
}
`;

describe('#476 slice: Collections8 addAll list merge', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('VaultMergeServlet: xss on println after addAll copies tainted slot by index', async () => {
    const r = await analyze(COLLECTIONS8_STYLE, 'VaultMergeServlet.java', 'java');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 20)).toBe(true);
  });

  it('VaultMergeSafeServlet: literals-only addAll stay clean', async () => {
    const r = await analyze(COLLECTIONS8_SAFE, 'VaultMergeSafeServlet.java', 'java');
    expect(flows(r, 'xss')).toHaveLength(0);
  });
});
