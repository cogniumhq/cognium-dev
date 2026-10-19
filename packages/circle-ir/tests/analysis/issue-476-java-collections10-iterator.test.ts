/**
 * cognium-dev#476 (slice) — Collections10: two while loops each declare `str` in
 * their own block; the first loop's println must stay tainted after the second loop.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const COLLECTIONS10_STYLE = `import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LedgerCopyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String s1 = request.getParameter("name");
        LinkedList c1 = new LinkedList();
        c1.addLast(s1);
        ArrayList c2 = new ArrayList();
        c2.add("abc");

        Iterator iter = c1.iterator();
        PrintWriter writer = response.getWriter();
        while (iter.hasNext()) {
            String str = (String) iter.next();
            writer.println(str);
        }

        iter = c2.iterator();
        while (iter.hasNext()) {
            String str = (String) iter.next();
            writer.println(str);
        }
    }
}
`;

describe('#476 slice: Collections10 block-scoped loop locals', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('LedgerCopyServlet: xss on first println only', async () => {
    const r = await analyze(COLLECTIONS10_STYLE, 'LedgerCopyServlet.java', 'java');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 23)).toBe(true);
    expect(xss.some(f => f.sink_line === 29)).toBe(false);
  });
});
