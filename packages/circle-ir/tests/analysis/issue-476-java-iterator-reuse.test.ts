/**
 * cognium-dev#476 (slice) — iterator reuse must not clear taint from an earlier
 * `str = iter.next()` when `iter` is later rebound (Collections10 shape).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const ITER_REUSE = `import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ThemeCopyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        LinkedList staged = new LinkedList();
        staged.addLast(note);
        ArrayList labels = new ArrayList();
        labels.add("abc");
        Iterator walk = staged.iterator();
        PrintWriter writer = response.getWriter();
        while (walk.hasNext()) {
            String chunk = (String) walk.next();
            writer.println(chunk);
        }
        walk = labels.iterator();
        while (walk.hasNext()) {
            String tag = (String) walk.next();
            writer.println(tag);
        }
    }
}
`;

describe('#476 slice: iterator variable rebound after tainted walk', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss from the first loop after walk is rebound for a literal list', async () => {
    const r = await analyze(ITER_REUSE, 'ThemeCopyServlet.java', 'java');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 22)).toBe(true);
    expect(xss.some(f => f.sink_line === 27)).toBe(false);
  });

});
