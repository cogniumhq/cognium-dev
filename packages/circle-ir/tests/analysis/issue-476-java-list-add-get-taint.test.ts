/**
 * cognium-dev#476 (slice) — `ArrayList.add(tainted)` then `get(0)` reaches sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const TAG_LIST = `import java.io.IOException;
import java.util.ArrayList;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TagListServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        ArrayList<String> staged = new ArrayList<>();
        staged.add(note);
        String out = staged.get(0);
        response.getWriter().println(out);
    }
}
`;

const TAG_LIST_FIXED = `import java.io.IOException;
import java.util.ArrayList;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TagListFixedServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        ArrayList<String> staged = new ArrayList<>();
        staged.add("fixed");
        String out = staged.get(0);
        response.getWriter().println(out);
    }
}
`;

describe('#476 slice: ArrayList add/get element taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TagListServlet: xss flow from getParameter through list add/get to println', async () => {
    const r = await analyze(TAG_LIST, 'TagListServlet.java', 'java');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 14)).toBe(true);
  });

  it('TagListFixedServlet: literal add stays clean at sink', async () => {
    const r = await analyze(TAG_LIST_FIXED, 'TagListFixedServlet.java', 'java');
    expect(flows(r, 'xss')).toHaveLength(0);
  });
});
