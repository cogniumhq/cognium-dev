/**
 * cognium-dev#476 (slice) — `System.arraycopy` from a tainted source array
 * propagates taint to the destination array for element reads.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const NOTE_COPY = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NoteCopyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        String[] staged = new String[1];
        staged[0] = note;
        String[] shipped = new String[1];
        System.arraycopy(staged, 0, shipped, 0, 1);
        response.getWriter().println(shipped[0]);
    }
}
`;

const NOTE_COPY_FIXED = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NoteCopyFixedServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        String[] staged = new String[1];
        staged[0] = "fixed";
        String[] shipped = new String[1];
        System.arraycopy(staged, 0, shipped, 0, 1);
        response.getWriter().println(shipped[0]);
    }
}
`;

describe('#476 slice: System.arraycopy element taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('NoteCopyServlet: xss flow from getParameter through arraycopy to println', async () => {
    const r = await analyze(NOTE_COPY, 'NoteCopyServlet.java', 'java');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 14)).toBe(true);
  });

  it('NoteCopyFixedServlet: literal in staged array stays clean at sink', async () => {
    const r = await analyze(NOTE_COPY_FIXED, 'NoteCopyFixedServlet.java', 'java');
    expect(flows(r, 'xss')).toEqual([]);
  });

  it('IndexSpanServlet: array element at (span-span) index after element store (#476 / Arrays4)', async () => {
    const code = `import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IndexSpanServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String itemLabel = request.getParameter("name");
        int span = 15432532;
        String[] slots = new String[10];
        slots[0] = itemLabel;
        PrintWriter writer = response.getWriter();
        writer.println(slots[span - span]);
    }
}`;
    const r = await analyze(code, 'IndexSpanServlet.java', 'java');
    expect(flows(r, 'xss').length).toBeGreaterThan(0);
  });
});
