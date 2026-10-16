/**
 * cognium-dev#476 (slice) — 2-D array element store/read propagates taint to sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const GRID_NOTE = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GridNoteServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        String[][] grid = new String[1][1];
        grid[0][0] = note;
        response.getWriter().println(grid[0][0]);
    }
}
`;

const GRID_NOTE_FIXED = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GridNoteFixedServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        String[][] grid = new String[1][1];
        grid[0][0] = "fixed";
        response.getWriter().println(grid[0][0]);
    }
}
`;

describe('#476 slice: 2-D array element taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('GridNoteServlet: xss flow from getParameter through grid[0][0] to println', async () => {
    const r = await analyze(GRID_NOTE, 'GridNoteServlet.java', 'java');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 12)).toBe(true);
  });

  it('GridNoteFixedServlet: literal cell stays clean at sink', async () => {
    const r = await analyze(GRID_NOTE_FIXED, 'GridNoteFixedServlet.java', 'java');
    expect(flows(r, 'xss')).toEqual([]);
  });
});
