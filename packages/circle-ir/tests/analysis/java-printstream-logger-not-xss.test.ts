/**
 * A Java print to a `PrintStream` or a logger is not XSS.
 *
 * The classless Java `println` / `print` xss entries exist to catch a servlet
 * writer whose receiver type was not resolved. When the receiver IS resolved,
 * and it is a `java.io.PrintStream` (stdout, stderr, a file) or a logger, the
 * write reaches a console, a file or a log, never an HTML document. #387
 * dropped the literal `System.out.println(x)` shape; a CLI tool more often
 * prints through a variable: a `PrintStream ps` parameter, a `PrintStream`
 * field in a small file logger, or the project's own `Logger out`.
 *
 * A `PrintStream` built on the servlet response's output stream does reach
 * the page, so a file that calls `getOutputStream()` keeps its sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const xssAt = (r: Awaited<ReturnType<typeof analyze>>) =>
  r.taint.sinks.filter(s => s.type === 'xss').map(s => s.line);

const servlet = (body: string[], extra: string[] = []) => [
  'import javax.servlet.http.*;',
  'import java.io.*;',
  'public class T extends HttpServlet {',
  ...extra,
  '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
  '    String p = req.getParameter("p");',
  ...body,
  '  }',
  '}',
].join('\n');

describe('Java PrintStream and logger receivers are not xss sinks', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops a print to a PrintStream parameter', async () => {
    const code = servlet(
      ['    report(new PrintStream(new FileOutputStream("r.csv")), p);'],
      [
        '  private void report(PrintStream ps, String v) {',
        '    ps.print(v);',
        '    ps.println(", " + v);',
        '    ps.printf("%s%n", v);',
        '  }',
      ],
    );
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toEqual([]);
    expect(r.taint.flows.filter(f => f.sink_type === 'xss')).toHaveLength(0);
  });

  it('drops a print to a PrintStream field (a small file logger)', async () => {
    const code = [
      'import java.io.*;',
      'public class FileLog {',
      '  private PrintStream out;',
      '  public FileLog(File f) throws IOException { out = new PrintStream(new FileOutputStream(f)); }',
      '  public void print(String message) { out.print(message); }',
      '  public void println(String message) { out.println(message); }',
      '  public void printf(String format, Object... args) { out.printf(format, args); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'FileLog.java', 'java');
    expect(xssAt(r)).toEqual([]);
  });

  it("drops a print to the project's own Logger type", async () => {
    const code = servlet(
      ['    out.println(p);', '    out.printf("%s%n", p);'],
      ['  interface Logger { void println(String s); void printf(String f, Object... a); }', '  private Logger out;'],
    );
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toEqual([]);
  });

  it('still reports a PrintWriter from getWriter()', async () => {
    const code = servlet(['    PrintWriter w = resp.getWriter();', '    w.println(p);']);
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toContain(7);
  });

  it("still reports a PrintStream built on the response's output stream", async () => {
    const code = servlet(['    PrintStream ps = new PrintStream(resp.getOutputStream());', '    ps.println(p);']);
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toContain(7);
    expect(r.taint.flows.some(f => f.sink_type === 'xss' && f.sink_line === 7)).toBe(true);
  });
});
