/**
 * cognium-dev#387 — `System.out` / `System.err` prints reported as CWE-79.
 *
 * The canonical Java xss sink set is class-scoped — `PrintWriter.println`,
 * `ServletOutputStream.println`, `WikiPrinter.println` — plus a CLASSLESS
 * `println` entry so an unresolved writer receiver is still caught. That
 * fallback also matched `System.out.println(x)` and `System.err.println(x)`,
 * so every console print of a tainted value was reported as XSS.
 *
 * Stdout and stderr are not a browser context: no HTML document, no script
 * execution, no HTTP response. There is no reading under which this is XSS.
 *
 * WHY IT MATTERS OUT OF PROPORTION TO ITS SUBTLETY: every Java class prints.
 * On the 500-repo vuln-localization benchmark, Java recall is fine (79% of
 * repos land a genuinely vulnerable file) but the engine emits ~306
 * security-typed findings per repo against ~8 real vulnerable files, so the
 * true file drowns and hit@3 collapses to 16%. This is one contributor to that
 * volume: 243 signatures across 135 files on OWASP Benchmark Java alone.
 *
 * WHY OUR FLAGSHIP JAVA BENCHMARK NEVER SHOWED IT: OWASP's scorer is
 * category-scoped — each test file declares one category and findings of other
 * types on it are never counted. All 243 of these are on `pathtraver` files and
 * none on an `xss` file, so the benchmark counts zero of them and "100% TPR,
 * 0% FPR" was never in tension with the real-repo flood. Scoring the fix
 * required making the differential gate type-aware first (#386).
 *
 * DROP, NOT RETYPE. CWE-117 (improper output neutralisation for logs) would be
 * a defensible label, since container stdout is routinely shipped to a log
 * aggregator. But Java `log_injection` is deliberately `Logger`-scoped, and
 * extending it to `System.out` is a separate ADDITIVE decision: console prints
 * are ubiquitous, so it would trade an xss flood for a log_injection flood of
 * the same cardinality and buy no localization improvement. Retyping was also
 * tried at the registry level and matched unpredictably — `System.err` missed
 * the new entry entirely while `PrintWriter.println` gained a spurious
 * `log_injection` beside its correct xss. Left to its own issue.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const xssAt = (r: Awaited<ReturnType<typeof analyze>>) =>
  r.taint.sinks.filter(s => s.type === 'xss').map(s => s.line);

describe('#387 — System.out/err prints are not xss sinks', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report System.out/System.err prints as xss', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class T extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    String p = req.getParameter("p");',
      '    System.out.println("got: " + p);',
      '    System.err.println("err: " + p);',
      '    System.out.print(p);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toEqual([]);
    expect(r.taint.flows.filter(f => f.sink_type === 'xss')).toHaveLength(0);
  });

  it('still reports a resolved PrintWriter receiver', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class T extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    String p = req.getParameter("p");',
      '    PrintWriter out = resp.getWriter();',
      '    out.println(p);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toContain(7);
  });

  it('still reports a CHAINED getWriter().println — the unresolved receiver the classless entry exists for', async () => {
    // This is the regression that would make the fix unacceptable: the drop is
    // scoped to sinks with no resolved class, which is the same set the
    // classless entry serves. If a chained writer call lands there too, it must
    // survive on the strength of the line-text check alone.
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class T extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    String p = req.getParameter("p");',
      '    resp.getWriter().println("hello " + p);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toContain(6);
  });

  it('keeps a System.out print of a CONSTANT clean, and does not disturb other types', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class T extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    String p = req.getParameter("p");',
      '    System.out.println("a constant");',
      '    Runtime.getRuntime().exec(p);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'T.java', 'java');
    expect(xssAt(r)).toEqual([]);
    // The command_injection sink on the next line is untouched.
    expect(r.taint.sinks.some(s => s.type === 'command_injection' && s.line === 7)).toBe(true);
  });
});
