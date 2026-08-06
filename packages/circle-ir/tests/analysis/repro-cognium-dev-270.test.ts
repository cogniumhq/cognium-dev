/**
 * cognium-dev#270 — `HttpServletRequest`/`HttpSession.getAttribute()` was an
 * over-broad XSS sink.
 *
 * `getAttribute` is a *read* — its return value is tainted (a SOURCE, already
 * registered as `io_input`), never an HTML-output context. It had been
 * registered as an `xss` sink with `arg_positions: []`, producing a degenerate
 * source==sink self-flow that flagged CWE-79 on route-helper reads and even on
 * `.equals(getSession().getAttribute(...))` comparisons. Removed (same
 * over-broad-sink family as #268 `StringBuilder.append`). The real sink is
 * wherever the read value is later written to a response, which the `io_input`
 * source reaches on its own.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../src/index.js';

describe('cognium-dev#270 — getAttribute is not an XSS sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('request.getAttribute() produces NO xss sink (but stays an io_input source)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class C {',
      '  String getPath(HttpServletRequest request) {',
      '    return (String) request.getAttribute("x");',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    expect(r.taint.sinks.some((s) => s.method === 'getAttribute' && s.type === 'xss')).toBe(false);
    expect(r.taint.sources.some((s) => s.type === 'io_input')).toBe(true);
  });

  it('getSession().getAttribute(x) in a comparison does not fire xss (the OWASP self-flow shape)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class C {',
      '  boolean f(HttpServletRequest request, String cookieName, String v) {',
      '    return v.equals(request.getSession().getAttribute(cookieName));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    const xss = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java').filter((x) => x.type === 'xss');
    expect(xss).toHaveLength(0);
  });

  it('a genuine reflected-XSS write still fires (recall preserved)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class C {',
      '  void h(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '    String s = req.getParameter("q");',
      '    res.getWriter().print(s);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    const xss = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java').filter((x) => x.type === 'xss');
    expect(xss.length).toBeGreaterThan(0);
  });
});
