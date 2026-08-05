/**
 * cognium-ai#268 — `StringBuilder.append` was an over-broad XSS sink.
 *
 * `StringBuilder`/`StringBuffer.append` were registered as `xss` (CWE-79)
 * sinks, so `generateFindings` reported CWE-79 on every append — in-memory
 * string construction, not an HTML-output context, and it fired even on a
 * constant argument. It was the #1 crit/high FP bucket on the top-100 Java
 * sweep. The sinks were removed globally; the real sink is wherever the built
 * string is later written to a response (PrintWriter, ServletOutputStream,
 * JspWriter, …), which taint propagation still reaches via `sb.toString()`.
 *
 * Measured 0 OWASP xss true-positive loss (every xss TP has a real HTML-output
 * sink).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../src/index.js';

describe('cognium-ai#268 — StringBuilder.append is not an XSS sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const xssFindings = async (code: string, file: string) => {
    const r = await analyze(code, file, 'java');
    return generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file).filter((x) => x.type === 'xss');
  };

  it('does NOT flag StringBuilder.append (tainted or constant) as xss (the issue repro)', async () => {
    const code = [
      'public class C {',
      '  String f(String s){',
      '    StringBuilder sb = new StringBuilder();',
      '    sb.append(s);',
      '    sb.append(System.lineSeparator());',
      '    return sb.toString();',
      '  }',
      '}',
    ].join('\n');
    expect(await xssFindings(code, 'C.java')).toHaveLength(0);
  });

  it('does NOT flag StringBuffer.append as xss', async () => {
    const code = [
      'public class C {',
      '  String f(String s){',
      '    StringBuffer sb = new StringBuffer();',
      '    sb.append(s);',
      '    return sb.toString();',
      '  }',
      '}',
    ].join('\n');
    expect(await xssFindings(code, 'C.java')).toHaveLength(0);
  });

  it('DOES flag a genuine HTML-output sink reached by tainted input (positive control)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class S {',
      '  void h(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '    String s = req.getParameter("q");',
      '    res.getWriter().print(s);',
      '  }',
      '}',
    ].join('\n');
    expect((await xssFindings(code, 'S.java')).length).toBeGreaterThan(0);
  });

  it('DOES flag a StringBuilder built from tainted input then written to a response (propagation preserved)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class W {',
      '  void h(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '    String s = req.getParameter("q");',
      '    StringBuilder sb = new StringBuilder();',
      '    sb.append("<b>").append(s);',
      '    res.getWriter().print(sb.toString());',
      '  }',
      '}',
    ].join('\n');
    expect((await xssFindings(code, 'W.java')).length).toBeGreaterThan(0);
  });
});
