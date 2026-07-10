/**
 * cognium-dev 3.163.0 — http_path -> xss reach-map coverage.
 *
 * Prior to 3.163.0 the `canSourceReachSink` matrix omitted `xss` from
 * the `http_path` allow-list, so URL path components (getRequestURI,
 * getRequestURL, getPathInfo, getServletPath) reflected back into HTML
 * output silently dropped their inline-colocation flow. SecuriBench
 * Micro Basic35 exercises exactly this shape and is annotated BAD
 * for `writer.println(req.getRequestURL())`.
 *
 * These pinning tests freeze the fix:
 *   - Positive: each of the 4 http_path accessors called inside a
 *     `writer.println(...)` sink must emit an xss finding.
 *   - Negative: sanitized wrapper (`ESAPI.encoder().encodeForHTML(...)`)
 *     must NOT emit — protects against blanket over-reach.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countXss = (r: any) =>
  (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xss').length;

describe('cognium-dev 3.163.0 — http_path → xss reach-map coverage', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  for (const accessor of [
    'getRequestURL',
    'getRequestURI',
    'getPathInfo',
    'getServletPath',
  ]) {
    it(`emits xss for writer.println(req.${accessor}()) [http_path → xss]`, async () => {
      const code = [
        'import javax.servlet.http.HttpServletRequest;',
        'import javax.servlet.http.HttpServletResponse;',
        'import java.io.PrintWriter;',
        'public class HttpPathXss {',
        '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
        '        PrintWriter writer = resp.getWriter();',
        `        writer.println(req.${accessor}());`,
        '    }',
        '}',
        '',
      ].join('\n');
      const r = await analyze(code, `HttpPathXss_${accessor}.java`, 'java');
      expect(countXss(r)).toBeGreaterThanOrEqual(1);
    });
  }

  it('SecuriBench Micro Basic35 full coverage — 6 xss findings', async () => {
    // Verbatim shape from securibench-micro/basic/Basic35.java.
    const code = [
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import java.io.PrintWriter;',
      'import java.util.Enumeration;',
      'public class Basic35 {',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '        Enumeration e = req.getHeaderNames();',
      '        while(e.hasMoreElements()) {',
      '            PrintWriter writer = resp.getWriter();',
      '            writer.println(req.getProtocol());',
      '            writer.println(req.getScheme());',
      '            writer.println(req.getAuthType());',
      '            writer.println(req.getQueryString());',
      '            writer.println(req.getRemoteUser());',
      '            writer.println(req.getRequestURL());',
      '        }',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'Basic35.java', 'java');
    expect(countXss(r)).toBeGreaterThanOrEqual(6);
  });

  it('sanitized http_path via ESAPI encodeForHTML must NOT emit xss', async () => {
    const code = [
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import java.io.PrintWriter;',
      'import org.owasp.esapi.ESAPI;',
      'public class HttpPathXssSanitized {',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '        PrintWriter writer = resp.getWriter();',
      '        String safe = ESAPI.encoder().encodeForHTML(req.getRequestURL().toString());',
      '        writer.println(safe);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'HttpPathXssSanitized.java', 'java');
    expect(countXss(r)).toBe(0);
  });
});
