/**
 * cognium-dev #915 — an output encoder inside a same-file private static
 * helper sanitizes the cross-file path that runs through it.
 *
 * OWASP xss-04 shape (BenchmarkTest02394 / 02401): the parameter comes from
 * `SeparateClassRequest.getTheParameter` in another file, goes through
 * `doSomething(request, param)`, which returns `ESAPI.encoder().encodeForHTML(param)`
 * via a local, and the result reaches `getWriter().format(...)`. The project
 * phase's caller-body sink step followed `param → bar` through the call and
 * reported a cross-file xss path, skipping the helper's encoder.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const REQUEST = `package org.example.helpers;

import javax.servlet.http.HttpServletRequest;

public class SeparateClassRequest {
    private HttpServletRequest request;

    public SeparateClassRequest(HttpServletRequest request) {
        this.request = request;
    }

    public String getTheParameter(String p) {
        return request.getParameter(p);
    }
}
`;

const servlet = (helperBody: string, sinkArg = 'bar') => `package org.example.testcode;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Xss extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        org.example.helpers.SeparateClassRequest scr =
                new org.example.helpers.SeparateClassRequest(request);
        String param = scr.getTheParameter("Xss");
        if (param == null) param = "";

        String bar = doSomething(request, param);

        Object[] obj = {"a", "b"};
        response.getWriter().format(java.util.Locale.US, ${sinkArg}, obj);
    }

    private static String doSomething(HttpServletRequest request, String param) throws IOException {
${helperBody}
    }
}
`;

async function xss(helperBody: string, sinkArg?: string) {
  const pa = await analyzeProject([
    { filePath: 'SeparateClassRequest.java', code: REQUEST, language: 'java' },
    { filePath: 'Xss.java', code: servlet(helperBody, sinkArg), language: 'java' },
  ], {});
  const paths = (pa.taint_paths ?? []).filter(p => p.sink.type === 'xss');
  const flows = pa.files.flatMap(f => (f.analysis.taint.flows ?? []).filter(x => x.sink_type === 'xss'));
  return paths.length + flows.length;
}

describe('#915 sanitizer inside a same-file static helper (cross-file path)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('encodeForHTML assigned to a local and returned: clean (BenchmarkTest02394 shape)', async () => {
    expect(await xss(`        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        return bar;`)).toBe(0);
  });

  it('encodeForHTML returned directly: clean', async () => {
    expect(await xss(`        return org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);`)).toBe(0);
  });

  it('helper that returns the raw parameter still fires', async () => {
    expect(await xss(`        String bar = param;
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper with one sanitized and one raw return still fires', async () => {
    expect(await xss(`        if (param.length() > 3) return org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        return param;`)).toBeGreaterThan(0);
  });

  it('encoded value with the raw parameter appended still fires', async () => {
    expect(await xss(`        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param) + param;
        return bar;`)).toBeGreaterThan(0);
  });

  it('a local reassigned after encoding still fires', async () => {
    expect(await xss(`        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        bar = param;
        return bar;`)).toBeGreaterThan(0);
  });

  it('the caller sinking the raw parameter itself still fires', async () => {
    expect(await xss(`        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        return bar;`, 'param')).toBeGreaterThan(0);
  });
});
