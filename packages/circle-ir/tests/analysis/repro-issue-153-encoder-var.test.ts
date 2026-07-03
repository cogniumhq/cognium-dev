/**
 * Regression lock for cognium-dev#153 — Java response-writer xss FP when a
 * recognized HTML/attribute encoder wraps the value on the *previous* line
 * (assignment to a local var) rather than inline in the write() argument.
 *
 * `findJavaResponseWriterXssFindings` in language-sources-pass.ts is a
 * text-pattern sink detector. Before 3.148.0 it only skipped when
 * `safeWrapRe.test(args)` matched a wrapper INSIDE the write() args
 * string, so
 *     String url = StringEscapeUtils.escapeHtml4(req.getParameter("url"));
 *     resp.getWriter().write("<a href=\"" + url + "\">click</a>");
 * emitted a high-severity xss FP even though `url` was already encoded.
 *
 * Fix: same-file `sanitizedVars` tracker. If every non-literal identifier
 * in the args set is in the sanitizedVars set, skip.
 *
 * Recall guard: the same shape without the sanitizer wrap MUST still fire.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { SastFinding } from '../../src/types/index.js';

const xssHigh = (findings: SastFinding[]): SastFinding[] =>
  findings.filter((f) => f.rule_id === 'xss' && f.severity === 'high');

describe('Issue #153 — same-file encoder-var suppresses response-writer xss FP', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppressed: StringEscapeUtils.escapeHtml4 on prev line → no xss', async () => {
    const code = `
package com.demo.flow.tier1.html_attribute;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;

public class V01BaselineSafe {
    public void link(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = StringEscapeUtils.escapeHtml4(req.getParameter("url"));
        resp.getWriter().write("<a href=\\"" + url + "\\">click</a>");
    }
}
`;
    const res = await analyze(code, 'V01BaselineSafe.java', 'java');
    expect(xssHigh(res.findings)).toEqual([]);
  });

  it('FP suppressed: OWASP Encode.forHtml on prev line → no xss', async () => {
    const code = `
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
public class E {
  public void h(HttpServletResponse resp, String raw) throws Exception {
    String safe = Encode.forHtml(raw);
    resp.getWriter().println("<div>" + safe + "</div>");
  }
}
`;
    const res = await analyze(code, 'E.java', 'java');
    expect(xssHigh(res.findings)).toEqual([]);
  });

  it('recall: no sanitizer wrap → xss still fires', async () => {
    const code = `
package com.demo.flow.tier1.html_attribute;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class V01BaselineTp {
    public void link(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("url");
        resp.getWriter().write("<a href=\\"" + url + "\\">click</a>");
    }
}
`;
    const res = await analyze(code, 'V01BaselineTp.java', 'java');
    expect(xssHigh(res.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: mixed sanitized + tainted → xss still fires', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
public class Mixed {
  public void link(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String url = StringEscapeUtils.escapeHtml4(req.getParameter("url"));
    String raw = req.getParameter("label");
    resp.getWriter().write("<a href=\\"" + url + "\\">" + raw + "</a>");
  }
}
`;
    const res = await analyze(code, 'Mixed.java', 'java');
    expect(xssHigh(res.findings).length).toBeGreaterThanOrEqual(1);
  });
});
