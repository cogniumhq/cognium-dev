/**
 * cognium-dev#641 — a sanitizer on one operand does not clear the sink.
 * The other operand still flows. Both operands escaped stays clean.
 * C# already did this in 4.13.1; this is the Java and JavaScript stage.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const xssFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

describe('#641 partial sanitizer does not clear the sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('Java: println(escapeHtml4(a) + b) still has an xss flow', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.IOException;',
      'import org.apache.commons.text.StringEscapeUtils;',
      'public class M extends HttpServlet {',
      '  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    String a = req.getParameter("a");',
      '    String b = req.getParameter("b");',
      '    resp.getWriter().println(StringEscapeUtils.escapeHtml4(a) + b);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'M.java', 'java');
    expect(xssFlows(r).length).toBeGreaterThan(0);
  });

  it('Java: println(escapeHtml4(a) + escapeHtml4(b)) stays clean', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.IOException;',
      'import org.apache.commons.text.StringEscapeUtils;',
      'public class M extends HttpServlet {',
      '  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    String a = req.getParameter("a");',
      '    String b = req.getParameter("b");',
      '    resp.getWriter().println(StringEscapeUtils.escapeHtml4(a) + StringEscapeUtils.escapeHtml4(b));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'M.java', 'java');
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('JS: res.send(escapeHtml(a) + b) still has an xss flow', async () => {
    const code = [
      "const express = require('express');",
      "const escapeHtml = require('escape-html');",
      'const app = express();',
      "app.get('/x', (req, res) => {",
      '  const a = req.query.a;',
      '  const b = req.query.b;',
      '  res.send(escapeHtml(a) + b);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'x.js', 'javascript');
    expect(xssFlows(r).length).toBeGreaterThan(0);
  });

  it('JS: res.send(escapeHtml(a) + escapeHtml(b)) stays clean', async () => {
    const code = [
      "const express = require('express');",
      "const escapeHtml = require('escape-html');",
      'const app = express();',
      "app.get('/x', (req, res) => {",
      '  const a = req.query.a;',
      '  const b = req.query.b;',
      '  res.send(escapeHtml(a) + escapeHtml(b));',
      '});',
    ].join('\n');
    const r = await analyze(code, 'x.js', 'javascript');
    expect(xssFlows(r)).toHaveLength(0);
  });
});
