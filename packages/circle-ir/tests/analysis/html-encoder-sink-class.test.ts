/**
 * An HTML-context encoder sanitizes the XSS class only.
 *
 * `param = ESAPI.encoder().encodeForHTML(param)` before a concatenated SQL
 * statement cleared the SQL injection flow: #589 kept the encoder's taint
 * alive for `trust_boundary` alone, and const-prop's "not tainted" verdict on
 * the derived `sql` vetoed the flow. Every encoder in
 * HTML_CONTEXT_ENCODER_METHODS now leaves every sink type but `xss` (and its
 * row's `external_taint_escape` credit) uncovered. Encoders of other families
 * (`encodeForSQL`, PreparedStatement binding) keep their credit.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import {
  HTML_CONTEXT_ENCODER_METHODS,
  HTML_CONTEXT_ENCODER_UNCOVERED_SINKS,
} from '../../src/analysis/constant-propagation/patterns.js';
import { SINK_TYPES } from '../../src/types/index.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const flowTypes = (r: IR) => (r.taint.flows ?? []).map(f => f.sink_type);

const HEAD = `package org.example;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
`;

/** Encode, then SQL concat. */
const sqlAfter = (encode: string) => `${HEAD}
public class Ins extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String param = request.getParameter("name");
        ${encode}
        String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:t");
            Statement statement = conn.createStatement();
            int count = statement.executeUpdate(sql);
        } catch (java.sql.SQLException e) {
            throw new ServletException(e);
        }
    }
}
`;

/** The same encoder written to the HTML response. */
const htmlAfter = (encode: string) => `${HEAD}
public class Show extends HttpServlet {
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String param = request.getParameter("name");
        ${encode}
        response.getWriter().println("<p>" + param + "</p>");
    }
}
`;

/** The same encoder before a shell command. */
const cmdAfter = (encode: string) => `${HEAD}
public class Ping extends HttpServlet {
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String param = request.getParameter("host");
        ${encode}
        String cmd = "ping -c 1 " + param;
        Runtime.getRuntime().exec(cmd);
    }
}
`;

const HTML_ENCODERS: Array<[string, string]> = [
  ['ESAPI encodeForHTML', 'param = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);'],
  ['ESAPI encodeForHTMLAttribute', 'param = org.owasp.esapi.ESAPI.encoder().encodeForHTMLAttribute(param);'],
  ['ESAPI encodeForJavaScript', 'param = org.owasp.esapi.ESAPI.encoder().encodeForJavaScript(param);'],
  ['ESAPI encodeForXML', 'param = org.owasp.esapi.ESAPI.encoder().encodeForXML(param);'],
  ['Commons escapeHtml', 'param = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);'],
  ['Spring htmlEscape', 'param = org.springframework.web.util.HtmlUtils.htmlEscape(param);'],
];

describe('an HTML-context encoder does not clear SQL injection', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the uncovered set is every sink type but xss and external_taint_escape', () => {
    for (const t of SINK_TYPES) {
      const covered = t === 'xss' || t === 'external_taint_escape';
      expect(HTML_CONTEXT_ENCODER_UNCOVERED_SINKS.has(t), t).toBe(!covered);
    }
    expect(HTML_CONTEXT_ENCODER_UNCOVERED_SINKS.has('trust_boundary')).toBe(true);
    expect(HTML_CONTEXT_ENCODER_METHODS.has('encodeForHTML')).toBe(true);
  });

  it('control: no encoder reports sql_injection', async () => {
    const r = await analyze(sqlAfter(''), 'Ins.java', 'java');
    expect(flowTypes(r)).toContain('sql_injection');
  });

  for (const [name, encode] of HTML_ENCODERS) {
    it(`${name} then SQL concat: sql_injection is still reported`, async () => {
      const r = await analyze(sqlAfter(encode), 'Ins.java', 'java');
      expect(flowTypes(r)).toContain('sql_injection');
    });

    it(`${name} then HTML output: xss stays cleared`, async () => {
      const r = await analyze(htmlAfter(encode), 'Show.java', 'java');
      expect(flowTypes(r)).not.toContain('xss');
    });
  }

  it('control: unencoded HTML output reports xss', async () => {
    const r = await analyze(htmlAfter(''), 'Show.java', 'java');
    expect(flowTypes(r)).toContain('xss');
  });

  it('ESAPI encodeForHTML then a shell command: command_injection is still reported', async () => {
    const r = await analyze(cmdAfter('param = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);'), 'Ping.java', 'java');
    expect(flowTypes(r)).toContain('command_injection');
  });

  it('C8 control: PreparedStatement with setString stays clean', async () => {
    const r = await analyze(`${HEAD}
public class Ins extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String param = request.getParameter("name");
        String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:t");
            java.sql.PreparedStatement statement = conn.prepareStatement(sql);
            statement.setString(1, param);
            int count = statement.executeUpdate();
        } catch (java.sql.SQLException e) {
            throw new ServletException(e);
        }
    }
}
`, 'Ins.java', 'java');
    expect(flowTypes(r)).not.toContain('sql_injection');
  });

  it('ESAPI encodeForSQL (not an HTML encoder) keeps its sql_injection credit', async () => {
    const r = await analyze(
      sqlAfter('param = org.owasp.esapi.ESAPI.encoder().encodeForSQL(new org.owasp.esapi.codecs.OracleCodec(), param);'),
      'Ins.java', 'java');
    expect(flowTypes(r)).not.toContain('sql_injection');
  });
});
