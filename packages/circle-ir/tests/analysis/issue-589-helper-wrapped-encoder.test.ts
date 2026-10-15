/**
 * cognium-dev#589 (slice): a same-file helper whose every return is a direct
 * call to a context-specific HTML encoder is recorded as uncovered for
 * `trust_boundary` exactly like the direct call, so
 * `shown = encodeForPage(nick); session.setAttribute("k", shown)` keeps its
 * `trust_boundary` flow, while the encoder still covers `xss` through the helper.
 * A helper with any other return, a mix of returns, or another sanitizer keeps
 * its by-name credit.
 *
 * SAST regression fixtures — the servlets are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const flowTypes = (r: IR, sinkLine: number) =>
  [...new Set((r.taint.flows ?? []).filter((f) => f.sink_line === sinkLine).map((f) => f.sink_type))].sort();
const sinkTypes = (r: IR, line: number) => [...new Set((r.taint.sinks ?? []).filter((s) => s.line === line).map((s) => s.type))].sort();

const HEAD = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;
`;

const servlet = (cls: string, body: string, helper: string) => `${HEAD}public class ${cls} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
${body}
    }
${helper}
}
`;

const ENCODER_HELPER = `    private String encodeForPage(String value) {
        return StringEscapeUtils.escapeHtml(value);
    }`;

describe('cognium-dev#589 helper-wrapped HTML encoder', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('DisplayNameServlet: setAttribute(shown) keeps trust_boundary through an encoder-only helper', async () => {
    const code = servlet('DisplayNameServlet', `        String nick = request.getParameter("nickname");
        String shown = encodeForPage(nick);
        request.getSession().setAttribute("displayName", shown);`, ENCODER_HELPER);
    const r = await analyze(code, 'DisplayNameServlet.java', 'java');
    // line 11 is the setAttribute
    expect(flowTypes(r, 11)).toEqual(['trust_boundary']);
  });

  it('DisplayNameShowServlet: the same helper written to HTML stays clean of xss', async () => {
    const code = servlet('DisplayNameShowServlet', `        String nick = request.getParameter("nickname");
        String shown = encodeForPage(nick);
        response.getWriter().print("<p>" + shown + "</p>");`, ENCODER_HELPER);
    const r = await analyze(code, 'DisplayNameShowServlet.java', 'java');
    expect(flowTypes(r, 11)).not.toContain('xss');
  });

  it('a helper that escapes HTML on one path and returns the raw value on another is not encoder-only', async () => {
    // Mixed returns keep today's behaviour (no extra trust_boundary credit change); the raw path is tainted anyway.
    const code = servlet('MixedServlet', `        String nick = request.getParameter("nickname");
        String shown = encodeForPage(nick);
        request.getSession().setAttribute("displayName", shown);`, `    private String encodeForPage(String value) {
        if (value.length() > 3) {
            return value;
        }
        return StringEscapeUtils.escapeHtml(value);
    }`);
    const r = await analyze(code, 'MixedServlet.java', 'java');
    expect(sinkTypes(r, 11)).toContain('trust_boundary');
    expect(flowTypes(r, 11)).toContain('trust_boundary');
  });

  it('a helper whose return is another sanitizer family keeps its all-sink credit', async () => {
    const code = servlet('NumericServlet', `        String nick = request.getParameter("nickname");
        String shown = digitsOnly(nick);
        request.getSession().setAttribute("displayName", shown);`, `    private String digitsOnly(String value) {
        return Integer.toString(Integer.parseInt(value));
    }`);
    const r = await analyze(code, 'NumericServlet.java', 'java');
    expect(flowTypes(r, 11)).toEqual([]);
  });

  it('two overloads, one encoder-only and one returning a different sanitizer, keep the all-sink credit', async () => {
    const code = servlet('OverloadServlet', `        String nick = request.getParameter("nickname");
        String shown = encodeForPage(nick, 1);
        request.getSession().setAttribute("displayName", shown);`, `    private String encodeForPage(String value) {
        return StringEscapeUtils.escapeHtml(value);
    }
    private String encodeForPage(String value, int n) {
        return Integer.toString(Integer.parseInt(value));
    }`);
    const r = await analyze(code, 'OverloadServlet.java', 'java');
    expect(flowTypes(r, 11)).toEqual([]);
  });

  it('a helper-wrapped encoder result overwritten by a constant is clean', async () => {
    const code = servlet('OverwriteServlet', `        String nick = request.getParameter("nickname");
        String shown = encodeForPage(nick);
        shown = "fixed";
        request.getSession().setAttribute("displayName", shown);`, ENCODER_HELPER);
    const r = await analyze(code, 'OverwriteServlet.java', 'java');
    expect(flowTypes(r, 12)).toEqual([]);
  });

  it('a raw operand joined to the helper result still reports', async () => {
    const code = servlet('JoinServlet', `        String nick = request.getParameter("nickname");
        String other = request.getParameter("other");
        String shown = encodeForPage(nick) + other;
        request.getSession().setAttribute("displayName", shown);`, ENCODER_HELPER);
    const r = await analyze(code, 'JoinServlet.java', 'java');
    expect(flowTypes(r, 12)).toContain('trust_boundary');
  });

  it('a two-parameter helper that encodes a different value keeps its by-name credit', async () => {
    const code = servlet('TwoParamServlet', `        String nick = request.getParameter("nickname");
        String shown = encodeForPage(nick, "x");
        request.getSession().setAttribute("displayName", shown);`, `    private String encodeForPage(String value, String other) {
        return StringEscapeUtils.escapeHtml(other);
    }`);
    const r = await analyze(code, 'TwoParamServlet.java', 'java');
    expect(flowTypes(r, 11)).toEqual([]);
  });
});
