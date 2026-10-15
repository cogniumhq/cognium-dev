/**
 * cognium-dev#673 — Java log_injection through a private helper applied at the
 * log call. A helper that does not remove CR/LF (an HTML-ish `<` replacement
 * named `escapeHtml`, or a `sanitize` that returns its input) must not clear
 * CWE-117; a helper that strips both CR and LF must.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const code = `package org.example.audit;

import javax.servlet.http.HttpServletRequest;

public class LoginAudit {

    private static String escapeHtml(String s) { return s.replace("<", "&lt;"); }
    private static String sanitize(String s) { return s; }
    private static String oneLine(String s) { return s.replace("\\r", " ").replace("\\n", " "); }
    private static String lfOnly(String s) { return s.replace("\\n", " "); }

    public void wrongContext(HttpServletRequest req) {
        java.util.logging.Logger.getLogger("audit").info("who " + escapeHtml(req.getParameter("login")));
    }

    public void identity(HttpServletRequest req) {
        java.util.logging.Logger.getLogger("audit").info("who " + sanitize(req.getParameter("login")));
    }

    public void stripped(HttpServletRequest req) {
        java.util.logging.Logger.getLogger("audit").info("who " + oneLine(req.getParameter("login")));
    }

    public void halfStripped(HttpServletRequest req) {
        java.util.logging.Logger.getLogger("audit").info("who " + lfOnly(req.getParameter("login")));
    }
}
`;

const lineOf = (text: string) => code.split('\n').findIndex(l => l.includes(text)) + 1;

describe('#673 Java log_injection through helpers at the log call', () => {
  let sinkLines: number[] = [];
  beforeAll(async () => {
    await initAnalyzer();
    const r = await analyze(code, 'LoginAudit.java', 'java');
    sinkLines = (r.taint.flows ?? []).filter(f => f.sink_type === 'log_injection' && !f.sanitized).map(f => f.sink_line);
  });

  it('fires when the helper is an HTML-context escape (wrong context)', () => {
    expect(sinkLines).toContain(lineOf('escapeHtml(req'));
  });

  it('fires when the helper returns its input unchanged', () => {
    expect(sinkLines).toContain(lineOf('sanitize(req'));
  });

  it('fires when the helper strips LF only', () => {
    expect(sinkLines).toContain(lineOf('lfOnly(req'));
  });

  it('stays clean when the helper strips both CR and LF', () => {
    expect(sinkLines).not.toContain(lineOf('oneLine(req'));
  });
});
