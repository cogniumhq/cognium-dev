/**
 * cognium-dev #1152 — gates static #118 java: insecure cookie shape must not
 * report spurious trust_boundary (only crlf + insecure-cookie).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const tbFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint?.flows ?? []).filter((f) => f.sink_type === 'trust_boundary' && !f.sanitized);

const static118JavaShape = `
public class InsecureCookieTp {
  public void doGet(jakarta.servlet.http.HttpServletRequest req,
                    jakarta.servlet.http.HttpServletResponse response) {
    String v = req.getParameter("v");
    jakarta.servlet.http.Cookie userCookie = new jakarta.servlet.http.Cookie("BenchmarkTest", v);
    response.addCookie(userCookie);
  }
}
`;

describe('#1152 static #118 java cookie trust_boundary regression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not report trust_boundary on FQ Cookie + addCookie (static #118)', async () => {
    const ir = await analyze(static118JavaShape, 'InsecureCookieTp.java', 'java');
    expect(tbFlows(ir)).toHaveLength(0);
  });
});
