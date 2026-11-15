/**
 * cognium-dev #1247 — variant `cookie_trusted` (java): HTTP parameter written
 * into a trust cookie must report `trust_boundary` (CWE-501).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const variantCookieTrustedJava = `
package com.demo.variants.trust_boundary;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class V02CookieTrusted {
  public void admin(HttpServletRequest req, HttpServletResponse res) {
    String flag = req.getParameter("admin");
    res.addCookie(new Cookie("is_admin", flag));
  }
}
`;

describe('#1247 Java cookie_trusted trust_boundary (variant)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports trust_boundary when getParameter flows into Cookie value', async () => {
    const ir = await analyze(variantCookieTrustedJava, 'V02CookieTrusted.java', 'java');
    const flows = (ir.taint?.flows ?? []).filter(
      (f) => f.sink_type === 'trust_boundary' && !f.sanitized,
    );
    expect(flows.length).toBeGreaterThanOrEqual(1);
    expect(flows.some((f) => f.source_type === 'http_param')).toBe(true);
  });
});