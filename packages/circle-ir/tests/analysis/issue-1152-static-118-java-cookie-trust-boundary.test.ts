/**
 * cognium-dev #1152 — gates static #118 java: insecure cookie shape must not
 * report spurious trust_boundary (only crlf + insecure-cookie).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const tbFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint?.flows ?? []).filter((f) => f.sink_type === 'trust_boundary' && !f.sanitized);

/** Mirrors sast-validation static #118 (`InsecureCookieTp.java`). */
const static118JavaShape = `
package com.demo.fpcorpus;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
public class InsecureCookieTp {
  public void set(HttpServletResponse resp, String sid) {
    Cookie c = new Cookie("SESSIONID", sid);
    c.setSecure(false);
    c.setHttpOnly(false);
    resp.addCookie(c);
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
