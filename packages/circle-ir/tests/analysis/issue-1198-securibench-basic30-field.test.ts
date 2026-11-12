/**
 * cognium-dev #1198 — SecuriBench Basic30: field-sensitive heap taint.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const BASIC30_SHAPE = `
package demo.basic;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FieldSensitiveCase {
    class Data {
        String value1;
        String value2;
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Data d = new Data();
        d.value2 = name;
        d.value1 = "abc";

        PrintWriter writer = resp.getWriter();
        writer.println(d.value1); /* OK */
        writer.println(d.value2); /* BAD */
    }
}
`;

describe('#1198 SecuriBench Basic30 field-sensitive heap fields', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss on d.value2 only, not on constant d.value1', async () => {
    const r = await analyze(BASIC30_SHAPE, 'FieldSensitiveCase.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(
      f => f.sink_type === 'xss' && !f.sanitized,
    );
    const lines = new Set(flows.map(f => f.sink_line));
    expect(lines.has(22)).toBe(false);
    expect(lines.has(23)).toBe(true);
  });
});
