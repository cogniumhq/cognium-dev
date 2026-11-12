/**
 * cognium-dev #1198 — SecuriBench Basic29: taint through linked Node fields.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const BASIC29_SHAPE = `
package demo.basic;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LinkedNodeCase {
    class Node {
        String value;
        Node next = null;
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Node head = new Node();
        Node next = new Node();
        head.next = next;
        next.value = name;

        PrintWriter writer = resp.getWriter();
        writer.println(next.value); /* BAD */
        writer.println(head.next.value); /* BAD */
        writer.println(head.value); /* OK */
    }
}
`;

describe('#1198 SecuriBench Basic29 linked Node heap fields', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss on direct and aliased field reads, not on untainted head.value', async () => {
    const r = await analyze(BASIC29_SHAPE, 'LinkedNodeCase.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(
      f => f.sink_type === 'xss' && !f.sanitized,
    );
    const lines = new Set(flows.map(f => f.sink_line));
    expect(lines.has(23)).toBe(true);
    expect(lines.has(24)).toBe(true);
    expect(lines.has(25)).toBe(false);
  });
});
