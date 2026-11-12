/**
 * cognium-dev #1198 — SecuriBench Basic16 shape: taint through setter into getter at sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

/** Renamed fields/methods from securibench.micro.basic.Basic16 (Widget heap structure). */
const BASIC16_SHAPE = `
package demo.basic;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HeapWidgetCase {
    public class Widget {
        String contents;

        public String getContents() {
            return contents;
        }

        public void setContents(String contents) {
            this.contents = contents;
        }
    }

  private static final String FIELD_NAME = "name";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String s = req.getParameter(FIELD_NAME);
        Widget w = new Widget();
        w.setContents(s);

        PrintWriter writer = resp.getWriter();
        writer.println(w.getContents()); /* BAD */
    }
}
`;

describe('#1198 SecuriBench Basic16 widget getter/setter', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss from http_param through field setter to getter sink', async () => {
    const r = await analyze(BASIC16_SHAPE, 'HeapWidgetCase.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss');
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.sink_line === 30)).toBe(true);
  });
});
