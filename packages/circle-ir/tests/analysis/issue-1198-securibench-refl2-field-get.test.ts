/**
 * cognium-dev #1198 — SecuriBench Refl2 shape: HTTP → instance field → Field.get → XSS sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const REFL2_SHAPE = `
package demo.refl;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Refl2Case {
    private static final String FIELD_NAME = "name";
    public String name;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        name = req.getParameter(FIELD_NAME);
        try {
            f(resp);
        } catch (Exception e) {
            System.err.println("An error occurred");
        }
    }

    private void f(ServletResponse resp) throws IOException, SecurityException, NoSuchFieldException,
        ClassNotFoundException, IllegalArgumentException, IllegalAccessException {
        PrintWriter writer = resp.getWriter();
        Field field = Class.forName("demo.refl.Refl2Case").getField("name");
        String myName = (String) field.get(this);
        writer.println(myName); /* BAD */
    }
}
`;

describe('#1198 SecuriBench Refl2 Field.get read', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss from field read via reflection', async () => {
    const r = await analyze(REFL2_SHAPE, 'Refl2Case.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss');
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.sink_line === 29)).toBe(true);
  });
});
