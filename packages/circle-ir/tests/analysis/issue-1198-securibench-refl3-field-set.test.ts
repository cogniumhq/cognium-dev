/**
 * cognium-dev #1198 — SecuriBench Refl3 shape: Field.set taints reflectively created instance field.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const REFL3_SHAPE = `
package demo.refl;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReflThreeCase {
    private static final String PARAM = "name";
    private String payload;

    public static class DynHolder {
        public String stored;
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        payload = req.getParameter(PARAM);
        PrintWriter writer = resp.getWriter();

        try {
            Class<?> clazz = Class.forName("demo.refl.ReflThreeCase$DynHolder");
            DynHolder holder = (DynHolder) clazz.newInstance();
            Field fld = clazz.getField("stored");
            fld.set(holder, payload);
            writer.println(holder.stored); /* BAD */
        } catch (ReflectiveOperationException e) {
            System.err.println("error");
        }
    }
}
`;

describe('#1198 SecuriBench Refl3 Field.set write', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss from field written via reflection', async () => {
    const r = await analyze(REFL3_SHAPE, 'ReflThreeCase.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss');
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.source_type === 'http_param')).toBe(true);
  });
});
