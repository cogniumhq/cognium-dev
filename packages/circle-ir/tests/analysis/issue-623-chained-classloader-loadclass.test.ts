/**
 * cognium-dev#623 (minimal slice) — `loadClass(tainted)` on a chained JDK
 * ClassLoader accessor receiver was not matched to the ClassLoader sink.
 *
 * SAST regression fixture — the handler is deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const code = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReflectiveFactory extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String impl = request.getParameter("handler");
        try {
            Class<?> a = Thread.currentThread().getContextClassLoader().loadClass(impl);
            Class<?> b = getClass().getClassLoader().loadClass(impl);
            ClassLoader loader = getClass().getClassLoader();
            Class<?> c = loader.loadClass(impl);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            Class<?> d = Thread.currentThread().getContextClassLoader().loadClass("com.example.DefaultHandler");
            Object e = Class.forName("mx.tools.NamingService").newInstance();
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }
}
`;

describe('cognium-dev#623 — chained ClassLoader.loadClass', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('code_injection at 11, 12 and 14; nothing at 23 or 24', async () => {
    const r = await analyze(code, 'ReflectiveFactory.java', 'java');
    const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
    expect(lines).toEqual([11, 12, 14]);
    const any = (r.taint.flows ?? []).filter((f) => f.sink_line === 23 || f.sink_line === 24);
    expect(any).toHaveLength(0);
  });
});
