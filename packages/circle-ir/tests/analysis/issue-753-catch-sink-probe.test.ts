import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const base = (catchBody: string) => `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class T extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String picked = request.getParameterNames().nextElement();
        String tool = "/usr/bin/tar ";
        String label = "";
        try {
            label = String.format("%s.tar", picked);
        } catch (Exception e) {
${catchBody}
        }
        Runtime.getRuntime().exec(tool + label);
    }
}`;

describe('catch body vs sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('empty catch keeps sinks', async () => {
    const r = await analyze(base(''), 'T.java', 'java');
    console.error('empty catch', { calls: r.calls?.length, sinks: r.taint?.sinks?.length });
    expect((r.taint.sinks ?? []).length).toBeGreaterThan(0);
  });

  it('return in catch keeps sinks', async () => {
    const r = await analyze(base('            return;'), 'T.java', 'java');
    expect((r.taint.sinks ?? []).length).toBeGreaterThan(0);
  });

  it('assign in catch', async () => {
    const empty = await analyze(base(''), 'T.java', 'java');
    const assign = await analyze(base('            label = "";'), 'T.java', 'java');
    console.error(
      'calls',
      empty.calls?.map((c) => c.name),
      assign.calls?.map((c) => c.name),
      'sinks',
      empty.taint?.sinks?.length,
      assign.taint?.sinks?.length,
    );
    expect((assign.taint.sinks ?? []).length).toBeGreaterThan(0);
  });
});
