/**
 * cognium-dev#590 — inner-class helper returns request data into the servlet sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const FIXTURE = `import javax.servlet.http.*;
public class BenchmarkTest extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String bar = new Test().doSomething(request);
    java.lang.Runtime.getRuntime().exec(bar);
  }
  class Test {
    String doSomething(HttpServletRequest request) {
      return request.getParameter("x");
    }
  }
}`;

describe('#590 inner-class doSomething helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports command_injection from getParameter through the inner helper return', async () => {
    const result = await analyze(FIXTURE, 'BenchmarkTest.java', 'java');
    const execLine = FIXTURE.split('\n').findIndex(l => l.includes('.exec(bar)')) + 1;
    const flows = result.taint.flows ?? [];
    expect(
      flows.some(
        f => f.sink_type === 'command_injection' && f.sink_line === execLine && f.source_type === 'http_param',
      ),
    ).toBe(true);
  });
});
