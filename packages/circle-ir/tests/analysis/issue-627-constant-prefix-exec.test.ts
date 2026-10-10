/**
 * cognium-dev#627 — `Runtime.exec(cmd + bar)` drops the flow when `cmd` is a
 * local string constant. The same concatenation with the literal written
 * inline (`"echo " + bar`) already flows. The sink filter treated the
 * argument as clean because the first identifier is a constant, and flow
 * matching then only consulted that identifier.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const servlet = (body: string) =>
  analyze(
    [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class V extends HttpServlet {',
      '  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {',
      body,
      '  }',
      '}',
    ].join('\n'),
    'V.java',
    'java',
  );

const cmdi = async (body: string) =>
  ((await servlet(body)).taint.flows ?? []).filter(
    f => f.sink_type === 'command_injection' && !f.sanitized,
  );

describe('#627 constant prefix does not hide a tainted exec operand', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flows through exec(cmd + bar) when cmd is a local string constant', async () => {
    const flows = await cmdi(`
    String bar = request.getParameter("q");
    String cmd = "echo ";
    Runtime r = Runtime.getRuntime();
    try { Process p = r.exec(cmd + bar); } catch (IOException e) { }
`);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.source_type === 'http_param')).toBe(true);
  });

  it('still flows when the constant prefix is an inline literal', async () => {
    const flows = await cmdi(`
    String bar = request.getParameter("q");
    Runtime r = Runtime.getRuntime();
    try { Process p = r.exec("echo " + bar); } catch (IOException e) { }
`);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('still flows when the prefix is not a constant', async () => {
    const flows = await cmdi(`
    String bar = request.getParameter("q");
    String cmd = request.getHeader("X-Cmd");
    Runtime r = Runtime.getRuntime();
    try { Process p = r.exec(cmd + bar); } catch (IOException e) { }
`);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('does not flow when every concat operand is a constant', async () => {
    const flows = await cmdi(`
    String bar = request.getParameter("q");
    String cmd = "echo ";
    String extra = "safe";
    Runtime r = Runtime.getRuntime();
    try { Process p = r.exec(cmd + extra); } catch (IOException e) { }
`);
    expect(flows).toEqual([]);
  });
});
