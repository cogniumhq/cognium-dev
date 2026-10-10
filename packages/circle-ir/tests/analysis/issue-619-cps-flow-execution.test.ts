/**
 * cognium-dev#619 — `new CpsFlowExecution(script, ...)` is script evaluation
 * (CWE-94), not an OS exec. The CWE-78 constructor allowlist (#129) dropped
 * the old command_injection registration, so the flow disappeared.
 *
 * SAST regression fixture — the handler is deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#619 — CpsFlowExecution is code injection', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('new CpsFlowExecution(tainted script) is code_injection, not command_injection', async () => {
    const code = `
import javax.servlet.http.*;
public class Cps {
  public Object create(HttpServletRequest req) {
    String script = req.getParameter("s");
    return new CpsFlowExecution(script, true, null, null);
  }
}
`;
    const r = await analyze(code, 'Cps.java', 'java');
    const flows = r.taint.flows ?? [];
    const codeInj = flows.filter((f) => f.sink_type === 'code_injection');
    const cmd = flows.filter((f) => f.sink_type === 'command_injection');
    expect(codeInj.length).toBeGreaterThanOrEqual(1);
    expect(cmd.length).toBe(0);
  });
});
