/**
 * cognium-dev #1247 — variant log4j_pattern: tainted `${…}` in Log4j format must
 * emit log_injection when the receiver is org.apache.logging.log4j.Logger without
 * a `Logger` import (FQN field type).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInjLines = (ir: Awaited<ReturnType<typeof analyze>>): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'log_injection' && !f.sanitized)
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

/** Aligns with java-vuln-demo …/V05Log4jPattern.java (variant log4j_pattern). */
const v05Log4jPattern = `import org.apache.logging.log4j.LogManager;
import javax.servlet.http.HttpServletRequest;
public class V05Log4jPattern {
    private static final org.apache.logging.log4j.Logger log = LogManager.getLogger(V05Log4jPattern.class);
    public void log4j(HttpServletRequest req) {
        String user = req.getParameter("user");
        log.info("login user=\${" + user + "}");
    }
}`;

describe('#1247 Java Log4j pattern log_injection (variant log4j_pattern)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('registers log_injection on FQN-typed Log4j Logger.info', async () => {
    const ir = await analyze(v05Log4jPattern, 'V05Log4jPattern.java', 'java');
    expect((ir.taint.sinks ?? []).some(s => s.type === 'log_injection')).toBe(true);
    const infoCall = ir.calls?.find(c => c.method_name === 'info' && c.receiver === 'log');
    expect(infoCall?.receiver_type_fqn).toBe('org.apache.logging.log4j.Logger');
  });

  it('emits a flow-backed log_injection for the Log4j lookup pattern', async () => {
    const ir = await analyze(v05Log4jPattern, 'V05Log4jPattern.java', 'java');
    expect(logInjLines(ir)).toEqual([7]);
  });
});