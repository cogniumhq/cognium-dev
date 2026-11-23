/**
 * cognium-dev#1378 — variant-regression `log_injection` / `slf4j_concat` / java.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowTypes = (ir: Awaited<ReturnType<typeof analyze>>, type: string): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === type)
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

const V50_SLF4J_CONCAT = `import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
public class V50Slf4jConcat {
    private static final Logger log = LoggerFactory.getLogger(V50Slf4jConcat.class);
    public void audit(HttpServletRequest req) {
        String user = req.getParameter("user");
        log.info("login attempt for user=" + user);
    }
}`;

describe('#1378 Java slf4j_concat log_injection', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reports log_injection for tainted string concat in SLF4J info', async () => {
    const ir = await analyze(V50_SLF4J_CONCAT, 'V50Slf4jConcat.java', 'java');
    expect(flowTypes(ir, 'log_injection').length).toBeGreaterThan(0);
    expect(flowTypes(ir, 'external_taint_escape')).toEqual([]);
  });
});