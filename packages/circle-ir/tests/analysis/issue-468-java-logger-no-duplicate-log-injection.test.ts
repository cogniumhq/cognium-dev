/**
 * #468 S2 — gated Java logger calls must not emit log_injection or
 * external_taint_escape (Decision 468-1 A).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowTypes = (ir: Awaited<ReturnType<typeof analyze>>, type: string): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === type)
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

describe('#468 S2 Java: no duplicate log_injection on gated loggers', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report log_injection or escape for SLF4J info with tainted concat', async () => {
    const code = `import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
public class Q {
    private static final Logger logger = LoggerFactory.getLogger(Q.class);
    void run(HttpServletRequest request) {
        logger.info("user=" + request.getParameter("x"));
    }
}`;
    const ir = await analyze(code, 'Q.java', 'java');
    expect(flowTypes(ir, 'log_injection')).toEqual([]);
    expect(flowTypes(ir, 'external_taint_escape')).toEqual([]);
  });

  it('keeps sql_injection on a real sink when the logger is gated clean', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
public class Q {
    void run(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        org.slf4j.LoggerFactory.getLogger("x").info(request.getParameter("a"));
        stmt.executeQuery("SELECT " + request.getParameter("b"));
    }
}`;
    const ir = await analyze(code, 'Q.java', 'java');
    expect(flowTypes(ir, 'log_injection')).toEqual([]);
    expect(flowTypes(ir, 'sql_injection').length).toBeGreaterThan(0);
  });
});
