/**
 * #468 (slice) — tainted values passed to JDK / SLF4J-style loggers are not
 * `external_taint_escape`. Logging is modelled separately as `log_injection`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const escapeLines = (ir: Awaited<ReturnType<typeof analyze>>): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

function servlet(imports: string, body: string): string {
  return `import javax.servlet.http.HttpServletRequest;
${imports}
public class Q {
    private com.acme.ship.ShipQueue queue;
    void run(HttpServletRequest request) {
        String qty = request.getParameter("qty");
${body}
    }
}
`;
}

describe('#468 Java: logger calls are not an external_taint_escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report an escape for SLF4J info / warn', async () => {
    const code = `import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
public class Q {
    private static final Logger log = LoggerFactory.getLogger(Q.class);
    private com.acme.ship.ShipQueue queue;
    void run(HttpServletRequest request) {
        String qty = request.getParameter("qty");
        log.info(qty);
        log.warn("x {}", qty);
    }
}`;
    const ir = await analyze(code, 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('does not report an escape for java.util.logging severe / fine', async () => {
    const body = `        java.util.logging.Logger.getLogger("x").severe(qty);
        java.util.logging.Logger.getLogger("x").fine(qty);`;
    const ir = await analyze(servlet('', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('keeps the escape when a formatted string is published to an external queue', async () => {
    const body = `        String note = MessageFormat.format("n={0}", qty);
        queue.publish(note);`;
    const ir = await analyze(servlet('import java.text.MessageFormat;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([8]);
  });
});
