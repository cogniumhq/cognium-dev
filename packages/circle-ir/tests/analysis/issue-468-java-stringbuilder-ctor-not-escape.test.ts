/**
 * #468 (slice) — a tainted value passed to a JDK `StringBuilder` / `StringBuffer`
 * constructor is not an `external_taint_escape`. Instance `append` was already
 * excluded via collectionMethods; the one-arg constructor was not.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const escapeLines = (ir: Awaited<ReturnType<typeof analyze>>): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

function servlet(body: string, extra = ''): string {
  return `import javax.servlet.http.HttpServletRequest;
public class Q {
    private com.acme.ship.ShipQueue queue;
    void run(HttpServletRequest request) {
        String qty = request.getParameter("qty");
${body}
    }
${extra}
}
`;
}

describe('#468 Java: StringBuilder construction is not an external_taint_escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report an escape at new StringBuilder(tainted)', async () => {
    const body = `        StringBuilder sb = new StringBuilder(qty);`;
    const ir = await analyze(servlet(body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('covers StringBuffer and fully-qualified java.lang names', async () => {
    const body = `        StringBuffer buf = new java.lang.StringBuffer(qty);
        java.lang.StringBuilder sb = new StringBuilder(qty);`;
    const ir = await analyze(servlet(body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('keeps the escape when the built string is published', async () => {
    const body = `        StringBuilder sb = new StringBuilder(qty);
        queue.publish(sb.toString());`;
    const ir = await analyze(servlet(body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([7]);
  });

  it('keeps a project StringBuilder imported from another package escaping', async () => {
    const body = `        StringBuilder sb = new StringBuilder(qty);`;
    const code = servlet(body).replace(
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletRequest;\nimport com.acme.text.StringBuilder;',
    );
    const ir = await analyze(code, 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([7]);
  });
});
