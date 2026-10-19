/**
 * #468 (slice) — a tainted value passed to `java.util.Objects` null-check helpers
 * is not an `external_taint_escape`. Publishing the checked reference still escapes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const escapeLines = (ir: IR): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

function servlet(imports: string, body: string, extra = ''): string {
  return `import javax.servlet.http.HttpServletRequest;
${imports}
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

describe('#468 Java: Objects null-check helpers are not an external_taint_escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report an escape at Objects.requireNonNull', async () => {
    const body = `        Objects.requireNonNull(qty);`;
    const ir = await analyze(servlet('import java.util.Objects;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('keeps the escape when the checked value is published', async () => {
    const body = `        String checked = Objects.requireNonNull(qty);
        queue.publish(checked);`;
    const ir = await analyze(servlet('import java.util.Objects;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([8]);
  });

  it('gates requireNonNullElse and fully-qualified Objects', async () => {
    const body = `        java.util.Objects.requireNonNull(qty);
        Objects.requireNonNullElse(qty, "fallback");`;
    const ir = await analyze(servlet('import java.util.Objects;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('keeps Objects imported from another package escaping', async () => {
    const body = `        Objects.requireNonNull(qty);`;
    const ir = await analyze(servlet('import com.acme.util.Objects;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([7]);
  });
});
