/**
 * #468 (slice) — a tainted value passed to a JDK static formatter
 * (`String.format`, `MessageFormat.format`) is not an `external_taint_escape`:
 * building a string sends the value nowhere. Receiver-gated: a class of that
 * name imported from another package or declared in the file, and an instance
 * `.format(...)` on an unknown receiver, still escape. Loggers, `StringBuilder`,
 * other helpers and classical sinks are unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const escapeLines = (ir: IR): number[] =>
  [...new Set((ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line))]
    .sort((a, b) => a - b);

const flowLines = (ir: IR, type: string): number[] =>
  [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))].sort((a, b) => a - b);

const QUANTITY = `import java.io.IOException;
import java.text.MessageFormat;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.acme.ship.ShipQueue;

public class QuantityLabelServlet extends HttpServlet {
    private ShipQueue queue;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String qty = request.getParameter("qty");
        String label = String.format("qty=%s", qty);
        String note = MessageFormat.format("n={0}", qty);
        queue.publish(label);
    }
}
`;

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

describe('#468 Java: JDK static formatters are not an external_taint_escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report an escape at String.format / MessageFormat.format', async () => {
    const ir = await analyze(QUANTITY, 'QuantityLabelServlet.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('keeps the escape at a publish call that receives the MessageFormat result', async () => {
    const body = `        String note = MessageFormat.format("n={0}", qty);
        queue.publish(note);`;
    const ir = await analyze(servlet('import java.text.MessageFormat;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([8]);
  });

  it('gates a MessageFormat imported through java.text.*, not one that is not imported at all', async () => {
    const body = `        String c = MessageFormat.format("q={0}", qty);`;
    expect(escapeLines(await analyze(servlet('import java.text.*;', body), 'Q.java', 'java'))).toEqual([]);
    expect(escapeLines(await analyze(servlet('', body), 'Q.java', 'java'))).toEqual([7]);
  });

  it('keeps a MessageFormat imported under an alias-style conflicting import escaping', async () => {
    const body = `        String c = MessageFormat.format("q={0}", qty);`;
    const ir = await analyze(servlet('import java.text.*;\nimport com.acme.text.MessageFormat;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([8]);
  });

  it('covers the Locale overload and fully-qualified receivers', async () => {
    const body = `        String a = String.format(java.util.Locale.ROOT, "q=%s", qty);
        String b = java.lang.String.format("q=%s", qty);
        String c = java.text.MessageFormat.format("q={0}", qty);`;
    const ir = await analyze(servlet('', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([]);
  });

  it('keeps a MessageFormat imported from another package escaping', async () => {
    const body = `        String c = MessageFormat.format("q={0}", qty);`;
    const ir = await analyze(servlet('import com.acme.text.MessageFormat;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([7]);
  });

  it('keeps an instance format() on an unknown receiver escaping', async () => {
    const body = `        com.acme.fmt.Formatter f = new com.acme.fmt.Formatter();
        String c = f.format("q=%s", qty);`;
    const ir = await analyze(servlet('', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([8]);
  });

  it('keeps the escape when the MessageFormat call is an argument of another call', async () => {
    const body = `        queue.publish(MessageFormat.format("q={0}", qty));
        queue.publish(
            MessageFormat.format("r={0}", qty));`;
    const ir = await analyze(servlet('import java.text.MessageFormat;', body), 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([7, 9]);
  });

  it('does not touch a classical sink fed by the formatted value', async () => {
    const xss = `import java.io.IOException;
import java.text.MessageFormat;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String qty = request.getParameter("qty");
        String label = MessageFormat.format("qty={0}", qty);
        response.getWriter().println(label);
    }
}
`;
    const ir2 = await analyze(xss, 'EchoServlet.java', 'java');
    expect(flowLines(ir2, 'xss')).toEqual([12]);
    expect(escapeLines(ir2)).toEqual([]);
  });
});
