/**
 * cognium-dev#814 slice S1 — Java bare-name taint is scoped to the declaring
 * method for const-prop and external_taint_escape (decision 814-1 A).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const flowsOf = (ir: IR, type: string): number[] =>
  [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))]
    .sort((a, b) => a - b);

const COLLISION = `import javax.servlet.http.*;
class Validator { static boolean ok(char ch) { return ch > 0; } }
public class B extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String name = req.getParameter("name");
        resp.getWriter().println(clean(name));
    }
    /** @sanitizer */ private String clean(String name) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            if (Validator.ok(ch)) { buf.append(ch); }
        }
        return buf.toString();
    }
}
`;

describe('#814 S1: method-scoped bare-name taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not pair handler taint with a same-named sanitizer parameter via bare alias', async () => {
    const ir = await analyze(COLLISION, 'B.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([]);
  });

  it('still reports xss on a direct write of the request parameter in the handler', async () => {
    const code = COLLISION.replace('resp.getWriter().println(clean(name));', 'resp.getWriter().println(name);');
    const sinkLine = code.split('\n').findIndex(l => l.includes('.println(name);')) + 1;
    const ir = await analyze(code, 'B.java', 'java');
    expect(flowsOf(ir, 'xss')).toContain(sinkLine);
  });

  it('rename-proof: renaming only the sanitizer parameter clears the collision', async () => {
    const code = COLLISION.replace('clean(String name)', 'clean(String word)');
    const ir = await analyze(code, 'B.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([]);
  });
});
