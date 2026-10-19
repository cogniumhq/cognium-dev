/**
 * cognium-dev#814 (slice) — `Character.getName` / `getType` on a tainted char are
 * not an external_taint_escape when the JDK receiver gate passes (#807 predicates).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const flowsOf = (ir: IR, type: string): number[] =>
  [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))]
    .sort((a, b) => a - b);

const GLYPH_FILTER = `import javax.servlet.http.*;
public class GlyphFilterServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String glyph = req.getParameter("glyph");
        resp.getWriter().write(keepNamedGlyphs(glyph));
    }
    /** @sanitizer */ private String keepNamedGlyphs(String glyph) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < glyph.length(); i++) {
            char c = glyph.charAt(i);
            if (Character.getName(c) != null && Character.getType(c) > 0) { out.append(c); }
        }
        return out.toString();
    }
}
`;

describe('#814 Java: Character metadata calls are not an external_taint_escape', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports nothing inside a sanitizer that uses getName/getType on each char', async () => {
    const ir = await analyze(GLYPH_FILTER, 'GlyphFilterServlet.java', 'java');
    expect(ir.taint.flows ?? []).toEqual([]);
  });

  it('still reports xss when getName output is written in the handler', async () => {
    const code = `import javax.servlet.http.*;
public class NameEchoServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String pin = req.getParameter("pin");
        resp.getWriter().write(Character.getName(pin.charAt(0)));
    }
}`;
    const sinkLine = code.split('\n').findIndex(l => l.includes('.write(Character.getName')) + 1;
    const ir = await analyze(code, 'NameEchoServlet.java', 'java');
    expect(flowsOf(ir, 'xss')).toContain(sinkLine);
  });

  it('keeps escape when a project Character class shadows the JDK metadata call', async () => {
    const code = `import javax.servlet.http.*;
public class ShadowServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String pin = req.getParameter("pin");
        if (Character.getName(pin.charAt(0)) != null) { return; }
    }
}
class Character {
    static String getName(char c) { return Audit.leak(c); }
}`;
    const leakLine = code.split('\n').findIndex(l => l.includes('Audit.leak')) + 1;
    const ir = await analyze(code, 'ShadowServlet.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toContain(leakLine);
  });
});
