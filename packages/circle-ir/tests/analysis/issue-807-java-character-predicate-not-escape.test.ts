/**
 * #807 — `java.lang.Character` classification predicates (`isLetter`,
 * `isDigit`, `isLetterOrDigit`, `isWhitespace`, ...) return a boolean about
 * their argument and keep no reference to it, so a tainted char tested with one
 * is not an `external_taint_escape`. Receiver-gated like the #468 formatters: a
 * class named `Character` declared in the file, or imported from another
 * package, still escapes. A real sink guarded by a predicate is unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const flowsOf = (ir: IR, type: string): number[] =>
  [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))]
    .sort((a, b) => a - b);

// A handler that sends the request value through a same-file filter whose
// parameter shares the handler variable's name.
const TAG_FILTER = `import javax.servlet.http.*;
public class TagFilterServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String tag = req.getParameter("tag");
        resp.getWriter().write(keepWordChars(tag));
    }
    /** @sanitizer */ private String keepWordChars(String tag) {
        StringBuilder out = new StringBuilder();
        for (int k = 0; k < tag.length(); k++) {
            char c = tag.charAt(k);
            if (Character.isLetterOrDigit(c)) { out.append(c); }
        }
        return out.toString();
    }
}
`;

function handler(head: string, body: string, extra = ''): string {
  return `${head}import javax.servlet.http.HttpServletRequest;
public class PinCheck {
    void check(HttpServletRequest req) throws Exception {
        String pin = req.getParameter("pin");
${body}
    }
${extra}
}
`;
}

describe('#807 Java: Character predicates are not an external_taint_escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reports nothing inside a char-filtering sanitizer helper', async () => {
    const ir = await analyze(TAG_FILTER, 'TagFilterServlet.java', 'java');
    expect(ir.taint.flows ?? []).toEqual([]);
  });

  it('does not report Character.isDigit on a tainted char in the handler', async () => {
    const body = `        char first = pin.charAt(0);
        if (Character.isDigit(first)) { return; }`;
    const ir = await analyze(handler('', body), 'PinCheck.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([]);
  });

  it('gates the fully qualified java.lang.Character spelling', async () => {
    const body = `        boolean blank = java.lang.Character.isWhitespace(pin.charAt(0));`;
    const ir = await analyze(handler('', body), 'PinCheck.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([]);
  });

  it('keeps a command sink guarded by a Character predicate', async () => {
    const body = `        if (Character.isLetter(pin.charAt(0))) {
            Runtime.getRuntime().exec(pin);
        }`;
    const ir = await analyze(handler('', body), 'PinCheck.java', 'java');
    expect(flowsOf(ir, 'command_injection')).toEqual([6]);
  });

  it('keeps the leak when a same-file class named Character shadows the JDK one', async () => {
    const body = `        boolean ok = Character.isLetter(pin);`;
    const extra = `}
class Character {
    static boolean isLetter(String v) { return Audit.send(v); }`;
    const ir = await analyze(handler('', body, extra), 'PinCheck.java', 'java');
    // The call resolves to the project method, whose body leaks at line 9.
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([9]);
  });

  it('keeps the escape for a Character imported from another package', async () => {
    const body = `        boolean ok = Character.isLetter(pin);`;
    const ir = await analyze(handler('import com.acme.text.Character;\n', body), 'PinCheck.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([6]);
  });

  it('keeps the escape for a non-predicate method on Character', async () => {
    const body = `        Character.registerName(pin);`;
    const ir = await analyze(handler('', body), 'PinCheck.java', 'java');
    expect(flowsOf(ir, 'external_taint_escape')).toEqual([5]);
  });
});
