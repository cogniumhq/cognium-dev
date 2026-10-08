/**
 * Java response-writer xss: precision and recall on the shapes behind the
 * OWASP BenchmarkJava xss false-positive rate (#585, #600).
 *
 * 1. The getWriter() pattern no longer fires on a write the taint matcher
 *    already resolved as an xss sink. It flagged every constant or encoded
 *    write there; the taint engine owns that verdict.
 * 2. PrintWriter.format/printf are sinks at every argument, so the Locale
 *    overload and later varargs are covered (#598).
 * 3. Taint assigned in one case of a switch survives to a later sink: the DFG
 *    records defs inside switch cases, const-prop joins the cases when the
 *    switch value is unknown, and a literal in a sibling case no longer counts
 *    as an overwrite.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type Result = Awaited<ReturnType<typeof analyze>>;
const xssFlows = (r: Result) => (r.taint.flows ?? []).filter(f => f.sink_type === 'xss');
const xssPattern = (r: Result) =>
  r.findings.filter(f => f.rule_id === 'xss' && /^Reflected XSS: HttpServletResponse/.test(f.message));

const servlet = (body: string) => `
import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
${body}
  }
}
`;

const run = (body: string) => analyze(servlet(body), 'T.java', 'java');

describe('response-writer xss precision (#585)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a constant picked out of a list is not xss', async () => {
    const r = await run(`
    String param = request.getHeader("Referer");
    String bar = "alsosafe";
    java.util.List<String> valuesList = new java.util.ArrayList<String>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.add("moresafe");
    valuesList.remove(0);
    bar = valuesList.get(1);
    response.getWriter().print(bar);`);
    expect(xssFlows(r)).toHaveLength(0);
    expect(xssPattern(r)).toHaveLength(0);
  });

  it('a tainted write is still reported, as a taint flow', async () => {
    const r = await run(`
    String bar = request.getParameter("p");
    response.getWriter().print(bar);`);
    expect(xssFlows(r).length).toBeGreaterThanOrEqual(1);
    expect(xssPattern(r)).toHaveLength(0);
  });
});

describe('PrintWriter.format/printf varargs (#598)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('printf(Locale, constant format, Object[] holding taint) is xss', async () => {
    const r = await run(`
    String bar = request.getParameter("p");
    Object[] obj = {"a", bar};
    response.getWriter().printf(java.util.Locale.US, "x %1$s %2$s", obj);`);
    expect(xssFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('printf(Locale, constant format, tainted vararg) is xss', async () => {
    const r = await run(`
    String bar = request.getParameter("p");
    response.getWriter().printf(java.util.Locale.US, "x %s", bar);`);
    expect(xssFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('format(constant, Object[] of constants) is not xss', async () => {
    const r = await run(`
    String bar = request.getParameter("p");
    Object[] obj = {"a", "b"};
    response.getWriter().format("x %1$s %2$s", obj);`);
    expect(xssFlows(r)).toHaveLength(0);
  });
});

describe('taint assigned inside a switch case', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sw = (target: string) => `
    String param = request.getParameter("p");
    String bar;
    char switchTarget = ${target};
    switch (switchTarget) {
      case 'A':
        bar = param;
        break;
      case 'B':
        bar = "bobs_your_uncle";
        break;
      case 'C':
      case 'D':
        bar = param;
        break;
      default:
        bar = "bobs_your_uncle";
        break;
    }
    response.getWriter().print(bar);`;

  it('a constant target that selects the tainted case is xss', async () => {
    const r = await run(sw(`"ABC".charAt(2)`));
    expect(xssFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('an unknown target is xss: any case may run', async () => {
    const r = await run(sw(`request.getHeader("h").charAt(0)`));
    expect(xssFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('a constant target that selects a literal case is not xss', async () => {
    const r = await run(sw(`"ABC".charAt(1)`));
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('a switch that assigns a literal in every case is not a flow (#101)', async () => {
    const r = await run(`
    String type = request.getParameter("type");
    String bar;
    switch (type) {
      case "daily":   bar = "<b>daily</b>";   break;
      case "weekly":  bar = "<b>weekly</b>";  break;
      default:        bar = "<b>default</b>"; break;
    }
    response.getWriter().print(bar);`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('the DFG records the assignments inside switch cases', async () => {
    const r = await run(sw(`request.getHeader("h").charAt(0)`));
    const barDefs = r.dfg.defs.filter(d => d.variable === 'bar');
    // the declaration plus one def per case body
    expect(barDefs.length).toBeGreaterThanOrEqual(5);
  });
});
