/**
 * cognium-dev #287 — `x = f(x)` drops taint (PARTIAL fix).
 *
 * A tainted C# local reassigned from an expression derived from itself lost its
 * taint, so `v = v.Trim()`, `v = v.Replace(...)`, `v = v + x` silently cleared
 * it. Assignment *into* a variable always worked; self-derived reassignment did
 * not. Two defects are fixed here and locked below:
 *
 * 1. `buildCSharpDFG` collected every def in a method body before resolving any
 *    use, so the scope map held only the LAST def of each variable. `DFGUse.def_id`
 *    is specified as the reaching definition, and with one def per variable last
 *    == reaching, which is why single-assignment code always worked. For a
 *    reassigned local every use bound to its final def, so the right-hand `v` in
 *    `v = v + ""` resolved to the def it was creating. `computeChains` skips a
 *    use whose def_id is the def it is building, so no forward chain existed:
 *    taint stopped at the first def while the sink read the second. It also
 *    emitted a *backwards* chain, because the use on the first def's own line
 *    resolved to the second.
 *
 * 2. `buildTaintFlow` labelled the source path step with the propagated
 *    variable rather than the source's own, naming `v` at a line where only
 *    `input` exists.
 *
 * A third defect blocked the end-to-end finding until #328 (see below):
 * `isFalsePositive` vetoes the flow because const-prop tracked the reassigned
 * local with `type: 'unknown'` and never marked it tainted. Removing that veto
 * restores every fixture but costs far more than it buys — measured on the
 * OWASP corpus at +141 true-positive cases against +422 false-positive cases —
 * so #328 exempts only the self-derived-reassignment shape (reaching-def chain
 * through `x = f(x)`) from the veto; the end-to-end cases at the bottom now run.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const sqli = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');

const run = async (body: string[]) =>
  analyze(
    [
      'using System.Data.SqlClient;',
      'public class R {',
      '  static SqlConnection conn;',
      '  public void Run(string input) {',
      ...body.map(l => '    ' + l),
      '  }',
      '}',
    ].join('\n'),
    'R.cs',
    'csharp'
  );

describe('#287 C# DFG: a reassigned local binds to its preceding def', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the right-hand use on the reassignment line reads the EARLIER def', async () => {
    const r = await run([
      'var v = input;',
      'v = v + "";',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    const defs = (r.dfg?.defs ?? []).filter(d => d.variable === 'v').sort((a, b) => a.line - b.line);
    expect(defs.length).toBe(2);
    const [first, second] = defs;

    const rhs = (r.dfg?.uses ?? []).filter(u => u.variable === 'v' && u.line === second.line);
    expect(rhs.length).toBeGreaterThan(0);
    // Before the fix these resolved to `second` — the def being created.
    for (const use of rhs) expect(use.def_id).toBe(first.id);
  });

  it('the chain runs forward, first def -> second def', async () => {
    const r = await run([
      'var v = input;',
      'v = v + "";',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    const defs = (r.dfg?.defs ?? []).filter(d => d.variable === 'v').sort((a, b) => a.line - b.line);
    const [first, second] = defs;
    const chains = r.dfg?.chains ?? [];
    expect(chains.some(c => c.from_def === first.id && c.to_def === second.id)).toBe(true);
    // The backwards chain was the other half of the defect.
    expect(chains.some(c => c.from_def === second.id && c.to_def === first.id)).toBe(false);
  });

  it('the sink use reads the LAST def', async () => {
    const r = await run([
      'var v = input;',
      'v = v.ToUpperInvariant();',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    const defs = (r.dfg?.defs ?? []).filter(d => d.variable === 'v').sort((a, b) => a.line - b.line);
    const sinkUse = (r.dfg?.uses ?? []).find(u => u.variable === 'v' && u.line === 7);
    expect(sinkUse?.def_id).toBe(defs[defs.length - 1].id);
  });

  it('a single-def local keeps its existing binding (no collateral rebinding)', async () => {
    const r = await run([
      'var v = input;',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    const defs = (r.dfg?.defs ?? []).filter(d => d.variable === 'v');
    expect(defs.length).toBe(1);
    const sinkUse = (r.dfg?.uses ?? []).find(u => u.variable === 'v' && u.line === 6);
    expect(sinkUse?.def_id).toBe(defs[0].id);
  });

  it('two locals reassigned in the same method do not cross-bind', async () => {
    const r = await run([
      'var a = input;',
      'var b = "safe";',
      'a = a + "";',
      'b = b + "";',
      'new SqlCommand("SELECT * FROM u WHERE id=" + a, conn);',
    ]);
    const uses = r.dfg?.uses ?? [];
    const defsOf = (n: string) =>
      (r.dfg?.defs ?? []).filter(d => d.variable === n).sort((x, y) => x.line - y.line);
    for (const name of ['a', 'b']) {
      const ds = defsOf(name);
      for (const u of uses.filter(u => u.variable === name && u.def_id !== null)) {
        expect(ds.some(d => d.id === u.def_id)).toBe(true);
      }
    }
  });
});

describe('#287 the flow path names the source variable', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the source step is the source variable, not the sink-side one', async () => {
    const r = await run([
      'var v = input;',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    const flow = sqli(r)[0];
    expect(flow).toBeDefined();
    const sourceStep = flow.path.find(s => s.type === 'source');
    // Was `v`, a variable that does not exist on the source line.
    expect(sourceStep?.variable).toBe('input');
  });

  it('controls still fire: no reassignment, and a plain alias', async () => {
    const direct = await run(['new SqlCommand("SELECT * FROM u WHERE id=" + input, conn);']);
    expect(sqli(direct).length).toBeGreaterThan(0);

    const alias = await run([
      'var v = input;',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    expect(sqli(alias).length).toBeGreaterThan(0);
  });
});

describe('#287 sanitizer credit is unaffected', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const servlet = (lines: string[]) =>
    analyze(
      [
        'import javax.servlet.http.*;',
        'public class E extends HttpServlet {',
        '  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
        ...lines.map(l => '    ' + l),
        '  }',
        '}',
      ].join('\n'),
      'E.java',
      'java'
    );

  const xss = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter(f => f.sink_type === 'xss');

  // The registry check that makes this pair meaningful: `Encode.forHtml` is a
  // registered sanitizer that removes `xss` (config-loader.ts DEFAULT_SANITIZERS).
  // `Encode.forJava` is NOT registered and would prove nothing — an earlier
  // draft of this test used it and "passed" for the wrong reason.
  it('a registered sanitizer on the reassignment suppresses the flow', async () => {
    const r = await servlet([
      'String v = req.getParameter("q");',
      'v = org.owasp.encoder.Encode.forHtml(v);',
      'resp.getWriter().println(v);',
    ]);
    for (const f of xss(r)) expect(f.sanitized).toBe(true);
  });

  it('the same shape without the sanitizer still fires (control)', async () => {
    const r = await servlet([
      'String v = req.getParameter("q");',
      'v = v + "";',
      'resp.getWriter().println(v);',
    ]);
    expect(xss(r).length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// cognium-dev#328 — the four fixtures from #287 plus the true positive it was
// reported against. `propagateTaint` returns each flow (DFG fix above), and the
// const-prop `variable_not_tainted` veto no longer discards it because the
// variable reaching the sink is a self-derived reassignment.
// ---------------------------------------------------------------------------
describe('#287 end-to-end (#328 self-reassignment veto exemption)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('R2 reassignment through concat fires', async () => {
    const r = await run([
      'var v = input;',
      'v = v + "";',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('R3 reassignment through a case transform fires', async () => {
    const r = await run([
      'var v = input;',
      'v = v.ToUpperInvariant();',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('chained reassignments fire', async () => {
    const r = await run([
      'var v = input;',
      'v = v.Trim();',
      'v = v.ToLowerInvariant();',
      'v = v + "!";',
      'new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);',
    ]);
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('San01AfterConcatTp — sanitizing after concatenation fires', async () => {
    const r = await analyze(
      [
        'using System.Data.SqlClient;',
        'public class San01AfterConcatTp {',
        '  public void Run(string id) {',
        '    var q = "SELECT * FROM u WHERE id=" + id;',
        '    q = q.Replace(";", "");',
        '    var cmd = new SqlCommand(q, null);',
        '  }',
        '}',
      ].join('\n'),
      'San01AfterConcatTp.cs',
      'csharp'
    );
    expect(sqli(r).length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// cognium-dev#328 — the bounds of the veto exemption. The positive case is a
// shape measured on Juliet C#; the negative cases are shapes the global lift got
// wrong and the scoped exemption must not.
// ---------------------------------------------------------------------------
describe('#328 const-prop veto exemption bounds', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const cmdi = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');

  it('(E) declare-then-assign from a source const-prop has no pattern for fires (Juliet CWE78 Environment_01)', async () => {
    const r = await analyze(
      [
        'using System.Diagnostics;',
        'public class T {',
        '  public void Bad() {',
        '    string data;',
        '    data = Environment.GetEnvironmentVariable("ADD");',
        '    Process process = Process.Start("/bin/ls " + data);',
        '  }',
        '}',
      ].join('\n'),
      'T.cs',
      'csharp'
    );
    expect(cmdi(r).length).toBeGreaterThan(0);
  });

  it('a same-named variable in a sibling method does not qualify (Juliet *_41 G2B sink)', async () => {
    const r = await analyze(
      [
        'using System.Diagnostics;',
        'public class T {',
        '  private static void GoodG2BSink(string data) {',
        '    Process process = Process.Start("/bin/ls " + data);',
        '  }',
        '  public void Bad() {',
        '    string data;',
        '    data = Environment.GetEnvironmentVariable("ADD");',
        '  }',
        '  private static void GoodG2B() {',
        '    string data;',
        '    data = "foo";',
        '    GoodG2BSink(data);',
        '  }',
        '}',
      ].join('\n'),
      'T.cs',
      'csharp'
    );
    // The environment read in Bad() (line 8) must never reach the sink in
    // GoodG2BSink (line 4).
    expect(cmdi(r).filter(f => f.source_line === 8 && f.sink_line === 4)).toEqual([]);
  });

  it('a safe-key container read stays vetoed (OWASP BenchmarkTest00288 shape)', async () => {
    const r = await analyze(
      [
        'import javax.servlet.http.*;',
        'public class E extends HttpServlet {',
        '  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {',
        '    String param = request.getParameter("p");',
        '    String bar = "safe!";',
        '    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();',
        '    map.put("keyA", "a_Value");',
        '    map.put("keyB", param);',
        '    bar = (String) map.get("keyB");',
        '    bar = (String) map.get("keyA");',
        '    response.getWriter().println(bar);',
        '  }',
        '}',
      ].join('\n'),
      'E.java',
      'java'
    );
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'xss' && f.source_line === 10)).toEqual([]);
  });
});
