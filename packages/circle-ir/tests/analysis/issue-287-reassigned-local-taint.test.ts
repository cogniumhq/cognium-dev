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
 * A third defect still blocks the end-to-end finding and is NOT fixed here:
 * `isFalsePositive` vetoes the flow because const-prop tracked the reassigned
 * local with `type: 'unknown'` and never marked it tainted. Removing that veto
 * restores every fixture but costs far more than it buys — measured on the
 * OWASP corpus at +141 true-positive cases against +422 false-positive cases —
 * so it needs a precision decision rather than an unattended change. Tracked
 * separately; the blocked end-to-end cases are the skipped block at the bottom.
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
// Still blocked by the const-prop veto described in the file header. These are
// the four fixtures from #287 plus the true positive it was reported against.
// The DFG fix above makes every one of them propagate — `propagateTaint`
// returns the flow — and `isFalsePositive` then discards it because const-prop
// tracked the reassigned local as `{ value: null, type: 'unknown' }` and never
// marked it tainted.
//
// Kept as `.skip` rather than deleted, and asserting the FIXED expectation, so
// whoever takes the precision decision can flip one word and see them pass.
// Do NOT convert these to assert the current (empty) result — that would pin
// the defect.
// ---------------------------------------------------------------------------
describe.skip('#287 end-to-end (blocked on the const-prop precision decision)', () => {
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
