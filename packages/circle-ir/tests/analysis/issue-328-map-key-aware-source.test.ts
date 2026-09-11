/**
 * cognium-dev#328 prerequisite — key-aware map reads.
 *
 * `Map.get` / `HashMap.get` / … are registered as unconditional `plugin_param`
 * sources with `return_tainted: true`, which models reading a config/plugin
 * parameter map populated from outside. Applied to *every* map it also makes a
 * read of a key that was never written into a source:
 *
 *   Map m = new HashMap();
 *   m.put("a", req.getParameter("name"));
 *   String s1 = (String) m.get("b");    // source today; provably yields null
 *
 * That is SecuriBench Micro `Collections6:47`, an `/* OK *␄/` line.
 *
 * **Asserted on `taint.sources`, not on findings, and that is deliberate.**
 * The resulting false positive is currently masked by the const-prop veto
 * tracked in #328, so a findings-level assertion would pass with or without
 * this gate and prove nothing. The gate's purpose is to make lifting that veto
 * safe — the sequencing chosen on #328 — so the observable contract is the
 * source list.
 *
 * Measured effect on that decision: lifting the veto previously added 5 `BAD`
 * and 3 `OK` SecuriBench lines; with this gate it adds 5 `BAD` and 2 `OK`.
 * `Collections6:47` is the one removed. The remaining two (`Session2:48`,
 * `Datastructures2:59`) are *not* key-insensitivity — they come from classless
 * `getAttribute` / `getData` source registrations, which is a separate and
 * larger issue recorded on #328.
 *
 * Soundness rests on knowing the map's whole contents, so all three negatives
 * below must keep their source.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const mapSources = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.sources ?? []).filter(
    s => s.type === 'plugin_param' && /\.get\(\)/.test(s.location ?? ''),
  );

const servlet = (body: string[], extra: string[] = []) =>
  analyze(
    [
      'import java.util.*;',
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class T extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      ...body.map(l => '    ' + l),
      '  }',
      ...extra,
      '}',
    ].join('\n'),
    'T.java',
    'java'
  );

describe('#328 prerequisite: a read of a never-written map key is not a source', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops the source for an unwritten literal key (Collections6 shape)', async () => {
    const r = await servlet([
      'Map m = new HashMap();',
      'm.put("a", req.getParameter("name"));',
      'String s1 = (String) m.get("b");',
      'resp.getWriter().println(s1);',
    ]);
    expect(mapSources(r).length).toBe(0);
  });

  it('keeps the source when that key WAS written', async () => {
    const r = await servlet([
      'Map m = new HashMap();',
      'm.put("a", req.getParameter("name"));',
      'String s2 = (String) m.get("a");',
      'resp.getWriter().println(s2);',
    ]);
    expect(mapSources(r).length).toBeGreaterThan(0);
  });

  it('keeps both when one key is written and another read — only the unwritten one goes', async () => {
    // The full Collections6 shape: `m.get("b")` is /* OK */, `m.get("a")` is /* BAD */.
    const r = await servlet([
      'Map m = new HashMap();',
      'm.put("a", req.getParameter("name"));',
      'String s1 = (String) m.get("b");',
      'String s2 = (String) m.get("a");',
      'resp.getWriter().println(s1);',
      'resp.getWriter().println(s2);',
    ]);
    const lines = mapSources(r).map(s => s.line).sort();
    expect(lines.length).toBe(1);
    // the surviving source is the `m.get("a")` read, one line after `m.get("b")`
    expect(lines[0]).toBe(9);
  });
});

describe('#328 prerequisite: the gate needs the map’s whole contents to be known', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('keeps the source when the map is NOT locally constructed', async () => {
    // A map arriving from elsewhere may already hold anything — this is the
    // case the `plugin_param` registration exists for.
    const r = await servlet([
      'Map m = getConfig();',
      'String s = (String) m.get("b");',
      'resp.getWriter().println(s);',
    ], ['  private Map getConfig() { return null; }']);
    expect(mapSources(r).length).toBeGreaterThan(0);
  });

  it('keeps the source when the map ESCAPES to another call', async () => {
    // `fill(m)` could put anything under any key out of sight.
    const r = await servlet([
      'Map m = new HashMap();',
      'm.put("a", req.getParameter("name"));',
      'fill(m);',
      'String s = (String) m.get("b");',
      'resp.getWriter().println(s);',
    ], ['  private void fill(Map x) { x.put("b", "z"); }']);
    expect(mapSources(r).length).toBeGreaterThan(0);
  });

  it('keeps the source when the read key is not a literal', async () => {
    // The key is unknown, not known-absent.
    const r = await servlet([
      'Map m = new HashMap();',
      'm.put("a", req.getParameter("name"));',
      'String k = req.getParameter("k");',
      'String s = (String) m.get(k);',
      'resp.getWriter().println(s);',
    ]);
    expect(mapSources(r).length).toBeGreaterThan(0);
  });
});
