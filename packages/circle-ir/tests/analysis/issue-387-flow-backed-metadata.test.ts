/**
 * cognium-dev#387 — `verification.flow_backed` on `generateFindings` output.
 *
 * `generateFindings` rebuilds its own source/sink pairs and emits one whenever
 * a DFG path OR the proximity fallback accepts it. The taint layer's flow
 * builders refuse most of those pairs, so the two surfaces disagree badly.
 * Measured on OWASP Benchmark Java: **2800 `taint.flows` rows against 8801
 * findings rows, with 6635 (75.4%) of findings having no flow reaching the
 * same sink.**
 *
 * That gap is the dominant driver of Java over-prediction — ~353
 * security-typed findings per repo against ~8 genuinely vulnerable files on
 * the 500-repo vuln-localization benchmark, where Java recall is fine (84%)
 * but hit@3 collapses to 14% because the true file drowns. And it is
 * invisible from the finding alone: an unbacked pairing looks exactly like a
 * proven one.
 *
 * PURE METADATA, BY DESIGN. No finding is added, removed, re-severitied or
 * re-ordered, and the verdict-signature surface (`type@source->sink`) cannot
 * change, so every corpus differential is a zero-delta by construction. The
 * point is to give a consumer the ~3x precision cut by filtering, without this
 * repo making that policy choice on their behalf.
 *
 * SINK-LEVEL, NOT EXACT-PAIR. Backing is true when some flow of the same
 * `sink_type` reaches the same line. A finding whose source line was
 * re-attributed by #361/#372 is still the same proven detection, so requiring
 * an exact source-line match would mark proven findings as unbacked.
 *
 * `undefined` means the question was not asked — the caller passed no `flows`.
 * It must never collapse to `false`, or a consumer filtering on
 * `flow_backed === false` would discard everything from a legacy call site.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const SERVLET = [
  'import javax.servlet.http.*;',
  'import java.io.*;',
  'public class T extends HttpServlet {',
  '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
  '    String p = req.getParameter("p");',
  '    PrintWriter out = resp.getWriter();',
  '    out.println(p);',
  '  }',
  '}',
].join('\n');

describe('#387 — verification.flow_backed', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('marks a finding the taint layer proved as backed', async () => {
    const r = await analyze(SERVLET, 'T.java', 'java');
    expect(r.taint.flows.some(f => f.sink_type === 'xss')).toBe(true);
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'T.java', SERVLET, 'java',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    const xss = fs.filter(f => f.type === 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.every(f => f.verification.flow_backed === true)).toBe(true);
  });

  it('is undefined — never false — when the caller passes no flows', async () => {
    // A legacy call site must not look like "we checked and found nothing";
    // a consumer filtering on `=== false` would otherwise discard everything.
    const r = await analyze(SERVLET, 'T.java', 'java');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'T.java', SERVLET, 'java',
      r.taint.sanitizers, r.types,
    );
    expect(fs.length).toBeGreaterThan(0);
    expect(fs.every(f => f.verification.flow_backed === undefined)).toBe(true);
  });

  it('marks a pairing the taint layer refused as unbacked', async () => {
    // Reduced from OWASP BenchmarkTest00010, where `taint.flows` holds exactly
    // one row while generateFindings returns seven. The session-attribute sink
    // below takes two constants as arguments — the tainted value never reaches
    // it — yet the pair is accepted on position.
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class U extends HttpServlet {',
      '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {',
      '    String cookieName = "fixed";',
      '    String key = "alsoFixed";',
      '    Cookie c = new Cookie(cookieName, key);',
      '    c.setPath(request.getRequestURI());',
      '    request.getSession().setAttribute(cookieName, key);',
      '    response.addCookie(c);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'U.java', 'java');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'U.java', code, 'java',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    const backedSinks = new Set(r.taint.flows.map(f => `${f.sink_type}@${f.sink_line}`));
    // Whatever the pairing path emits, the flag must agree with taint.flows.
    for (const f of fs) {
      expect(f.verification.flow_backed).toBe(backedSinks.has(`${f.type}@${f.line}`));
    }
  });

  it('is false — not undefined — when the caller passes an EMPTY flows array', async () => {
    // An empty `taint.flows` is the taint layer saying it proved nothing in
    // this file, which is where unbacked pairings concentrate. The path below
    // is a constant; the request parameter never reaches it. If these read
    // "unknown", a consumer keeping `flow_backed !== false` retains precisely
    // the findings the field exists to let it drop.
    const code = [
      'import javax.servlet.http.*;',
      'public class V extends HttpServlet {',
      '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {',
      '    String p = request.getParameter("p");',
      '    java.io.File f = new java.io.File("/etc/app.conf");',
      '    new java.io.FileInputStream(f);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'V.java', 'java');
    expect(r.taint.flows).toEqual([]);
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'V.java', code, 'java',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    expect(fs.length).toBeGreaterThan(0);
    expect(fs.every(f => f.verification.flow_backed === false)).toBe(true);
  });

  it('does not change the finding set, only its metadata', async () => {
    // The guarantee the change rests on: filtering is the consumer's choice,
    // so this must be observably pure metadata.
    const r = await analyze(SERVLET, 'T.java', 'java');
    const withFlows = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'T.java', SERVLET, 'java',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    const sig = (f: { type: string; source?: { line: number }; line: number }) =>
      `${f.type}@${f.source?.line}->${f.line}`;
    const withoutFlows = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'T.java', SERVLET, 'java',
      r.taint.sanitizers, r.types,
    );
    // #372 adds flow-derived rows when flows are supplied, so compare the
    // pairing-path signatures that exist in both.
    const a = new Set(withoutFlows.map(sig));
    expect([...a].every(s => withFlows.map(sig).includes(s))).toBe(true);
    expect(withFlows.every(f => f.severity !== undefined && f.confidence !== undefined)).toBe(true);
  });
});
