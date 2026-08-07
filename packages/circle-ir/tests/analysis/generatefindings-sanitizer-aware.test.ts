/**
 * `generateFindings` sanitizer-awareness (cognium-dev — the scan-path FP lever).
 *
 * Historically `generateFindings` (the path downstream scans build reports from)
 * did its own source→sink DFG path-finding and ignored the pass-level
 * `TaintSanitizer`s that `taint.flows` honors, so a guarded value that
 * `taint.flows` suppressed still surfaced in the scan. The new optional
 * `sanitizers` argument makes it drop a finding when a sanitizer AT the sink's
 * line covers the sink type — mirroring the taint-propagation sink-line filter.
 * Backward-compatible: callers that pass no sanitizers get the old behavior.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../src/index.js';

describe('generateFindings sanitizer-awareness', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // `Paths.get(x).getFileName().toString()` strips directory components — a
  // path-traversal sanitizer emitted at the referencing (sink) line.
  const guarded = [
    'import java.nio.file.*;',
    'import javax.servlet.http.*;',
    'public class C {',
    '  void h(HttpServletRequest req) throws Exception {',
    '    String leaf = Paths.get(req.getParameter("f")).getFileName().toString();',
    '    Files.readAllBytes(Paths.get("/base", leaf));',
    '  }',
    '}',
  ].join('\n');

  it('WITHOUT sanitizers: the guarded path still fires (legacy behavior preserved)', async () => {
    const r = await analyze(guarded, 'C.java', 'java');
    const pt = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java', guarded, 'java');
    expect(pt.some((x) => x.type === 'path_traversal')).toBe(true);
  });

  it('WITH sanitizers: the guarded path is suppressed', async () => {
    const r = await analyze(guarded, 'C.java', 'java');
    const pt = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'C.java', guarded, 'java', r.taint.sanitizers ?? [],
    );
    expect(pt.filter((x) => x.type === 'path_traversal')).toHaveLength(0);
  });

  // Tier 2 (DFG reaching-def walk): sanitizer on the ASSIGNMENT line, sink on a
  // later line — the OWASP BenchmarkTest00713 shape. Tier 1 (sink-line) misses
  // it; the reaching-def walk credits the sanitizer on `bar`'s def line.
  const tier2 = [
    'import org.apache.commons.lang.StringEscapeUtils;',
    'import javax.servlet.http.*;',
    'public class C {',
    '  void h(HttpServletRequest req, HttpServletResponse res) throws Exception {',
    '    String param = req.getParameter("q");',
    '    String bar = StringEscapeUtils.escapeHtml(param);',
    '    Object[] obj = {"a", "b"};',
    '    res.getWriter().format(java.util.Locale.US, bar, obj);',
    '  }',
    '}',
  ].join('\n');

  it('WITHOUT sanitizers: the assignment-line-sanitized path still fires', async () => {
    const r = await analyze(tier2, 'C.java', 'java');
    const xss = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java', tier2, 'java');
    expect(xss.some((x) => x.type === 'xss')).toBe(true);
  });

  it('WITH sanitizers: a sanitizer on the reaching-def (assignment) line suppresses it (tier 2)', async () => {
    const r = await analyze(tier2, 'C.java', 'java');
    const xss = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'C.java', tier2, 'java', r.taint.sanitizers ?? [],
    );
    expect(xss.filter((x) => x.type === 'xss')).toHaveLength(0);
  });

  it('WITH sanitizers: an unguarded path still fires (recall preserved)', async () => {
    const code = [
      'import java.nio.file.*;',
      'import javax.servlet.http.*;',
      'public class C {',
      '  void h(HttpServletRequest req) throws Exception {',
      '    Files.readAllBytes(Paths.get("/base", req.getParameter("f")));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    const pt = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'C.java', code, 'java', r.taint.sanitizers ?? [],
    );
    expect(pt.some((x) => x.type === 'path_traversal')).toBe(true);
  });
});
