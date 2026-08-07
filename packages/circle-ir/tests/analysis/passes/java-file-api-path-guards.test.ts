/**
 * Java java.io.File path-traversal guard sanitizers (cognium-dev#269) —
 * `!file.getCanonicalPath().startsWith(base)` containment guard and
 * `new File(x).getName()` basename strip. The existing detectors covered only
 * the nio `Path` API (`resolve().normalize()+startsWith`, `Paths.get().getFileName()`);
 * these add the older java.io.File equivalents.
 *
 * Verified at both layers: `taint.flows` (sanitizer-honoring) and — since the
 * generateFindings sanitizer-awareness landed — the scan path when sanitizers
 * are passed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../../src/index.js';

describe('Java java.io.File path-traversal guards (cognium-dev#269)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const ptFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
  const ptScan = (r: Awaited<ReturnType<typeof analyze>>) =>
    generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java', undefined, 'java', r.taint.sanitizers ?? [])
      .filter((x) => x.type === 'path_traversal');

  it('getCanonicalPath().startsWith(base) reject-guard suppresses (flows + scan)', async () => {
    const code = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class C {',
      '  void h(HttpServletRequest req) throws Exception {',
      '    File f = new File("/base/", req.getParameter("n"));',
      '    if (!f.getCanonicalPath().startsWith("/base/")) throw new RuntimeException();',
      '    new FileInputStream(f);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    expect(ptFlows(r)).toHaveLength(0);
    expect(ptScan(r)).toHaveLength(0);
  });

  it('new File(x).getName() basename strip suppresses (flows + scan)', async () => {
    const code = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class C {',
      '  void h(HttpServletRequest req) throws Exception {',
      '    String leaf = new File(req.getParameter("n")).getName();',
      '    new FileInputStream(new File("/base/", leaf));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    expect(ptFlows(r)).toHaveLength(0);
    expect(ptScan(r)).toHaveLength(0);
  });

  it('an unguarded tainted path still fires (recall preserved)', async () => {
    const code = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class C {',
      '  void h(HttpServletRequest req) throws Exception {',
      '    new FileInputStream(new File("/base/" + req.getParameter("n")));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });
});
