/**
 * Java `if (x.contains("..")) throw/return` path-traversal reject-guard
 * (cognium-dev#269 CWE-22 review).
 *
 * A user path checked for a `..` traversal token and rejected before any
 * filesystem use is not exploitable. This is applied as a SinkFilter sink drop
 * (Stage 15d) rather than a sanitizer, so it reaches the `generateFindings`
 * scan path too — generateFindings does its own DFG path-finding and is not
 * sanitizer-aware.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../../src/index.js';

describe('Java path_traversal reject-guard (cognium-dev#269)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const pt = async (body: string) => {
    const code = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class C {',
      '  void h(HttpServletRequest req) throws Exception {',
      '    String name = req.getParameter("f");',
      body,
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java');
    return generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java').filter((x) => x.type === 'path_traversal');
  };

  it('SUPPRESS: inline reject-guard before the filesystem use', async () => {
    const out = await pt('    if (name.contains("..")) throw new RuntimeException();\n    new FileInputStream(new File("/base/" + name));');
    expect(out).toHaveLength(0);
  });

  it('SUPPRESS: block reject-guard with return, and a one-hop derivation', async () => {
    const out = await pt('    if (name.contains("..")) {\n      return;\n    }\n    File f = new File("/base/", name);\n    new FileInputStream(f);');
    expect(out).toHaveLength(0);
  });

  it('FIRE: no guard — a plain tainted path is still path_traversal', async () => {
    const out = await pt('    new FileInputStream(new File("/base/" + name));');
    expect(out.length).toBeGreaterThan(0);
  });

  it('FIRE: guard AFTER the sink does not retroactively sanitize', async () => {
    const out = await pt('    new FileInputStream(new File("/base/" + name));\n    if (name.contains("..")) throw new RuntimeException();');
    expect(out.length).toBeGreaterThan(0);
  });
});
