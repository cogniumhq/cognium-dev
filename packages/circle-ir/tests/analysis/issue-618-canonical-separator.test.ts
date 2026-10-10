/**
 * cognium-dev#618 — a canonical-path `startsWith` without a trailing
 * separator is not a containment check. `/safe/dir-evil` passes
 * `startsWith("/safe/dir")`. ESAPI CVE-2022-23457
 * (`dir.getCanonicalPath().startsWith(parent.getCanonicalPath())`) must
 * keep the path_traversal flow. The same check with `File.separator`, or a
 * base literal that ends in `/`, stays clean (#101 / #269).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const traversalAt = (r: Awaited<ReturnType<typeof analyze>>, line: number) =>
  (r.taint.flows ?? []).filter(
    f => f.sink_type === 'path_traversal' && !f.sanitized && f.sink_line === line,
  );

describe('#618 canonical startsWith needs a separator', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const java = (guard: string) => {
    const code = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class E extends HttpServlet {',
      '  public void doGet(HttpServletRequest req, File parent) throws Exception {',
      '    String input = req.getParameter("f");',
      '    File dir = new File(input);',
      `    ${guard}`,
      '    new FileInputStream(dir);',
      '  }',
      '}',
    ].join('\n');
    const sinkLine = code.split('\n').findIndex(l => l.includes('new File(input)')) + 1;
    return analyze(code, 'E.java', 'java').then(r => ({ r, sinkLine }));
  };

  it('bare parent.getCanonicalPath() does not suppress new File(input)', async () => {
    const { r, sinkLine } = await java(
      'if (!dir.getCanonicalPath().startsWith(parent.getCanonicalPath())) throw new IOException("bad");',
    );
    expect(traversalAt(r, sinkLine).length).toBeGreaterThan(0);
  });

  it('parent.getCanonicalPath() + File.separator still suppresses', async () => {
    const { r, sinkLine } = await java(
      'if (!dir.getCanonicalPath().startsWith(parent.getCanonicalPath() + File.separator)) throw new IOException("bad");',
    );
    expect(traversalAt(r, sinkLine)).toHaveLength(0);
  });

  it('a base literal that ends in / still suppresses', async () => {
    const { r, sinkLine } = await java(
      'if (!dir.getCanonicalPath().startsWith("/safe/dir/")) throw new IOException("bad");',
    );
    expect(traversalAt(r, sinkLine)).toHaveLength(0);
  });
});
