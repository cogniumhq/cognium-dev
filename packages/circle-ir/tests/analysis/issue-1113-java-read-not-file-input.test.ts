/**
 * cognium-dev #1113 — the classless `read` file_input source is Python-only.
 *
 * `{ method: 'read', type: 'file_input' }` sat in DEFAULT_SOURCES with no class
 * and no `languages`, so in Java it matched every `x.read(buf)`. Java's
 * `InputStream.read(buf)` returns a byte count; the call is not file input.
 * OWASP BenchmarkJava's generated cases all carry a dead
 * `if (inputParam instanceof InputStream) { int i = ((InputStream) inputParam).read(buf); … }`
 * branch, so once #1109 made `SeparateClassRequest.getTheParameter` a source,
 * 19 off-category signatures on safe files started at that `read` line
 * (xss on crypto/hash cases, crlf/trust_boundary on securecookie cases).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flowsOf = async (code: string, file: string, lang: 'java' | 'python') => {
  const r = await analyze(code, file, lang);
  return { flows: r.taint?.flows ?? [], sources: r.taint?.sources ?? [] };
};

// BenchmarkTest00632 shape (hash, expected=false): the param only reaches the
// writer through an encoder, and the InputStream branch is dead.
const HASH = `import javax.servlet.http.*;
public class HashCase extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String bar = "constant";
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("sha-384");
    byte[] input = {(byte) '?'};
    Object inputParam = bar;
    if (inputParam instanceof String) input = ((String) inputParam).getBytes();
    if (inputParam instanceof java.io.InputStream) {
      byte[] strInput = new byte[1000];
      int i = ((java.io.InputStream) inputParam).read(strInput);
      if (i == -1) return;
      input = java.util.Arrays.copyOf(strInput, i);
    }
    md.update(input);
    response.getWriter().println("Sensitive value '" + new String(input) + "' hashed");
  }
}
`;

// BenchmarkTest01522 shape (securecookie): a real request source feeds the
// cookie; the InputStream branch is dead.
const COOKIE = `import javax.servlet.http.*;
public class CookieCase extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    if (param == null) param = "";
    byte[] input = new byte[1000];
    String str = "?";
    Object inputParam = param;
    if (inputParam instanceof String) str = ((String) inputParam);
    if (inputParam instanceof java.io.InputStream) {
      int i = ((java.io.InputStream) inputParam).read(input);
      if (i == -1) return;
      str = new String(input, 0, i);
    }
    Cookie cookie = new Cookie("SomeCookie", str);
    cookie.setSecure(true);
    response.addCookie(cookie);
  }
}
`;

describe('#1113 Java InputStream.read is not a file_input source', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('registers no file_input source for a Java read(buf) call', async () => {
    const { sources } = await flowsOf(HASH, 'HashCase.java', 'java');
    expect(sources.filter(s => s.type === 'file_input')).toEqual([]);
  });

  it('reports no flow from the dead InputStream branch to the writer (hash shape)', async () => {
    const { flows } = await flowsOf(HASH, 'HashCase.java', 'java');
    expect(flows.filter(f => f.sink_type === 'xss')).toEqual([]);
  });

  it('attributes securecookie flows to the request source, not the read line', async () => {
    const { flows } = await flowsOf(COOKIE, 'CookieCase.java', 'java');
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(f => f.source_type !== 'file_input')).toBe(true);
    expect(flows.every(f => f.source_line === 4)).toBe(true);
  });

  it('keeps Python file.read() as a file_input source', async () => {
    const py = `def handler(path):
    f = open("/srv/data.txt")
    data = f.read()
    eval(data)
`;
    const { sources } = await flowsOf(py, 'h.py', 'python');
    expect(sources.some(s => s.type === 'file_input' && s.line === 3)).toBe(true);
  });

  it('OWASP corpus cases when CORPUS_ROOT is set', async () => {
    const root = process.env.CORPUS_ROOT;
    if (!root) return;
    const dir = `${root}/.owasp-benchmark-java/src/main/java/org/owasp/benchmark/testcode`;
    for (const n of ['00618', '00632', '00639', '00641']) {
      const p = `${dir}/BenchmarkTest${n}.java`;
      if (!existsSync(p)) continue;
      const { flows } = await flowsOf(readFileSync(p, 'utf8'), `BenchmarkTest${n}.java`, 'java');
      expect(flows.filter(f => f.sink_type === 'xss'), n).toEqual([]);
    }
    for (const n of ['00655', '01522', '01523', '01524']) {
      const p = `${dir}/BenchmarkTest${n}.java`;
      if (!existsSync(p)) continue;
      const { flows } = await flowsOf(readFileSync(p, 'utf8'), `BenchmarkTest${n}.java`, 'java');
      expect(flows.filter(f => f.source_type === 'file_input'), n).toEqual([]);
    }
  });
});
