/**
 * #618 (regression since 3.64.0, ESAPI CVE-2022-23457) — a canonical-path
 * `startsWith` containment guard is credited only when the base it is compared
 * against ends in a path separator.
 *
 *   dir.getCanonicalPath().startsWith(parent.getCanonicalPath())
 *
 * accepts `/safe/dir-evil` for a base of `/safe/dir`, so it is not a
 * containment check. `base + File.separator` (or `"/"`, `'/'`), a literal that
 * ends in a separator, and a local variable that holds such a base are real
 * guards and stay clean.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../src/index.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const ptFlows = (r: IR) => (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
const ptScan = (r: IR) =>
  generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'C.java', undefined, 'java', r.taint.sanitizers ?? [])
    .filter(x => x.type === 'path_traversal');

const analyzeJava = (code: string) => analyze(code, 'C.java', 'java');

/** ESAPI `DefaultValidator.getValidDirectoryPath`, reduced. */
const esapi = (check: string) => `import java.io.File;
import java.io.IOException;

public class DefaultValidator {
    public File getValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws Exception {
        try {
            File dir = new File( input );
            if (!dir.exists()) {
                throw new Exception("not found");
            }
            ${check}
            return dir;
        } catch (IOException e) {
            throw new Exception("bad path");
        }
    }
}
`;

describe('#618 canonical-path startsWith needs a separator-anchored base', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('ESAPI shape (no separator on the base) still reports path_traversal', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith(parent.getCanonicalPath()) ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
    expect(ptScan(r).length).toBeGreaterThan(0);
  });

  it('a literal base without a trailing separator is not a guard', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith("/srv/data") ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it('a base held in a variable that has no separator is not a guard', async () => {
    const r = await analyzeJava(esapi(
      'String base = parent.getCanonicalPath();\n            if ( !dir.getCanonicalPath().startsWith(base) ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it('is rename-proof', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith(parent.getCanonicalPath()) ) { throw new Exception("outside"); }')
      .replace(/dir/g, 'leaf').replace(/parent/g, 'root').replace(/input/g, 'raw'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it.each([
    ['File.separator', 'parent.getCanonicalPath() + File.separator'],
    ['a "/" literal', 'parent.getCanonicalPath() + "/"'],
    ["a '/' char", "parent.getCanonicalPath() + '/'"],
    ['File.separatorChar', 'parent.getCanonicalPath() + File.separatorChar'],
    ['a literal that ends in "/"', '"/srv/data/"'],
  ])('a base anchored with %s stays clean', async (_n, arg) => {
    const r = await analyzeJava(esapi(
      `if ( !dir.getCanonicalPath().startsWith(${arg}) ) { throw new Exception("outside"); }`));
    expect(ptFlows(r)).toHaveLength(0);
    expect(ptScan(r)).toHaveLength(0);
  });

  it('a separator-anchored base held in a local variable stays clean (maintainer negative)', async () => {
    const code = `import java.io.*;
import javax.servlet.http.*;

public class Reader {
    public void read(HttpServletRequest req) throws IOException {
        File root = new File("/srv/data");
        File f = new File(root, req.getParameter("name"));
        String base = root.getCanonicalPath() + File.separator;
        if (!f.getCanonicalPath().startsWith(base)) throw new IOException("bad");
        new FileInputStream(f).close();
    }
}
`;
    const r = await analyzeJava(code);
    expect(ptFlows(r)).toHaveLength(0);
    expect(ptScan(r)).toHaveLength(0);
  });

  it('the same variable shape without the separator reports', async () => {
    const code = `import java.io.*;
import javax.servlet.http.*;

public class Reader {
    public void read(HttpServletRequest req) throws IOException {
        File root = new File("/srv/data");
        File f = new File(root, req.getParameter("name"));
        String base = root.getCanonicalPath();
        if (!f.getCanonicalPath().startsWith(base)) throw new IOException("bad");
        new FileInputStream(f).close();
    }
}
`;
    const r = await analyzeJava(code);
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it('a base that cannot be resolved (a parameter) keeps the existing credit', async () => {
    const code = `import java.io.*;
import javax.servlet.http.*;

public class Reader {
    public void read(HttpServletRequest req, String base) throws IOException {
        File f = new File("/srv/data", req.getParameter("name"));
        if (!f.getCanonicalPath().startsWith(base)) throw new IOException("bad");
        new FileInputStream(f).close();
    }
}
`;
    const r = await analyzeJava(code);
    expect(ptFlows(r)).toHaveLength(0);
  });

  it('separator mid-expression (… + File.separator + "subdir") is not a guard', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith(parent.getCanonicalPath() + File.separator + "subdir") ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it('separator inside replace(...) is not a guard', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith(parent.getCanonicalPath().replace(File.separator, "")) ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it('a literal that merely contains the word "separator" is not a guard', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith("/var/separator") ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

  it('a Windows literal base ending in an escaped backslash stays clean', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith("C:\\\\data\\\\") ) { throw new Exception("outside"); }'));
    expect(ptFlows(r)).toHaveLength(0);
    expect(ptScan(r)).toHaveLength(0);
  });

  it('a parameter base is not poisoned by an assignment in an earlier method', async () => {
    const code = `import java.io.*;
import javax.servlet.http.*;

public class Reader {
    void helper() { String base = parent.getCanonicalPath(); }
    void read(HttpServletRequest req, String base) throws IOException {
        File f = new File("/srv/data", req.getParameter("name"));
        if (!f.getCanonicalPath().startsWith(base)) throw new IOException("bad");
        new FileInputStream(f).close();
    }
}
`;
    const r = await analyzeJava(code);
    expect(ptFlows(r)).toHaveLength(0);
  });

  it('an empty-string literal base is not a guard', async () => {
    const r = await analyzeJava(esapi(
      'if ( !dir.getCanonicalPath().startsWith("") ) { throw new Exception("outside"); }'));
    expect(ptFlows(r).length).toBeGreaterThan(0);
  });

});
