/**
 * #614 (slice) — a same-named local in a safe sibling method is not tainted.
 *
 * Const-prop reports tainted names as `method:var` plus an unscoped alias of
 * each. The collection / iterator flow supplement matched a sink argument on
 * the UNSCOPED alias, so when `bad()` and `good*()` used the same local names
 * (the Juliet layout: `data`, `root`, `file`), the safe method's sink was
 * credited to the vulnerable method's taint, anchored to the nearest unrelated
 * source in the safe method (`System.getProperty("os.name")`). Membership is now
 * decided by the sink's own method whenever scoped entries exist for the name.
 * A field assigned in one method and used in another stays tainted in both
 * (SecuriBench Inter4); only locals are scoped.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowSinkLines = async (code: string, type: string) => {
  const ir = await analyze(code, 'T.java', 'java');
  return [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))].sort((a, b) => a - b);
};

const PREVIEW = `import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class UploadPreview {
    public void previewDefault() throws IOException {
        String fileName = "readme.txt";
        String baseDir;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            baseDir = "C:\\\\previews\\\\";
        } else {
            baseDir = "/srv/previews/";
        }
        File target = new File(baseDir + fileName);
        if (target.exists()) {
            FileInputStream in = new FileInputStream(target);
            in.close();
        }
    }

    public void previewFromEnv() throws IOException {
        String fileName = System.getenv("PREVIEW_FILE");
        String baseDir;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            baseDir = "C:\\\\previews\\\\";
        } else {
            baseDir = "/srv/previews/";
        }
        File target = new File(baseDir + fileName);
        if (target.exists()) {
            FileInputStream in = new FileInputStream(target);
            in.close();
        }
    }
}
`;

describe('#614 a same-named local in another method is not tainted', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('previewDefault (lines 14, 16) is clean; previewFromEnv (29, 31) still fires', async () => {
    const lines = await flowSinkLines(PREVIEW, 'path_traversal');
    expect(lines).not.toContain(14);
    expect(lines).not.toContain(16);
    expect(lines).toEqual(expect.arrayContaining([29, 31]));
  });

  it('is rename-proof: different method, class and variable names behave the same', async () => {
    const code = PREVIEW
      .replace(/UploadPreview/g, 'Shelf').replace(/previewDefault/g, 'quiet').replace(/previewFromEnv/g, 'loud')
      .replace(/fileName/g, 'leaf').replace(/baseDir/g, 'root').replace(/target/g, 'node');
    const lines = await flowSinkLines(code, 'path_traversal');
    expect(lines).not.toContain(16);
    expect(lines).toEqual(expect.arrayContaining([31]));
  });

  it('the XPath variant (CWE-643) splits the same way', async () => {
    const code = `import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

public class Lookup {
    public String lookupDefault() throws Exception {
        String name = "alice";
        String prefix;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            prefix = "//win/";
        } else {
            prefix = "//nix/";
        }
        String query = prefix + name;
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate(query, (Object) null);
    }

    public String lookupFromEnv() throws Exception {
        String name = System.getenv("LOOKUP_NAME");
        String prefix;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            prefix = "//win/";
        } else {
            prefix = "//nix/";
        }
        String query = prefix + name;
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate(query, (Object) null);
    }
}
`;
    const lines = await flowSinkLines(code, 'xpath_injection');
    expect(lines).not.toContain(15);
    expect(lines).toContain(28);
  });

  it('a field assigned in one method and written in another stays tainted', async () => {
    const code = `import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FieldHop {
    private String name;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        name = req.getParameter("name");
        f(resp);
    }

    private void f(ServletResponse resp) throws IOException {
        PrintWriter writer = resp.getWriter();
        writer.println(this.name);
    }
}
`;
    const lines = await flowSinkLines(code, 'xss');
    expect(lines).toContain(17);
  });
});
