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
import { generateFindings } from '../../src/analysis/findings.js';

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

  it('a local that shadows a tainted field stays clean; this.name still fires', async () => {
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
        good(resp);
    }

    private void f(ServletResponse resp) throws IOException {
        PrintWriter writer = resp.getWriter();
        writer.println(this.name);
    }

    private void good(ServletResponse resp) throws IOException {
        PrintWriter writer = resp.getWriter();
        String name = "readme.txt";
        writer.println(name);
    }
}
`;
    const ir = await analyze(code, 'T.java', 'java');
    const xss = (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss');
    const sinkLines = [...new Set(xss.map(f => f.sink_line))].sort((a, b) => a - b);
    // this.name in f() — line 18
    expect(sinkLines).toContain(18);
    // local name in good() — line 24
    expect(sinkLines).not.toContain(24);
  });
});

describe('#614 field-use check is scoped to this class and to the sink\'s own overload', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('`item.name` on another object does not share the tainted field; this.name still fires', async () => {
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
        good(resp);
    }

    private void f(ServletResponse resp) throws IOException {
        PrintWriter writer = resp.getWriter();
        writer.println(this.name);
    }

    private void good(ServletResponse resp) throws IOException {
        PrintWriter writer = resp.getWriter();
        Item item = new Item();
        writer.println(item.name);
    }
}

class Item {
    String name = "readme.txt";
}
`;
    const ir = await analyze(code, 'T.java', 'java');
    const xss = (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss');
    const sinkLines = [...new Set(xss.map(f => f.sink_line))].sort((a, b) => a - b);
    // this.name in f() — line 18
    expect(sinkLines).toContain(18);
    // item.name in good() — line 24
    expect(sinkLines).not.toContain(24);
  });

  it('an overload that declares a local of the field\'s name is not a bare field read', async () => {
    const code = `import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FieldHop {
    private String name;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        name = req.getParameter("name");
        show(resp);
        show(resp, 1);
    }

    private void show(ServletResponse resp) throws IOException {
        PrintWriter writer = resp.getWriter();
        writer.println(name);
    }

    private void show(ServletResponse resp, int n) throws IOException {
        PrintWriter writer = resp.getWriter();
        String name = "readme.txt";
        writer.println(name);
    }
}
`;
    const ir = await analyze(code, 'T.java', 'java');
    const xss = (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss');
    const sinkLines = [...new Set(xss.map(f => f.sink_line))].sort((a, b) => a - b);
    // bare field read in show(resp) — line 18
    expect(sinkLines).toContain(18);
    // shadowing local in show(resp, n) — line 24
    expect(sinkLines).not.toContain(24);
  });
});

describe('#614 call-chain source (SecuriBench Inter3 shape) stays pinned', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // Shorter stand-in for SecuriBench Micro Inter3: a request parameter flows
  // through two private methods to a sink, with an unused public method that
  // reuses the same parameter name below it. This fixture pins the real
  // getParameter line as the finding's primary source on a two-hop chain.
  // On the real nine-method Inter3 row, hop decay can still let findings
  // grouping prefer the dead parameter via proximity; re-ranking that
  // (prefer a flow-backed source) remains a follow-up. Before #614 the
  // bare-name match credited doGet's `name` onto the unused method's sink.
  const code = `import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ChainServlet extends HttpServlet {
    private PrintWriter writer;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        writer = resp.getWriter();
        a(name);
    }

    private void a(String name) {
        b(name);
    }

    private void b(String name) {
        writer.println(name);
    }

    public void unused(String name) {
        writer.println(name);
    }
}
`;

  it('taint.flows keeps the getParameter line (11) as the source of the chain sink (line 21)', async () => {
    const ir = await analyze(code, 'ChainServlet.java', 'java');
    const xss = (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss' && f.sink_line === 21);
    expect(xss.map(f => f.source_line)).toContain(11);
  });

  it('the finding at line 21 is attributed to the getParameter line, not the dead parameter (24)', async () => {
    const ir = await analyze(code, 'ChainServlet.java', 'java');
    const findings = generateFindings(
      ir.taint.sources ?? [], ir.taint.sinks ?? [], ir.dfg, 'ChainServlet.java', code, 'java',
      ir.taint.sanitizers ?? [], ir.types ?? [], ir.taint.flows ?? [],
    );
    const atSink = findings.filter(f => f.type === 'xss' && f.sink.line === 21);
    expect(atSink).toHaveLength(1);
    expect(atSink[0].source.line).toBe(11);
    expect((atSink[0].evidence?.sources ?? []).map(s => s.line)).toContain(11);
  });
});

