/**
 * #584 (slice) — extend the #328 gate: a `Map*.get("<k>")` read on a map that
 * is constructed locally, never escapes, and only ever receives string-literal
 * values yields a literal, so it is not a `plugin_param` source. The source
 * registrations are unchanged; a map that holds (or may hold) anything tainted
 * keeps its source, and so do non-local and escaping maps.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const mapSources = (r: IR) =>
  (r.taint.sources ?? []).filter(s => s.type === 'plugin_param' && /\.get\(\)/.test(s.location ?? ''));
const sinkTypes = (r: IR) => new Set((r.taint.flows ?? []).map(f => f.sink_type));

const servlet = (body: string[], extra: string[] = []) =>
  analyze(
    [
      'import java.io.*;',
      'import java.util.*;',
      'import javax.servlet.http.*;',
      'public class T extends HttpServlet {',
      '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {',
      ...body.map(l => '    ' + l),
      '  }',
      ...extra,
      '}',
    ].join('\n'),
    'T.java',
    'java',
  );

describe('#584 literal-only local map reads are not plugin_param sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('WelcomeServlet: no source and no xss', async () => {
    const r = await analyze(`import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WelcomeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String> labels = new HashMap<>();
        labels.put("title", "Welcome");
        response.getWriter().println(labels.get("title"));
    }
}
`, 'WelcomeServlet.java', 'java');
    expect(mapSources(r)).toHaveLength(0);
    expect(sinkTypes(r).has('xss')).toBe(false);
  });

  it('inline literal-only reads in sql / command / path sinks have no source or flow', async () => {
    const r = await servlet([
      'Map<String, String> tables = new HashMap<>();',
      'tables.put("users", "app_users");',
      'java.sql.Statement st = null;',
      'st.executeQuery("SELECT * FROM " + tables.get("users"));',
      'Map<String, String> tools = new HashMap<>();',
      'tools.put("ls", "/bin/ls");',
      'Runtime.getRuntime().exec(tools.get("ls"));',
      'Map<String, String> paths = new TreeMap<>();',
      'paths.put("cfg", "/etc/app.cfg");',
      'new File(paths.get("cfg"));',
    ]);
    expect(mapSources(r)).toHaveLength(0);
    expect((r.taint.flows ?? []).filter(f => f.source_line === f.sink_line)).toHaveLength(0);
  });

  it('is rename-proof and covers a read held in a local first', async () => {
    const r = await servlet([
      'HashMap<String, String> zz = new HashMap<String, String>();',
      'zz.put("k1", "v1");',
      'zz.put("k2", "v2");',
      'String got = zz.get("k2");',
      'response.getWriter().println(got);',
    ]);
    expect(mapSources(r)).toHaveLength(0);
    expect(sinkTypes(r).has('xss')).toBe(false);
  });

  it('ReportFilterServlet: a tainted put keeps the source and the xss', async () => {
    const r = await servlet([
      'Map<String, String> fields = new HashMap<>();',
      'fields.put("region", request.getParameter("region"));',
      'response.getWriter().print(fields.get("region"));',
    ]);
    expect(mapSources(r).length).toBeGreaterThan(0);
    expect(sinkTypes(r).has('xss')).toBe(true);
    expect((r.taint.flows ?? []).some(f => f.sink_type === 'xss' && f.source_type === 'http_param')).toBe(true);
  });

  it('keeps the source on a tainted key when another key is literal-only', async () => {
    const r = await servlet([
      'Map<String, String> m = new HashMap<>();',
      'm.put("title", "Welcome");',
      'm.put("other", request.getParameter("o"));',
      'response.getWriter().println(m.get("other"));',
    ]);
    expect(mapSources(r).length).toBeGreaterThan(0);
    expect(sinkTypes(r).has('xss')).toBe(true);
  });

  it('keeps the source when the map is mutated through putAll / compute / merge', async () => {
    for (const mut of [
      'm.putAll(other);',
      'm.merge("title", other.get("t"), (a, b) -> b);',
      'm.computeIfAbsent("title", kk -> request.getParameter("x"));',
    ]) {
      const r = await servlet([
        'Map<String, String> other = new HashMap<>();',
        'Map<String, String> m = new HashMap<>();',
        'm.put("title", "Welcome");',
        mut,
        'response.getWriter().println(m.get("title"));',
      ]);
      expect(mapSources(r).filter(s => s.line === 10).length, mut).toBeGreaterThan(0);
    }
  });

  it('key shuffle: literal key b stays clean when key a is tainted', async () => {
    const r = await servlet([
      'Map<String, String> m = new HashMap<>();',
      'm.put("a", request.getParameter("x"));',
      'm.put("b", "fixed");',
      'response.getWriter().println(m.get("b"));',
    ]);
    expect(mapSources(r)).toHaveLength(0);
    expect(sinkTypes(r).has('xss')).toBe(false);
  });

  it('key shuffle: read of key a still reports when that key is tainted', async () => {
    const r = await servlet([
      'Map<String, String> m = new HashMap<>();',
      'm.put("a", request.getParameter("x"));',
      'm.put("b", "fixed");',
      'response.getWriter().println(m.get("a"));',
    ]);
    expect(mapSources(r).length).toBeGreaterThan(0);
    expect(sinkTypes(r).has('xss')).toBe(true);
  });

  it('field-held map filled with literals in the constructor is not a source (named-query shape)', async () => {
    const r = await analyze(
      `import java.io.IOException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NamedQueryServlet extends HttpServlet {
  private final Map<String, String> queries = new HashMap<>();

  public NamedQueryServlet() {
    queries.put("all", "SELECT id FROM users");
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Statement st = null;
    st.executeQuery(queries.get("all"));
    response.getWriter().println(queries.get("all"));
  }
}
`,
      'NamedQueryServlet.java',
      'java',
    );
    expect(mapSources(r)).toHaveLength(0);
    expect(sinkTypes(r).has('xss')).toBe(false);
    expect(sinkTypes(r).has('sql_injection')).toBe(false);
  });

  it('field map with a tainted put still reports xss', async () => {
    const r = await analyze(
      `import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MutableFieldMapServlet extends HttpServlet {
  private final Map<String, String> labels = new HashMap<>();

  public MutableFieldMapServlet() {
    labels.put("title", "Welcome");
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    labels.put("title", request.getParameter("t"));
    response.getWriter().println(labels.get("title"));
  }
}
`,
      'MutableFieldMapServlet.java',
      'java',
    );
    expect(mapSources(r).length).toBeGreaterThan(0);
    expect(sinkTypes(r).has('xss')).toBe(true);
  });

  it('keeps the source for a map that is not locally constructed, or that escapes (#328 negatives)', async () => {
    const a = await servlet([
      'Map<String, String> m = getConfig();',
      'response.getWriter().println(m.get("b"));',
    ], ['  private Map<String, String> getConfig() { return null; }']);
    expect(mapSources(a).length).toBeGreaterThan(0);

    const b = await servlet([
      'Map<String, String> m = new HashMap<>();',
      'm.put("b", "lit");',
      'fill(m);',
      'response.getWriter().println(m.get("b"));',
    ], ['  private void fill(Map<String, String> x) { x.put("b", "z"); }']);
    expect(mapSources(b).length).toBeGreaterThan(0);
  });
});
