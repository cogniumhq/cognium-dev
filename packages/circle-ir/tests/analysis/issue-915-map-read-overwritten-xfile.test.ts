/**
 * cognium-dev #915 — a map read that is overwritten before use does not start
 * a project-phase xss path.
 *
 * The 23 safe OWASP xss cases the nightly sweep still flags (BenchmarkTest00288,
 * 02135, 02052, …) all come from the project phase, not from per-file flows.
 * Each one reads the request value back out of a local map
 * (`bar = (String) map.get("keyB")`, a `plugin_param` source) and then replaces
 * it before it is used: `bar = (String) map.get("keyA")` reads the literal
 * entry, or the helper returns an unrelated constant-derived value. The
 * interprocedural phase matched the source's variable by name, so it reported
 * the caller-body sink, and it marked the helper's return as a source even
 * when no source value reaches the `return`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const servlet = (doPostBody: string, helperBody = '        return param;') => `package org.example.testcode;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Xss extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("Xss");
        if (param == null) param = "";
${doPostBody}
    }

    private static String doSomething(HttpServletRequest request, String param) throws IOException {
${helperBody}
    }

    static class Holder {
        String v;
    }
}
`;

const OTHER = `package org.example.testcode;

public class Other {
    public static String wrap(String s) {
        return s.trim();
    }
}
`;

async function xssPaths(doPostBody: string, helperBody?: string) {
  const pa = await analyzeProject([
    { filePath: 'Xss.java', code: servlet(doPostBody, helperBody), language: 'java' },
    { filePath: 'Other.java', code: OTHER, language: 'java' },
  ], {});
  return (pa.taint_paths ?? []).filter(p => p.sink.type === 'xss').length;
}

const CALLER_MAP = `        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        bar = (String) map.get("keyB");`;

const SINK_HELPER = `        String bar = doSomething(request, param);
        response.getWriter().write(bar);`;

describe('#915 overwritten map read in the project phase', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('caller reads the request key, then the literal key: clean (BenchmarkTest00288 shape)', async () => {
    expect(await xssPaths(`${CALLER_MAP}
        bar = (String) map.get("keyA");
        response.getWriter().write(bar);`)).toBe(0);
  });

  it('caller sinks the request key read: still fires', async () => {
    expect(await xssPaths(`${CALLER_MAP}
        response.getWriter().write(bar);`)).toBeGreaterThan(0);
  });

  it('caller passes the map read through a helper in another file: still fires', async () => {
    expect(await xssPaths(`${CALLER_MAP}
        bar = Other.wrap(bar);
        response.getWriter().write(bar);`)).toBeGreaterThan(0);
  });

  it('caller sinks a map read that only some paths assign: still fires', async () => {
    expect(await xssPaths(`        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", param);
        String bar = "";
        if (param.length() > 1) {
            bar = (String) map.get("keyB");
        }
        response.getWriter().write(bar);`)).toBeGreaterThan(0);
  });

  it('helper returns a map read that only some paths assign: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", param);
        String bar = "";
        if (param.length() > 1) {
            bar = (String) map.get("keyB");
        }
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper reads the map, then returns an unrelated value: clean (BenchmarkTest02135 shape)', async () => {
    expect(await xssPaths(SINK_HELPER, `        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("key", param);
        String c = (String) map.get("key");
        String d = c.substring(0, c.length() - 1);
        String g = "barbarians_at_the_gate";
        String bar = Other.wrap(g);
        return bar;`)).toBe(0);
  });

  it('helper passes the map read through a statement that spans lines, then returns an unrelated value: clean', async () => {
    expect(await xssPaths(SINK_HELPER, `        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("key", param);
        String c = (String) map.get("key");
        String d = c.substring(0, c.length() - 1);
        String e =
                new String(
                        d.getBytes());
        String f = e.split(" ")[0];
        String g = "barbarians_at_the_gate";
        String bar = Other.wrap(g);
        return bar;`)).toBe(0);
  });

  it('helper reads the request key, then the literal key: clean (BenchmarkTest02052 shape)', async () => {
    expect(await xssPaths(SINK_HELPER, `        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        bar = (String) map.get("keyB");
        bar = (String) map.get("keyA");
        return bar;`)).toBe(0);
  });

  it('helper returns the request key read: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", param);
        String bar = (String) map.get("keyB");
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper returns a value derived from the map read: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", param);
        String c = (String) map.get("keyB");
        String bar = c.substring(0, c.length() - 1);
        return bar;`)).toBeGreaterThan(0);
  });

  // A source that reaches the return through a container or an object field:
  // the Java DFG has no def-use chain for these, so a missing chain is not
  // proof that the return is clean.
  const MAP_READ = `        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", param);
        String c = (String) map.get("keyB");`;

  it('helper builds the request source into a StringBuilder: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `        StringBuilder sb = new StringBuilder();
        String c = request.getHeader("X");
        sb.append("v=").append(c);
        String bar = sb.toString();
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper appends the map read to a StringBuilder: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        StringBuilder sb = new StringBuilder();
        sb.append(c);
        String bar = sb.toString();
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper stores the map read in an array: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        String[] arr = new String[1];
        arr[0] = c;
        String bar = arr[0];
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper adds the map read to a list: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        java.util.List<String> l = new java.util.ArrayList<String>();
        l.add(c);
        String bar = l.get(0);
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper stores the map read in a field: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        Holder h = new Holder();
        h.v = c;
        String bar = h.v;
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper has a lambda that returns a literal, then returns the map read: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        java.util.function.Supplier<String> s = () -> {
            return "x";
        };
        String bar = c;
        return bar;`)).toBeGreaterThan(0);
  });

  // A source stored into an object inside an assignment statement: the
  // assigned local is clean, but the object now carries the source.
  it('helper swaps the request source into an AtomicReference: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `        java.util.concurrent.atomic.AtomicReference<String> ref = new java.util.concurrent.atomic.AtomicReference<String>("");
        String c = request.getHeader("X");
        String old = ref.getAndSet(c);
        String bar = ref.get();
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper swaps the map read into an AtomicReference: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        java.util.concurrent.atomic.AtomicReference<String> ref = new java.util.concurrent.atomic.AtomicReference<String>("");
        String old = ref.getAndSet(c);
        String bar = ref.get();
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper replaces a map entry with the map read: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        Object old = map.replace("keyA", c);
        String bar = (String) map.get("keyA");
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper stores the map read in an array through a chained assignment: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        String[] arr = new String[1];
        String p = arr[0] = c;
        String bar = arr[0];
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper stores the map read in a field through a chained assignment: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        Holder h = new Holder();
        String r = h.v = c;
        String bar = h.v;
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper adds the map read to a list through a static call: still fires', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        java.util.List<String> l = new java.util.ArrayList<String>();
        boolean added = java.util.Collections.addAll(l, c);
        String bar = l.get(0);
        return bar;`)).toBeGreaterThan(0);
  });

  it('helper passes the map read through a static call and a constructor, then returns an unrelated value: clean', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        String d = String.valueOf(c);
        String e = new String(d.getBytes());
        String f = java.net.URLDecoder.decode(e, "UTF-8");
        String g = "barbarians_at_the_gate";
        String bar = Other.wrap(g);
        return bar;`)).toBe(0);
  });

  it('helper has "->" inside a string literal, then returns an unrelated value: clean', async () => {
    expect(await xssPaths(SINK_HELPER, `${MAP_READ}
        String d = c.substring(0, c.length() - 1);
        String g = "a -> b";
        String bar = Other.wrap(g);
        return bar;`)).toBe(0);
  });
});
