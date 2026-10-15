/**
 * #621 — `ClassLoader.getResource` / `getResourceAsStream` with a name that
 * is not a constant reach a CWE-22 sink again. The CVE-2018-9159 shape is a
 * request-derived resource name handed to a `classLoader` field of the
 * resource class. A string-literal argument stays clean (#233 precision).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const pathFlows = async (code: string, file = 'Probe.java') => {
  const r = await analyze(code, file, 'java');
  return {
    flows: (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'path_traversal'),
    sinks: (r.taint?.sinks ?? []).filter((s: any) => s.type === 'path_traversal'),
  };
};

describe('ClassLoader resource lookup as CWE-22 sink (#621)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('constructor-supplied name reaching this.classLoader.getResourceAsStream fires', async () => {
    const { flows } = await pathFlows(`
import javax.servlet.http.HttpServletRequest;
public class StaticFiles {
  private final String location;
  private final ClassLoader loader;
  public StaticFiles(String location) {
    this.location = location;
    this.loader = Thread.currentThread().getContextClassLoader();
  }
  public java.io.InputStream open(HttpServletRequest req) {
    String name = req.getParameter("file");
    return this.loader.getResourceAsStream(name);
  }
}`);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows[0].sink_type).toBe('path_traversal');
  });

  it('request-derived name reaching this.classLoader.getResource fires (field receiver)', async () => {
    const { flows } = await pathFlows(`
import javax.servlet.http.HttpServletRequest;
public class Assets {
  private ClassLoader classLoader = Assets.class.getClassLoader();
  public java.net.URL find(HttpServletRequest req) {
    String rel = req.getParameter("p");
    return this.classLoader.getResource(rel);
  }
}`);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('parameter ClassLoader receiver with tainted name fires', async () => {
    const { flows } = await pathFlows(`
import javax.servlet.http.HttpServletRequest;
public class Lookup {
  public java.net.URL find(ClassLoader cl, HttpServletRequest req) {
    return cl.getResource(req.getParameter("n"));
  }
}`);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('Spark ClassPathResource shape: public constructor path reaches the loader lookup', async () => {
    const { sinks } = await pathFlows(`
public class PathResource {
  private final String path;
  private final ClassLoader classLoader;
  public PathResource(String path) {
    this.path = path;
    this.classLoader = Thread.currentThread().getContextClassLoader();
  }
  public java.io.InputStream getInputStream() {
    return this.classLoader.getResourceAsStream(this.path);
  }
  public java.net.URL getURL() {
    return this.classLoader.getResource(this.path);
  }
}`);
    expect(sinks.map((s: any) => s.method).sort()).toEqual(['getResource', 'getResourceAsStream']);
  });

  it('CVE-2018-9159 shape: constructor path reaches both loader lookups as flows', async () => {
    const { flows } = await pathFlows(`
package spark.resource;
public class ClassPathResource extends AbstractFileResolvingResource {
  private final String path;
  private ClassLoader classLoader;
  public ClassPathResource(String path) { this(path, (ClassLoader) null); }
  public ClassPathResource(String path, ClassLoader classLoader) {
    this.path = path;
    this.classLoader = (classLoader != null ? classLoader : getDefaultClassLoader());
  }
  public InputStream getInputStream() throws IOException {
    InputStream is = this.classLoader.getResourceAsStream(this.path);
    return is;
  }
  public URL getURL() throws IOException {
    URL url = this.classLoader.getResource(this.path);
    return url;
  }
}`, 'ClassPathResource.java');
    expect(flows.map((f: any) => f.sink_line).sort((a: number, b: number) => a - b)).toEqual([12, 16]);
  });

  it('safe mirror: constant resource name is clean', async () => {
    const { flows, sinks } = await pathFlows(`
import javax.servlet.http.HttpServletRequest;
public class Fixed {
  private final ClassLoader loader = Fixed.class.getClassLoader();
  public java.io.InputStream open(HttpServletRequest req) {
    String ignored = req.getParameter("file");
    return this.loader.getResourceAsStream("templates/index.html");
  }
  public java.net.URL url(ClassLoader cl) {
    return cl.getResource("META-INF/app.properties");
  }
}`);
    expect(flows).toEqual([]);
    expect(sinks).toEqual([]);
  });

  it('safe mirror: a name held in a constant is clean', async () => {
    const { flows } = await pathFlows(`
import javax.servlet.http.HttpServletRequest;
public class Fixed2 {
  private static final String NAME = "banner.txt";
  public java.io.InputStream open(ClassLoader cl, HttpServletRequest req) {
    String ignored = req.getParameter("file");
    return cl.getResourceAsStream(NAME);
  }
}`);
    expect(flows).toEqual([]);
  });

  it('does not widen to Class.getResource or a Spring ResourceLoader', async () => {
    const { flows } = await pathFlows(`
import javax.servlet.http.HttpServletRequest;
import org.springframework.core.io.ResourceLoader;
public class Other {
  public Object a(HttpServletRequest req, ResourceLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
  public Object b(HttpServletRequest req) {
    return Other.class.getResource(req.getParameter("n"));
  }
}`);
    expect(flows).toEqual([]);
  });
});
