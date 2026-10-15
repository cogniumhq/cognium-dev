/**
 * #621 — `ClassLoader.getResource` / `getResourceAsStream` with a name that
 * is not a constant reach a CWE-22 sink again. The CVE-2018-9159 shape is a
 * request-derived resource name handed to a `classLoader` field of the
 * resource class. A string-literal argument stays clean (#233 precision).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { createWithJdkTypes } from '../../src/resolution/type-hierarchy.js';

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
  describe('declared receiver type decides the match (follow-up to #724)', () => {
    const head = `import javax.servlet.http.HttpServletRequest;\n`;

    it('inline fully-qualified Spring ResourceLoader parameter named loader does not fire', async () => {
      const { flows, sinks } = await pathFlows(`${head}
public class InlineFqn {
  public Object load(HttpServletRequest req, org.springframework.core.io.ResourceLoader loader) {
    String name = req.getParameter("n");
    return loader.getResource(name);
  }
}`);
      expect(flows).toEqual([]);
      expect(sinks).toEqual([]);
    });

    it('wildcard-imported Spring ResourceLoader field and parameter named loader do not fire', async () => {
      const { flows, sinks } = await pathFlows(`${head}
import org.springframework.core.io.*;
public class Wildcard {
  private ResourceLoader loader;
  public Object viaField(HttpServletRequest req) {
    return loader.getResource(req.getParameter("n"));
  }
  public Object viaParam(HttpServletRequest req, ResourceLoader loader) {
    String name = req.getParameter("n");
    return loader.getResource(name);
  }
}`);
      expect(flows).toEqual([]);
      expect(sinks).toEqual([]);
    });

    it('wildcard-imported ResourcePatternResolver named classLoader does not fire', async () => {
      const { flows } = await pathFlows(`${head}
import org.springframework.core.io.support.*;
public class Resolver {
  public Object find(HttpServletRequest req, ResourcePatternResolver classLoader) throws Exception {
    return classLoader.getResources(req.getParameter("n"));
  }
  public Object one(HttpServletRequest req, ResourcePatternResolver classLoader) {
    return classLoader.getResource(req.getParameter("n"));
  }
}`);
      expect(flows).toEqual([]);
    });

    it('a user type declared in the same file that does not extend ClassLoader does not fire', async () => {
      const { flows, sinks } = await pathFlows(`${head}
public class UserType {
  public Object a(HttpServletRequest req, MyLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
  public Object b(HttpServletRequest req, TemplateClassPathLoader classLoader) {
    return classLoader.getResourceAsStream(req.getParameter("n"));
  }
}
class MyLoader {
  Object getResource(String n) { return n; }
}
class TemplateClassPathLoader {
  Object getResourceAsStream(String n) { return n; }
}`);
      expect(flows).toEqual([]);
      expect(sinks).toEqual([]);
    });

    it('a same-file user type whose own parent is in the same file and not a ClassLoader does not fire', async () => {
      const { flows } = await pathFlows(`${head}
public class Chain {
  public Object a(HttpServletRequest req, ChildLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}
class BaseLoader {
  Object getResource(String n) { return n; }
}
class ChildLoader extends BaseLoader {}`);
      expect(flows).toEqual([]);
    });

    it('keeps firing: an imported custom loader type declared in another file', async () => {
      const { flows } = await pathFlows(`package com.acme.web;
import javax.servlet.http.HttpServletRequest;
import com.acme.loading.MyLoader;
public class Imported {
  public java.net.URL find(HttpServletRequest req, MyLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a same-package custom loader type with no declaration in this file', async () => {
      const { flows } = await pathFlows(`package com.acme.web;
import javax.servlet.http.HttpServletRequest;
public class SamePackage {
  public java.io.InputStream open(HttpServletRequest req, MyLoader loader) {
    String name = req.getParameter("n");
    return loader.getResourceAsStream(name);
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a same-file user type whose parent is declared elsewhere', async () => {
      const { flows } = await pathFlows(`${head}
import com.acme.loading.BaseLoader;
public class ExternalParent {
  public java.net.URL find(HttpServletRequest req, MyLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}
class MyLoader extends BaseLoader {}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a same-file subclass of URLClassLoader', async () => {
      const { flows } = await pathFlows(`${head}
import java.net.URL;
import java.net.URLClassLoader;
public class UrlSub {
  public URL find(HttpServletRequest req, MyLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}
class MyLoader extends URLClassLoader {
  MyLoader() { super(new URL[0]); }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a same-file URLClassLoader subclass whose receiver name does not look like a loader', async () => {
      const { flows } = await pathFlows(`${head}
import java.net.URL;
import java.net.URLClassLoader;
public class Plugins {
  public URL find(HttpServletRequest req, PluginRepo repo) {
    return repo.getResource(req.getParameter("n"));
  }
}
class PluginRepo extends URLClassLoader {
  PluginRepo() { super(new URL[0]); }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('registers the JDK class loader chain in the common type hierarchy', () => {
      const h = createWithJdkTypes();
      expect(h.isSubtypeOf('java.net.URLClassLoader', 'ClassLoader')).toBe(true);
      expect(h.isSubtypeOf('URLClassLoader', 'java.lang.ClassLoader')).toBe(true);
      expect(h.isSubtypeOf('SecureClassLoader', 'ClassLoader')).toBe(true);
      expect(h.isSubtypeOf('URLClassLoader', 'SecureClassLoader')).toBe(true);
      expect(h.isSubtypeOf('ClassLoader', 'URLClassLoader')).toBe(false);
    });

    it('keeps firing: a same-file subclass of SecureClassLoader (fully qualified)', async () => {
      const { flows } = await pathFlows(`${head}
public class SecureSub {
  public java.io.InputStream open(HttpServletRequest req, MyLoader loader) {
    return loader.getResourceAsStream(req.getParameter("n"));
  }
}
class MyLoader extends java.security.SecureClassLoader {}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: this.classLoader field typed as a custom URLClassLoader subclass', async () => {
      const { flows } = await pathFlows(`${head}
import java.net.URL;
import java.net.URLClassLoader;
public class Holder {
  private final MyLoader classLoader;
  public Holder(MyLoader classLoader) { this.classLoader = classLoader; }
  public URL find(HttpServletRequest req) {
    return this.classLoader.getResource(req.getParameter("n"));
  }
}
class MyLoader extends URLClassLoader {
  MyLoader() { super(new URL[0]); }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: this.classLoader field typed as a custom loader declared elsewhere', async () => {
      const { flows } = await pathFlows(`package com.acme.web;
import javax.servlet.http.HttpServletRequest;
public class Holder {
  private final MyLoader classLoader;
  public Holder(MyLoader classLoader) { this.classLoader = classLoader; }
  public java.io.InputStream open(HttpServletRequest req) {
    return this.classLoader.getResourceAsStream(req.getParameter("n"));
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a method type parameter bounded by ClassLoader', async () => {
      const { flows } = await pathFlows(`${head}
public class Generic {
  public <T extends ClassLoader> java.net.URL find(HttpServletRequest req, T loader) {
    String name = req.getParameter("n");
    return loader.getResource(name);
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a class type parameter bounded by ClassLoader', async () => {
      const { flows } = await pathFlows(`${head}
public class GenericHolder<T extends ClassLoader> {
  private T loader;
  public java.io.InputStream open(HttpServletRequest req) {
    return loader.getResourceAsStream(req.getParameter("n"));
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('a field typed Object named loader does not fire', async () => {
      const { sinks } = await pathFlows(`${head}
public class Untyped {
  private Object loader;
  public Object a(HttpServletRequest req) {
    return loader.getResource(req.getParameter("n"));
  }
}`);
      expect(sinks).toEqual([]);
    });

    it('keeps firing: java.lang.ClassLoader written inline with a tainted name', async () => {
      const { flows } = await pathFlows(`${head}
public class InlineClassLoader {
  public java.net.URL find(HttpServletRequest req, java.lang.ClassLoader loader) {
    String name = req.getParameter("n");
    return loader.getResource(name);
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: ClassLoader receiver named loader with a tainted name', async () => {
      const { flows } = await pathFlows(`${head}
public class Plain {
  public java.net.URL find(HttpServletRequest req, ClassLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: URLClassLoader receiver (a ClassLoader subtype)', async () => {
      const { flows } = await pathFlows(`${head}
import java.net.URLClassLoader;
public class UrlLoader {
  public java.net.URL find(HttpServletRequest req, URLClassLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: receiver is Thread.currentThread().getContextClassLoader()', async () => {
      const { flows } = await pathFlows(`${head}
public class ContextLoader {
  public java.io.InputStream open(HttpServletRequest req) {
    String name = req.getParameter("n");
    return Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a local var initialised from getContextClassLoader()', async () => {
      const { flows } = await pathFlows(`${head}
public class VarLoader {
  public java.net.URL open(HttpServletRequest req) {
    var loader = Thread.currentThread().getContextClassLoader();
    return loader.getResource(req.getParameter("n"));
  }
}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('keeps firing: a user subclass of ClassLoader declared in the same file', async () => {
      const { flows } = await pathFlows(`${head}
public class Sub {
  public java.net.URL open(HttpServletRequest req, PluginClassLoader loader) {
    return loader.getResource(req.getParameter("n"));
  }
}
class PluginClassLoader extends ClassLoader {}`);
      expect(flows.length).toBeGreaterThan(0);
    });

    it('literal names stay clean for every receiver shape', async () => {
      const { flows, sinks } = await pathFlows(`${head}
import org.springframework.core.io.*;
public class Literals {
  public Object a(ClassLoader loader, java.net.URLClassLoader u, ResourceLoader r, MyLoader m) {
    Object x = loader.getResource("a.txt");
    Object y = u.getResourceAsStream("b.txt");
    Object z = r.getResource("classpath:c.txt");
    Object w = m.getResource("d.txt");
    return Thread.currentThread().getContextClassLoader().getResource("e.txt");
  }
}`);
      expect(flows).toEqual([]);
      expect(sinks).toEqual([]);
    });
  });
});
