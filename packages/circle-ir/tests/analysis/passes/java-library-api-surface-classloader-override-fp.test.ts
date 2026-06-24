/**
 * Sprint 47 — cognium-dev #168.
 *
 * Java `code_injection` (CWE-94) fires HIGH inside `ClassLoader` subclass
 * overrides of `loadClass(String)` / `findClass(String)`. These methods
 * are *required by the JDK contract* to look up the named class — the
 * trust decision belongs to whoever invokes the loader, not the loader
 * implementation itself.
 *
 * Stage 9g in `sink-filter-pass.ts` tags such sinks with
 * `library-api-surface:caller-responsibility` when the enclosing class
 * extends `ClassLoader` / `URLClassLoader` / `SecureClassLoader` OR is
 * named `*ClassLoader` / `*CachingProvider`, OR the sink lives inside a
 * `public/protected Class<?> loadClass/findClass(String)` method body.
 * Severity is then downgraded to MEDIUM via the central hook.
 *
 * Recall: arbitrary `Class.forName(<tainted>)` outside a classloader
 * override remains untagged HIGH.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import { LIBRARY_API_SURFACE_TAG } from '../../../src/analysis/library-api-surface-downgrade.js';

const codeInjectionSinks = (
  arr: Array<{ type?: string; tags?: string[]; line?: number; method?: string }> | undefined,
) => (arr ?? []).filter((s) => s.type === 'code_injection');

describe('cognium-dev #168 — ClassLoader override library-API surface', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP — subclass extends ClassLoader, overrides loadClass — any sink
  //         inside the body is tagged.
  // --------------------------------------------------------------------------
  it('extends ClassLoader + loadClass override — sink tagged', async () => {
    const code = `
public class MyLoader extends ClassLoader {
  public Class<?> loadClass(String name) throws ClassNotFoundException {
    return Class.forName(name);
  }
}`;
    const r = await analyze(code, 'MyLoader.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    // Every code_injection sink inside the override body should be tagged.
    for (const s of sinks) {
      expect(s.tags?.includes(LIBRARY_API_SURFACE_TAG)).toBe(true);
    }
  });

  // --------------------------------------------------------------------------
  // 2. FP — subclass extends URLClassLoader, overrides findClass — tagged
  // --------------------------------------------------------------------------
  it('extends URLClassLoader + findClass override — sink tagged', async () => {
    const code = `
import java.net.URLClassLoader;
import java.net.URL;
public class PluginLoader extends URLClassLoader {
  public PluginLoader(URL[] urls) { super(urls); }
  protected Class<?> findClass(String name) throws ClassNotFoundException {
    return Class.forName(name);
  }
}`;
    const r = await analyze(code, 'PluginLoader.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    for (const s of sinks) {
      expect(s.tags?.includes(LIBRARY_API_SURFACE_TAG)).toBe(true);
    }
  });

  // --------------------------------------------------------------------------
  // 3. FP — class name *CachingProvider with loadClass override — tagged
  // --------------------------------------------------------------------------
  it('class name *CachingProvider + loadClass override — sink tagged', async () => {
    const code = `
public class CacheCachingProvider {
  public Class<?> loadClass(String name) throws ClassNotFoundException {
    return Class.forName(name);
  }
}`;
    const r = await analyze(code, 'CacheCachingProvider.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    for (const s of sinks) {
      expect(s.tags?.includes(LIBRARY_API_SURFACE_TAG)).toBe(true);
    }
  });

  // --------------------------------------------------------------------------
  // 4. Recall — Class.forName(tainted) inside a *non-loader* class is NOT
  //             tagged (real HIGH sink).
  // --------------------------------------------------------------------------
  it('recall: Class.forName(tainted) in business class — NOT tagged', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
public class PluginService {
  public Object resolve(HttpServletRequest req) throws Exception {
    String impl = req.getParameter("impl");
    return Class.forName(impl);
  }
}`;
    const r = await analyze(code, 'PluginService.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'forName');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 5. Recall — class extends a non-ClassLoader parent — NOT tagged
  // --------------------------------------------------------------------------
  it('recall: extends ArrayList with method called loadClass — NOT tagged', async () => {
    const code = `
import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;
public class WeirdList extends ArrayList<String> {
  public Object lookup(HttpServletRequest req) throws Exception {
    String name = req.getParameter("c");
    return Class.forName(name);
  }
}`;
    const r = await analyze(code, 'WeirdList.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'forName');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });
});
