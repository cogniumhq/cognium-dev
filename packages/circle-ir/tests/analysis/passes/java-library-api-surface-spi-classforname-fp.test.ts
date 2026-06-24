/**
 * Sprint 47 — cognium-dev #165.
 *
 * Java `code_injection` (CWE-94) fires HIGH on `Class.forName(<var>)` when
 * the loader is implementing the Java SPI (`META-INF/services/...`) pattern.
 * The SPI mechanism is *designed* to instantiate caller-declared
 * implementation classes; flagging it as code-injection is a false positive
 * at the library-API boundary.
 *
 * Stage 9f in `sink-filter-pass.ts` tags such sinks with
 * `library-api-surface:caller-responsibility` when the enclosing source
 * file contains a `getResources("META-INF/services/...")` call within ±30
 * lines of the `Class.forName(<var>)` callsite. Severity is then downgraded
 * to MEDIUM via the central hook in `analyzer.ts`.
 *
 * Recall: arbitrary `Class.forName(<user-input>)` outside the SPI pattern
 * remains untagged and fires at full HIGH severity.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import { LIBRARY_API_SURFACE_TAG } from '../../../src/analysis/library-api-surface-downgrade.js';

const codeInjectionSinks = (
  arr: Array<{ type?: string; tags?: string[]; line?: number; method?: string }> | undefined,
) => (arr ?? []).filter((s) => s.type === 'code_injection');

describe('cognium-dev #165 — SPI Class.forName library-API surface', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP — Class.forName fed by getResources("META-INF/services/...") loader
  // --------------------------------------------------------------------------
  it('SPI loader: Class.forName(tainted) with META-INF/services nearby — tagged', async () => {
    const code = `
import java.util.Enumeration;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
public class SpiLoader {
  public Object load(ClassLoader cl, HttpServletRequest req) throws Exception {
    Enumeration<URL> urls = cl.getResources("META-INF/services/foo.Bar");
    String name = req.getParameter("impl");
    Class<?> klass = Class.forName(name);
    return klass.getDeclaredConstructor().newInstance();
  }
}`;
    const r = await analyze(code, 'SpiLoader.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'forName');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.every((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 2. FP — single-line SPI resource pattern variant
  // --------------------------------------------------------------------------
  it('SPI loader with different services subpath — tagged', async () => {
    const code = `
import java.net.URL;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;
public class JdbcLoader {
  public Class<?> resolve(ClassLoader cl, HttpServletRequest req) throws Exception {
    Enumeration<URL> svc = cl.getResources("META-INF/services/java.sql.Driver");
    String impl = req.getParameter("driver");
    return Class.forName(impl);
  }
}`;
    const r = await analyze(code, 'JdbcLoader.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'forName');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.every((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 3. Recall — Class.forName(tainted) with NO META-INF/services pattern
  //             nearby remains a real HIGH sink (untagged).
  // --------------------------------------------------------------------------
  it('recall: Class.forName(tainted) without SPI pattern — NOT tagged', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
public class Loader {
  public Class<?> load(HttpServletRequest req) throws Exception {
    String name = req.getParameter("cls");
    return Class.forName(name);
  }
}`;
    const r = await analyze(code, 'Loader.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'forName');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 4. Recall — getResources("config.properties") nearby is NOT SPI; sink
  //             remains untagged HIGH.
  // --------------------------------------------------------------------------
  it('recall: getResources("config.properties") near Class.forName — NOT tagged', async () => {
    const code = `
import java.net.URL;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;
public class CfgLoader {
  public Class<?> resolve(ClassLoader cl, HttpServletRequest req) throws Exception {
    Enumeration<URL> cfg = cl.getResources("config.properties");
    String impl = req.getParameter("driver");
    return Class.forName(impl);
  }
}`;
    const r = await analyze(code, 'CfgLoader.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'forName');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });
});
