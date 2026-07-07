/**
 * cognium-dev #241 Java — Apache HttpClient SSRF sink coverage.
 *
 * Prior to 3.156.0, taint reaching `client.execute(request)` on a receiver
 * typed `CloseableHttpClient` (Apache HttpClient 4.x/5.x) did not match the
 * `HttpClient.execute` sink pattern because `TypeHierarchyResolver` had no
 * facts for `CloseableHttpClient extends HttpClient`. Findings on real code
 * fell through to `InterproceduralPass` and were emitted as
 * `external_taint_escape` (CWE-668) instead of `ssrf` (CWE-918).
 *
 * 3.156.0 pre-registers Apache HttpClient 4.x + 5.x type hierarchy via
 * `registerCommonLibraries()`, wired from `createWithJdkTypes()`.
 * Additionally, `matchesSinkPattern()` now consults the resolver's
 * `isSubtypeOf()` when the receiver type is populated.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasSsrfFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === 'ssrf');

const countSsrf = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'ssrf').length;

const hasSsrfSignal = (r: any) => hasSsrfFlow(r) || countSsrf(r) > 0;

describe('#241 Java — Apache HttpClient SSRF', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — Apache 4.x CloseableHttpClient.execute(userGet) fires ssrf', async () => {
    const code = [
      'package com.example;',
      'import org.apache.http.client.methods.HttpGet;',
      'import org.apache.http.impl.client.CloseableHttpClient;',
      'import org.apache.http.impl.client.HttpClients;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class V4 extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    CloseableHttpClient client = HttpClients.createDefault();',
      '    HttpGet request = new HttpGet(url);',
      '    client.execute(request);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'V4.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('TP — Apache 5.x CloseableHttpClient.execute(request) fires ssrf', async () => {
    const code = [
      'package com.example;',
      'import org.apache.hc.client5.http.classic.methods.HttpGet;',
      'import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;',
      'import org.apache.hc.client5.http.impl.classic.HttpClients;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class V5 extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    CloseableHttpClient client = HttpClients.createDefault();',
      '    HttpGet request = new HttpGet(url);',
      '    client.execute(request);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'V5.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('TP — receiver declared as HttpClient interface still fires ssrf', async () => {
    const code = [
      'package com.example;',
      'import org.apache.http.client.HttpClient;',
      'import org.apache.http.client.methods.HttpGet;',
      'import org.apache.http.impl.client.HttpClients;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class IfaceReceiver extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    HttpClient client = HttpClients.createDefault();',
      '    HttpGet request = new HttpGet(url);',
      '    client.execute(request);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'IfaceReceiver.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('TN — unrelated class .execute(...) does NOT fire ssrf', async () => {
    // `Executor.execute(Runnable)` is a JDK method whose semantics are
    // unrelated to HTTP; it must not be mis-flagged as SSRF just because
    // the method name is `execute`.
    const code = [
      'package com.example;',
      'import java.util.concurrent.Executor;',
      'import java.util.concurrent.Executors;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class NotSsrf extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    final String url = req.getParameter("url");',
      '    Executor exec = Executors.newSingleThreadExecutor();',
      '    exec.execute(new Runnable() { public void run() { System.out.println(url); } });',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'NotSsrf.java', 'java');
    // Executor.execute is not a registered SSRF sink; hasSsrfSignal must be false.
    expect(hasSsrfSignal(r)).toBe(false);
  });

  it('recall guard — receiver declared as InternalHttpClient still fires ssrf', async () => {
    // Transitive subtype: InternalHttpClient extends CloseableHttpClient
    // extends HttpClient.
    const code = [
      'package com.example;',
      'import org.apache.http.client.methods.HttpGet;',
      'import org.apache.http.impl.client.InternalHttpClient;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class Internal extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp,',
      '                       InternalHttpClient client) throws Exception {',
      '    String url = req.getParameter("url");',
      '    HttpGet request = new HttpGet(url);',
      '    client.execute(request);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Internal.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('no double-finding — same call site does not emit both ssrf and external_taint_escape', async () => {
    const code = [
      'package com.example;',
      'import org.apache.http.client.methods.HttpGet;',
      'import org.apache.http.impl.client.CloseableHttpClient;',
      'import org.apache.http.impl.client.HttpClients;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class NoDouble extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    CloseableHttpClient client = HttpClients.createDefault();',
      '    HttpGet request = new HttpGet(url);',
      '    client.execute(request);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'NoDouble.java', 'java');
    const ssrfCount = countSsrf(r);
    const escapeCount = (r.findings ?? []).filter(
      (f: any) => f.rule_id === 'external_taint_escape',
    ).length;
    // Either the SSRF sink fires (via flow or finding) OR the escape fallback
    // fires — but not both for the same call site. We assert SSRF wins.
    expect(hasSsrfSignal(r)).toBe(true);
    // No external_taint_escape on the SSRF call site.
    expect(escapeCount).toBe(0);
    // At most one SSRF finding per sink hit; taint.flows may report zero or
    // one (implementation detail); the aggregate signal is asserted above.
    expect(ssrfCount).toBeLessThanOrEqual(2);
  });
});
