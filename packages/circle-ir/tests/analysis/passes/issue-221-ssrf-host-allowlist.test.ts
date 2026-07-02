/**
 * #221 (3.144.1) — SSRF host-allowlist sanitizer gate.
 *
 * Extends `findJavaUrlOpenStreamSsrfFindings` (Sprint 85 detector, #189)
 * to credit two narrow, unambiguous host-allowlist shapes as sanitizers
 * that suppress the ssrf finding when they dominate the sink line:
 *
 *   1. `<ALLOWLIST>.contains(<url>.getHost())` — Set/List membership
 *   2. `<url>.getHost().equals(literal)` / `equalsIgnoreCase(literal)`
 *
 * Deliberately narrow. `url.startsWith("https://")` is NOT recognized
 * (per Sprint 85 note — scheme-only checks don't constrain the host).
 * Recall on the openStream/openConnection/getContent TP path unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countSsrf = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'ssrf').length;

const hasSsrfFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === 'ssrf');

const hasSsrfSignal = (r: any) => hasSsrfFlow(r) || countSsrf(r) > 0;

describe('#221 — SSRF host-allowlist sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // SAFE — allowlist.contains(url.getHost())  → NO ssrf finding
  // -------------------------------------------------------------------------
  it('SAFE — List.contains(url.getHost()) allowlist suppresses ssrf', async () => {
    const code = [
      'import java.net.HttpURLConnection;',
      'import java.net.URL;',
      'import java.util.Arrays;',
      'import java.util.List;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfSafe {',
      '    private static final List<String> ALLOWED = Arrays.asList("api.example.com");',
      '    public byte[] fetch(HttpServletRequest req) throws Exception {',
      '        String urlParam = req.getParameter("url");',
      '        URL url = new URL(urlParam);',
      '        if (!ALLOWED.contains(url.getHost())) throw new IllegalArgumentException();',
      '        HttpURLConnection conn = (HttpURLConnection) url.openConnection();',
      '        return conn.getInputStream().readAllBytes();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfSafe.java', 'java');
    expect(hasSsrfSignal(r)).toBe(false);
  });

  it('SAFE — Set.contains(url.getHost()) allowlist suppresses ssrf', async () => {
    const code = [
      'import java.net.URL;',
      'import java.util.Set;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfSafeSet {',
      '    private static final Set<String> HOSTS = Set.of("api.example.com", "cdn.example.com");',
      '    public void fetch(HttpServletRequest req) throws Exception {',
      '        String urlParam = req.getParameter("url");',
      '        URL u = new URL(urlParam);',
      '        if (!HOSTS.contains(u.getHost())) throw new IllegalArgumentException();',
      '        u.openStream();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfSafeSet.java', 'java');
    expect(hasSsrfSignal(r)).toBe(false);
  });

  it('SAFE — url.getHost().equals(literal) suppresses ssrf', async () => {
    const code = [
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfSafeEquals {',
      '    public void fetch(HttpServletRequest req) throws Exception {',
      '        String urlParam = req.getParameter("url");',
      '        URL u = new URL(urlParam);',
      '        if (!u.getHost().equals("api.example.com")) throw new IllegalArgumentException();',
      '        u.openStream();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfSafeEquals.java', 'java');
    expect(hasSsrfSignal(r)).toBe(false);
  });

  it('SAFE — url.getHost().equalsIgnoreCase(literal) suppresses ssrf', async () => {
    const code = [
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfSafeEqualsIC {',
      '    public void fetch(HttpServletRequest req) throws Exception {',
      '        String urlParam = req.getParameter("url");',
      '        URL u = new URL(urlParam);',
      '        if (!u.getHost().equalsIgnoreCase("API.EXAMPLE.COM")) throw new IllegalArgumentException();',
      '        u.openConnection();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfSafeEqualsIC.java', 'java');
    expect(hasSsrfSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // TP recall guards — sink must still fire
  // -------------------------------------------------------------------------
  it('TP — no host check on openConnection still fires', async () => {
    const code = [
      'import java.net.HttpURLConnection;',
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfTp {',
      '    public byte[] fetch(HttpServletRequest req) throws Exception {',
      '        URL url = new URL(req.getParameter("url"));',
      '        HttpURLConnection conn = (HttpURLConnection) url.openConnection();',
      '        return conn.getInputStream().readAllBytes();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfTp.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('TP — startsWith("https://") is NOT a sanitizer (Sprint 85 note)', async () => {
    const code = [
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfWeak {',
      '    public void fetch(HttpServletRequest req) throws Exception {',
      '        String urlParam = req.getParameter("url");',
      '        if (urlParam != null && urlParam.startsWith("https://")) {',
      '            URL u = new URL(urlParam);',
      '            u.openStream();',
      '        }',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfWeak.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('TP — allowlist that comes AFTER the sink line does not suppress', async () => {
    // Guard placed after sink cannot dominate it.
    const code = [
      'import java.net.URL;',
      'import java.util.Arrays;',
      'import java.util.List;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfPostGuard {',
      '    private static final List<String> ALLOWED = Arrays.asList("api.example.com");',
      '    public void fetch(HttpServletRequest req) throws Exception {',
      '        String urlParam = req.getParameter("url");',
      '        URL u = new URL(urlParam);',
      '        u.openStream();',
      '        if (!ALLOWED.contains(u.getHost())) throw new IllegalArgumentException();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfPostGuard.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('TP — .contains(someUnrelatedVar.getHost()) does not suppress', async () => {
    // The allowlist check must reference a variable that reaches the sink.
    // A different var's getHost() is not evidence that the sink var is safe.
    const code = [
      'import java.net.URL;',
      'import java.util.Arrays;',
      'import java.util.List;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class SsrfWrongVar {',
      '    private static final List<String> ALLOWED = Arrays.asList("api.example.com");',
      '    public void fetch(HttpServletRequest req) throws Exception {',
      '        URL safeUrl = new URL("https://api.example.com");',
      '        if (!ALLOWED.contains(safeUrl.getHost())) throw new IllegalArgumentException();',
      '        URL bad = new URL(req.getParameter("url"));',
      '        bad.openStream();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SsrfWrongVar.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });
});
