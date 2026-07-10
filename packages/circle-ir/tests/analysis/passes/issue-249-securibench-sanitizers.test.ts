/**
 * cognium-dev #249 — SecuriBench Micro FPR drift.
 *
 * Root cause: Sprint 82 (#189) reclassified
 * `HttpServletResponse.sendRedirect` from `ssrf` → `open_redirect`
 * (config-loader.ts:1296-1299) without updating the URL-encoder
 * sanitizer cluster (config-loader.ts:2261-2266 and 2319). The drift
 * surfaced as an FP on SecuriBench Micro
 * `sanitizers/Sanitizers3.java` — `URLEncoder.encode("/user/"+name)`
 * before `sendRedirect` was no longer covered.
 *
 * 3.162.0 adds `'open_redirect'` to the `URLEncoder.encode` /
 * `encodeForURL` / `encodeURL` / `urlEncode` / `escapeUrl` /
 * `escapeURL` sanitizer entries. This suite pins the expected
 * behaviour:
 *   - URL-encoder + sendRedirect  → no open_redirect finding (TN)
 *   - raw sendRedirect            → open_redirect finding (TP recall)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countFindingsOfType = (r: any, ruleId: string): number =>
  (r.findings ?? []).filter((f: any) => f.rule_id === ruleId).length;

const hasUnsanitizedFlow = (r: any, sinkType: string): boolean =>
  ((r.taint?.flows ?? []) as any[]).some(
    (f) => f.sink_type === sinkType && !f.sanitized
  );

const hasSignal = (r: any, ruleId: string, sinkType: string): boolean =>
  hasUnsanitizedFlow(r, sinkType) || countFindingsOfType(r, ruleId) > 0;

describe('#249 SecuriBench Micro URL-encoder sanitizer — open_redirect (3.162.0)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ==========================================================================
  // TN — URL-encoder covers open_redirect (the Sanitizers3 shape)
  // ==========================================================================

  it('TN — URLEncoder.encode + sendRedirect does NOT fire open_redirect (Sanitizers3.java shape)', async () => {
    const code = [
      'package securibench.micro.sanitizers;',
      'import java.io.IOException;',
      'import java.net.URLEncoder;',
      'import java.util.Locale;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      '',
      'public class Sanitizers3 {',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '        String s = req.getParameter("name");',
      '        String name = s.toLowerCase(Locale.UK);',
      '        resp.sendRedirect(URLEncoder.encode("/user/" + name, "UTF-8"));',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'Sanitizers3.java', 'java');
    expect(hasSignal(r, 'open_redirect', 'open_redirect')).toBe(false);
  });

  it('TN — encodeForURL wrapper + sendRedirect does NOT fire open_redirect', async () => {
    const code = [
      'package demo;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      '',
      'public class SafeRedirectWrapper {',
      '    static String encodeForURL(String s) { return s; }',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '        String target = req.getParameter("next");',
      '        resp.sendRedirect(encodeForURL(target));',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'SafeRedirectWrapper.java', 'java');
    expect(hasSignal(r, 'open_redirect', 'open_redirect')).toBe(false);
  });

  it('TN — urlEncode alias + sendRedirect does NOT fire open_redirect', async () => {
    const code = [
      'package demo;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      '',
      'public class UrlEncodeAlias {',
      '    static String urlEncode(String s) { return s; }',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '        String target = req.getParameter("next");',
      '        resp.sendRedirect(urlEncode(target));',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'UrlEncodeAlias.java', 'java');
    expect(hasSignal(r, 'open_redirect', 'open_redirect')).toBe(false);
  });

  // ==========================================================================
  // TP — raw sendRedirect still fires (recall retention)
  // ==========================================================================

  it('TP — raw sendRedirect(req.getParameter(...)) still fires open_redirect (Sprint 82 recall retained)', async () => {
    const code = [
      'package demo;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      '',
      'public class UnsafeRedirect {',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '        String target = req.getParameter("next");',
      '        resp.sendRedirect(target);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'UnsafeRedirect.java', 'java');
    expect(hasSignal(r, 'open_redirect', 'open_redirect')).toBe(true);
  });

  // ==========================================================================
  // TP — encode-then-decode bypass (URLDecoder.decode as re-taint source)
  // ==========================================================================

  it('TP — URLDecoder.decode(URLEncoder.encode(...)) + sendRedirect fires open_redirect (Sanitizers5.java shape)', async () => {
    const code = [
      'package securibench.micro.sanitizers;',
      'import java.io.IOException;',
      'import java.net.URLDecoder;',
      'import java.net.URLEncoder;',
      'import java.util.Locale;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      '',
      'public class Sanitizers5 {',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '        String s = req.getParameter("name");',
      '        String name = s.toLowerCase(Locale.UK);',
      '        String enc = URLEncoder.encode("/user/" + name, "UTF-8");',
      '        String dec = URLDecoder.decode(enc, "UTF-8");',
      '        resp.sendRedirect(dec);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'Sanitizers5.java', 'java');
    expect(hasSignal(r, 'open_redirect', 'open_redirect')).toBe(true);
  });
});
