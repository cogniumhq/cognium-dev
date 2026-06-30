/**
 * Sprint 85 — #189 variant-regression: ssrf cluster (6 cells).
 *
 * Engine inventory on 3.134.0 found 2 of 6 FN: both Java URL.openStream()
 * variants. The four JavaScript cells (axios/got/http.get/request)
 * already TP via the existing nodejs.json sink rows.
 *
 * One new pattern detector closes the Java cells:
 *
 *   findJavaUrlOpenStreamSsrfFindings —
 *     `new URL(<servlet-request taint>)` → `.openStream()` /
 *     `.openConnection()` / `.getContent()` receiver chains. Fires
 *     across an intermediate `URL u = new URL(url);` binding that the
 *     cross-statement flow construction misses. Also fires when the
 *     tainted URL is gated only by a weak prefix allowlist
 *     (`url.startsWith("https://")`) — such a check is NOT a sanitizer
 *     because the host is still attacker-controlled.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countSsrf = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'ssrf').length;

const hasSsrfFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === 'ssrf');

const hasSsrfSignal = (r: any) => hasSsrfFlow(r) || countSsrf(r) > 0;

describe('#189 Sprint 85 — ssrf cluster (Java URL.openStream detector)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // V01 basic_fetch — taint flows through `URL u = new URL(url);` to
  //                   `u.openStream()`
  // -------------------------------------------------------------------------
  it('TP — `new URL(req.getParameter(...))` → `u.openStream()` fires', async () => {
    const code = [
      'package com.example;',
      'import java.io.InputStream;',
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class V01 extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    URL u = new URL(url);',
      '    InputStream in = u.openStream();',
      '    in.close();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'V01.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  // V01-alt — direct chained form `new URL(taint).openStream()`
  it('TP — chained `new URL(taint).openStream()` fires', async () => {
    const code = [
      'package com.example;',
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class V01b extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    new URL(url).openStream();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'V01b.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // V02 weak_allowlist — `if (url.startsWith("https://"))` is NOT a sanitizer
  // -------------------------------------------------------------------------
  it('TP — weak prefix allowlist (`startsWith("https://")`) still fires', async () => {
    const code = [
      'package com.example;',
      'import java.io.InputStream;',
      'import java.net.URL;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import javax.servlet.http.HttpServlet;',
      'public class V02 extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String url = req.getParameter("url");',
      '    if (url != null && url.startsWith("https://")) {',
      '      URL u = new URL(url);',
      '      InputStream in = u.openStream();',
      '      in.close();',
      '    }',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'V02.java', 'java');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // TN — literal URL, no taint involved
  // -------------------------------------------------------------------------
  it('TN — literal `new URL("https://example.com").openStream()` does NOT fire', async () => {
    const code = [
      'package com.example;',
      'import java.io.InputStream;',
      'import java.net.URL;',
      'public class NoTaint {',
      '  public void run() throws Exception {',
      '    URL u = new URL("https://example.com");',
      '    InputStream in = u.openStream();',
      '    in.close();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'NoTaint.java', 'java');
    expect(hasSsrfSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // Sanity — JavaScript cells from baseline (already-TP via configured sinks)
  // -------------------------------------------------------------------------
  it('JS sanity — `axios.get(req.query.url)` emits ssrf flow', async () => {
    const code = [
      "const express = require('express');",
      "const axios = require('axios');",
      'const app = express();',
      "app.get('/fetch', async (req, res) => {",
      '  const url = req.query.url;',
      '  const resp = await axios.get(url);',
      '  res.send(resp.data);',
      '});',
      'module.exports = app;',
    ].join('\n');
    const r = await analyze(code, 'axios.js', 'javascript');
    expect(hasSsrfSignal(r)).toBe(true);
  });

  it('JS sanity — `http.get(req.query.url, cb)` emits ssrf flow', async () => {
    const code = [
      "const express = require('express');",
      "const http = require('http');",
      'const app = express();',
      "app.get('/fetch', (req, res) => {",
      '  const url = req.query.url;',
      '  http.get(url, (incoming) => { res.send(""); });',
      '});',
      'module.exports = app;',
    ].join('\n');
    const r = await analyze(code, 'httpget.js', 'javascript');
    expect(hasSsrfSignal(r)).toBe(true);
  });
});
