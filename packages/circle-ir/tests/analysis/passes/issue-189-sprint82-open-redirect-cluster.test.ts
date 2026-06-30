/**
 * Sprint 82 — #189 variant-regression: open_redirect cluster (10 cells).
 *
 * Engine inventory on 3.131.0 found 9 of 10 FN. The remaining 9 FN cells
 * are closed by a triad of engine fixes plus four new pattern detectors:
 *
 *   Engine fixes (configured-sink path):
 *     - Java sendRedirect mis-typing (was `ssrf`, corrected to
 *       `open_redirect` at config-loader.ts; closes java__V01).
 *     - Sink-type-aware flow dedup at 4 sites in taint-propagation-pass
 *       (`res.redirect` is both `open_redirect` and `crlf`; closes
 *       js__v01).
 *     - `canSourceReachSink` http_* → open_redirect reach map gap in
 *       findings.ts (closes go__v01, plus enables Java/JS fixes).
 *
 *   Pattern detectors (this file):
 *     A. go    `<rw>.Header().Set("Location", taint)`
 *     B. py    `resp.headers["Location"] = taint`
 *     C. rust  `.append_header(("Location", taint))`
 *     D. js/html  `location.href = taint`, `window.location = taint`,
 *                 `<meta>.content = '<...>;url=' + taint`,
 *                 `location.assign(taint)` / `location.replace(taint)`
 *
 * Each detector has a TP that reproduces the corpus shape verbatim and a
 * TN-control that proves the detector does not over-fire on the obvious
 * sanitized variant.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countOpenRedirect = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'open_redirect').length;

const hasOpenRedirectFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some(f => f.sink_type === 'open_redirect');

describe('#189 Sprint 82 — open_redirect cluster (engine + 4 pattern detectors)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // Engine fix 1: Java sendRedirect re-typed open_redirect.
  // -------------------------------------------------------------------------
  it('FN-J1 java open_redirect — sendRedirect now emits open_redirect (not ssrf)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class X {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '    String next = req.getParameter("next");',
      '    res.sendRedirect(next);',
      '  }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'V01RedirectParam.java', 'java');
    expect(hasOpenRedirectFlow(r)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Engine fix 2: sink-type-aware flow dedup (res.redirect is both
  // open_redirect AND crlf; both flows must survive dedup).
  // -------------------------------------------------------------------------
  it('FN-J2 js open_redirect — res.redirect emits BOTH open_redirect AND crlf flows', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/r', (req, res) => {",
      '  res.redirect(req.query.next);',
      '});',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_redirect_param.js', 'javascript');
    const flows = (r.taint?.flows ?? []) as any[];
    const sinkTypes = new Set(flows.map(f => f.sink_type));
    expect(sinkTypes.has('open_redirect')).toBe(true);
    expect(sinkTypes.has('crlf')).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Engine fix 3: canSourceReachSink reach map — http_param → open_redirect.
  // -------------------------------------------------------------------------
  it('FN-G1 go open_redirect — http.Redirect(w, r, FormValue("next"), 302)', async () => {
    const code = [
      'package main',
      'import "net/http"',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '    http.Redirect(w, r, r.FormValue("next"), 302)',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_redirect_param.go', 'go');
    expect(hasOpenRedirectFlow(r)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Detector A — Go: ResponseWriter.Header().Set("Location", taint)
  // -------------------------------------------------------------------------
  it('TP-A1 go open_redirect — w.Header().Set("Location", FormValue("url")) must fire', async () => {
    const code = [
      'package main',
      'import "net/http"',
      'func openHeader(w http.ResponseWriter, r *http.Request) {',
      '    w.Header().Set("Location", r.FormValue("url"))',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v02_location_header.go', 'go');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-A1 go open_redirect — Header().Set with literal value must NOT fire', async () => {
    const code = [
      'package main',
      'import "net/http"',
      'func ok(w http.ResponseWriter, r *http.Request) {',
      '    w.Header().Set("Location", "/safe")',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v02_safe.go', 'go');
    expect(countOpenRedirect(r)).toBe(0);
  });

  it('TN-A2 go open_redirect — Header().Set("X-Custom", taint) must NOT fire as open_redirect', async () => {
    const code = [
      'package main',
      'import "net/http"',
      'func custom(w http.ResponseWriter, r *http.Request) {',
      '    w.Header().Set("X-Custom-Header", r.FormValue("u"))',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v02_custom.go', 'go');
    expect(countOpenRedirect(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Detector B — Python Flask: resp.headers["Location"] = taint
  // -------------------------------------------------------------------------
  it('TP-B1 py open_redirect — resp.headers["Location"] = request.args.get("url") must fire', async () => {
    const code = [
      'from flask import Flask, request, Response',
      'app = Flask(__name__)',
      '@app.route("/h")',
      'def h():',
      '    loc = request.args.get("url", "")',
      '    resp = Response("ok")',
      '    resp.headers["Location"] = loc',
      '    return resp',
      '',
    ].join('\n');
    const r = await analyze(code, 'v02_location_header.py', 'python');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-B1 py open_redirect — resp.headers["Location"] = literal must NOT fire', async () => {
    const code = [
      'from flask import Flask, Response',
      'app = Flask(__name__)',
      '@app.route("/h")',
      'def h():',
      '    resp = Response("ok")',
      '    resp.headers["Location"] = "/safe"',
      '    return resp',
      '',
    ].join('\n');
    const r = await analyze(code, 'v02_safe.py', 'python');
    expect(countOpenRedirect(r)).toBe(0);
  });

  it('TN-B2 py open_redirect — resp.headers["X-Custom"] = taint must NOT fire as open_redirect', async () => {
    const code = [
      'from flask import Flask, request, Response',
      'app = Flask(__name__)',
      '@app.route("/h")',
      'def h():',
      '    val = request.args.get("x", "")',
      '    resp = Response("ok")',
      '    resp.headers["X-Custom"] = val',
      '    return resp',
      '',
    ].join('\n');
    const r = await analyze(code, 'v02_custom.py', 'python');
    expect(countOpenRedirect(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Detector C — Rust Actix: append_header(("Location", taint))
  // -------------------------------------------------------------------------
  it('TP-C1 rust open_redirect — HttpResponse::Found().append_header(("Location", taint)) must fire', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      'pub async fn go(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {',
      '    let next = q.get("next").cloned().unwrap_or_default();',
      '    HttpResponse::Found().append_header(("Location", next)).finish()',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_redirect_param.rs', 'rust');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-C1 rust open_redirect — append_header with literal value must NOT fire', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      'pub async fn safe(_q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {',
      '    HttpResponse::Found().append_header(("Location", "/safe")).finish()',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_safe.rs', 'rust');
    expect(countOpenRedirect(r)).toBe(0);
  });

  it('TN-C2 rust open_redirect — append_header(("X-Custom", taint)) must NOT fire as open_redirect', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      'pub async fn custom(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {',
      '    let val = q.get("x").cloned().unwrap_or_default();',
      '    HttpResponse::Ok().append_header(("X-Custom", val)).finish()',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_custom.rs', 'rust');
    expect(countOpenRedirect(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Detector D — HTML/JS DOM open_redirect
  // -------------------------------------------------------------------------
  it('TP-D1 html open_redirect — location.href = <URLSearchParams.get> must fire', async () => {
    const code = [
      '<!DOCTYPE html>',
      '<html><head>',
      '  <script>',
      "    const next = new URLSearchParams(location.search).get('next');",
      '    location.href = next;',
      '  </script>',
      '</head><body></body></html>',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_redirect_param.html', 'html');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-D1 html open_redirect — location.href = literal must NOT fire', async () => {
    const code = [
      '<!DOCTYPE html>',
      '<html><head>',
      "  <script>location.href = '/safe';</script>",
      '</head><body></body></html>',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_safe.html', 'html');
    expect(countOpenRedirect(r)).toBe(0);
  });

  it('TP-D2 html open_redirect — <meta>.content = "0;url=" + location.hash must fire', async () => {
    const code = [
      '<!DOCTYPE html>',
      '<html><head>',
      '  <meta http-equiv="refresh" content="0;url=REDIRECT_URL">',
      "  <script>document.querySelector('meta').content = '0;url=' + location.hash.slice(1);</script>",
      '</head><body></body></html>',
      '',
    ].join('\n');
    const r = await analyze(code, 'v03_meta_refresh.html', 'html');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-D2 html open_redirect — <meta>.content = literal must NOT fire', async () => {
    const code = [
      '<!DOCTYPE html>',
      '<html><head>',
      '  <meta http-equiv="refresh" content="0;url=/home">',
      "  <script>document.querySelector('meta').content = '0;url=/home';</script>",
      '</head><body></body></html>',
      '',
    ].join('\n');
    const r = await analyze(code, 'v03_safe.html', 'html');
    expect(countOpenRedirect(r)).toBe(0);
  });

  it('TP-D3 html open_redirect — window.location = URLSearchParams.get must fire', async () => {
    const code = [
      '<!DOCTYPE html>',
      '<html><head><title>x</title></head>',
      "<body><script>window.location = new URLSearchParams(location.search).get('u');</script></body></html>",
      '',
    ].join('\n');
    const r = await analyze(code, 'v03_window_location.html', 'html');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TP-D4 js open_redirect — location.assign(URLSearchParams.get) must fire', async () => {
    const code = [
      "const next = new URLSearchParams(location.search).get('next');",
      'location.assign(next);',
      '',
    ].join('\n');
    const r = await analyze(code, 'v_assign.js', 'javascript');
    expect(countOpenRedirect(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-D4 js open_redirect — location.assign("/safe") must NOT fire', async () => {
    const code = ["location.assign('/safe');", ''].join('\n');
    const r = await analyze(code, 'v_safe_assign.js', 'javascript');
    expect(countOpenRedirect(r)).toBe(0);
  });
});
