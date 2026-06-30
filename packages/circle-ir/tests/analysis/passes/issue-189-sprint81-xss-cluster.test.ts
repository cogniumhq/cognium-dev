/**
 * Sprint 81 — #189 variant-regression: xss cluster (11 FN cells).
 *
 * Engine inventory on 3.129.0 found cell 8 (React `dangerouslySetInnerHTML`)
 * already FIRES; cell 5 (`eval(location.hash)`) is a corpus-manifest
 * mis-tag (engine correctly emits `code_injection`, not xss — deferred
 * as corpus correction). The remaining 9 FN cells are closed by six new
 * pattern detectors:
 *
 *   A. go    fmt.Fprintf(w, ...)             where w is http.ResponseWriter
 *   B. java  res.getWriter().{print,println,write}(...)  receiver-chain
 *   C. js    Vue template `v-html="<taint>"`
 *   D. ts    Angular `DomSanitizer.bypassSecurityTrust*(...)` non-literal
 *   F. py    Flask route returning `"..." + taint + "..."` / f-string
 *   G. py    `Markup(<taint>)` wrap fed to Jinja `Template(...).render(...)`
 *
 * Each detector has a TP that reproduces the corpus shape verbatim and a
 * TN-control that proves the detector does not over-fire on the obvious
 * sanitized variant.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countXss = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'xss').length;

describe('#189 Sprint 81 — xss cluster pattern detectors (6 new)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // A. Go — fmt.Fprintf to http.ResponseWriter
  // -------------------------------------------------------------------------
  it('FN-A1 go xss — fmt.Fprintf(w, "<h1>%s</h1>", q) must fire', async () => {
    const code = [
      'package main',
      'import (',
      '    "fmt"',
      '    "net/http"',
      ')',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '    q := r.URL.Query().Get("q")',
      '    fmt.Fprintf(w, "<h1>%s</h1>", q)',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_reflected_body.go', 'go');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-A1 go xss — fmt.Fprintf wrapped in html.EscapeString must NOT fire', async () => {
    const code = [
      'package main',
      'import (',
      '    "fmt"',
      '    "html"',
      '    "net/http"',
      ')',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '    q := r.URL.Query().Get("q")',
      '    fmt.Fprintf(w, "<h1>%s</h1>", html.EscapeString(q))',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_escape.go', 'go');
    expect(countXss(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // B. Java — HttpServletResponse.getWriter().{print,println,write}
  // -------------------------------------------------------------------------
  it('FN-B1 java xss — res.getWriter().print(taint) must fire', async () => {
    const code = [
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'public class V03AttributeCtx {',
      '    public void handle(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '        String u = req.getParameter("u");',
      '        res.getWriter().print("<a href=\\"" + u + "\\">x</a>");',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'V03AttributeCtx.java', 'java');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-B1 java xss — getWriter().print wrapped in Encode.forHtml must NOT fire', async () => {
    const code = [
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.servlet.http.HttpServletResponse;',
      'import org.owasp.encoder.Encode;',
      'public class V03AttributeCtxSafe {',
      '    public void handle(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '        String u = req.getParameter("u");',
      '        res.getWriter().print("<a href=\\"" + Encode.forHtml(u) + "\\">x</a>");',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_encode_for_html.java', 'java');
    expect(countXss(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // C. JS — Vue v-html directive
  // -------------------------------------------------------------------------
  it('FN-C1 js xss — Vue template with v-html bound to route taint must fire', async () => {
    const code = [
      "const app = new Vue({",
      "  el: '#app',",
      "  data() {",
      "    const params = new URLSearchParams(window.location.search);",
      "    return { q: params.get('q') };",
      "  },",
      "  template: '<div v-html=\"q\"></div>'",
      "});",
      '',
    ].join('\n');
    const r = await analyze(code, 'v13_vue_vhtml.js', 'javascript');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-C1 js xss — Vue template with v-html bound to literal must NOT fire', async () => {
    const code = [
      "const app = new Vue({",
      "  el: '#app',",
      "  data() {",
      "    return { q: '<b>safe literal</b>' };",
      "  },",
      "  template: '<div v-html=\"q\"></div>'",
      "});",
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_vue_literal.js', 'javascript');
    expect(countXss(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // D. TS — Angular DomSanitizer.bypassSecurityTrust*
  // -------------------------------------------------------------------------
  it('FN-D1 ts xss — DomSanitizer.bypassSecurityTrustHtml(taint) must fire', async () => {
    const code = [
      "import { Component } from '@angular/core';",
      "import { DomSanitizer, SafeHtml } from '@angular/platform-browser';",
      "import { ActivatedRoute } from '@angular/router';",
      '@Component({ selector: "app-x", template: "<div [innerHTML]=safe></div>" })',
      'export class XComponent {',
      '  safe: SafeHtml;',
      '  constructor(private s: DomSanitizer, private route: ActivatedRoute) {',
      "    const q = this.route.snapshot.queryParams['q'];",
      '    this.safe = this.s.bypassSecurityTrustHtml(q);',
      '  }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v14_angular_bypass.ts', 'typescript');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-D1 ts xss — DomSanitizer.bypassSecurityTrustHtml with literal must NOT fire', async () => {
    const code = [
      "import { Component } from '@angular/core';",
      "import { DomSanitizer, SafeHtml } from '@angular/platform-browser';",
      '@Component({ selector: "app-x", template: "<div [innerHTML]=safe></div>" })',
      'export class XComponent {',
      '  safe: SafeHtml;',
      '  constructor(private s: DomSanitizer) {',
      "    this.safe = this.s.bypassSecurityTrustHtml('<b>safe</b>');",
      '  }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_angular_literal.ts', 'typescript');
    expect(countXss(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // F. Python — Flask string concat / f-string returns
  // -------------------------------------------------------------------------
  it('FN-F1 py xss — Flask route returning "<h1>" + q + "</h1>" must fire', async () => {
    const code = [
      'from flask import Flask, request',
      'app = Flask(__name__)',
      '@app.route("/")',
      'def index():',
      '    q = request.args.get("q", "")',
      '    return "<h1>" + q + "</h1>"',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_reflected_body.py', 'python');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('FN-F2 py xss — Flask route returning f-string with tainted param must fire', async () => {
    const code = [
      'from flask import Flask, request',
      'app = Flask(__name__)',
      '@app.route("/link")',
      'def link():',
      '    u = request.args.get("u", "")',
      "    return f'<a href=\"{u}\">x</a>'",
      '',
    ].join('\n');
    const r = await analyze(code, 'v03_attribute_ctx.py', 'python');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-F1 py xss — Flask route returning escape()-wrapped concat must NOT fire', async () => {
    const code = [
      'from flask import Flask, request',
      'from markupsafe import escape',
      'app = Flask(__name__)',
      '@app.route("/")',
      'def index():',
      '    q = request.args.get("q", "")',
      '    return "<h1>" + escape(q) + "</h1>"',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_escape.py', 'python');
    expect(countXss(r)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // G. Python — Jinja Markup wrap bypass
  // -------------------------------------------------------------------------
  it('FN-G1 py xss — Markup(taint) flowing to Template().render must fire', async () => {
    const code = [
      'from flask import Flask, request',
      'from markupsafe import Markup',
      'from jinja2 import Template',
      'app = Flask(__name__)',
      '@app.route("/")',
      'def index():',
      '    t = request.args.get("t", "")',
      '    wrapped = Markup(t)',
      '    return Template("{{ v }}").render(v=wrapped)',
      '',
    ].join('\n');
    const r = await analyze(code, 'v04_script_ctx.py', 'python');
    expect(countXss(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN-G1 py xss — Template().render without Markup wrap (autoescape on) must NOT fire', async () => {
    const code = [
      'from flask import Flask, request',
      'from jinja2 import Template',
      'app = Flask(__name__)',
      '@app.route("/")',
      'def index():',
      '    t = request.args.get("t", "")',
      '    return Template("{{ v }}").render(v=t)',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_no_markup.py', 'python');
    expect(countXss(r)).toBe(0);
  });
});
