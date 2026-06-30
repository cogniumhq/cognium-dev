/**
 * Sprint 83 — #189 variant-regression: code_injection cluster (8 cells).
 *
 * Engine inventory on 3.132.0 found 4 of 8 FN. The remaining 4 FN cells
 * are closed by four new pattern detectors (all in language-sources-pass):
 *
 *   A. go    `plugin.Open(<tainted>)` / `plugin.Lookup(...)`
 *   B. js    `(0, eval)(x)`, `globalThis.eval(x)`, aliased `const f = eval`
 *   C. py    `code.InteractiveInterpreter().runsource(<tainted>)` (gated on
 *            `import code` to avoid colliding with user-defined `code` ids)
 *   D. rust  `evalexpr::eval(<tainted>)`, `libloading::Library::new(...)`,
 *            `mlua/rlua` `<lua>.load(<src>).{exec|eval|call}(...)`
 *
 * Each detector has at least one TP that reproduces the corpus shape and a
 * TN-control that proves the detector does not over-fire on a sanitized or
 * literal-only variant.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countCodeInjection = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'code_injection').length;

const hasCodeInjectionFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some(
    f => f.sink_type === 'code_injection',
  );

const hasCodeInjectionSignal = (r: any) =>
  hasCodeInjectionFlow(r) || countCodeInjection(r) > 0;

describe('#189 Sprint 83 — code_injection cluster (4 pattern detectors)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // A. Go plugin.Open / plugin.Lookup
  // -------------------------------------------------------------------------
  it('A-TP go code_injection — plugin.Open(path) with *http.Request taint', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "net/http"',
      '  "plugin"',
      ')',
      '',
      'func codePlugin(w http.ResponseWriter, r *http.Request) {',
      '  path := r.FormValue("path")',
      '  plugin.Open(path)',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'go_plugin.go', 'go');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('A-TN go code_injection — plugin.Open with literal path does NOT fire', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "net/http"',
      '  "plugin"',
      ')',
      '',
      'func codePlugin(w http.ResponseWriter, r *http.Request) {',
      '  plugin.Open("/usr/lib/myplugin.so")',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'go_plugin_literal.go', 'go');
    // No code_injection finding from the new pattern detector (literal arg).
    const fromNewDetector = (r.findings ?? []).filter(
      (f: any) =>
        f.rule_id === 'code_injection' &&
        typeof f.id === 'string' &&
        f.id.includes('go-plugin-'),
    );
    expect(fromNewDetector.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // B. JS indirect eval — (0, eval)(x), globalThis.eval(x), aliased eval
  // -------------------------------------------------------------------------
  it('B-TP js code_injection — (0, eval)(req.body) indirect eval', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.post('/e', express.text(), (req, res) => {",
      '  const code = req.body;',
      '  (0, eval)(code);',
      '  res.end();',
      '});',
      '',
    ].join('\n');
    const r = await analyze(code, 'js_indirect_eval.js', 'javascript');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('B-TP2 js code_injection — globalThis.eval(req.query.x)', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/e', (req, res) => {",
      '  const x = req.query.x;',
      '  globalThis.eval(x);',
      '  res.end();',
      '});',
      '',
    ].join('\n');
    const r = await analyze(code, 'js_globalthis_eval.js', 'javascript');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('B-TP3 js code_injection — aliased eval `const f = eval; f(taint)`', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      'const f = eval;',
      "app.post('/e', express.text(), (req, res) => {",
      '  const code = req.body;',
      '  f(code);',
      '  res.end();',
      '});',
      '',
    ].join('\n');
    const r = await analyze(code, 'js_aliased_eval.js', 'javascript');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('B-TN js code_injection — (0, eval)("1 + 1") with literal arg does NOT fire', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/e', (req, res) => {",
      '  (0, eval)("1 + 1");',
      '  res.end();',
      '});',
      '',
    ].join('\n');
    const r = await analyze(code, 'js_indirect_eval_literal.js', 'javascript');
    const fromNewDetector = (r.findings ?? []).filter(
      (f: any) =>
        f.rule_id === 'code_injection' &&
        typeof f.id === 'string' &&
        f.id.includes('js-indirect-eval'),
    );
    expect(fromNewDetector.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // C. Python code.InteractiveInterpreter().runsource — gated on `import code`
  // -------------------------------------------------------------------------
  it('C-TP py code_injection — code.InteractiveInterpreter().runsource(req.get_data())', async () => {
    const code = [
      'import code',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '',
      '@app.route("/v", methods=["POST"])',
      'def v():',
      '    snippet = request.get_data(as_text=True)',
      '    code.InteractiveInterpreter().runsource(snippet)',
      '    return "ok"',
      '',
    ].join('\n');
    const r = await analyze(code, 'py_vm_context.py', 'python');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('C-TN py code_injection — user-defined `code` var without `import code` does NOT fire', async () => {
    const code = [
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '',
      '@app.route("/v")',
      'def v():',
      '    code = request.args.get("c", "")',
      '    return code',
      '',
    ].join('\n');
    const r = await analyze(code, 'py_no_import_code.py', 'python');
    // Detector must not fire — no `import code` namespace gate satisfied.
    const fromNewDetector = (r.findings ?? []).filter(
      (f: any) =>
        f.rule_id === 'code_injection' &&
        typeof f.id === 'string' &&
        f.id.includes('py-interactive-interpreter'),
    );
    expect(fromNewDetector.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // D. Rust evalexpr / libloading / mlua dynamic-load
  // -------------------------------------------------------------------------
  it('D-TP rust code_injection — evalexpr::eval(&body) on Actix String param', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      '',
      'pub async fn eval_endpoint(body: String) -> HttpResponse {',
      '    let _ = evalexpr::eval(&body);',
      '    HttpResponse::Ok().body("ok")',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'rust_eval.rs', 'rust');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('D-TP2 rust code_injection — libloading::Library::new(path) with web::Path taint', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      '',
      'pub async fn load_endpoint(path: web::Path<String>) -> HttpResponse {',
      '    let _ = libloading::Library::new(path.into_inner());',
      '    HttpResponse::Ok().body("ok")',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'rust_libloading.rs', 'rust');
    expect(hasCodeInjectionSignal(r)).toBe(true);
  });

  it('D-TN rust code_injection — evalexpr::eval("1 + 1") with literal does NOT fire', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      '',
      'pub async fn eval_endpoint(_body: String) -> HttpResponse {',
      '    let _ = evalexpr::eval("1 + 1");',
      '    HttpResponse::Ok().body("ok")',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'rust_eval_literal.rs', 'rust');
    const fromNewDetector = (r.findings ?? []).filter(
      (f: any) =>
        f.rule_id === 'code_injection' &&
        typeof f.id === 'string' &&
        f.id.includes('rust-eval-crate'),
    );
    expect(fromNewDetector.length).toBe(0);
  });
});
