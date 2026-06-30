/**
 * Sprint 90 — #189 variant-regression: xxe (3) + ssti (2) + path (1)
 * cluster.
 *
 * Baseline against 3.137.0 corpus showed **3 of 6 FN**:
 *   - go     xxe   xml.NewDecoder(r.Body) + d.Strict=false   (FN → TP)
 *   - py     ssti  jinja2.Template(req.args.get(...))         (FN → TP)
 *   - js     ssti  Handlebars.compile(req.query.t)            (FN → TP)
 *
 * Already-TP cells (regression lockdown):
 *   - java   xxe   DocumentBuilderFactory parse
 *   - js     xxe   libxmljs.parseXml({ noent: true })
 *   - rust   path  Path::new(...).join(taint) → fs::read_to_string
 *
 * New detectors:
 *   - findGoXmlDecoderXxeFindings           (CWE-611)
 *   - findPythonJinjaTemplateSstiFindings   (CWE-1336)
 *   - findJsTemplateInjectionSstiFindings   (CWE-1336)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countRule = (r: any, ruleId: string) =>
  ((r.findings ?? []) as any[]).filter((f) => f.rule_id === ruleId).length;

const hasFlowOfType = (r: any, sinkType: string) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === sinkType);

const hasXxeSignal = (r: any) =>
  hasFlowOfType(r, 'xxe') ||
  hasFlowOfType(r, 'xml_entity_expansion') ||
  countRule(r, 'xml_entity_expansion') > 0 ||
  countRule(r, 'xml-entity-expansion') > 0;

const hasSstiSignal = (r: any) =>
  hasFlowOfType(r, 'template_injection') || countRule(r, 'template_injection') > 0;

const hasPathSignal = (r: any) =>
  hasFlowOfType(r, 'path_traversal') || countRule(r, 'path_traversal') > 0;

describe('#189 Sprint 90 — xxe + ssti + path cluster', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -- A. Go XXE: xml.NewDecoder(r.Body) + d.Strict=false --------------

  it('A-TP: xml.NewDecoder(r.Body); d.Strict=false fires xml_entity_expansion', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "encoding/xml"',
      '  "net/http"',
      ')',
      '',
      'type Doc struct { XMLName xml.Name; Body string `xml:",innerxml"` }',
      '',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  dec := xml.NewDecoder(r.Body)',
      '  dec.Strict = false',
      '  var d Doc',
      '  if err := dec.Decode(&d); err != nil { http.Error(w, "bad", 400); return }',
      '  w.Write([]byte(d.Body))',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/a.go', 'go');
    expect(hasXxeSignal(r)).toBe(true);
  });

  it('A-TN: xml.NewDecoder(r.Body) with default Strict=true does NOT fire (Go decoder detector)', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "encoding/xml"',
      '  "net/http"',
      ')',
      '',
      'type Doc struct { XMLName xml.Name }',
      '',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  dec := xml.NewDecoder(r.Body)',
      '  var d Doc',
      '  dec.Decode(&d)',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/b.go', 'go');
    // Detector-specific guard: the Go decoder pattern detector should
    // NOT fire when Strict isn't set to false.
    const findings = (r.findings ?? []) as any[];
    expect(
      findings.some(
        (f) =>
          f.rule_id === 'xml_entity_expansion' &&
          /go-xml-decoder/.test(f.id || ''),
      ),
    ).toBe(false);
  });

  // -- B. Python SSTI: jinja2.Template(tainted) -----------------------

  it('B-TP: Template(request.args.get("t")).render() fires template_injection', async () => {
    const code = [
      'from flask import Flask, request',
      'from jinja2 import Template',
      'app = Flask(__name__)',
      '',
      "@app.route('/r')",
      'def r():',
      "    src = request.args.get('t', '')",
      '    t = Template(src)',
      "    return t.render(user='guest')",
    ].join('\n');
    const r = await analyze(code, '/x/t.py', 'python');
    expect(hasSstiSignal(r)).toBe(true);
  });

  it('B-TN: Template(literal).render(...) does NOT fire', async () => {
    const code = [
      'from jinja2 import Template',
      '',
      'def render():',
      "    return Template('Hello {{ name }}').render(name='guest')",
    ].join('\n');
    const r = await analyze(code, '/x/u.py', 'python');
    expect(countRule(r, 'template_injection')).toBe(0);
  });

  // -- C. JS SSTI: Handlebars.compile / ejs.render --------------------

  it('C-TP: Handlebars.compile(req.query.t) fires template_injection', async () => {
    const code = [
      "const express = require('express');",
      "const Handlebars = require('handlebars');",
      'const app = express();',
      "app.get('/r', (req, res) => {",
      "  const src = req.query.t || '';",
      '  const tpl = Handlebars.compile(src);',
      "  res.send(tpl({ user: 'guest' }));",
      '});',
    ].join('\n');
    const r = await analyze(code, '/x/h.js', 'javascript');
    expect(hasSstiSignal(r)).toBe(true);
  });

  it('C-TP-ejs: ejs.render(req.body, data) fires template_injection', async () => {
    const code = [
      "const express = require('express');",
      "const ejs = require('ejs');",
      'const app = express();',
      "app.use(express.text());",
      "app.post('/r', (req, res) => {",
      '  const src = req.body;',
      "  res.send(ejs.render(src, { user: 'guest' }));",
      '});',
    ].join('\n');
    const r = await analyze(code, '/x/e.js', 'javascript');
    expect(hasSstiSignal(r)).toBe(true);
  });

  it('C-TN: Handlebars.compile(literal) does NOT fire', async () => {
    const code = [
      "const Handlebars = require('handlebars');",
      "const tpl = Handlebars.compile('Hello {{ name }}');",
      "module.exports = (name) => tpl({ name });",
    ].join('\n');
    const r = await analyze(code, '/x/h2.js', 'javascript');
    expect(countRule(r, 'template_injection')).toBe(0);
  });

  // -- D. Already-TP cells (regression lockdown) -----------------------

  it('D-TP-java-xxe: DocumentBuilderFactory parse fires xxe', async () => {
    const code = [
      'import javax.xml.parsers.*;',
      'import org.springframework.web.bind.annotation.*;',
      'import org.w3c.dom.Document;',
      'import java.io.ByteArrayInputStream;',
      '',
      '@RestController',
      'public class C {',
      '  @PostMapping("/p")',
      '  public String p(@RequestBody String xml) throws Exception {',
      '    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();',
      '    DocumentBuilder db = dbf.newDocumentBuilder();',
      '    Document doc = db.parse(new ByteArrayInputStream(xml.getBytes()));',
      '    return doc.getDocumentElement().getNodeName();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/X.java', 'java');
    expect(hasXxeSignal(r)).toBe(true);
  });

  it('D-TP-js-libxmljs: libxmljs.parseXml(body, {noent:true}) fires xxe', async () => {
    const code = [
      "const express = require('express');",
      "const libxmljs = require('libxmljs');",
      'const app = express();',
      "app.use(express.text({ type: '*/*' }));",
      "app.post('/x', (req, res) => {",
      '  const doc = libxmljs.parseXml(req.body, { noent: true, noblanks: true });',
      '  res.send(doc.toString());',
      '});',
    ].join('\n');
    const r = await analyze(code, '/x/lx.js', 'javascript');
    expect(hasXxeSignal(r)).toBe(true);
  });

  it('D-TP-rust-path: Path::new(...).join(taint) → fs::read_to_string fires path_traversal', async () => {
    const code = [
      'use actix_web::{get, web, HttpResponse, Responder};',
      'use std::collections::HashMap;',
      'use std::path::Path;',
      'use std::fs;',
      '',
      '#[get("/r")]',
      'async fn handler(q: web::Query<HashMap<String, String>>) -> impl Responder {',
      '    let name = q.get("name").cloned().unwrap_or_default();',
      '    let p = Path::new("/var/www/").join(&name);',
      '    match fs::read_to_string(&p) {',
      '        Ok(s) => HttpResponse::Ok().body(s),',
      '        Err(_) => HttpResponse::NotFound().finish(),',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/p.rs', 'rust');
    expect(hasPathSignal(r)).toBe(true);
  });
});
