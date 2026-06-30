/**
 * Sprint 89 — #189 variant-regression: deserialization (4) + xpath (3)
 * cluster.
 *
 * Baseline against 3.137.0 corpus showed **3 of 7 FN**:
 *   - go    deser   gob.NewDecoder(r.Body).Decode(&p)            (FN → TP)
 *   - js    deser   JSON.parse(req.body)                          (FN → TP)
 *   - js    xpath   document.evaluate(taint, ...)                 (FN → TP)
 *
 * The remaining 4 cells were already TP via existing configured sinks
 * (java SnakeYAML Yaml.load, rust bincode::deserialize,
 * python lxml tree.xpath, java XPath.evaluate). They are re-pinned
 * here as regression guards.
 *
 * New detectors:
 *   - findGoGobDeserializationFindings      (CWE-502)
 *   - findJsJsonParseBodyFindings           (CWE-502 / CWE-1321)
 *   - findJsDomXpathInjectionFindings       (CWE-643)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countRule = (r: any, ruleId: string) =>
  ((r.findings ?? []) as any[]).filter((f) => f.rule_id === ruleId).length;

const hasFlowOfType = (r: any, sinkType: string) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === sinkType);

const hasDeserSignal = (r: any) =>
  hasFlowOfType(r, 'deserialization') ||
  hasFlowOfType(r, 'insecure_deserialization') ||
  countRule(r, 'insecure_deserialization') > 0;

const hasXpathSignal = (r: any) =>
  hasFlowOfType(r, 'xpath_injection') || countRule(r, 'xpath_injection') > 0;

describe('#189 Sprint 89 — deserialization + xpath cluster', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -- A. Go gob.NewDecoder(r.Body).Decode -----------------------------

  it('A-TP: gob.NewDecoder(r.Body).Decode(&p) fires insecure_deserialization', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "encoding/gob"',
      '  "net/http"',
      ')',
      '',
      'type Payload struct { Name string }',
      '',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  var p Payload',
      '  dec := gob.NewDecoder(r.Body)',
      '  if err := dec.Decode(&p); err != nil {',
      '    http.Error(w, "bad", 400); return',
      '  }',
      '  w.Write([]byte(p.Name))',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/a.go', 'go');
    expect(hasDeserSignal(r)).toBe(true);
  });

  it('A-TP-inline: gob.NewDecoder(r.Body).Decode(...) inline fires', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "encoding/gob"',
      '  "net/http"',
      ')',
      '',
      'type P struct { X string }',
      '',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  var p P',
      '  gob.NewDecoder(r.Body).Decode(&p)',
      '  w.Write([]byte(p.X))',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/b.go', 'go');
    expect(hasDeserSignal(r)).toBe(true);
  });

  it('A-TN: gob.NewDecoder on a local file does NOT fire', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "encoding/gob"',
      '  "os"',
      ')',
      '',
      'type P struct { X string }',
      '',
      'func h() {',
      '  f, _ := os.Open("/tmp/state.gob")',
      '  defer f.Close()',
      '  var p P',
      '  dec := gob.NewDecoder(f)',
      '  dec.Decode(&p)',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/c.go', 'go');
    const findings = (r.findings ?? []) as any[];
    expect(findings.some((f) => f.rule_id === 'insecure_deserialization')).toBe(
      false,
    );
  });

  // -- B. JS JSON.parse(req.body) --------------------------------------

  it('B-TP: JSON.parse(req.body) fires insecure_deserialization', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.use(express.text({ type: '*/*' }));",
      "app.post('/parse', (req, res) => {",
      '  const obj = JSON.parse(req.body);',
      '  res.json({ ok: true, type: typeof obj });',
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/p.js', 'javascript');
    expect(hasDeserSignal(r)).toBe(true);
  });

  it('B-TP-aliased: JSON.parse(aliasOfBody) fires', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.use(express.text());",
      "app.post('/p', (req, res) => {",
      '  const raw = req.body;',
      '  const obj = JSON.parse(raw);',
      '  res.json(obj);',
      '});',
    ].join('\n');
    const r = await analyze(code, '/x/q.js', 'javascript');
    expect(hasDeserSignal(r)).toBe(true);
  });

  it('B-TN: JSON.parse(literal) does NOT fire as insecure_deserialization', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.post('/p', (req, res) => {",
      "  const obj = JSON.parse('{\"a\":1}');",
      "  res.send('ok');",
      '});',
    ].join('\n');
    const r = await analyze(code, '/x/r.js', 'javascript');
    expect(countRule(r, 'insecure_deserialization')).toBe(0);
  });

  // -- C. JS DOM document.evaluate -------------------------------------

  it('C-TP: document.evaluate(taint, ...) fires xpath_injection', async () => {
    const code = [
      'function search(doc) {',
      "  const q = new URLSearchParams(window.location.search).get('q');",
      "  const expr = \"//user[name='\" + q + \"']\";",
      '  const result = doc.evaluate(expr, doc, null, XPathResult.ANY_TYPE, null);',
      '  return result;',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/x.js', 'javascript');
    expect(hasXpathSignal(r)).toBe(true);
  });

  it('C-TN: document.evaluate(literal) does NOT fire', async () => {
    const code = [
      'function search(doc) {',
      "  const result = doc.evaluate('//user', doc, null, XPathResult.ANY_TYPE, null);",
      '  return result;',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/y.js', 'javascript');
    expect(countRule(r, 'xpath_injection')).toBe(0);
  });

  // -- D. Already-TP cells (regression lockdown) -----------------------

  it('D-TP-java-snakeyaml: new Yaml().load(req.body) fires deserialization', async () => {
    const code = [
      'import org.springframework.web.bind.annotation.*;',
      'import org.yaml.snakeyaml.Yaml;',
      'import org.yaml.snakeyaml.constructor.Constructor;',
      '',
      '@RestController',
      'public class C {',
      '  @PostMapping("/y")',
      '  public Object load(@RequestBody String body) {',
      '    Yaml y = new Yaml(new Constructor(Object.class));',
      '    return y.load(body);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/Y.java', 'java');
    expect(hasFlowOfType(r, 'deserialization')).toBe(true);
  });

  it('D-TP-py-lxml: tree.xpath(taint) fires xpath_injection', async () => {
    const code = [
      'from flask import Flask, request',
      'from lxml import etree',
      'app = Flask(__name__)',
      '',
      "@app.route('/f')",
      'def f():',
      "    name = request.args.get('name', '')",
      "    tree = etree.parse('/etc/users.xml')",
      '    return str(tree.xpath("//user[name=\'" + name + "\']"))',
    ].join('\n');
    const r = await analyze(code, '/x/x.py', 'python');
    expect(hasXpathSignal(r)).toBe(true);
  });

  it('D-TP-java-xpath: XPath.evaluate(taint, doc) fires xpath_injection', async () => {
    const code = [
      'import javax.xml.xpath.*;',
      'import org.springframework.web.bind.annotation.*;',
      'import org.w3c.dom.Document;',
      '',
      '@RestController',
      'public class C {',
      '  @GetMapping("/f")',
      '  public String f(@RequestParam("name") String name, Document doc) throws Exception {',
      '    XPath xpath = XPathFactory.newInstance().newXPath();',
      '    String expr = "//user[name=\'" + name + "\']";',
      '    return xpath.evaluate(expr, doc);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/X.java', 'java');
    expect(hasFlowOfType(r, 'xpath_injection')).toBe(true);
  });
});
