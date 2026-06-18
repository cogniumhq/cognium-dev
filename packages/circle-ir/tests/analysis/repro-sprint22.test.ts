/**
 * Repro for cognium-dev Sprint 22 — OOP object-flow taint FN, sink-agnostic
 * closure (#104).
 *
 * Sprint 16/18 (#78) introduced OOP field-sensitivity for **injection** sinks
 * (sql_injection, command_injection). Sprint 21 (#105) confirmed the same
 * mechanism works for ssrf and nosql_injection. This sprint extends OOP
 * object-flow coverage to all remaining Tier-1 non-injection sink types
 * across Python and JavaScript.
 *
 * Mechanism reuse: each fixture has a constructor-injected field
 * (`self.<x>` Python / `this.<x>` JS) consumed by a sibling method that
 * calls the sink. `findOopFieldReadSources` (LanguageSourcesPass) emits a
 * synthetic taint source at the field-read site, and the standard
 * TaintPropagationPass produces a flow to the configured sink.
 *
 * Sprint 22 changes that this fixture suite locks in:
 *   - LanguageSourcesPass.findOopFieldReadSources extended to JS/TS,
 *     including inline `constructor(x) { this.x = x; }` syntax.
 *   - isFalsePositive (constant-propagation) exempts `self.X`/`this.X`
 *     OOP field-path variables from the const-prop "variable_not_tainted"
 *     suppression (was silently zeroing JS OOP flows).
 *   - SinkFilterPass Stage 5 (Python xpath_injection FP reducer)
 *     recognises OOP field-path sources so xpath sinks under
 *     constructor-injected fields aren't dropped.
 *   - New sink-config entries (config-loader.ts):
 *     * Python `logging.{info,warning,error,debug,critical,log,exception}`
 *       log_injection (CWE-117).
 *     * Python pymongo classless `find_one/update_one/.../count_documents`
 *       nosql_injection (CWE-943).
 *     * JS ldapjs `ldap.search/searchSync` ldap_injection (CWE-90).
 *     * JS xpath module `xpath.{select,select1,evaluate,parse}`
 *       xpath_injection (CWE-643).
 *     * JS libxmljs/xmldom `parseXml/parseXmlString/parseFromString` xxe
 *       (CWE-611).
 *     * JS ejs/handlebars/pug/mustache/nunjucks `render/compile/...`
 *       code_injection (SSTI, CWE-94).
 *
 * Target release: circle-ir 3.72.0 / cognium-dev 3.72.0.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev OOP object-flow taint — Sprint 22 (#104)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsByType = (
    flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined,
    sinkType: string,
  ) => (flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

  // ---------------------------------------------------------------------------
  // Python — 9 OOP non-injection shapes (each expects ≥1 flow).
  // ---------------------------------------------------------------------------

  it('#104 PY.ssrf — Sprint 21 lock; requests.get(self.url) → ssrf', async () => {
    const code = `import requests
class HttpClient:
    def __init__(self, url):
        self.url = url
    def fetch(self):
        return requests.get(self.url)
`;
    const r = await analyze(code, 'oop_ssrf.py', 'python');
    expect(flowsByType(r.taint.flows, 'ssrf').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.path_traversal — open(self.path) → path_traversal', async () => {
    const code = `class FileReader:
    def __init__(self, path):
        self.path = path
    def read(self):
        return open(self.path).read()
`;
    const r = await analyze(code, 'oop_path.py', 'python');
    expect(flowsByType(r.taint.flows, 'path_traversal').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.open_redirect — flask.redirect(self.dest) → open_redirect', async () => {
    const code = `from flask import redirect
class Redirector:
    def __init__(self, dest):
        self.dest = dest
    def go(self):
        return redirect(self.dest)
`;
    const r = await analyze(code, 'oop_redirect.py', 'python');
    expect(flowsByType(r.taint.flows, 'open_redirect').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.log_injection — logging.info(self.msg) → log_injection', async () => {
    const code = `import logging
class Logger:
    def __init__(self, msg):
        self.msg = msg
    def write(self):
        logging.info(self.msg)
`;
    const r = await analyze(code, 'oop_loginj.py', 'python');
    expect(flowsByType(r.taint.flows, 'log_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.ldap_injection — ldap.search_s with self.user → ldap_injection', async () => {
    const code = `import ldap
class LdapClient:
    def __init__(self, user):
        self.user = user
    def search(self, conn):
        return conn.search_s('dc=example', 2, '(uid=' + self.user + ')')
`;
    const r = await analyze(code, 'oop_ldap.py', 'python');
    expect(flowsByType(r.taint.flows, 'ldap_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.xpath_injection — tree.xpath(f"...{self.q}...") → xpath_injection', async () => {
    const code = `class XmlQ:
    def __init__(self, q):
        self.q = q
    def find(self, tree):
        return tree.xpath(f"//user[@id='{self.q}']")
`;
    const r = await analyze(code, 'oop_xpath.py', 'python');
    expect(flowsByType(r.taint.flows, 'xpath_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.nosql_injection — db.users.find_one({...self.name}) → nosql_injection', async () => {
    const code = `class UserRepo:
    def __init__(self, name):
        self.name = name
    def find(self, db):
        return db.users.find_one({"$where": self.name})
`;
    const r = await analyze(code, 'oop_nosql.py', 'python');
    expect(flowsByType(r.taint.flows, 'nosql_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.ssti — Template(self.tmpl).render() → code_injection', async () => {
    const code = `from jinja2 import Template
class Renderer:
    def __init__(self, tmpl):
        self.tmpl = tmpl
    def render(self):
        return Template(self.tmpl).render()
`;
    const r = await analyze(code, 'oop_ssti.py', 'python');
    expect(flowsByType(r.taint.flows, 'code_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 PY.deserialization — pickle.loads(self.data) → deserialization', async () => {
    const code = `import pickle
class Deserializer:
    def __init__(self, data):
        self.data = data
    def load(self):
        return pickle.loads(self.data)
`;
    const r = await analyze(code, 'oop_deser.py', 'python');
    expect(flowsByType(r.taint.flows, 'deserialization').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // JavaScript — 7 OOP non-injection shapes (each expects ≥1 flow).
  // ---------------------------------------------------------------------------

  it('#104 JS.nosql_injection — Sprint 21 lock; db.collection.findOne({...this.name}) → nosql_injection', async () => {
    const code = `class UserRepo {
  constructor(name) { this.name = name; }
  async find(db) { return db.collection('users').findOne({"$where": this.name}); }
}
`;
    const r = await analyze(code, 'oop_nosql.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'nosql_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 JS.log_injection — console.log(this.msg) → log_injection', async () => {
    const code = `class Logger {
  constructor(msg) { this.msg = msg; }
  write() { console.log(this.msg); }
}
`;
    const r = await analyze(code, 'oop_loginj.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'log_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 JS.ldap_injection — ldap.search filter built from this.user → ldap_injection', async () => {
    const code = `const ldap = require('ldapjs');
class LdapClient {
  constructor(user) { this.user = user; }
  search(cb) { return ldap.search('dc=ex', { filter: '(uid=' + this.user + ')' }, cb); }
}
`;
    const r = await analyze(code, 'oop_ldap.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'ldap_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 JS.xpath_injection — xpath.select("..." + this.q) → xpath_injection', async () => {
    const code = `const xpath = require('xpath');
class XmlQ {
  constructor(q) { this.q = q; }
  find(doc) { return xpath.select("//user[@id='" + this.q + "']", doc); }
}
`;
    const r = await analyze(code, 'oop_xpath.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'xpath_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 JS.deserialization — node-serialize unserialize(this.data) → deserialization', async () => {
    const code = `const serialize = require('node-serialize');
class Deserializer {
  constructor(data) { this.data = data; }
  load() { return serialize.unserialize(this.data); }
}
`;
    const r = await analyze(code, 'oop_deser.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'deserialization').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 JS.xxe — libxml.parseXml(this.src, {noent:true}) → xxe', async () => {
    const code = `const libxml = require('libxmljs');
class XmlParser {
  constructor(src) { this.src = src; }
  parse() { return libxml.parseXml(this.src, {noent: true, dtdload: true}); }
}
`;
    const r = await analyze(code, 'oop_xxe.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'xxe').length).toBeGreaterThanOrEqual(1);
  });

  it('#104 JS.ssti — ejs.render(this.tmpl) → code_injection', async () => {
    const code = `const ejs = require('ejs');
class Renderer {
  constructor(tmpl) { this.tmpl = tmpl; }
  render() { return ejs.render(this.tmpl); }
}
`;
    const r = await analyze(code, 'oop_ssti.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'code_injection').length).toBeGreaterThanOrEqual(1);
  });
});
