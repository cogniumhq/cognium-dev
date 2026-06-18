/**
 * Cross-file taint regression matrix.
 *
 * Locks the cross-file source→sink chaining that closed #106. The original
 * issue claimed cross-file taint was unresolved across Python/JS/Java/Go; the
 * post-Sprint-22 (#104) engine actually handles it correctly in PY/JS/Java
 * and partially in Go. Without explicit regression tests the only existing
 * cross-file coverage was Python sql/cmd via `repro-sprint13.test.ts` (#74),
 * which left this combination silently exposed.
 *
 * Each fixture asserts:
 *   - `analyzeProject([controller, helper])` returns ≥1 TaintPath where
 *     `source.file !== sink.file`, `source.type === 'http_param'` (the
 *     controller's HTTP source, not the helper's `interprocedural_param`
 *     fallback), and `sink.type` matches the expected vulnerability.
 *
 * Residual Go gaps are tracked separately:
 *   - #53  — Go `"const" + tainted` taint preservation (blocks GO.cmd here)
 *   - #107 — Go `log_injection` sink config
 *   - #108 — Go `code_injection`/SSTI sink config for text/html template
 *
 * Target: circle-ir 3.73.0.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cross-file taint regression matrix (#106 closure)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const xfilePaths = (
    paths: Array<{
      sanitized?: boolean;
      source?: { file?: string; type?: string };
      sink?: { file?: string; type?: string };
    }> | undefined,
    sinkType: string,
  ) =>
    (paths ?? []).filter(
      (p) =>
        !p.sanitized &&
        p.sink?.type === sinkType &&
        p.source?.file !== p.sink?.file &&
        p.source?.type === 'http_param',
    );

  // ---------------------------------------------------------------------------
  // Python — controller (flask) → helper (sink)
  // ---------------------------------------------------------------------------

  it('#106 PY.ldap — Flask request.args → helper.do_search → ldap.search_s', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.py',
        language: 'python',
        code: `from helper import do_search
from flask import Flask, request
app = Flask(__name__)
@app.route('/s')
def s():
  u = request.args.get('u')
  return do_search(u)
`,
      },
      {
        filePath: 'helper.py',
        language: 'python',
        code: `import ldap
def do_search(u):
  conn = ldap.initialize('ldap://x')
  return conn.search_s('dc=ex', 2, '(uid=' + u + ')')
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'ldap_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#106 PY.xxe — Flask request.args → helper.parse_xml → lxml.etree.fromstring', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.py',
        language: 'python',
        code: `from helper import parse_xml
from flask import Flask, request
app = Flask(__name__)
@app.route('/x')
def x():
  s = request.args.get('s')
  return parse_xml(s)
`,
      },
      {
        filePath: 'helper.py',
        language: 'python',
        code: `from lxml import etree
def parse_xml(s):
  parser = etree.XMLParser(resolve_entities=True)
  return etree.fromstring(s, parser)
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'xxe').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // JavaScript — express controller → helper (sink)
  // ---------------------------------------------------------------------------

  it('#106 JS.xpath — Express req.query → helper.doFind → xpath.select', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.js',
        language: 'javascript',
        code: `const express = require('express');
const { doFind } = require('./helper');
const app = express();
app.get('/f', (req, res) => { res.send(doFind(req.query.q)); });
`,
      },
      {
        filePath: 'helper.js',
        language: 'javascript',
        code: `const xpath = require('xpath');
function doFind(q) {
  return xpath.select("//user[@id='" + q + "']");
}
module.exports = { doFind };
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'xpath_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#106 JS.ldap — Express req.query → helper.doSearch → ldap.search', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.js',
        language: 'javascript',
        code: `const express = require('express');
const { doSearch } = require('./helper');
const app = express();
app.get('/l', (req, res) => { res.send(doSearch(req.query.u)); });
`,
      },
      {
        filePath: 'helper.js',
        language: 'javascript',
        code: `const ldap = require('ldapjs');
function doSearch(u) {
  return ldap.search('dc=ex', { filter: '(uid=' + u + ')' });
}
module.exports = { doSearch };
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'ldap_injection').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // Java — servlet controller → helper class (sink)
  // ---------------------------------------------------------------------------

  it('#106 JAVA.sqli — HttpServletRequest → XfHelper.lookup → Statement.executeQuery', async () => {
    const r = await analyzeProject([
      {
        filePath: 'XfController.java',
        language: 'java',
        code: `import javax.servlet.http.*;
public class XfController extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String u = req.getParameter("u");
    new XfHelper().lookup(u);
  }
}
`,
      },
      {
        filePath: 'XfHelper.java',
        language: 'java',
        code: `import java.sql.*;
public class XfHelper {
  Connection conn;
  public void lookup(String u) throws Exception {
    Statement s = conn.createStatement();
    s.executeQuery("SELECT * FROM u WHERE name='" + u + "'");
  }
}
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'sql_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#106 JAVA.cmd — HttpServletRequest → XfHelper.ping → Runtime.exec', async () => {
    const r = await analyzeProject([
      {
        filePath: 'XfController.java',
        language: 'java',
        code: `import javax.servlet.http.*;
public class XfController extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String h = req.getParameter("h");
    new XfHelper().ping(h);
  }
}
`,
      },
      {
        filePath: 'XfHelper.java',
        language: 'java',
        code: `public class XfHelper {
  public void ping(String h) throws Exception {
    Runtime.getRuntime().exec("ping " + h);
  }
}
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'command_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#106 JAVA.xxe — HttpServletRequest → XfHelper.parse → DocumentBuilder.parse', async () => {
    const r = await analyzeProject([
      {
        filePath: 'XfController.java',
        language: 'java',
        code: `import javax.servlet.http.*;
public class XfController extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String s = req.getParameter("s");
    new XfHelper().parse(s);
  }
}
`,
      },
      {
        filePath: 'XfHelper.java',
        language: 'java',
        code: `import javax.xml.parsers.*;
import java.io.*;
public class XfHelper {
  public void parse(String s) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    db.parse(new InputSource(new StringReader(s)));
  }
}
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'xxe').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // Go — controller → helper (sink). GO.cmd / GO.logi / GO.ssti tracked on
  // #53 / #107 / #108 respectively; only the working shape is locked here.
  // ---------------------------------------------------------------------------

  it('#106 GO.sqli — net/http handler → Query helper → db.Query', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.go',
        language: 'go',
        code: `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
  u := r.URL.Query().Get("u")
  Query(u)
}
`,
      },
      {
        filePath: 'helper.go',
        language: 'go',
        code: `package main
import "database/sql"
var db *sql.DB
func Query(u string) {
  db.Query("SELECT * FROM users WHERE name = '" + u + "'")
}
`,
      },
    ]);
    expect(xfilePaths(r.taint_paths, 'sql_injection').length).toBeGreaterThanOrEqual(1);
  });
});
