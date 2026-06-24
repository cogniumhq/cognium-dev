/**
 * Repro for cognium-dev#86 — Sprint 5 coverage additions:
 *
 *   1. JWT verification disabled (CWE-347) — pure pattern pass on
 *      jwt.decode/jwt.verify/JWT.require/Jwts.parser().parse.
 *   2. ReDoS (CWE-1333) — taint flow into re.{match,search,compile,…},
 *      Pattern.compile, String.matches, regexp.Compile.
 *   3. Format-string injection (CWE-134) — taint flow into String.format /
 *      Formatter.format / fmt.Sprintf.
 *
 * NOTE: SAST regression fixtures — every handler below is *deliberately*
 * vulnerable so the detector can be measured. Do not "fix" the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#86 — Sprint 5: JWT, ReDoS, format-string', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ---------------------------------------------------------------------
  // JWT verify disabled — CWE-347
  // ---------------------------------------------------------------------

  it('flags PyJWT decode with verify_signature: False', async () => {
    const code = `
import jwt
def auth(tok):
    return jwt.decode(tok, "secret", options={"verify_signature": False})
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
    expect(finds[0].cwe).toBe('CWE-347');
  });

  it('flags PyJWT decode with algorithms=["none"]', async () => {
    const code = `
import jwt
def auth(tok):
    return jwt.decode(tok, "secret", algorithms=["none"])
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag PyJWT decode with HS256 (negative control)', async () => {
    const code = `
import jwt
def auth(tok):
    return jwt.decode(tok, "secret", algorithms=["HS256"])
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');
    expect(finds.length).toBe(0);
  });

  it('flags jsonwebtoken verify with algorithms: ["none"]', async () => {
    const code = `
const jwt = require('jsonwebtoken');
function auth(tok) {
  return jwt.verify(tok, secret, { algorithms: ['none'] });
}
`;
    const r = await analyze(code, 't.js', 'javascript');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('flags jsonwebtoken verify with null key', async () => {
    const code = `
const jwt = require('jsonwebtoken');
function auth(tok) {
  return jwt.verify(tok, null);
}
`;
    const r = await analyze(code, 't.js', 'javascript');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('flags Java auth0 JWT.require(Algorithm.none())', async () => {
    const code = `
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
public class T {
  public Object check(String tok) {
    return JWT.require(Algorithm.none()).build().verify(tok);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------
  // ReDoS — CWE-1333
  // ---------------------------------------------------------------------

  it('flags tainted regex passed to Python re.match', async () => {
    const code = `
import re
from flask import request
def handle():
    pat = request.args.get("pattern")
    return re.match(pat, "input")
`;
    const r = await analyze(code, 't.py', 'python');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'redos');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('flags tainted regex passed to Python re.compile', async () => {
    const code = `
import re
from flask import request
def handle():
    pat = request.args.get("pattern")
    return re.compile(pat)
`;
    const r = await analyze(code, 't.py', 'python');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'redos');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('flags tainted regex passed to Java Pattern.compile', async () => {
    const code = `
import java.util.regex.Pattern;
public class T {
  public void handle(javax.servlet.http.HttpServletRequest req) {
    String pat = req.getParameter("p");
    Pattern p = Pattern.compile(pat);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'redos');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------
  // Format-string injection — CWE-134
  // ---------------------------------------------------------------------

  it('flags tainted format string passed to Java String.format', async () => {
    const code = `
public class T {
  public String fmt(javax.servlet.http.HttpServletRequest req) {
    String f = req.getParameter("fmt");
    return String.format(f, "a1", "a2");
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'format_string');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });
});

describe('cognium-dev#86 — Sprint 6: CRLF, CSRF, XML-bomb, mass-assignment', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ---------------------------------------------------------------------
  // CRLF / HTTP response splitting — CWE-113
  // ---------------------------------------------------------------------

  it('flags Java setHeader of user-controlled parameter as crlf', async () => {
    const code = `
public class T {
  public void h(javax.servlet.http.HttpServletRequest req,
                javax.servlet.http.HttpServletResponse res) {
    String t = req.getParameter("t");
    res.setHeader("X-Tag", t);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'crlf');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('Java setHeader is no longer classified as xss (regression guard)', async () => {
    const code = `
public class T {
  public void h(javax.servlet.http.HttpServletRequest req,
                javax.servlet.http.HttpServletResponse res) {
    String t = req.getParameter("t");
    res.setHeader("X-Tag", t);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const xssFlows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'xss');
    expect(xssFlows.length).toBe(0);
  });

  it('flags JS res.setHeader of req.query as crlf', async () => {
    const code = `
function h(req, res) {
  res.setHeader('X-Tag', req.query.t);
}
`;
    const r = await analyze(code, 't.js', 'javascript');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'crlf');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  // cognium-dev #132 — Express/Koa `res.cookie(name, value, [opts])` is
  // CRLF-safe by construction: the cookie helper serialises via
  // `cookie.serialize()` which URL-encodes CR (%0D) / LF (%0A). The
  // historic Sprint 6 assertion that this shape flags as CRLF is
  // inverted by Stage 8d in SinkFilterPass. The raw-header path
  // `res.setHeader('Set-Cookie', tainted)` continues to fire (see #132
  // recall test in tests/analysis/passes/crlf-stage8-fp.test.ts).
  it('does NOT flag JS res.cookie of req.query as crlf (cookie helper is CRLF-safe, #132)', async () => {
    const code = `
function h(req, res) {
  res.cookie('session', req.query.s);
}
`;
    const r = await analyze(code, 't.js', 'javascript');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'crlf');
    expect(flows.length).toBe(0);
  });

  // ---------------------------------------------------------------------
  // CSRF protection disabled — CWE-352
  // ---------------------------------------------------------------------

  it('flags Spring HttpSecurity.csrf().disable()', async () => {
    const code = `
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
public class T {
  public void cfg(HttpSecurity http) throws Exception {
    http.csrf().disable();
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'csrf-protection-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
    expect(finds[0].cwe).toBe('CWE-352');
  });

  it('flags Spring lambda DSL csrf(c -> c.disable())', async () => {
    const code = `
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
public class T {
  public void cfg(HttpSecurity http) throws Exception {
    http.csrf(c -> c.disable());
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'csrf-protection-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('flags Django @csrf_exempt decorator', async () => {
    const code = `
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def view(request):
    return None
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'csrf-protection-disabled');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag Spring config without csrf disable (negative)', async () => {
    const code = `
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
public class T {
  public void cfg(HttpSecurity http) throws Exception {
    http.authorizeRequests().anyRequest().authenticated();
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'csrf-protection-disabled');
    expect(finds.length).toBe(0);
  });

  // ---------------------------------------------------------------------
  // XML entity expansion (XML bomb / billion-laughs) — CWE-776
  // ---------------------------------------------------------------------

  it('flags Java SAXParserFactory without disallow-doctype feature', async () => {
    const code = `
import javax.xml.parsers.SAXParserFactory;
public class T {
  public void parse(String xml) throws Exception {
    SAXParserFactory f = SAXParserFactory.newInstance();
    f.newSAXParser().parse(new java.io.StringBufferInputStream(xml), null);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion');
    expect(finds.length).toBeGreaterThanOrEqual(1);
    expect(finds[0].cwe).toBe('CWE-776');
  });

  it('flags Java DocumentBuilderFactory without safe features', async () => {
    const code = `
import javax.xml.parsers.DocumentBuilderFactory;
public class T {
  public void parse(String xml) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.newDocumentBuilder().parse(xml);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag Java SAXParserFactory WITH disable-doctype (negative)', async () => {
    const code = `
import javax.xml.parsers.SAXParserFactory;
public class T {
  public void parse(String xml) throws Exception {
    SAXParserFactory f = SAXParserFactory.newInstance();
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    f.newSAXParser().parse(new java.io.StringBufferInputStream(xml), null);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion');
    expect(finds.length).toBe(0);
  });

  it('flags Python lxml etree.fromstring', async () => {
    const code = `
from lxml import etree
def parse(xml):
    return etree.fromstring(xml)
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag Python lxml when defusedxml is imported (negative)', async () => {
    const code = `
import defusedxml
from defusedxml import etree
def parse(xml):
    return etree.fromstring(xml)
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion');
    expect(finds.length).toBe(0);
  });

  // ---------------------------------------------------------------------
  // Mass-assignment / over-posting — CWE-915
  // ---------------------------------------------------------------------

  it('flags Python User(**request.form) splat constructor', async () => {
    const code = `
from flask import request
from models import User
def create():
    return User(**request.form)
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'mass-assignment');
    expect(finds.length).toBeGreaterThanOrEqual(1);
    expect(finds[0].cwe).toBe('CWE-915');
  });

  it('flags Python User(**request.get_json()) splat constructor', async () => {
    const code = `
from flask import request
from models import User
def create():
    return User(**request.get_json())
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'mass-assignment');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('flags JS object spread {...req.body} as mass-assignment', async () => {
    const code = `
function update(req) {
  return { ...req.body, id: 1 };
}
`;
    const r = await analyze(code, 't.js', 'javascript');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'mass-assignment');
    expect(finds.length).toBeGreaterThanOrEqual(1);
  });

  it('flags JS Object.assign(user, req.body) as mass_assignment taint flow', async () => {
    const code = `
function update(req) {
  const user = {};
  Object.assign(user, req.body);
  return user;
}
`;
    const r = await analyze(code, 't.js', 'javascript');
    const flows = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'mass_assignment');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag explicit allow-list construction (negative)', async () => {
    const code = `
from flask import request
from models import User
def create():
    return User(name=request.form['name'])
`;
    const r = await analyze(code, 't.py', 'python');
    const finds = (r.findings ?? []).filter((f) => f.rule_id === 'mass-assignment');
    expect(finds.length).toBe(0);
  });
});
