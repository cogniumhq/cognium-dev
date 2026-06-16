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
