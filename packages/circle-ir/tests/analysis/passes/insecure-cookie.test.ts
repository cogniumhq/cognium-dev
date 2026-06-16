/**
 * Regression tests for cognium-dev #43 — `insecure_cookie` (CWE-614) for
 * Express `res.cookie(name, value, options)` on JavaScript and TypeScript.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

describe('insecure-cookie pass (#43)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const insecureCookieFindings = (r: { findings?: Array<{ rule_id: string }> }) =>
    (r.findings ?? []).filter(f => f.rule_id === 'insecure-cookie');

  it('JS: res.cookie() with no options is flagged', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('session', req.query.uid);
  res.send('ok');
});
`;
    const r = await analyze(code, 'a.js', 'javascript');
    const f = insecureCookieFindings(r);
    expect(f).toHaveLength(1);
    expect(f[0].cwe).toBe('CWE-614');
    expect(f[0].severity).toBe('medium');
    expect(f[0].line).toBe(5);
  });

  it('JS: res.cookie() with options but no flags is flagged', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('session', req.query.uid, { maxAge: 86400000 });
  res.send('ok');
});
`;
    const r = await analyze(code, 'b.js', 'javascript');
    const f = insecureCookieFindings(r);
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(5);
  });

  it('JS: res.cookie() with secure=false and httpOnly=false is flagged', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('session', req.query.uid, { secure: false, httpOnly: false });
  res.send('ok');
});
`;
    const r = await analyze(code, 'c.js', 'javascript');
    expect(insecureCookieFindings(r)).toHaveLength(1);
  });

  it('JS: res.cookie() with secure=true and httpOnly=true is NOT flagged', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('session', req.query.uid, { secure: true, httpOnly: true });
  res.send('ok');
});
`;
    const r = await analyze(code, 'd.js', 'javascript');
    expect(insecureCookieFindings(r)).toHaveLength(0);
  });

  it('JS: res.cookie() with only secure=true (missing httpOnly) is flagged', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('session', req.query.uid, { secure: true });
  res.send('ok');
});
`;
    const r = await analyze(code, 'e.js', 'javascript');
    const f = insecureCookieFindings(r);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('httpOnly');
  });

  it('JS: res.cookie() with only httpOnly=true (missing secure) is flagged', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  res.cookie('session', req.query.uid, { httpOnly: true });
  res.send('ok');
});
`;
    const r = await analyze(code, 'f.js', 'javascript');
    const f = insecureCookieFindings(r);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('secure');
  });

  it('TS: res.cookie() w/o flags is flagged', async () => {
    const code = `
import express, { Request, Response } from 'express';
const app = express();
app.get('/login', (req: Request, res: Response) => {
  res.cookie('auth', String(req.query.user), { maxAge: 86400000 });
  res.send('ok');
});
`;
    const r = await analyze(code, 'g.ts', 'typescript');
    const f = insecureCookieFindings(r);
    expect(f).toHaveLength(1);
    expect(f[0].cwe).toBe('CWE-614');
  });

  it('reply.cookie() (Fastify-style) w/o flags is flagged', async () => {
    const code = `
async function handler(req, reply) {
  reply.cookie('token', req.body.token, { path: '/' });
  reply.send('ok');
}
`;
    const r = await analyze(code, 'h.js', 'javascript');
    expect(insecureCookieFindings(r)).toHaveLength(1);
  });

  it('does NOT flag res.clearCookie()', async () => {
    const code = `
function handler(req, res) {
  res.clearCookie('session');
  res.send('ok');
}
`;
    const r = await analyze(code, 'i.js', 'javascript');
    expect(insecureCookieFindings(r)).toHaveLength(0);
  });

  it('does NOT flag obj.cookie on a non-response receiver', async () => {
    // `jar.cookie(...)` where jar is e.g. a tough-cookie CookieJar — not Express.
    const code = `
const jar = new CookieJar();
jar.cookie('session', 'value', { maxAge: 0 });
`;
    const r = await analyze(code, 'j.js', 'javascript');
    expect(insecureCookieFindings(r)).toHaveLength(0);
  });

  it('does NOT flag Java res.cookie(...) method call (Java arm matches new Cookie ctor, not method calls)', async () => {
    const code = `
public class Foo {
  public void f(HttpServletResponse res) {
    res.cookie("a", "b", null);
  }
}
`;
    const r = await analyze(code, 'Foo.java', 'java');
    expect(insecureCookieFindings(r)).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // Python (Flask / Django / Starlette response.set_cookie)
  // -----------------------------------------------------------------------

  it('Python: response.set_cookie() without flags is flagged', async () => {
    const code = `
def handler(request, response):
    response.set_cookie('session', request.GET['uid'])
    return response
`;
    const r = await analyze(code, 'a.py', 'python');
    const f = insecureCookieFindings(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe('CWE-614');
  });

  it('Python: response.set_cookie(..., secure=True, httponly=True) is NOT flagged', async () => {
    const code = `
def handler(request, response):
    response.set_cookie('session', request.GET['uid'], secure=True, httponly=True)
    return response
`;
    const r = await analyze(code, 'b.py', 'python');
    expect(insecureCookieFindings(r)).toHaveLength(0);
  });

  it('Python: response.set_cookie(..., secure=True) (missing httponly) is flagged', async () => {
    const code = `
def handler(request, response):
    response.set_cookie('session', request.GET['uid'], secure=True)
    return response
`;
    const r = await analyze(code, 'c.py', 'python');
    const f = insecureCookieFindings(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].message.toLowerCase()).toContain('httponly');
  });

  // -----------------------------------------------------------------------
  // Java (javax.servlet.http.Cookie)
  // -----------------------------------------------------------------------

  it('Java: new Cookie(...) without setSecure/setHttpOnly is flagged', async () => {
    const code = `
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
public class A {
  public void f(HttpServletResponse res) {
    Cookie c = new Cookie("session", "value");
    res.addCookie(c);
  }
}
`;
    const r = await analyze(code, 'A.java', 'java');
    const f = insecureCookieFindings(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe('CWE-614');
  });

  it('Java: new Cookie(...) WITH setSecure(true) + setHttpOnly(true) is NOT flagged', async () => {
    const code = `
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
public class A {
  public void f(HttpServletResponse res) {
    Cookie c = new Cookie("session", "value");
    c.setSecure(true);
    c.setHttpOnly(true);
    res.addCookie(c);
  }
}
`;
    const r = await analyze(code, 'B.java', 'java');
    expect(insecureCookieFindings(r)).toHaveLength(0);
  });

  it('Java: new Cookie(...) with only setSecure(true) (missing setHttpOnly) is flagged', async () => {
    const code = `
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
public class A {
  public void f(HttpServletResponse res) {
    Cookie c = new Cookie("session", "value");
    c.setSecure(true);
    res.addCookie(c);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    expect(insecureCookieFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('emits one finding per call site (no duplicates)', async () => {
    const code = `
function handler(req, res) {
  res.cookie('a', '1');
  res.cookie('b', '2', { secure: true });
  res.cookie('c', '3', { secure: true, httpOnly: true });
}
`;
    const r = await analyze(code, 'k.js', 'javascript');
    const f = insecureCookieFindings(r);
    expect(f).toHaveLength(2);
    expect(f.map(x => x.line).sort()).toEqual([3, 4]);
  });
});
