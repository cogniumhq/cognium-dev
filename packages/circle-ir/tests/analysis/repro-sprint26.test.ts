/**
 * Repro for Sprint 26 — bundle fixes for #117, #118, #109.
 *
 * #117 (CWE-501 Trust Boundary):
 *   Sink existed in `config-loader.ts` with `arg_positions: [0]` (looked at
 *   the KEY only). OWASP CWE-501 test cases taint the VALUE
 *   (`session.setAttribute("k", request.getParameter("name"))`), so 83/83
 *   cases under-fired. Fix: change to `arg_positions: [0, 1]` and add
 *   `ServletContext.setAttribute` / `HttpServletRequest.setAttribute`.
 *
 * #118 (CWE-614 Insecure Cookie):
 *   `insecure-cookie-pass.ts:detectJavaCookieCtor` required
 *   `method_name === 'Cookie'`. OWASP cases use FQ form
 *   `new javax.servlet.http.Cookie(...)` without an import, producing
 *   `method_name === 'javax.servlet.http.Cookie'`. Fix: accept
 *   `method.endsWith('.Cookie')` and FQ receiver_type tails.
 *
 * #109 (CWE-260/798 Hardcoded Credentials):
 *   `scan-secrets-pass.ts` had two detection layers: (1) provider-prefix
 *   regexes (AWS/GitHub/etc.) and (2) entropy-based base64/hex/UUID.
 *   Config-style constants like `DB_PASSWORD = "Pr0d-DB-pass!2024"`
 *   contain `!` which fails the base64/hex regexes — missed entirely.
 *   Fix: add Layer 1b "named-credential assignment" detection that flags
 *   any literal string assigned to an identifier whose name matches
 *   /password|secret|api_key|auth_token|private_key|access_key/i.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

describe('Sprint 26 — #117 trust_boundary (CWE-501)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const tbFlows = (ir: CircleIR) =>
    (ir.taint?.flows ?? []).filter((f) => f.sink_type === 'trust_boundary');

  it('flags HttpSession.setAttribute with tainted VALUE (OWASP shape)', async () => {
    const code = `
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    String name = request.getParameter("name");
    HttpSession session = request.getSession();
    session.setAttribute("userName", name);
  }
}
`;
    const ir = await analyze(code, 'Tb1.java', 'java');
    expect(tbFlows(ir).length).toBeGreaterThanOrEqual(1);
  });

  it('flags ServletContext.setAttribute with tainted value', async () => {
    const code = `
import jakarta.servlet.*;
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest request) {
    String name = request.getParameter("name");
    ServletContext ctx = request.getServletContext();
    ctx.setAttribute("k", name);
  }
}
`;
    const ir = await analyze(code, 'Tb2.java', 'java');
    expect(tbFlows(ir).length).toBeGreaterThanOrEqual(1);
  });

  it('flags HttpServletRequest.setAttribute with tainted value', async () => {
    const code = `
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest request) {
    String name = request.getParameter("name");
    request.setAttribute("k", name);
  }
}
`;
    const ir = await analyze(code, 'Tb3.java', 'java');
    expect(tbFlows(ir).length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag setAttribute with literal value (no taint)', async () => {
    const code = `
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession();
    session.setAttribute("userName", "literal");
  }
}
`;
    const ir = await analyze(code, 'TbSafe.java', 'java');
    expect(tbFlows(ir)).toHaveLength(0);
  });
});

describe('Sprint 26 — #118 insecure-cookie FQ constructor', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const icFinds = (findings: Array<{ rule_id?: string }> | undefined) =>
    (findings ?? []).filter((f) => f.rule_id === 'insecure-cookie');

  it('flags fully-qualified new javax.servlet.http.Cookie(...) (OWASP shape)', async () => {
    const code = `
public class A {
  public void doGet(jakarta.servlet.http.HttpServletRequest req,
                    jakarta.servlet.http.HttpServletResponse response) {
    String v = req.getParameter("v");
    javax.servlet.http.Cookie userCookie = new javax.servlet.http.Cookie("BenchmarkTest", v);
    response.addCookie(userCookie);
  }
}
`;
    const ir = await analyze(code, 'IcFq.java', 'java');
    expect(icFinds(ir.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('still flags unqualified new Cookie(...) with no Secure/HttpOnly', async () => {
    const code = `
import javax.servlet.http.*;
public class A {
  public void doGet(HttpServletResponse response) {
    Cookie c = new Cookie("name", "value");
    response.addCookie(c);
  }
}
`;
    const ir = await analyze(code, 'IcShort.java', 'java');
    expect(icFinds(ir.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag Cookie with both Secure+HttpOnly set', async () => {
    const code = `
import javax.servlet.http.*;
public class A {
  public void doGet(HttpServletResponse response) {
    Cookie c = new Cookie("name", "value");
    c.setSecure(true);
    c.setHttpOnly(true);
    response.addCookie(c);
  }
}
`;
    const ir = await analyze(code, 'IcSafe.java', 'java');
    expect(icFinds(ir.findings)).toHaveLength(0);
  });
});

describe('Sprint 26 — #109 hardcoded named-credential (CWE-798)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const credFinds = (findings: Array<{ rule_id?: string; line?: number }> | undefined) =>
    (findings ?? []).filter((f) => f.rule_id === 'hardcoded-credential');

  it('flags Java DB_PASSWORD = "Pr0d-DB-pass!2024"', async () => {
    const code = `
public class DbConfig {
  public static final String DB_PASSWORD = "Pr0d-DB-pass!2024";
  public static final String DB_USER = "admin";
}
`;
    const ir = await analyze(code, 'DbConfig.java', 'java');
    expect(credFinds(ir.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('flags Python DB_PASSWORD = "Pr0d-DB-pass!2024"', async () => {
    const code = `
DB_PASSWORD = "Pr0d-DB-pass!2024"
DB_USER = "admin"
`;
    const ir = await analyze(code, 'db_config.py', 'python');
    expect(credFinds(ir.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('flags JavaScript const DB_PASSWORD = "Pr0d-DB-pass!2024"', async () => {
    const code = `
const DB_PASSWORD = "Pr0d-DB-pass!2024";
const DB_USER = "admin";
module.exports = { DB_PASSWORD, DB_USER };
`;
    const ir = await analyze(code, 'db_config.js', 'javascript');
    expect(credFinds(ir.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('flags Go const DBPassword = "Pr0d-DB-pass!2024"', async () => {
    const code = `
package config
const DBPassword = "Pr0d-DB-pass!2024"
const DBUser = "admin"
`;
    const ir = await analyze(code, 'db_config.go', 'go');
    expect(credFinds(ir.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT flag credential read from process.env', async () => {
    const code = `
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_USER = process.env.DB_USER;
`;
    const ir = await analyze(code, 'env.js', 'javascript');
    expect(credFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag function declaration containing "password"', async () => {
    const code = `
function checkPassword(input) {
  return input === "test";
}
`;
    const ir = await analyze(code, 'fn.js', 'javascript');
    expect(credFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag string comparison against literal', async () => {
    const code = `
function check(password) {
  if (password === "expected") {
    return true;
  }
}
`;
    const ir = await analyze(code, 'cmp.js', 'javascript');
    expect(credFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag placeholder values', async () => {
    const code = `
const DB_PASSWORD = "<your-password-here>";
const API_KEY = "REPLACE_ME";
`;
    const ir = await analyze(code, 'tpl.js', 'javascript');
    expect(credFinds(ir.findings)).toHaveLength(0);
  });
});
