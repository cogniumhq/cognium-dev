/**
 * Tests for tls-verify-disabled pass (CWE-295). Covers Go, Python, JS/TS, Java.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const tlsOff = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'tls-verify-disabled');

describe('tls-verify-disabled pass', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // ---------------- Go ----------------
  it('Go: tls.Config{InsecureSkipVerify: true} is flagged', async () => {
    const code = `
package main
import "crypto/tls"
func client() *tls.Config {
  return &tls.Config{InsecureSkipVerify: true}
}
`;
    const r = await analyze(code, 'a.go', 'go');
    const f = tlsOff(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe('CWE-295');
  });

  // ---------------- Python ----------------
  it('Python: requests.get(verify=False) is flagged', async () => {
    const code = `
import requests
def fetch(u):
    return requests.get(u, verify=False)
`;
    const r = await analyze(code, 'a.py', 'python');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: requests.post(..., verify=False) is flagged', async () => {
    const code = `
import requests
def send(u, d):
    return requests.post(u, json=d, verify=False)
`;
    const r = await analyze(code, 'b.py', 'python');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: ssl._create_unverified_context() is flagged', async () => {
    const code = `
import ssl
def ctx():
    return ssl._create_unverified_context()
`;
    const r = await analyze(code, 'c.py', 'python');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: ssl._create_default_https_context = ssl._create_unverified_context is flagged', async () => {
    const code = `
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
`;
    const r = await analyze(code, 'd.py', 'python');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: requests.get(u) (default verify) is NOT flagged', async () => {
    const code = `
import requests
def fetch(u):
    return requests.get(u)
`;
    const r = await analyze(code, 'e.py', 'python');
    expect(tlsOff(r)).toHaveLength(0);
  });

  // ---------------- JS / TS ----------------
  it('JS: https.request({rejectUnauthorized: false}) is flagged', async () => {
    const code = `
const https = require('https');
function go() {
  return https.request({ host: 'x', rejectUnauthorized: false });
}
`;
    const r = await analyze(code, 'a.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: new https.Agent({rejectUnauthorized: false}) is flagged', async () => {
    const code = `
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });
`;
    const r = await analyze(code, 'b.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: NODE_TLS_REJECT_UNAUTHORIZED = "0" assignment is flagged', async () => {
    const code = `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
`;
    const r = await analyze(code, 'c.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('TS: axios.create({ httpsAgent: ... rejectUnauthorized: false }) is flagged', async () => {
    const code = `
import axios from 'axios';
import https from 'https';
const client = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false })
});
`;
    const r = await analyze(code, 'd.ts', 'typescript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  // ---------------- Java ----------------
  it('Java: setHostnameVerifier((h,s) -> true) is flagged', async () => {
    const code = `
import javax.net.ssl.HttpsURLConnection;
public class A {
  public void f(HttpsURLConnection c) {
    c.setHostnameVerifier((h, s) -> true);
  }
}
`;
    const r = await analyze(code, 'A.java', 'java');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Java: setHostnameVerifier(NoopHostnameVerifier.INSTANCE) is flagged', async () => {
    const code = `
public class A {
  public void f(SSLConnectionSocketFactory.Builder b) {
    b.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);
  }
}
`;
    const r = await analyze(code, 'B.java', 'java');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });
});
