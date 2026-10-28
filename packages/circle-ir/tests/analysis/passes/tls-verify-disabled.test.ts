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
  it('Go: x509.Verify without intermediate denylist guard is flagged (issue-894 S3)', async () => {
    const code = `
package main

import "crypto/x509"

func verifyLeaf(leaf *x509.Certificate, roots, inter *x509.CertPool) error {
  opts := x509.VerifyOptions{
    Roots:         roots,
    Intermediates: inter,
  }
  _, err := leaf.Verify(opts)
  return err
}
`;
    const r = await analyze(code, 'issue-894-x509-intermediate-denylist_tp.go', 'go');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Go: x509.Verify flags TP when denylist appears only in a comment (#960)', async () => {
    const code = `
package main

import "crypto/x509"

// Intake fixture: no intermediate denylist in code — comment must not suppress.
func verifyLeaf(leaf *x509.Certificate, roots, inter *x509.CertPool) error {
  _, err := leaf.Verify(x509.VerifyOptions{
    Roots:         roots,
    Intermediates: inter,
  })
  return err
}
`;
    const r = await analyze(code, 'x509_intermediate_denylist_tp.go', 'go');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Go: x509.Verify with deniedIntermediates guard is NOT flagged (#960 safe)', async () => {
    const code = `
package main

import (
  "crypto/x509"
  "errors"
)

func verifyLeafSafe(leaf *x509.Certificate, roots, inter *x509.CertPool, deniedIntermediates map[string]bool) error {
  if deniedIntermediates[leaf.Subject.CommonName] {
    return errors.New("denylisted intermediate")
  }
  _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
  if err != nil {
    return err
  }
  if deniedIntermediates[leaf.Subject.CommonName] {
    return errors.New("denylisted intermediate")
  }
  return nil
}
`;
    const r = await analyze(code, 'x509_intermediate_denylist_safe.go', 'go');
    expect(tlsOff(r)).toHaveLength(0);
  });

  it('Go: x509.Verify with intermediate denylist guard is NOT flagged (issue-894 S3 safe)', async () => {
    const code = `
package main

import "crypto/x509"

func intermediateDenylist() map[string]bool { return map[string]bool{} }

func verifyLeafSafe(leaf *x509.Certificate, roots, inter *x509.CertPool) error {
  deny := intermediateDenylist()
  if deny[leaf.Subject.CommonName] {
    return x509.CertificateInvalidError{}
  }
  _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
  return err
}
`;
    const r = await analyze(code, 'issue-894-x509-intermediate-safe.go', 'go');
    expect(tlsOff(r)).toHaveLength(0);
  });

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

  it('JS: checkServerIdentity with loose IP folding is flagged (issue-894 S2)', async () => {
    const code = `
'use strict';
const tls = require('tls');

function looseIp(value) {
  return String(value).replace(/[^\\d.]/g, '');
}

function checkServerIdentity(host, cert) {
  const cn = (cert.subject && cert.subject.CN) || '';
  if (looseIp(host) !== '' && looseIp(host) === looseIp(cn)) return undefined;
  return new Error('mismatch');
}

function connect(userHost) {
  return tls.connect({ host: userHost, port: 443, servername: userHost, checkServerIdentity });
}

module.exports = { connect };
`;
    const r = await analyze(code, 'issue-894-tls-loose-ip.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: checkServerIdentity with NFKC normalize is flagged (issue-894 S4)', async () => {
    const code = `
'use strict';
const tls = require('tls');

function checkServerIdentity(host, cert) {
  const cn = (cert.subject && cert.subject.CN) || '';
  const h = String(host).normalize('NFKC');
  const c = String(cn).normalize('NFKC');
  if (h === c) return undefined;
  return new Error('mismatch');
}

function connect(userHost) {
  return tls.connect({ host: userHost, port: 443, servername: userHost, checkServerIdentity });
}
`;
    const r = await analyze(code, 'issue-894-tls-fullwidth.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: checkServerIdentity with DNS SAN match is flagged (issue-894 S4)', async () => {
    const code = `
'use strict';
const tls = require('tls');

function checkServerIdentity(host, cert) {
  const altnames = cert.subjectaltname;
  if (!altnames) return new Error('no san');
  const parts = String(altnames).split(/,\\s*/);
  for (const p of parts) {
    const name = p.replace(/^DNS:/i, '').trim();
    if (name === host) return undefined;
  }
  return new Error('mismatch');
}

function connect(userHost) {
  return tls.connect({ host: userHost, port: 443, servername: userHost, checkServerIdentity });
}
`;
    const r = await analyze(code, 'issue-894-tls-dns-san.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: issuer chain walk without denylist is flagged (issue-894 S4)', async () => {
    const code = `
'use strict';
const tls = require('tls');

function checkServerIdentity(host, cert) {
  for (let c = cert; c; c = c.issuerCertificate) {
    if (!c.valid_to) return new Error('bad cert');
  }
  return undefined;
}

function connect(userHost) {
  return tls.connect({ host: userHost, port: 443, servername: userHost, checkServerIdentity });
}
`;
    const r = await analyze(code, 'issue-894-tls-untrusted-intermediate.js', 'javascript');
    expect(tlsOff(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: checkServerIdentity that returns undefined is flagged (issue-894 S1)', async () => {
    const code = `
const https = require('https');
function client() {
  return https.request({
    host: 'example.com',
    checkServerIdentity: (host, cert) => undefined,
  });
}
`;
    const r = await analyze(code, 'issue-894-tls-host.js', 'javascript');
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

  // ---------------- C# ----------------
  const cs = (b: string) => `using System.Net; using System.Net.Http;\nclass C { void M() { ${b} } }`;

  it('C#: an always-true certificate-validation callback is flagged', async () => {
    for (const b of [
      `ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true;`,
      `var h = new HttpClientHandler(); h.ServerCertificateCustomValidationCallback = (m,c,ch,e) => true;`,
      `var cb = new RemoteCertificateValidationCallback((s,c,ch,e) => true);`,
      `ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => { return true; };`,
      `var h = new HttpClientHandler(); h.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;`,
    ]) {
      expect(tlsOff(await analyze(cs(b), 'C.cs', 'csharp')).length).toBeGreaterThanOrEqual(1);
    }
  });

  it('C#: a callback that actually validates is NOT flagged', async () => {
    expect(tlsOff(await analyze(cs(`ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => e == System.Net.Security.SslPolicyErrors.None;`), 'C.cs', 'csharp'))).toHaveLength(0);
    expect(tlsOff(await analyze(cs(`ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => { return ValidateChain(c); };`), 'C.cs', 'csharp'))).toHaveLength(0);
  });
});
