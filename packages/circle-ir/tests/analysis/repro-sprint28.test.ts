/**
 * Repro for Sprint 28 — bundle fixes for #110 + #109 remaining CWEs.
 *
 * #110 (xss mistyping of non-XSS sinks):
 *   `configs/sinks/xss.yaml` had an unscoped `{ method: "write" }` entry
 *   that matched ANY `.write()` call across all languages — fs.writeFile,
 *   open().write, bcrypt callbacks, credential writes. Fix: class-scope
 *   the entry to `ServletOutputStream` (PrintWriter/JspWriter already
 *   class-scoped).
 *
 * #109 remaining (credential / crypto rule layer):
 *   New pattern passes added for the remaining CWEs in the matrix:
 *     - CWE-916 weak-password-hash       (fast hash / low-cost KDF on credential)
 *     - CWE-256 plaintext-password-storage (write credential to disk/store
 *                                          without prior hash)
 *     - CWE-523 cleartext-credential-transport (HTTP POST credential
 *                                              over http:// URL)
 *     - CWE-261 weak-password-encoding  (base64/hex on credential —
 *                                       encoding != encryption)
 *   CWE-260 shipped in 3.80.0 (Sprint 26). CWE-257 already covered by
 *   weak-crypto (`hardcoded-key`).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

const xssFlows = (ir: CircleIR) =>
  (ir.taint?.flows ?? []).filter((f) => f.sink_type === 'xss');

const findsByRule = (ir: CircleIR, rule: string) =>
  (ir.findings ?? []).filter((f) => f.rule_id === rule);

describe('Sprint 28 — #110 xss mistyping (FP)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does NOT mistype bcrypt.hash as xss', async () => {
    const code = `
const bcrypt = require('bcrypt');
function register(req, res) {
  const password = req.body.password;
  bcrypt.hash(password, 12, (err, hashed) => {
    res.send('ok');
  });
}
`;
    const ir = await analyze(code, 'safe_bcrypt.js', 'javascript');
    expect(xssFlows(ir)).toHaveLength(0);
  });

  it('does NOT mistype https.request as xss', async () => {
    const code = `
const https = require('https');
function send(req) {
  const data = req.body.payload;
  const r = https.request({ host: 'api.example.com', method: 'POST' });
  r.write(data);
  r.end();
}
`;
    const ir = await analyze(code, 'safe_https.js', 'javascript');
    expect(xssFlows(ir)).toHaveLength(0);
  });

  it('does NOT mistype open().write of credentials as xss', async () => {
    const code = `
from flask import request
def save():
    password = request.form['password']
    with open('creds.txt', 'w') as f:
        f.write(password)
    return 'ok'
`;
    const ir = await analyze(code, 'open_write.py', 'python');
    expect(xssFlows(ir)).toHaveLength(0);
  });

  it('does NOT mistype fs.writeFile of password as xss', async () => {
    const code = `
const fs = require('fs');
function save(req) {
  const password = req.body.password;
  fs.writeFile('creds.txt', password, () => {});
}
`;
    const ir = await analyze(code, 'fs_write.js', 'javascript');
    expect(xssFlows(ir)).toHaveLength(0);
  });
});

describe('Sprint 28 — #109 weak-password-hash (CWE-916)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flags python hashlib.sha256(password)', async () => {
    const code = `
import hashlib
def store(password):
    return hashlib.sha256(password.encode()).hexdigest()
`;
    const ir = await analyze(code, 'wph_py.py', 'python');
    expect(findsByRule(ir, 'weak-password-hash').length).toBeGreaterThanOrEqual(1);
  });

  it('flags python bcrypt with low cost (rounds=4)', async () => {
    const code = `
import bcrypt
def store(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))
`;
    const ir = await analyze(code, 'wph_bcrypt.py', 'python');
    expect(findsByRule(ir, 'weak-password-hash').length).toBeGreaterThanOrEqual(1);
  });

  it('flags JS bcrypt.hash with low cost', async () => {
    const code = `
const bcrypt = require('bcrypt');
function register(password) {
  return bcrypt.hashSync(password, 4);
}
`;
    const ir = await analyze(code, 'wph_bcrypt.js', 'javascript');
    expect(findsByRule(ir, 'weak-password-hash').length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire on hashlib.sha256 of non-credential data', async () => {
    const code = `
import hashlib
def fingerprint(message):
    return hashlib.sha256(message).hexdigest()
`;
    const ir = await analyze(code, 'wph_neg.py', 'python');
    expect(findsByRule(ir, 'weak-password-hash')).toHaveLength(0);
  });
});

describe('Sprint 28 — #109 weak-password-encoding (CWE-261)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flags python base64.b64encode(password)', async () => {
    const code = `
import base64
def store(password):
    return base64.b64encode(password.encode())
`;
    const ir = await analyze(code, 'wpe_py.py', 'python');
    expect(findsByRule(ir, 'weak-password-encoding').length).toBeGreaterThanOrEqual(1);
  });

  it('flags JS Buffer.from(password).toString("base64")', async () => {
    const code = `
function store(password) {
  return Buffer.from(password).toString('base64');
}
`;
    const ir = await analyze(code, 'wpe_js.js', 'javascript');
    expect(findsByRule(ir, 'weak-password-encoding').length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire on base64-encoding image bytes', async () => {
    const code = `
import base64
def to_data_url(image_bytes):
    return base64.b64encode(image_bytes)
`;
    const ir = await analyze(code, 'wpe_neg.py', 'python');
    expect(findsByRule(ir, 'weak-password-encoding')).toHaveLength(0);
  });

  it('does NOT fire on HTTP Basic auth header construction', async () => {
    const code = `
import base64
def auth_header(username, password):
    creds = username + ':' + password
    return 'Basic ' + base64.b64encode(creds.encode()).decode()
`;
    const ir = await analyze(code, 'wpe_basic.py', 'python');
    expect(findsByRule(ir, 'weak-password-encoding')).toHaveLength(0);
  });
});

describe('Sprint 28 — #109 cleartext-credential-transport (CWE-523)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flags python requests.post over http:// with password body', async () => {
    const code = `
import requests
def login(password):
    requests.post('http://api.example.com/login', json={'password': password})
`;
    const ir = await analyze(code, 'cct_py.py', 'python');
    expect(findsByRule(ir, 'cleartext-credential-transport').length).toBeGreaterThanOrEqual(1);
  });

  it('flags JS axios.post over http:// with password body', async () => {
    const code = `
const axios = require('axios');
function login(password) {
  axios.post('http://api.example.com/login', { password: password });
}
`;
    const ir = await analyze(code, 'cct_js.js', 'javascript');
    expect(findsByRule(ir, 'cleartext-credential-transport').length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire on https:// requests', async () => {
    const code = `
const axios = require('axios');
function login(password) {
  axios.post('https://api.example.com/login', { password: password });
}
`;
    const ir = await analyze(code, 'cct_https.js', 'javascript');
    expect(findsByRule(ir, 'cleartext-credential-transport')).toHaveLength(0);
  });

  it('does NOT fire on http://localhost (dev environment)', async () => {
    const code = `
const axios = require('axios');
function login(password) {
  axios.post('http://localhost:3000/login', { password: password });
}
`;
    const ir = await analyze(code, 'cct_local.js', 'javascript');
    expect(findsByRule(ir, 'cleartext-credential-transport')).toHaveLength(0);
  });
});

describe('Sprint 28 — #109 plaintext-password-storage (CWE-256)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flags python open().write(password)', async () => {
    const code = `
def save(password):
    with open('creds.txt', 'w') as f:
        f.write(password)
`;
    const ir = await analyze(code, 'pps_py.py', 'python');
    expect(findsByRule(ir, 'plaintext-password-storage').length).toBeGreaterThanOrEqual(1);
  });

  it('flags JS fs.writeFile of password', async () => {
    const code = `
const fs = require('fs');
function save(password) {
  fs.writeFile('creds.txt', password, () => {});
}
`;
    const ir = await analyze(code, 'pps_js.js', 'javascript');
    expect(findsByRule(ir, 'plaintext-password-storage').length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire when password is hashed before writing (inline)', async () => {
    const code = `
import bcrypt
def save(password):
    with open('creds.txt', 'wb') as f:
        f.write(bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)))
`;
    const ir = await analyze(code, 'pps_safe.py', 'python');
    expect(findsByRule(ir, 'plaintext-password-storage')).toHaveLength(0);
  });

  it('does NOT fire when password is hashed before writing (prior call)', async () => {
    const code = `
import bcrypt
def save(password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
    with open('creds.txt', 'wb') as f:
        f.write(hashed)
`;
    const ir = await analyze(code, 'pps_safe2.py', 'python');
    // Note: this test asserts that bcrypt-hashed value `hashed` is what's
    // written, and `hashed` is not credential-named — so no finding either way.
    expect(findsByRule(ir, 'plaintext-password-storage')).toHaveLength(0);
  });
});

describe('Sprint 28 — recall locks (Sprint 26 + earlier)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('Sprint 26 #109 CWE-260 lock — hardcoded credential still fires', async () => {
    const code = `
public class DbConfig {
  public static final String DB_PASSWORD = "Pr0d-DB-pass!2024";
}
`;
    const ir = await analyze(code, 'DbConfig.java', 'java');
    expect(findsByRule(ir, 'hardcoded-credential').length).toBeGreaterThanOrEqual(1);
  });

  it('weak-hash CWE-328 lock — MD5 still fires', async () => {
    const code = `
import java.security.MessageDigest;
public class A {
  public byte[] hash(byte[] in) throws Exception {
    return MessageDigest.getInstance("MD5").digest(in);
  }
}
`;
    const ir = await analyze(code, 'Md5.java', 'java');
    expect(findsByRule(ir, 'weak-hash').length).toBeGreaterThanOrEqual(1);
  });

  it('weak-crypto CWE-327 lock — AES/ECB still fires', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public Cipher getCipher() throws Exception {
    return Cipher.getInstance("AES/ECB/PKCS5Padding");
  }
}
`;
    const ir = await analyze(code, 'AesEcb.java', 'java');
    expect(findsByRule(ir, 'weak-crypto').length).toBeGreaterThanOrEqual(1);
  });
});
