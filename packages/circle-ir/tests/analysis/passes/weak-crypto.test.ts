/**
 * Tests for weak-crypto pass (CWE-327). Covers Java, Python, JS/TS, Go.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const weakCrypto = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-crypto');

describe('weak-crypto pass', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // ---------------- Java ----------------
  it('Java: Cipher.getInstance("DES") is flagged (weak-cipher)', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public Cipher c() throws Exception {
    return Cipher.getInstance("DES");
  }
}
`;
    const r = await analyze(code, 'A.java', 'java');
    const f = weakCrypto(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe('CWE-327');
  });

  it('Java: Cipher.getInstance("AES/ECB/PKCS5Padding") is flagged (ecb-mode)', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public Cipher c() throws Exception {
    return Cipher.getInstance("AES/ECB/PKCS5Padding");
  }
}
`;
    const r = await analyze(code, 'B.java', 'java');
    const f = weakCrypto(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f.some((x: any) => /ECB/i.test(x.message))).toBe(true);
  });

  it('Java: Cipher.getInstance("AES") (defaults to ECB) is flagged', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public Cipher c() throws Exception {
    return Cipher.getInstance("AES");
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Java: Cipher.getInstance("AES/GCM/NoPadding") is NOT flagged', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public Cipher c() throws Exception {
    return Cipher.getInstance("AES/GCM/NoPadding");
  }
}
`;
    const r = await analyze(code, 'D.java', 'java');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  it('Java: KeyGenerator.getInstance("DES") is flagged', async () => {
    const code = `
import javax.crypto.KeyGenerator;
public class A {
  public KeyGenerator k() throws Exception {
    return KeyGenerator.getInstance("DES");
  }
}
`;
    const r = await analyze(code, 'E.java', 'java');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  // ---------------- Python ----------------
  it('Python: pycrypto DES.new is flagged', async () => {
    const code = `
from Crypto.Cipher import DES
def enc(k, data):
    c = DES.new(k, DES.MODE_CBC)
    return c.encrypt(data)
`;
    const r = await analyze(code, 'a.py', 'python');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: AES.new(key, AES.MODE_ECB) is flagged (ecb-mode)', async () => {
    const code = `
from Crypto.Cipher import AES
def enc(k, data):
    c = AES.new(k, AES.MODE_ECB)
    return c.encrypt(data)
`;
    const r = await analyze(code, 'b.py', 'python');
    const f = weakCrypto(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f.some((x: any) => /ECB/i.test(x.message))).toBe(true);
  });

  it('Python: cryptography algorithms.TripleDES is flagged', async () => {
    const code = `
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def enc(key):
    return algorithms.TripleDES(key)
`;
    const r = await analyze(code, 'c.py', 'python');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  // ---------------- JS / TS ----------------
  it('JS: crypto.createCipher(...) (deprecated) is flagged', async () => {
    const code = `
const crypto = require('crypto');
function enc(pwd, data) {
  const c = crypto.createCipher('aes-256-cbc', pwd);
  return Buffer.concat([c.update(data), c.final()]);
}
`;
    const r = await analyze(code, 'a.js', 'javascript');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: crypto.createCipheriv("des-cbc", ...) is flagged (weak-cipher)', async () => {
    const code = `
const crypto = require('crypto');
function enc(k, iv, data) {
  const c = crypto.createCipheriv('des-cbc', k, iv);
  return Buffer.concat([c.update(data), c.final()]);
}
`;
    const r = await analyze(code, 'b.js', 'javascript');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: crypto.createCipheriv("aes-128-ecb", ...) is flagged (ecb-mode)', async () => {
    const code = `
const crypto = require('crypto');
function enc(k, iv, data) {
  const c = crypto.createCipheriv('aes-128-ecb', k, iv);
  return Buffer.concat([c.update(data), c.final()]);
}
`;
    const r = await analyze(code, 'c.js', 'javascript');
    const f = weakCrypto(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f.some((x: any) => /ECB/i.test(x.message))).toBe(true);
  });

  it('JS: crypto.createCipheriv("aes-256-gcm", ...) is NOT flagged', async () => {
    const code = `
const crypto = require('crypto');
function enc(k, iv, data) {
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([c.update(data), c.final()]);
}
`;
    const r = await analyze(code, 'd.js', 'javascript');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  // ---------------- Go ----------------
  it('Go: des.NewCipher is flagged', async () => {
    const code = `
package main
import "crypto/des"
func enc(key []byte) {
  _, _ = des.NewCipher(key)
}
`;
    const r = await analyze(code, 'a.go', 'go');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Go: des.NewTripleDESCipher is flagged', async () => {
    const code = `
package main
import "crypto/des"
func enc(key []byte) {
  _, _ = des.NewTripleDESCipher(key)
}
`;
    const r = await analyze(code, 'b.go', 'go');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Go: rc4.NewCipher is flagged', async () => {
    const code = `
package main
import "crypto/rc4"
func enc(key []byte) {
  _, _ = rc4.NewCipher(key)
}
`;
    const r = await analyze(code, 'c.go', 'go');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });
});
