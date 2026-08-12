/**
 * Tests for weak-hash pass (CWE-328). Covers Java, Python, JS/TS, Go.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const weakHash = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-hash');

describe('weak-hash pass', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // ---------------- Java ----------------
  it('Java: MessageDigest.getInstance("MD5") is flagged', async () => {
    const code = `
import java.security.MessageDigest;
public class A {
  public byte[] h(byte[] in) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    return md.digest(in);
  }
}
`;
    const r = await analyze(code, 'A.java', 'java');
    const f = weakHash(r);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe('CWE-328');
  });

  it('Java: MessageDigest.getInstance("SHA-1") is flagged', async () => {
    const code = `
import java.security.MessageDigest;
public class A {
  public byte[] h(byte[] in) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    return md.digest(in);
  }
}
`;
    const r = await analyze(code, 'B.java', 'java');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Java: MessageDigest.getInstance("SHA-256") is NOT flagged', async () => {
    const code = `
import java.security.MessageDigest;
public class A {
  public byte[] h(byte[] in) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    return md.digest(in);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    expect(weakHash(r)).toHaveLength(0);
  });

  it('Java: DigestUtils.md5Hex is flagged', async () => {
    const code = `
import org.apache.commons.codec.digest.DigestUtils;
public class A {
  public String h(String in) {
    return DigestUtils.md5Hex(in);
  }
}
`;
    const r = await analyze(code, 'D.java', 'java');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  // ---------------- Python ----------------
  it('Python: hashlib.md5() is flagged', async () => {
    const code = `
import hashlib
def h(x):
    return hashlib.md5(x).hexdigest()
`;
    const r = await analyze(code, 'a.py', 'python');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: hashlib.sha1() is flagged', async () => {
    const code = `
import hashlib
def h(x):
    return hashlib.sha1(x).hexdigest()
`;
    const r = await analyze(code, 'b.py', 'python');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: hashlib.new("md5", ...) is flagged', async () => {
    const code = `
import hashlib
def h(x):
    return hashlib.new("md5", x).hexdigest()
`;
    const r = await analyze(code, 'c.py', 'python');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: hashlib.sha256() is NOT flagged', async () => {
    const code = `
import hashlib
def h(x):
    return hashlib.sha256(x).hexdigest()
`;
    const r = await analyze(code, 'd.py', 'python');
    expect(weakHash(r)).toHaveLength(0);
  });

  // ---------------- JS / TS ----------------
  it('JS: crypto.createHash("md5") is flagged', async () => {
    const code = `
const crypto = require('crypto');
function h(x) { return crypto.createHash('md5').update(x).digest('hex'); }
`;
    const r = await analyze(code, 'a.js', 'javascript');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: crypto.createHmac("sha1", ...) is flagged', async () => {
    const code = `
const crypto = require('crypto');
function h(k, x) { return crypto.createHmac('sha1', k).update(x).digest('hex'); }
`;
    const r = await analyze(code, 'b.js', 'javascript');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('JS: crypto.createHash("sha256") is NOT flagged', async () => {
    const code = `
const crypto = require('crypto');
function h(x) { return crypto.createHash('sha256').update(x).digest('hex'); }
`;
    const r = await analyze(code, 'c.js', 'javascript');
    expect(weakHash(r)).toHaveLength(0);
  });

  // ---------------- Go ----------------
  it('Go: md5.New() is flagged', async () => {
    const code = `
package main
import (
  "crypto/md5"
)
func h(b []byte) []byte {
  h := md5.New()
  h.Write(b)
  return h.Sum(nil)
}
`;
    const r = await analyze(code, 'a.go', 'go');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Go: sha1.Sum(...) is flagged', async () => {
    const code = `
package main
import (
  "crypto/sha1"
)
func h(b []byte) [20]byte {
  return sha1.Sum(b)
}
`;
    const r = await analyze(code, 'b.go', 'go');
    expect(weakHash(r).length).toBeGreaterThanOrEqual(1);
  });

  // C#/.NET (cognium-dev#: Phase-2 C# core audit) — System.Security.Cryptography
  const cs = (snippet: string) => `public class C { void M(byte[] data, byte[] key) { ${snippet} } }`;
  const csFlags = async (snippet: string) =>
    weakHash(await analyze(cs(snippet), 'C.cs', 'csharp')).length > 0;

  it('C#: MD5.Create() / SHA1.Create() / MD5.HashData() are flagged', async () => {
    expect(await csFlags('var a = MD5.Create();')).toBe(true);
    expect(await csFlags('var a = SHA1.Create();')).toBe(true);
    expect(await csFlags('var a = MD5.HashData(data);')).toBe(true);
  });

  it('C#: weak provider constructors are flagged', async () => {
    expect(await csFlags('var a = new MD5CryptoServiceProvider();')).toBe(true);
    expect(await csFlags('var a = new SHA1Managed();')).toBe(true);
    expect(await csFlags('var a = new HMACMD5(key);')).toBe(true);
  });

  it('C#: named factories with a weak literal algorithm are flagged', async () => {
    expect(await csFlags('var a = HashAlgorithm.Create("MD5");')).toBe(true);
    expect(await csFlags('var a = CryptoConfig.CreateFromName("SHA1");')).toBe(true);
    expect(await csFlags('var a = HMAC.Create("HMACSHA1");')).toBe(true);
    expect(await csFlags('var a = HashAlgorithm.Create("SHA");')).toBe(true); // "SHA" == SHA-1
  });

  it('C#: strong algorithms and non-crypto Create() are NOT flagged', async () => {
    expect(await csFlags('var a = SHA256.Create();')).toBe(false);
    expect(await csFlags('var a = SHA512.HashData(data);')).toBe(false);
    expect(await csFlags('var a = new SHA256Managed();')).toBe(false);
    expect(await csFlags('var a = new HMACSHA256(key);')).toBe(false);
    expect(await csFlags('var a = HashAlgorithm.Create("SHA256");')).toBe(false);
    expect(await csFlags('var a = builder.Create();')).toBe(false);
    expect(await csFlags('var a = CryptoConfig.CreateFromName(algo);')).toBe(false); // non-literal
  });
});
