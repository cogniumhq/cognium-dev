/**
 * Weak-crypto test-file allowlist tests.
 *
 * cognium-dev #239 C.2 — test / spec files with KAT vectors legitimately
 * use fixed IVs, hardcoded keys, and weak hashes. Suppress weak-crypto
 * findings on paths recognised by isTestPath().
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const weakCrypto = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-crypto');

describe('weak-crypto pass — #239 C.2 test-file allowlist', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // ---- Weak-cipher fixture: DES / RC4 usage under test paths must be dropped.
  const javaWeakCipher = `
import javax.crypto.Cipher;
public class A {
  public Cipher c() throws Exception { return Cipher.getInstance("DES"); }
}
`;

  it('drops findings under Java Maven src/test/', async () => {
    const r = await analyze(javaWeakCipher, 'src/test/java/com/foo/CryptoTest.java', 'java');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  it('drops findings under Python tests/', async () => {
    const code = `import hashlib
h = hashlib.md5(b"abc").hexdigest()
`;
    const r = await analyze(code, 'tests/unit/test_hash.py', 'python');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  it('drops findings under Go *_test.go', async () => {
    const code = `package crypto
import "crypto/md5"
func Sum() []byte { return md5.New().Sum(nil) }
`;
    const r = await analyze(code, 'pkg/crypto/aes_test.go', 'go');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  it('drops findings under JS *.test.js', async () => {
    const code = `const crypto = require('crypto');
const h = crypto.createHash('md5').update('x').digest('hex');
`;
    const r = await analyze(code, 'src/foo.test.js', 'javascript');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  it('drops findings under Jest __tests__/', async () => {
    const code = `const crypto = require('crypto');
crypto.createHash('sha1').update('x').digest();
`;
    const r = await analyze(code, 'src/__tests__/hash.test.js', 'javascript');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  it('drops findings under RSpec spec/ (Python fixture for language coverage)', async () => {
    const code = `import hashlib
h = hashlib.sha1(b"x").hexdigest()
`;
    const r = await analyze(code, 'spec/legacy_hash.py', 'python');
    expect(weakCrypto(r)).toHaveLength(0);
  });

  // ---- Preserve: identical shape under production path still fires.

  it('preserves findings under Java src/main/', async () => {
    const r = await analyze(javaWeakCipher, 'src/main/java/com/foo/CryptoService.java', 'java');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });

  it('preserves findings under Java src/app/ (non-test path)', async () => {
    const r = await analyze(javaWeakCipher, 'src/app/foo/CryptoUtil.java', 'java');
    expect(weakCrypto(r).length).toBeGreaterThanOrEqual(1);
  });
});
