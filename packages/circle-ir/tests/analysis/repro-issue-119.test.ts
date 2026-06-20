/**
 * Repro for cognium-dev#119 — CWE-328 weak-hash recall gaps.
 *
 * OWASP Java benchmark v3.67.0 snapshot: 89 TP / 40 FN (69% recall).
 * Issue hypothesised the chained `MessageDigest.getInstance("MD5").digest(...)`
 * form was missing; probe revealed that shape already works. The actual
 * 40 FN gap comes from three other shapes:
 *
 *   1. Apache Commons getter form: `DigestUtils.getMd5Digest()`,
 *      `DigestUtils.getSha1Digest()`, `DigestUtils.getShaDigest()`.
 *   2. Apache Commons algorithm constants:
 *      `MessageDigest.getInstance(MessageDigestAlgorithms.MD5)` etc.
 *   3. Variable / field / final-local algorithm names:
 *      `final String algo = "MD5"; MessageDigest.getInstance(algo)`.
 *
 * Fix (`weak-hash-pass.ts`): add `COMMONS_DIGEST_GETTERS` table, add
 * `COMMONS_ALGO_CONSTANTS` table, and add `resolveJavaAlgo()` that
 * resolves the algorithm argument via inline literal → Apache constant
 * → constant-propagation `symbols` → regex-scanned source bindings.
 *
 * SHA-256/SHA-512 and unrelated `.parse()`-like APIs MUST remain unflagged.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#119 — weak-hash recall (CWE-328)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const weakHashFinds = (findings: Array<{ rule_id?: string }> | undefined) =>
    (findings ?? []).filter((f) => f.rule_id === 'weak-hash');

  // ─── FN recall gaps (must FLAG after fix) ──────────────────────────────

  it('flags Apache Commons DigestUtils.getMd5Digest()', async () => {
    const code = `
import org.apache.commons.codec.digest.DigestUtils;
public class A {
  public byte[] hash(byte[] input) {
    return DigestUtils.getMd5Digest().digest(input);
  }
}
`;
    const ir = await analyze(code, 'GetMd5Digest.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  it('flags Apache Commons DigestUtils.getSha1Digest()', async () => {
    const code = `
import org.apache.commons.codec.digest.DigestUtils;
public class A {
  public byte[] hash(byte[] input) {
    return DigestUtils.getSha1Digest().digest(input);
  }
}
`;
    const ir = await analyze(code, 'GetSha1Digest.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  it('flags getInstance(MessageDigestAlgorithms.MD5) constant', async () => {
    const code = `
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import java.security.MessageDigest;
public class A {
  public byte[] hash(byte[] input) throws Exception {
    MessageDigest md = MessageDigest.getInstance(MessageDigestAlgorithms.MD5);
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'AlgoConst.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  it('flags getInstance(localFinal) with String local final binding', async () => {
    const code = `
public class A {
  public byte[] hash(byte[] input) throws Exception {
    final String algorithm = "MD5";
    java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'LocalFinal.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  it('flags getInstance(STATIC_FINAL) with static field binding', async () => {
    const code = `
public class A {
  private static final String ALGO = "MD5";
  public byte[] hash(byte[] input) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance(ALGO);
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'StaticFinal.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  it('flags chained getInstance("MD5").digest(input)', async () => {
    // Already-working shape — lock to prevent regression.
    const code = `
import java.security.MessageDigest;
public class A {
  public byte[] hash(byte[] input) throws Exception {
    return MessageDigest.getInstance("MD5").digest(input);
  }
}
`;
    const ir = await analyze(code, 'Chained.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  // ─── Recall regressions (existing TPs must still fire) ────────────────

  it('still flags typed-local MessageDigest.getInstance("SHA-1")', async () => {
    const code = `
import java.security.MessageDigest;
public class A {
  public byte[] hash(byte[] input) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'TypedLocal.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  it('still flags DigestUtils.md5Hex()', async () => {
    const code = `
import org.apache.commons.codec.digest.DigestUtils;
public class A {
  public String hash(String input) {
    return DigestUtils.md5Hex(input);
  }
}
`;
    const ir = await analyze(code, 'Md5Hex.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(1);
  });

  // ─── Negative locks (must NOT flag) ────────────────────────────────────

  it('does NOT flag SHA-256 inline literal', async () => {
    const code = `
public class A {
  public byte[] hash(byte[] input) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'Sha256.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag SHA-256 via local final binding', async () => {
    const code = `
public class A {
  public byte[] hash(byte[] input) throws Exception {
    final String algorithm = "SHA-256";
    java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'Sha256Local.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag DigestUtils.sha256Hex()', async () => {
    const code = `
import org.apache.commons.codec.digest.DigestUtils;
public class A {
  public String hash(String input) {
    return DigestUtils.sha256Hex(input);
  }
}
`;
    const ir = await analyze(code, 'Sha256Hex.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag getInstance with unresolved runtime variable', async () => {
    // No literal binding anywhere — algorithm is truly dynamic.
    // Conservative: cannot prove weak → must not flag.
    const code = `
public class A {
  public byte[] hash(String algorithm, byte[] input) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
    return md.digest(input);
  }
}
`;
    const ir = await analyze(code, 'DynamicAlgo.java', 'java');
    expect(weakHashFinds(ir.findings)).toHaveLength(0);
  });
});
