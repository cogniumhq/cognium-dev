/**
 * Repro for cognium-dev#116 — CWE-327 weak-crypto over-fires on
 * `KeyGenerator.getInstance("AES")`.
 *
 * OWASP Java benchmark v3.67.0 snapshot: weak-crypto precision 58.3%
 * (130 TP / 93 FP), 85% of all Java FPs. Issue hypothesised the cause
 * was over-firing on `Cipher.getInstance("AES/CBC/...")` safe modes;
 * probe confirmed Cipher detection correctly distinguishes safe vs ECB
 * via `classifyJavaCipherSpec`. The actual root cause is:
 *
 *   `KeyGenerator.getInstance("AES")` is the canonical, safe way to
 *   generate AES key material. `KeyGenerator` has NO cipher mode —
 *   the mode is chosen later by `Cipher.getInstance("AES/CBC/...")`.
 *   The pass treated KeyGenerator identically to Cipher, including
 *   the rule "AES with no mode defaults to ECB" — flagging every
 *   `KeyGenerator.getInstance("AES")` call as ECB-mode high-severity.
 *
 * Fix (`weak-crypto-pass.ts`): split `isCipherFactory` into
 * `isCipherInstance` (full Cipher logic, both weak-base and ECB) and
 * `isKeyGenInstance` (weak-base ONLY — no ECB check). Weak algorithms
 * (`KeyGenerator.getInstance("DES")` etc.) still flag.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#116 — weak-crypto KeyGenerator ECB FP', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const wcFinds = (findings: Array<{ rule_id?: string }> | undefined) =>
    (findings ?? []).filter((f) => f.rule_id === 'weak-crypto');

  // ─── FP locks (must NOT flag after fix) ────────────────────────────────

  it('does NOT flag KeyGenerator.getInstance("AES")', async () => {
    const code = `
import javax.crypto.KeyGenerator;
public class A {
  public void g() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("AES");
  }
}
`;
    const ir = await analyze(code, 'KeyGenAes.java', 'java');
    expect(wcFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag fully-qualified javax.crypto.KeyGenerator.getInstance("AES")', async () => {
    const code = `
public class A {
  public void g() throws Exception {
    javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
  }
}
`;
    const ir = await analyze(code, 'KeyGenFQ.java', 'java');
    expect(wcFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag KeyGenerator.getInstance("HmacSHA256")', async () => {
    const code = `
import javax.crypto.KeyGenerator;
public class A {
  public void g() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
  }
}
`;
    const ir = await analyze(code, 'KeyGenHmac.java', 'java');
    expect(wcFinds(ir.findings)).toHaveLength(0);
  });

  // ─── Recall locks: KeyGenerator with weak algorithm still flags ────────

  it('still flags KeyGenerator.getInstance("DES") (weak-cipher)', async () => {
    const code = `
import javax.crypto.KeyGenerator;
public class A {
  public void g() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("DES");
  }
}
`;
    const ir = await analyze(code, 'KeyGenDes.java', 'java');
    const findings = wcFinds(ir.findings);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatchObject({ issue: 'weak-cipher' });
  });

  it('still flags KeyGenerator.getInstance("RC4")', async () => {
    const code = `
import javax.crypto.KeyGenerator;
public class A {
  public void g() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("RC4");
  }
}
`;
    const ir = await analyze(code, 'KeyGenRc4.java', 'java');
    const findings = wcFinds(ir.findings);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatchObject({ issue: 'weak-cipher' });
  });

  it('still flags KeyGenerator.getInstance("Blowfish")', async () => {
    const code = `
import javax.crypto.KeyGenerator;
public class A {
  public void g() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("Blowfish");
  }
}
`;
    const ir = await analyze(code, 'KeyGenBf.java', 'java');
    const findings = wcFinds(ir.findings);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatchObject({ issue: 'weak-cipher' });
  });

  // ─── Cipher behavior unchanged ─────────────────────────────────────────

  it('still flags Cipher.getInstance("AES") (defaults to ECB)', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public void enc() throws Exception {
    Cipher c = Cipher.getInstance("AES");
  }
}
`;
    const ir = await analyze(code, 'CipherAesDefault.java', 'java');
    const findings = wcFinds(ir.findings);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatchObject({ issue: 'ecb-mode' });
  });

  it('still flags Cipher.getInstance("AES/ECB/PKCS5Padding")', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public void enc() throws Exception {
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
  }
}
`;
    const ir = await analyze(code, 'CipherAesEcb.java', 'java');
    const findings = wcFinds(ir.findings);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toMatchObject({ issue: 'ecb-mode' });
  });

  it('does NOT flag Cipher.getInstance("AES/CBC/PKCS5Padding")', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public void enc() throws Exception {
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
  }
}
`;
    const ir = await analyze(code, 'CipherAesCbc.java', 'java');
    expect(wcFinds(ir.findings)).toHaveLength(0);
  });

  it('does NOT flag Cipher.getInstance("AES/GCM/NoPadding")', async () => {
    const code = `
import javax.crypto.Cipher;
public class A {
  public void enc() throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
  }
}
`;
    const ir = await analyze(code, 'CipherAesGcm.java', 'java');
    expect(wcFinds(ir.findings)).toHaveLength(0);
  });

  // ─── Canonical OWASP benchmark shape ───────────────────────────────────

  it('does NOT flag OWASP-style key-derivation + safe-mode Cipher pair', async () => {
    // Composite of the most common OWASP Java crypto-category test:
    //   KeyGenerator.getInstance("AES") + Cipher.getInstance("AES/CBC/PKCS5Padding")
    // Both legitimate APIs — engine must emit ZERO weak-crypto findings.
    const code = `
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
public class BT {
  public void doPost(jakarta.servlet.http.HttpServletRequest req) throws Exception {
    String param = req.getParameter("a");
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(128);
    SecretKey key = kg.generateKey();
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] ct = c.doFinal(param.getBytes());
  }
}
`;
    const ir = await analyze(code, 'OwaspSafe.java', 'java');
    expect(wcFinds(ir.findings)).toHaveLength(0);
  });
});
