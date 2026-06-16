/**
 * Repro for cognium-dev#87 — coverage gap: insecure crypto CONFIGURATION
 * not detected. The existing `weak-crypto` pass already covers ECB and weak
 * cipher names; this adds the three remaining constant-pattern variants:
 *
 *   CWE-329 — static / zero IV       (`new IvParameterSpec(new byte[16])`)
 *   CWE-321 — hardcoded symmetric key (`new SecretKeySpec("…".getBytes(), ...)`)
 *   CWE-326 — weak RSA key size       (`kpg.initialize(<2048)`)
 *
 * NOTE: SAST regression fixtures — every example is *deliberately* vulnerable
 * so the detector can be measured. Do not "fix" the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#87 — weak-crypto-config (IV / key / RSA)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -----------------------------------------------------------------------
  // CWE-329 — static / zero IV
  // -----------------------------------------------------------------------

  it('fires CWE-329 on new IvParameterSpec(new byte[16]) (zero IV)', async () => {
    const code = `
import javax.crypto.spec.IvParameterSpec;
public class C {
  public IvParameterSpec t() {
    return new IvParameterSpec(new byte[16]);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-329'
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('fires CWE-329 on new IvParameterSpec("static".getBytes())', async () => {
    const code = `
import javax.crypto.spec.IvParameterSpec;
public class C {
  public IvParameterSpec t() {
    return new IvParameterSpec("fixedIV1234567890".getBytes());
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-329'
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire CWE-329 on new IvParameterSpec(randomBytes)', async () => {
    const code = `
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
public class C {
  public IvParameterSpec t() {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-329'
    );
    expect(f.length).toBe(0);
  });

  // -----------------------------------------------------------------------
  // CWE-321 — hardcoded symmetric key
  // -----------------------------------------------------------------------

  it('fires CWE-321 on new SecretKeySpec("literal".getBytes(), "AES")', async () => {
    const code = `
import javax.crypto.spec.SecretKeySpec;
public class C {
  public SecretKeySpec t() {
    return new SecretKeySpec("1234567890123456".getBytes(), "AES");
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-321'
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire CWE-321 on new SecretKeySpec(generatedKey, "AES")', async () => {
    const code = `
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
public class C {
  public SecretKeySpec t() throws Exception {
    byte[] key = KeyGenerator.getInstance("AES").generateKey().getEncoded();
    return new SecretKeySpec(key, "AES");
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-321'
    );
    expect(f.length).toBe(0);
  });

  // -----------------------------------------------------------------------
  // CWE-326 — weak RSA key size
  // -----------------------------------------------------------------------

  it('fires CWE-326 on KeyPairGenerator.initialize(512)', async () => {
    const code = `
import java.security.KeyPairGenerator;
public class C {
  public void t() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(512);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-326'
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('fires CWE-326 on KeyPairGenerator.initialize(1024)', async () => {
    const code = `
import java.security.KeyPairGenerator;
public class C {
  public void t() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-326'
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('does NOT fire CWE-326 on KeyPairGenerator.initialize(2048)', async () => {
    const code = `
import java.security.KeyPairGenerator;
public class C {
  public void t() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-326'
    );
    expect(f.length).toBe(0);
  });

  it('does NOT fire CWE-326 on KeyPairGenerator.initialize(4096)', async () => {
    const code = `
import java.security.KeyPairGenerator;
public class C {
  public void t() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(4096);
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-326'
    );
    expect(f.length).toBe(0);
  });

  // -----------------------------------------------------------------------
  // ECB regression — still fires (existing coverage shouldn't regress).
  // -----------------------------------------------------------------------

  it('ECB regression: Cipher.getInstance("AES/ECB/PKCS5Padding") still fires', async () => {
    const code = `
import javax.crypto.Cipher;
public class C {
  public Cipher t() throws Exception {
    return Cipher.getInstance("AES/ECB/PKCS5Padding");
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    const f = (r.findings ?? []).filter(
      (x) => x.rule_id === 'weak-crypto' && x.cwe === 'CWE-327'
    );
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
