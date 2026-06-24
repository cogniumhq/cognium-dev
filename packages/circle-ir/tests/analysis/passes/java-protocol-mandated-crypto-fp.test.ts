/**
 * Tests for #175 — protocol-mandated weak-crypto / weak-password-hash
 * suppression in protocol-mandated legacy-auth implementations
 * (NTLM / Kerberos / SMB1 / SASL CRAM-MD5 / HTTP Digest).
 *
 * Repro shapes (from AsyncHttpClient NtlmEngine):
 *   - DES/ECB at NtlmEngine.java:499 (LM hash, required by MS-NLMP)
 *   - RC4 at NtlmEngine.java:530 (session-key sealing, MS-NLMP)
 *   - MD4 at NtlmEngine.java:603 (NT hash, MS-NLMP)
 *
 * Suppression strategy: drop the finding when the file is in a
 * protocol-mandated context. Matches conservative pattern of Sprints 38-45.
 *
 * Recall lock: a `Cipher.getInstance("DES")` in a non-protocol file with
 * no NTLM/Krb5 class and no RFC citation keeps firing.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const weakCryptoFindings = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-crypto');

const weakPwHashFindings = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-password-hash');

describe('#175 — protocol-mandated weak-crypto FP suppression', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // -------- Path-based suppression --------

  it('FP shape 1: DES/ECB in NTLM path is NOT flagged', async () => {
    const code = `
import javax.crypto.Cipher;
public class NtlmEngine {
    public Cipher lmHash() throws Exception {
        return Cipher.getInstance("DES/ECB/NoPadding");
    }
}
`;
    const r = await analyze(
      code,
      'client/src/main/java/org/asynchttpclient/ntlm/NtlmEngine.java',
      'java',
    );
    expect(weakCryptoFindings(r)).toHaveLength(0);
  });

  it('FP shape 2: DES/ECB in Kerberos path is NOT flagged', async () => {
    const code = `
import javax.crypto.Cipher;
public class Krb5Helper {
    public Cipher preAuth() throws Exception {
        return Cipher.getInstance("DES/ECB/NoPadding");
    }
}
`;
    const r = await analyze(
      code,
      'src/main/java/org/apache/kerberos/Krb5Helper.java',
      'java',
    );
    expect(weakCryptoFindings(r)).toHaveLength(0);
  });

  it('FP shape 3: RC4 in SMB signing path is NOT flagged', async () => {
    const code = `
import javax.crypto.Cipher;
public class SmbSigner {
    public Cipher sealKey() throws Exception {
        return Cipher.getInstance("RC4");
    }
}
`;
    const r = await analyze(
      code,
      'src/main/java/org/example/smb/SmbSigner.java',
      'java',
    );
    expect(weakCryptoFindings(r)).toHaveLength(0);
  });

  // -------- Citation-based suppression --------

  it('FP shape 4: MS-NLMP citation comment suppresses DES even outside protocol path', async () => {
    const code = `
import javax.crypto.Cipher;
public class MyAuthLib {
    // MS-NLMP §3.3.1: LM hash construction requires DES.
    public Cipher lmHash() throws Exception {
        return Cipher.getInstance("DES/ECB/NoPadding");
    }
}
`;
    const r = await analyze(code, 'src/main/java/com/example/MyAuthLib.java', 'java');
    expect(weakCryptoFindings(r)).toHaveLength(0);
  });

  it('FP shape 5: RFC 4757 citation comment suppresses RC4 even outside protocol path', async () => {
    const code = `
import javax.crypto.Cipher;
public class Foo {
    // RFC 4757: Kerberos RC4-HMAC required for legacy AD interop.
    public Cipher sealKey() throws Exception {
        return Cipher.getInstance("RC4");
    }
}
`;
    const r = await analyze(code, 'src/main/java/com/example/Foo.java', 'java');
    expect(weakCryptoFindings(r)).toHaveLength(0);
  });

  // -------- Recall locks --------

  it('RECALL: DES/ECB in a non-protocol path with no citation IS flagged', async () => {
    const code = `
import javax.crypto.Cipher;
public class MyAuth {
    public Cipher c() throws Exception {
        return Cipher.getInstance("DES/ECB/NoPadding");
    }
}
`;
    const r = await analyze(code, 'src/main/java/com/example/MyAuth.java', 'java');
    expect(weakCryptoFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('RECALL: SHA-256 of password in a non-protocol file IS flagged (weak-password-hash)', async () => {
    const code = `
import java.security.MessageDigest;
public class AuthSvc {
    public byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());
        return md.digest();
    }
}
`;
    const r = await analyze(code, 'src/main/java/com/example/AuthSvc.java', 'java');
    expect(weakPwHashFindings(r).length).toBeGreaterThanOrEqual(1);
  });
});
