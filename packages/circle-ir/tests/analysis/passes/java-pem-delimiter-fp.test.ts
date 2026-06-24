/**
 * Tests for #176 — PEM-format delimiter false-positive suppression in
 * scan-secrets-pass (Layer 1, PEM private key provider pattern).
 *
 * Repro shapes (from mock-server):
 *   1. Parser constant:    `String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";`
 *   2. contains() argument: `if (pem.contains("-----BEGIN RSA PRIVATE KEY-----"))`
 *   3. Error message:      `throw new IllegalArgumentException("... '-----BEGIN PRIVATE KEY-----' ...")`
 *
 * Recall lock: real embedded keys (multi-line or single-line with body
 * inline) keep firing because the body-adjacency check finds base64-shape
 * text within 5 lines of the BEGIN delimiter.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const credFindings = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'hardcoded-credential');

describe('scan-secrets #176 — PEM delimiter FP', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('FP shape 1: BEGIN_PRIVATE_KEY constant assignment (no body) is NOT flagged', async () => {
    const code = `
public class PEMToFile {
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
}
`;
    const r = await analyze(code, 'src/main/java/org/example/PEMToFile.java', 'java');
    expect(credFindings(r)).toHaveLength(0);
  });

  it('FP shape 2: pem.contains("-----BEGIN RSA PRIVATE KEY-----") is NOT flagged', async () => {
    const code = `
public class WebhookServer {
    public boolean isPemKey(String pem) {
        if (pem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
            return true;
        }
        return false;
    }
}
`;
    const r = await analyze(code, 'src/main/java/org/example/WebhookServer.java', 'java');
    expect(credFindings(r)).toHaveLength(0);
  });

  it('FP shape 3: error message referencing the delimiter is NOT flagged', async () => {
    const code = `
public class CertificateConfigurationValidator {
    public void validate(String content) {
        if (content == null) {
            throw new IllegalArgumentException(
                "Ensure the file contains a '-----BEGIN PRIVATE KEY-----' block."
            );
        }
    }
}
`;
    const r = await analyze(code, 'src/main/java/org/example/CertificateConfigurationValidator.java', 'java');
    expect(credFindings(r)).toHaveLength(0);
  });

  it('RECALL: real multi-line embedded PEM key IS flagged', async () => {
    // Java string concatenation forming a real PEM block.
    // Body lines have ≥30 chars of [A-Za-z0-9+/] → body-adjacency check fires.
    const code = `
public class Keys {
    public static final String PRIVATE_KEY =
        "-----BEGIN PRIVATE KEY-----\\n" +
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\\n" +
        "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\\n" +
        "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\\n" +
        "-----END PRIVATE KEY-----";
}
`;
    const r = await analyze(code, 'src/main/java/org/example/Keys.java', 'java');
    expect(credFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('RECALL: single-line embedded PEM key with inline body IS flagged', async () => {
    // The base64 body is on the same line as BEGIN, so the body-adjacency
    // check finds the ≥30-char base64 run on that line.
    const code = `
public class Keys {
    public static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R-----END PRIVATE KEY-----";
}
`;
    const r = await analyze(code, 'src/main/java/org/example/Keys.java', 'java');
    expect(credFindings(r).length).toBeGreaterThanOrEqual(1);
  });
});
