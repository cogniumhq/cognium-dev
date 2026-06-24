/**
 * Tests for #174 — CLI option-key constant false-positive suppression in
 * scan-secrets-pass (Layer 1b, named-credential matcher).
 *
 * Repro shapes (from wiremock):
 *   private static final String HTTPS_KEYSTORE_PASSWORD    = "keystore-password";
 *   private static final String HTTPS_KEY_MANAGER_PASSWORD = "key-manager-password";
 *   private static final String HTTPS_TRUSTSTORE_PASSWORD  = "truststore-password";
 *   private static final String HTTPS_CA_KEYSTORE_PASSWORD = "ca-keystore-password";
 *
 * The LHS identifier matches `*PASSWORD*`, but the RHS value is a kebab-case
 * CLI option name (joptsimple / picocli / argparse4j flag), not a credential.
 *
 * Recall lock: real password values containing uppercase / underscores /
 * dots / special chars don't match the all-lowercase-kebab regex.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const credFindings = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'hardcoded-credential');

describe('scan-secrets #174 — CLI option-key constant FP', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('FP shape 1: HTTPS_KEYSTORE_PASSWORD = "keystore-password" is NOT flagged', async () => {
    const code = `
public class HttpsSettings {
    private static final String HTTPS_KEYSTORE_PASSWORD = "keystore-password";
}
`;
    const r = await analyze(code, 'src/main/java/com/example/HttpsSettings.java', 'java');
    expect(credFindings(r)).toHaveLength(0);
  });

  it('FP shape 2: HTTPS_KEY_MANAGER_PASSWORD = "key-manager-password" is NOT flagged', async () => {
    const code = `
public class HttpsSettings {
    private static final String HTTPS_KEY_MANAGER_PASSWORD = "key-manager-password";
}
`;
    const r = await analyze(code, 'src/main/java/com/example/HttpsSettings.java', 'java');
    expect(credFindings(r)).toHaveLength(0);
  });

  it('FP shape 3: CA_KEYSTORE_PASSWORD = "ca-keystore-password" is NOT flagged', async () => {
    const code = `
public class HttpsSettings {
    private static final String CA_KEYSTORE_PASSWORD = "ca-keystore-password";
}
`;
    const r = await analyze(code, 'src/main/java/com/example/HttpsSettings.java', 'java');
    expect(credFindings(r)).toHaveLength(0);
  });

  it('RECALL: real password with uppercase + special char IS flagged', async () => {
    // "Pr0d-DB-pass!2024" has uppercase + digit + special char → fails the
    // CLI_OPTION_KEY_RE (all-lowercase-kebab-only) → still treated as credential.
    const code = `
public class DbConfig {
    private static final String DB_PASSWORD = "Pr0d-DB-pass!2024";
}
`;
    const r = await analyze(code, 'src/main/java/com/example/DbConfig.java', 'java');
    expect(credFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('RECALL: STRIPE_API_KEY with underscore-bearing value IS flagged', async () => {
    // "sk_live_abc..." (≥24 chars after sk_live_) matches the Stripe
    // provider regex directly. The CLI option-key gate is irrelevant for
    // provider hits — it only gates the named-credential matcher.
    // This confirms the suppression doesn't accidentally block provider
    // patterns. Literal split to avoid push-protection while still
    // exercising the runtime Stripe-key regex.
    const code = `
public class ApiConfig {
    private static final String STRIPE_API_KEY = "sk_` + 'live_abcdef0123456789ABCDEFGH"' + `;
}
`;
    const r = await analyze(code, 'src/main/java/com/example/ApiConfig.java', 'java');
    expect(credFindings(r).length).toBeGreaterThanOrEqual(1);
  });
});
