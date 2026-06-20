/**
 * Tests for Pass #90: scan-secrets (category: security, CWE-798)
 *
 * Note: all hardcoded credentials below are deliberately fabricated
 * patterns used solely to exercise the regex matchers. None are
 * real secrets.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { ScanSecretsPass } from '../../../src/analysis/passes/scan-secrets-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function makeIR(file: string, language: CircleIR['meta']['language'] = 'typescript'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language, loc: 10, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function makeCtx(
  ir: CircleIR,
  code: string,
  priorFindings: SastFinding[] = [],
): { ctx: PassContext; findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [...priorFindings];
  const ctx: PassContext = {
    graph,
    code,
    language: ir.meta.language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
    getFindings: () => findings,
  };
  return { ctx, findings };
}

/** Convenience: run pass, return only newly-emitted findings (excluding seeded prior ones). */
function runPass(
  file: string,
  code: string,
  language: CircleIR['meta']['language'] = 'typescript',
  priorFindings: SastFinding[] = [],
): SastFinding[] {
  const ir = makeIR(file, language);
  const { ctx, findings } = makeCtx(ir, code, priorFindings);
  new ScanSecretsPass().run(ctx);
  return findings.slice(priorFindings.length);
}

// ---------------------------------------------------------------------------
// Layer 1: provider-pattern detection
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — provider patterns', () => {
  it('detects AWS access key (AKIA) in Python', () => {
    const code = `aws_key = "AKIAIOSFODNN7EXAMPLE"\n`;
    const out = runPass('app.py', code, 'python');
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('hardcoded-credential');
    expect(out[0].cwe).toBe('CWE-798');
    expect(out[0].severity).toBe('critical');
    expect(out[0].level).toBe('error');
    expect(out[0].evidence?.provider).toBe('AWS access key');
  });

  it('detects AWS access key in JavaScript', () => {
    const code = `const key = 'AKIAIOSFODNN7EXAMPLE';`;
    const out = runPass('app.js', code, 'javascript');
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('hardcoded-credential');
  });

  it('detects AWS access key in Java', () => {
    const code = `String key = "AKIAIOSFODNN7EXAMPLE";`;
    const out = runPass('App.java', code, 'java');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('AWS access key');
  });

  it('detects GitHub PAT (ghp_) classic', () => {
    const code = `token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`;
    const out = runPass('app.py', code, 'python');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('GitHub personal access token');
  });

  it('detects GitHub gho_/ghs_/ghu_/ghr_ variants', () => {
    const code = [
      `a = "gho_abcdefghijklmnopqrstuvwxyz0123456789"`,
      `b = "ghs_abcdefghijklmnopqrstuvwxyz0123456789"`,
      `c = "ghu_abcdefghijklmnopqrstuvwxyz0123456789"`,
      `d = "ghr_abcdefghijklmnopqrstuvwxyz0123456789"`,
    ].join('\n');
    const out = runPass('app.py', code, 'python');
    const ruleHits = out.filter(f => f.rule_id === 'hardcoded-credential');
    expect(ruleHits).toHaveLength(4);
    const providers = ruleHits.map(f => f.evidence?.provider).sort();
    expect(providers).toEqual([
      'GitHub OAuth token',
      'GitHub refresh token',
      'GitHub server-to-server token',
      'GitHub user-to-server token',
    ]);
  });

  it('detects Stripe sk_live_ secret key in Go', () => {
    // Literal split to avoid tripping GitHub push protection while still
    // exercising the runtime Stripe-key regex.
    const code = 'var key = "sk_' + 'live_abcdef0123456789ABCDEFGH"';
    const out = runPass('main.go', code, 'go');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('Stripe live secret key');
    expect(out[0].severity).toBe('critical');
  });

  it('detects Stripe pk_live_ publishable key as warning (lower severity)', () => {
    const code = `const key = "pk_live_abcdef0123456789ABCDEFGH";`;
    const out = runPass('app.js', code, 'javascript');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('Stripe live publishable key');
    expect(out[0].severity).toBe('high');
    expect(out[0].level).toBe('warning');
  });

  it('detects OpenAI API key', () => {
    const code = `key = "sk-` + 'a'.repeat(48) + `"`;
    const out = runPass('app.py', code, 'python');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('OpenAI API key');
  });

  it('detects Anthropic API key sk-ant-', () => {
    const code = `key = "sk-ant-` + 'A'.repeat(95) + `"`;
    const out = runPass('app.py', code, 'python');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('Anthropic API key');
  });

  it('detects Slack token xoxb-', () => {
    const code = `const tok = "xoxb-1234567890-abcdef";`;
    const out = runPass('app.js', code, 'javascript');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('Slack token');
  });

  it('detects Google API key AIza', () => {
    const code = `key = "AIza` + 'A'.repeat(35) + `"`;
    const out = runPass('app.py', code, 'python');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('Google API key');
  });

  it('detects JWT in Authorization header literal', () => {
    const header =
      'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
      '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ' +
      '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const code = `const auth = "${header}";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('JSON Web Token');
  });

  it('detects PEM private key block inline in JS template literal', () => {
    const code =
      'const key = `-----BEGIN RSA PRIVATE KEY-----\nMIIE...`;\n';
    const out = runPass('app.js', code, 'javascript');
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out.some(f => f.evidence?.provider === 'PEM private key')).toBe(true);
  });

  it('detects npm token npm_', () => {
    const code = `token = "npm_abcdefghijklmnopqrstuvwxyz0123456789"`;
    const out = runPass('app.py', code, 'python');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('npm access token');
  });

  it('detects GitHub token inside an HTML attribute value', () => {
    const code = `<script data-token="ghp_abcdefghijklmnopqrstuvwxyz0123456789"></script>`;
    const out = runPass('index.html', code, 'html');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('GitHub personal access token');
  });

  it('detects AWS access key in a Rust let-binding', () => {
    const code = `let aws_key: &str = "AKIAIOSFODNN7EXAMPLE";`;
    const out = runPass('src/lib.rs', code, 'rust');
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('hardcoded-credential');
    expect(out[0].evidence?.provider).toBe('AWS access key');
  });

  it('detects a GitHub token inside a Rust raw string literal', () => {
    // Rust raw strings: r"..." — provider scan reads the raw line so the
    // `r` prefix is irrelevant.
    const code = `let token = r"ghp_abcdefghijklmnopqrstuvwxyz0123456789";`;
    const out = runPass('src/auth.rs', code, 'rust');
    expect(out).toHaveLength(1);
    expect(out[0].evidence?.provider).toBe('GitHub personal access token');
  });

  it('flags fake AKIA inside a JS line comment (we do not trust comments)', () => {
    const code = `// rotated: AKIAIOSFODNN7EXAMPLE`;
    const out = runPass('app.js', code, 'javascript');
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('hardcoded-credential');
  });
});

// ---------------------------------------------------------------------------
// All-7-languages coverage matrix — locks in language parity for AWS AKIA
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — all 7 supported languages', () => {
  const akia = 'AKIAIOSFODNN7EXAMPLE';
  const cases: Array<{
    lang: CircleIR['meta']['language'];
    file: string;
    code: string;
  }> = [
    { lang: 'java',       file: 'src/main/java/App.java', code: `String key = "${akia}";` },
    { lang: 'javascript', file: 'src/app.js',             code: `const key = "${akia}";` },
    { lang: 'typescript', file: 'src/app.ts',             code: `const key: string = "${akia}";` },
    { lang: 'python',     file: 'src/app.py',             code: `key = "${akia}"` },
    { lang: 'go',         file: 'cmd/main.go',            code: `var key = "${akia}"` },
    { lang: 'rust',       file: 'src/lib.rs',             code: `let key = "${akia}";` },
    { lang: 'bash',       file: 'scripts/deploy.sh',      code: `KEY="${akia}"` },
    { lang: 'html',       file: 'public/index.html',      code: `<meta data-key="${akia}">` },
  ];

  for (const { lang, file, code } of cases) {
    it(`detects AWS AKIA in ${lang}`, () => {
      const out = runPass(file, code, lang);
      expect(out).toHaveLength(1);
      expect(out[0].rule_id).toBe('hardcoded-credential');
      expect(out[0].evidence?.provider).toBe('AWS access key');
      expect(out[0].file).toBe(file);
    });
  }
});

// ---------------------------------------------------------------------------
// Layer 1: false-positive guards
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — FP guards', () => {
  it('skips test files entirely', () => {
    const code = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const out = runPass('src/__tests__/foo.test.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });

  it('skips spec files', () => {
    const code = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const out = runPass('tests/service.spec.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });

  it('skips Java *Test.java files', () => {
    const code = `String key = "AKIAIOSFODNN7EXAMPLE";`;
    const out = runPass('src/test/java/FooTest.java', code, 'java');
    expect(out).toHaveLength(0);
  });

  it('does not flag bash env-var reference', () => {
    const code = `password=$MY_PASSWORD\n`;
    const out = runPass('deploy.sh', code, 'bash');
    expect(out).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Layer 2: Shannon entropy
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — entropy detection', () => {
  it('flags a 64-char high-entropy base64 blob assigned to apiKey', () => {
    // Hand-crafted to be base64-shape, length 64, high entropy.
    const blob = 'aZ8Q3pV7tR1xL5mN9wK2yP4uH6jB0sC1eD2fG3iJ4kM5lO6nQ7oR8tU9vW0xY1zS';
    const code = `const apiKey = "${blob}";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('hardcoded-credential-entropy');
    expect(out[0].severity).toBe('high');
    expect(out[0].level).toBe('warning');
  });

  it('does NOT flag a UUID v4', () => {
    const code = `const id = "550e8400-e29b-41d4-a716-446655440000";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });

  it('does NOT flag a bare SHA-256 hash with no credential context', () => {
    const sha =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const code = `const checksum = "${sha}";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });

  it('does NOT flag placeholder values', () => {
    const code = [
      `const a = "changeme-changeme-changeme";`,
      `const b = "your-api-key-here-please";`,
      `const c = "replace-me-replace-me-replace";`,
    ].join('\n');
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });

  it('does NOT flag strings inside test/expect calls', () => {
    const blob = 'aZ8Q3pV7tR1xL5mN9wK2yP4uH6jB0sC1eD2fG3iJ4kM5lO6nQ7oR8tU9vW0xY1zS';
    const code = `expect(token).toBe("${blob}");`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });

  it('does NOT flag base64-encoded JSON config blob', () => {
    // Pre-computed base64 of '{"role":"admin","perms":["read","write","exec"]}'
    const b64 = globalThis.btoa(
      '{"role":"admin","perms":["read","write","exec"]}',
    );
    const code = `const config = "${b64}";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Dedup vs. legacy Bash detection
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — dedup vs. LanguageSourcesPass', () => {
  it('does not emit a second finding when LanguageSourcesPass already reported the same line', () => {
    // Pre-seed a prior `hardcoded-credential` finding on line 1, as
    // findBashPatternFindings would have produced for a `PASSWORD=` line.
    const prior: SastFinding[] = [{
      id: 'hardcoded-credential-deploy.sh-1',
      pass: 'language-sources',
      category: 'security',
      rule_id: 'hardcoded-credential',
      cwe: 'CWE-798',
      severity: 'high',
      level: 'error',
      message: 'Hardcoded credential: password contains a literal value',
      file: 'deploy.sh',
      line: 1,
    }];
    // Line 1 contains an OpenAI key — scan-secrets would otherwise fire.
    const code = `OPENAI_KEY="sk-` + 'a'.repeat(48) + `"\n`;
    const out = runPass('deploy.sh', code, 'bash', prior);
    const onLine1 = out.filter(f => f.line === 1 && f.rule_id === 'hardcoded-credential');
    expect(onLine1).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Severity mapping summary
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — severity mapping', () => {
  it('provider patterns → critical/error', () => {
    const code = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out[0].severity).toBe('critical');
    expect(out[0].level).toBe('error');
  });

  it('entropy branch → high/warning', () => {
    const blob = 'aZ8Q3pV7tR1xL5mN9wK2yP4uH6jB0sC1eD2fG3iJ4kM5lO6nQ7oR8tU9vW0xY1zS';
    const code = `const apiKey = "${blob}";`;
    const out = runPass('app.ts', code, 'typescript');
    expect(out[0].severity).toBe('high');
    expect(out[0].level).toBe('warning');
  });
});

// ---------------------------------------------------------------------------
// #125 — context-gated entropy (4-gate FP reduction)
//
// Top-20 Java OSS harness exposed 762/791 (96.3%) FPs on the entropy layer
// across 5 distinct patterns (PlantUML annotations, base64 CSS blobs, public
// display constants, hutool astronomical-data arrays, public encoding
// alphabets). Sprint 32 added 4 context gates:
//   Gate 1: annotation-arg suppression (@Annotation(...), #[derive(...)])
//   Gate 2: generated-file wholesale skip (path + filename heuristics)
//   Gate 3: string-array constant-table suppression (≥3 string literals in
//           an enclosed `=\s*[{\[]` span)
//   Gate 4: field-name strengthening (credential keyword required on LHS;
//           literal length floor of 32 chars)
// ---------------------------------------------------------------------------

describe('ScanSecretsPass — #125 context-gated entropy', () => {
  // High-entropy base64-shape literal, length 64 — well above gate's 32 floor
  // and 4.1 threshold. Reused across negative tests below.
  const HIGH_ENT = 'aZ8Q3pV7tR1xL5mN9wK2yP4uH6jB0sC1eD2fG3iJ4kM5lO6nQ7oR8tU9vW0xY1zS';

  // -----------------------------------------------------------------------
  // Negative locks — must NOT fire after the gates land
  // -----------------------------------------------------------------------

  it('pattern A: @Original(key="...") annotation arg → 0 entropy findings', () => {
    // PlantUML graphviz-port attribution: ~530 of 762 harness FPs.
    const code = [
      `package net.sourceforge.plantuml.graphviz;`,
      ``,
      `public class FooPort {`,
      `  @Original(key="${HIGH_ENT}")`,
      `  public void foo() {}`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/FooPort.java', code, 'java');
    const ent = out.filter(f => f.rule_id === 'hardcoded-credential-entropy');
    expect(ent).toHaveLength(0);
  });

  it('pattern B: base64 CSS blob string-concat → 0 entropy findings', () => {
    // PlantUML EmbeddedResources.java pattern: 110 of 762 harness FPs.
    // No credential field name on LHS → Gate 4 alone is enough.
    const code = [
      `public class EmbeddedResources {`,
      `  public static final String CSS_BLOB =`,
      `    "${HIGH_ENT}" +`,
      `    "${HIGH_ENT}" +`,
      `    "${HIGH_ENT}";`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/EmbeddedResources.java', code, 'java');
    const ent = out.filter(f => f.rule_id === 'hardcoded-credential-entropy');
    expect(ent).toHaveLength(0);
  });

  it('pattern C: DONORS public-display string const → 0 entropy findings', () => {
    // PlantUML PSystemDonors.DONORS pattern: 24 of 762 harness FPs.
    const code = [
      `public class PSystemDonors {`,
      `  public static final String DONORS =`,
      `    "${HIGH_ENT}" +`,
      `    "${HIGH_ENT}";`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/PSystemDonors.java', code, 'java');
    const ent = out.filter(f => f.rule_id === 'hardcoded-credential-entropy');
    expect(ent).toHaveLength(0);
  });

  it('pattern D: SolarTerms astronomical-data array → 0 entropy findings', () => {
    // hutool SolarTerms.java pattern: 36 of 762 harness FPs. Gate 3 catches
    // this via the ≥3-string array opener.
    const code = [
      `public class SolarTerms {`,
      `  public static final String[] solarTerms = {`,
      `    "9778397bd097c36b0b6fc9274c91aa3b0bac",`,
      `    "97b6b97bd19801ec9210c965cc920e97bcb0",`,
      `    "97bd09801d98082c95f8c9761cc920f97bb0",`,
      `    "97bd097c36b0b6fc9274c91aa3b0bac95f61",`,
      `  };`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/SolarTerms.java', code, 'java');
    const ent = out.filter(f => f.rule_id === 'hardcoded-credential-entropy');
    expect(ent).toHaveLength(0);
  });

  it('pattern E: public Base32 alphabet → 0 entropy findings', () => {
    // hutool DEFAULT_ALPHABET pattern: 8 of 762 harness FPs. RFC 4648
    // Base32 alphabet — public spec, not a secret. No credential keyword on
    // LHS, Gate 4 suppresses. (Length is exactly 32, ≥ floor.)
    const code = [
      `public class Base32 {`,
      `  public static final String DEFAULT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/Base32.java', code, 'java');
    const ent = out.filter(f => f.rule_id === 'hardcoded-credential-entropy');
    expect(ent).toHaveLength(0);
  });

  it('Gate 2: generated path (gen/) → 0 findings', () => {
    // Wholesale skip — even provider patterns are suppressed inside
    // generated paths (matches isTestFile precedent).
    const code = `String key = "${HIGH_ENT}";`;
    const out = runPass('src/main/java/gen/lib/foo.java', code, 'java');
    expect(out).toHaveLength(0);
  });

  it('Gate 2: generated filename (__c.java) → 0 findings', () => {
    // Wholesale skip — filename pattern from graphviz/plantuml
    // generated-C-source naming convention.
    const code = `String key = "${HIGH_ENT}";`;
    const out = runPass('src/main/java/dtdisc__c.java', code, 'java');
    expect(out).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // Recall locks — true positives must STILL fire
  // -----------------------------------------------------------------------

  it('recall: credential-named field with high-entropy literal → 1 finding', () => {
    // Field name matches CREDENTIAL_NAME_RE (`api_key`), literal length 64,
    // base64-shape, high entropy. Gate 4 satisfied → entropy layer fires.
    const code = [
      `public class Cfg {`,
      `  public static final String API_KEY = "${HIGH_ENT}";`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/Cfg.java', code, 'java');
    const ent = out.filter(f => f.rule_id === 'hardcoded-credential-entropy');
    expect(ent).toHaveLength(1);
    expect(ent[0].severity).toBe('high');
    expect(ent[0].level).toBe('warning');
    expect(ent[0].cwe).toBe('CWE-798');
  });

  it('recall: AWS AKIA inside annotation arg still fires (Layer 1 unaffected by Gate 1)', () => {
    // Gate 1 only suppresses the entropy layer. Provider patterns (Layer 1)
    // are unconditional — known-shape AWS keys must still be reported even
    // when embedded in a `@Schema(example = ...)` doc annotation.
    const code = [
      `public class UserDto {`,
      `  @Schema(example = "AKIAIOSFODNN7EXAMPLE")`,
      `  private String awsKey;`,
      `}`,
    ].join('\n');
    const out = runPass('src/main/java/UserDto.java', code, 'java');
    const provider = out.filter(f => f.rule_id === 'hardcoded-credential');
    expect(provider).toHaveLength(1);
    expect(provider[0].evidence?.provider).toBe('AWS access key');
  });

  it('recall: Layer 1b named-credential matcher unaffected by entropy gates', () => {
    // `DB_PASSWORD = "..."` is the named-credential matcher in Layer 1b
    // (not entropy). It uses its own credential-keyword regex on the LHS
    // (requires prefix char + credential keyword, e.g. `DB_PASSWORD`) and
    // emits `hardcoded-credential`, not `hardcoded-credential-entropy`.
    // Must still fire — entropy gates don't touch Layer 1b.
    const code = `DB_PASSWORD = "Pr0d-DB-pass!2024"`;
    const out = runPass('app.py', code, 'python');
    const named = out.filter(f => f.rule_id === 'hardcoded-credential');
    expect(named.length).toBeGreaterThanOrEqual(1);
    expect(named[0].evidence?.kind).toBe('named-credential');
  });
});
