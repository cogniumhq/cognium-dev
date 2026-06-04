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
