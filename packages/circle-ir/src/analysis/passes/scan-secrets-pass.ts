/**
 * Pass #90: scan-secrets (category: security, CWE-798)
 *
 * Detects hardcoded credentials across all 7 supported languages
 * (Java, JS/TS, Python, Go, Rust, Bash, HTML).
 *
 * Two detection layers:
 *
 *   1. Provider-specific regex patterns. ~16 high-confidence prefixes /
 *      shapes (AWS AKIA, GitHub `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`,
 *      Stripe `sk_live_`/`pk_live_`, OpenAI `sk-`, Anthropic `sk-ant-`,
 *      Slack `xox[baprs]-`, Google `AIza`, JWT `eyJ..eyJ..`, PEM private
 *      keys, npm `npm_`). Each match emits a finding with
 *      `rule_id: 'hardcoded-credential'` (matches the legacy Bash
 *      detection in LanguageSourcesPass).
 *
 *   2. Shannon-entropy scan of inline string literals. For each
 *      base64-shaped or hex-shaped quoted string above the length gate,
 *      compute Shannon entropy; flag if it crosses the per-shape
 *      threshold. Heavily denylisted (UUIDs, bare SHA hashes, common
 *      placeholders like "changeme" / "your-key-here", env-var refs)
 *      and gated against test-file paths. Emits
 *      `rule_id: 'hardcoded-credential-entropy'` (distinct rule so users
 *      can filter the noisier entropy branch without losing provider
 *      coverage).
 *
 * Both layers dedupe against any prior `hardcoded-credential` /
 * `hardcoded-credential-entropy` findings already in the pipeline's
 * findings buffer, so the pre-existing Bash detection
 * (`findBashPatternFindings` in language-sources-pass.ts) is never
 * double-reported.
 *
 * Test files (path-based heuristic) are skipped entirely.
 *
 * Detection is regex-based on the raw source text, so the pass works
 * on every language without per-grammar tree walking. This is the same
 * approach used by `language-sources-pass.findBashPatternFindings` and
 * `todo-in-prod-pass`.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SastFinding, Severity, SarifLevel } from '../../types/index.js';

// ---------------------------------------------------------------------------
// Test-file skip heuristic
// ---------------------------------------------------------------------------

/** Path components and filename suffixes that mark test/fixture files. */
const TEST_PATH_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__tests?__|__mocks?__|fixtures?|testdata)(?:[\\/]|$)/i;
const TEST_FILENAME_RE = /(?:\.(?:test|spec)\.[cm]?[jt]sx?|_test\.go|_test\.py|Test\.java|Tests\.java)$/i;

function isTestFile(file: string): boolean {
  return TEST_PATH_RE.test(file) || TEST_FILENAME_RE.test(file);
}

// ---------------------------------------------------------------------------
// Provider patterns (layer 1)
// ---------------------------------------------------------------------------

interface ProviderPattern {
  /** Display name, included in `evidence.provider`. */
  name: string;
  /** Anchored regex; should use `g` flag for line-level scanning via test loop. */
  regex: RegExp;
  severity: Severity;
  level: SarifLevel;
  /** Suggested remediation hint for the finding. */
  fix: string;
}

const PROVIDER_PATTERNS: ProviderPattern[] = [
  {
    name: 'AWS access key',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical', level: 'error',
    fix: 'Rotate the AWS access key immediately and move it to an environment variable or AWS Secrets Manager.',
  },
  {
    name: 'GitHub personal access token',
    regex: /\bghp_[A-Za-z0-9]{36}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the token at https://github.com/settings/tokens and store secrets in CI/CD secrets, not source.',
  },
  {
    name: 'GitHub OAuth token',
    regex: /\bgho_[A-Za-z0-9]{36}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the OAuth token and store secrets outside source control.',
  },
  {
    name: 'GitHub user-to-server token',
    regex: /\bghu_[A-Za-z0-9]{36}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the GitHub user-to-server token and store secrets outside source control.',
  },
  {
    name: 'GitHub server-to-server token',
    regex: /\bghs_[A-Za-z0-9]{36}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the GitHub server-to-server token and store secrets outside source control.',
  },
  {
    name: 'GitHub refresh token',
    regex: /\bghr_[A-Za-z0-9]{36}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the GitHub refresh token and store secrets outside source control.',
  },
  {
    name: 'Stripe live secret key',
    regex: /\bsk_live_[A-Za-z0-9]{24,}\b/,
    severity: 'critical', level: 'error',
    fix: 'Rotate the Stripe secret key in the Stripe Dashboard and load it from a secrets manager.',
  },
  {
    name: 'Stripe live publishable key',
    regex: /\bpk_live_[A-Za-z0-9]{24,}\b/,
    severity: 'high', level: 'warning',
    fix: 'Publishable keys are not secret but should still not be checked in to back-end source files; verify front-end vs back-end context.',
  },
  {
    name: 'OpenAI API key',
    regex: /\bsk-[A-Za-z0-9]{48}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the OpenAI key at https://platform.openai.com/api-keys and load from environment.',
  },
  {
    name: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the Anthropic key in the Console and load from environment.',
  },
  {
    name: 'Slack token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the Slack token and load from environment.',
  },
  {
    name: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: 'critical', level: 'error',
    fix: 'Restrict the Google API key by referrer / IP in the GCP console or revoke it.',
  },
  {
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    severity: 'critical', level: 'error',
    fix: 'JWTs in source carry whatever scope they were minted with; rotate signing keys and remove the token.',
  },
  {
    name: 'PEM private key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    severity: 'critical', level: 'error',
    fix: 'Remove the private key from source control immediately, rotate the corresponding public key, and store keys outside the repository.',
  },
  {
    name: 'npm access token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: 'critical', level: 'error',
    fix: 'Revoke the npm token at https://www.npmjs.com/settings/<user>/tokens and load from environment.',
  },
];

// ---------------------------------------------------------------------------
// Named-credential patterns (layer 1b)
//
// Catches config-style constant assignments where the LHS identifier carries
// a credential keyword (PASSWORD / SECRET / TOKEN / API_KEY / PRIVATE_KEY /
// ACCESS_KEY) and the RHS is a non-trivial string literal. Covers the cases
// the provider-prefix layer misses (custom passwords like
// "Pr0d-DB-pass!2024") and the entropy layer misses (low-entropy English /
// punctuation-heavy values that fail the base64-ish / hex-ish gate).
//
// Cross-language: works on Python / JS / TS / Java / Go / Rust because it
// operates on raw line text and only requires the LHS-keyword → `=`/`:` →
// quoted-literal shape, which is shared across all six. The Bash detector
// in language-sources-pass.ts already covers shell-syntax assignments.
//
// FP guards:
//   - Skip placeholder values (changeme / your-key-here / etc).
//   - Skip empty / single-char values.
//   - Skip values that are obviously dynamic (env-var refs, function calls,
//     concatenation, template-literal interpolation).
//   - Skip lines that look like function / method declarations (parameter
//     names with credential keywords are common: `func setPassword(pw string)`).
//   - Skip lines that look like comparisons (`==`, `===`, `!=`).
//
// (cognium-dev #109 — CWE-260 hardcoded credential in config files.)
// ---------------------------------------------------------------------------

const CRED_KEYWORD_RE =
  /\b([A-Za-z_$][\w$]*?(?:password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key)[\w$]*?)\s*[:=]\s*["'`]([^"'`\s$][^"'`\n]{2,})["'`]/i;

const CRED_DYNAMIC_VALUE_RE = /\$\{|process\.env|os\.environ|os\.Getenv|System\.getenv/;
const CRED_FUNCTION_DECL_RE = /\b(?:function|func|def|fn)\s+\w+\s*\(/;
const CRED_COMPARISON_RE = /(?:===?|!==?|>=|<=|<>)\s*["'`]/;

/** Variable / parameter / field declarations whose IDENTIFIER carries the credential keyword. */
function isLikelyCredentialAssignment(line: string): { name: string; value: string } | null {
  // Skip function declarations: `def login(password): ...`, `func auth(token string) {`
  if (CRED_FUNCTION_DECL_RE.test(line)) return null;
  // Skip equality comparisons that happen to involve a string literal.
  if (CRED_COMPARISON_RE.test(line)) return null;

  const m = line.match(CRED_KEYWORD_RE);
  if (!m) return null;
  const name = m[1];
  const value = m[2];

  // Reject placeholder / dynamic values (the entropy layer's denylist
  // also catches these; duplicated here so this layer is self-contained).
  if (PLACEHOLDER_RE.test(value)) return null;
  if (CRED_DYNAMIC_VALUE_RE.test(value)) return null;
  // Single-char / obviously-empty values.
  if (value.length < 3) return null;
  // Reject all-same-char (e.g. "xxx", "----").
  if (isAllSameChar(value)) return null;

  return { name, value };
}

// ---------------------------------------------------------------------------
// Entropy patterns (layer 2)
// ---------------------------------------------------------------------------

/**
 * Single-line string-literal extraction across languages.
 * Matches "...", '...', `...`. Group 1: opening delimiter; Group 2: content.
 *
 * Intentionally does NOT try to parse escapes or multi-line strings —
 * we want the literal-text content as the user wrote it, which is what
 * Shannon entropy needs to see.
 */
const STRING_LITERAL_RE = /(["'`])((?:\\.|(?!\1).){8,200})\1/g;

const BASE64ISH_RE = /^[A-Za-z0-9+/=_-]+$/;
const HEXISH_RE = /^[a-fA-F0-9]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const PLACEHOLDER_RE =
  /(?:changeme|your[-_]?(?:key|secret|token|password)(?:[-_]?here)?|replace[-_]?me|example[-_]?(?:key|secret|token)?|placeholder|todo|fixme|test[-_]?(?:key|secret|token)|fake[-_]?(?:key|secret|token)|dummy|sample|insert[-_]?your)/i;

/** Bare cryptographic-hash shapes (MD5 / SHA1 / SHA256) — high entropy but rarely a secret on their own. */
function isBareHashShape(s: string): boolean {
  const n = s.length;
  if (n !== 32 && n !== 40 && n !== 64) return false;
  return HEXISH_RE.test(s);
}

function isAllSameChar(s: string): boolean {
  if (s.length < 2) return false;
  const c = s.charAt(0);
  for (let i = 1; i < s.length; i++) if (s.charAt(i) !== c) return false;
  return true;
}

/** Decode base64 best-effort; return decoded text or null. Universal (no Node Buffer). */
function tryBase64Decode(s: string): string | null {
  // Quick reject: base64 length must be a multiple of 4 when padded.
  if (s.length % 4 !== 0 && !/=+$/.test(s)) return null;
  try {
    return globalThis.atob(s);
  } catch {
    return null;
  }
}

/** True if the base64 decodes to something that starts with `{` or `[` (i.e. JSON). */
function looksLikeBase64Json(s: string): boolean {
  const decoded = tryBase64Decode(s);
  if (!decoded) return false;
  const trimmed = decoded.trimStart();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  const len = s.length;
  let h = 0;
  for (const n of freq.values()) {
    const p = n / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Words near the literal that imply credential context — used to lower the entropy threshold. */
const CREDENTIAL_NAME_RE = /(?:key|secret|token|password|passwd|credential|api[_-]?key)/i;

// ---------------------------------------------------------------------------
// Per-line FP-guard substrings (entropy layer only)
// ---------------------------------------------------------------------------

const TEST_CALL_RE = /\b(?:expect|assert|describe|it|test)\s*\(/;
const COMMENT_EXAMPLE_RE = /(?:\/\/|#)\s*(?:example|sample|test|fixture)/i;

// ---------------------------------------------------------------------------
// Pass implementation
// ---------------------------------------------------------------------------

export interface ScanSecretsPassResult {
  /** Number of findings emitted in each layer (for debugging / tests). */
  providerFindings: number;
  entropyFindings: number;
}

export class ScanSecretsPass implements AnalysisPass<ScanSecretsPassResult> {
  readonly name = 'scan-secrets';
  readonly category = 'security' as const;

  run(ctx: PassContext): ScanSecretsPassResult {
    const file = ctx.graph.ir.meta.file;

    if (isTestFile(file)) {
      return { providerFindings: 0, entropyFindings: 0 };
    }

    const lines = ctx.code.split('\n');
    const prior = ctx.getFindings?.() ?? [];
    // Build dedup index keyed on `${line}:${rule_id}` for O(1) lookup.
    const seen = new Set<string>();
    for (const f of prior) {
      if (f.file !== file) continue;
      if (f.rule_id === 'hardcoded-credential' || f.rule_id === 'hardcoded-credential-entropy') {
        seen.add(`${f.line}:${f.rule_id}`);
      }
    }

    let providerFindings = 0;
    let entropyFindings = 0;

    // Layer 1: provider patterns (line-by-line).
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const lineNum = i + 1;
      for (const pattern of PROVIDER_PATTERNS) {
        const m = pattern.regex.exec(lineText);
        if (!m) continue;

        const key = `${lineNum}:hardcoded-credential`;
        if (seen.has(key)) continue;
        seen.add(key);

        ctx.addFinding({
          id: `hardcoded-credential-${file}-${lineNum}`,
          pass: this.name,
          category: this.category,
          rule_id: 'hardcoded-credential',
          cwe: 'CWE-798',
          severity: pattern.severity,
          level: pattern.level,
          message: `Hardcoded credential: ${pattern.name} detected`,
          file,
          line: lineNum,
          snippet: lineText.trim().substring(0, 120),
          fix: pattern.fix,
          evidence: { provider: pattern.name, match: m[0].substring(0, 40) },
        });
        providerFindings += 1;
        // First provider hit on a line is enough — same value won't match two
        // unrelated providers because patterns are prefix-anchored.
        break;
      }
    }

    // Layer 1b: named-credential constant assignments (config-style).
    // Operates line-by-line on raw source text; cross-language by construction
    // (PASSWORD/SECRET/TOKEN/API_KEY/PRIVATE_KEY/ACCESS_KEY identifier =
    // quoted literal). FP guards in `isLikelyCredentialAssignment`.
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const lineNum = i + 1;

      const hit = isLikelyCredentialAssignment(lineText);
      if (!hit) continue;

      const key = `${lineNum}:hardcoded-credential`;
      if (seen.has(key)) continue;
      seen.add(key);

      ctx.addFinding({
        id: `hardcoded-credential-${file}-${lineNum}`,
        pass: this.name,
        category: this.category,
        rule_id: 'hardcoded-credential',
        cwe: 'CWE-798',
        severity: 'high',
        level: 'error',
        message: `Hardcoded credential: \`${hit.name}\` assigned a literal value`,
        file,
        line: lineNum,
        snippet: lineText.trim().substring(0, 120),
        fix: 'Move the credential to an environment variable or secrets manager; never commit live secrets to source control.',
        evidence: { kind: 'named-credential', name: hit.name },
      });
      providerFindings += 1;
    }

    // Layer 2: Shannon-entropy scan on string literals.
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const lineNum = i + 1;

      if (TEST_CALL_RE.test(lineText)) continue;
      if (COMMENT_EXAMPLE_RE.test(lineText)) continue;

      // Reset regex state per line; STRING_LITERAL_RE is global.
      STRING_LITERAL_RE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = STRING_LITERAL_RE.exec(lineText)) !== null) {
        const value = match[2];
        if (!this.isCandidate(value)) continue;
        if (!this.passesEntropyGate(value, lineText)) continue;

        const key = `${lineNum}:hardcoded-credential-entropy`;
        if (seen.has(key)) continue;
        // Also dedup against provider-pattern hits on the same line — the
        // entropy branch is purely additive coverage.
        if (seen.has(`${lineNum}:hardcoded-credential`)) continue;
        seen.add(key);

        ctx.addFinding({
          id: `hardcoded-credential-entropy-${file}-${lineNum}`,
          pass: this.name,
          category: this.category,
          rule_id: 'hardcoded-credential-entropy',
          cwe: 'CWE-798',
          severity: 'high',
          level: 'warning',
          message: `Possible hardcoded secret: high-entropy string literal (${value.length} chars)`,
          file,
          line: lineNum,
          snippet: lineText.trim().substring(0, 120),
          fix: 'If this is a credential, move it to environment / secrets manager. If it is sample data, add an `example` / `test` marker or disable this pass via `disabledPasses: [\'scan-secrets\']`.',
          evidence: { kind: 'entropy', length: value.length },
        });
        entropyFindings += 1;
      }
    }

    return { providerFindings, entropyFindings };
  }

  /** Length + shape + denylist filter before entropy is computed. */
  private isCandidate(s: string): boolean {
    if (s.length < 20 || s.length > 200) return false;
    if (!BASE64ISH_RE.test(s) && !HEXISH_RE.test(s)) return false;
    if (UUID_RE.test(s)) return false;
    if (isBareHashShape(s)) return false;
    if (isAllSameChar(s)) return false;
    if (PLACEHOLDER_RE.test(s)) return false;
    // Skip strings that are themselves a recognizable base64-encoded JSON
    // payload (configs, PEM-bundles, etc.).
    if (looksLikeBase64Json(s)) return false;
    return true;
  }

  /**
   * Shannon-entropy gate. Base64-shaped strings need higher entropy than
   * hex-shaped (hex alphabet is 4 bits/char by construction). When the
   * surrounding line contains a credential-shaped variable name, both
   * thresholds drop by 0.2 bits/char.
   */
  private passesEntropyGate(value: string, lineText: string): boolean {
    const isHex = HEXISH_RE.test(value);
    const boost = CREDENTIAL_NAME_RE.test(lineText) ? 0.2 : 0;
    const threshold = isHex ? (3.5 - boost) : (4.3 - boost);
    const h = shannonEntropy(value);
    return h >= threshold;
  }
}
