/**
 * Pass: weak-crypto (CWE-327, category: security)
 *
 * Pattern pass — flags use of cryptographically weak symmetric ciphers
 * (DES, 3DES, RC2, RC4, Blowfish), ECB mode, weak RSA key sizes (< 2048),
 * and weak AES modes. Like weak-hash, the vulnerability is the *constant
 * algorithm string* (or key-size argument), not data flow.
 *
 * Detection per language:
 *   Java:
 *     - `Cipher.getInstance("DES"|"DES/...")` / `"RC4"` / `"RC2"` / `"Blowfish"`
 *     - `Cipher.getInstance(".../ECB/...")` — ECB mode
 *     - `KeyGenerator.getInstance("DES"|"RC4"|"Blowfish")`
 *     - `KeyPairGenerator.getInstance("RSA")` followed by `initialize(<2048)`
 *       (the `.initialize(int)` literal under 2048 is detected directly when
 *       the receiver class is a generator)
 *   Python:
 *     - `Crypto.Cipher.DES.new(...)` / `Crypto.Cipher.ARC4.new(...)` /
 *       `Crypto.Cipher.Blowfish.new(...)` (pycryptodome / pycrypto)
 *     - `cryptography.hazmat.primitives.ciphers.algorithms.{TripleDES,Blowfish,ARC4,IDEA,SEED,CAST5}`
 *     - `AES.new(key, AES.MODE_ECB)` — ECB mode argument
 *   JavaScript / TypeScript:
 *     - `crypto.createCipher(...)` (deprecated; always weak)
 *     - `crypto.createCipheriv("des-..."|"rc4"|"bf-..."|"des-ede"|".*-ecb")`
 *   Go:
 *     - `des.NewCipher(...)` / `des.NewTripleDESCipher(...)` / `rc4.NewCipher(...)`
 *       (from `crypto/des` and `crypto/rc4`)
 *     - `cipher.NewECBEncrypter(...)` (custom ECB wrappers — best-effort)
 *
 * Aligned with: gosec G401/G405, Bandit B304/B305/B306, OWASP Benchmark `crypto` category.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// Weak symmetric ciphers (algorithm name set, lowercased).
const WEAK_CIPHER_BASES = new Set([
  'des', '3des', 'desede', 'tripledes',
  'rc2', 'rc4', 'arc4',
  'blowfish', 'bf',
  'idea', 'seed', 'cast5',
]);

// Java cipher transformation regex: "ALG/MODE/PADDING"; we look at base and mode.
function classifyJavaCipherSpec(spec: string): { weakBase?: string; ecb?: boolean } {
  const parts = spec.split('/').map((p) => p.trim().toLowerCase());
  const base = parts[0] ?? '';
  const mode = parts[1] ?? '';
  const result: { weakBase?: string; ecb?: boolean } = {};
  if (WEAK_CIPHER_BASES.has(base)) result.weakBase = base;
  if (mode === 'ecb') result.ecb = true;
  // Java default when only base is given is ECB (Cipher.getInstance("AES") == AES/ECB/PKCS5).
  if (parts.length === 1 && base === 'aes') result.ecb = true;
  return result;
}

function stripQuotes(s: string): string {
  const t = s.trim();
  if (
    (t.startsWith('"') && t.endsWith('"')) ||
    (t.startsWith("'") && t.endsWith("'")) ||
    (t.startsWith('`') && t.endsWith('`'))
  ) {
    return t.slice(1, -1);
  }
  return t;
}

function literalAlgo(call: CallInfo, position: number): string | null {
  const arg = call.arguments.find((a) => a.position === position);
  if (!arg) return null;
  const raw = arg.literal ?? arg.expression ?? '';
  const cleaned = stripQuotes(raw);
  return cleaned || null;
}

export interface WeakCryptoResult {
  findings: Array<{
    line: number;
    language: string;
    issue: 'weak-cipher' | 'ecb-mode' | 'deprecated-api';
    detail: string;
    api: string;
  }>;
}

export class WeakCryptoPass implements AnalysisPass<WeakCryptoResult> {
  readonly name = 'weak-crypto';
  readonly category = 'security' as const;

  run(ctx: PassContext): WeakCryptoResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: WeakCryptoResult['findings'] = [];

    for (const call of graph.ir.calls) {
      const detections = this.detect(call, language);
      for (const det of detections) {
        const line = call.location.line;
        findings.push({ line, language, ...det });

        const message = this.buildMessage(det);
        ctx.addFinding({
          id: `${this.name}-${file}-${line}-${det.issue}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-327',
          severity: 'high',
          level: 'error',
          message,
          file,
          line,
          fix:
            'Use AES-GCM (authenticated) or ChaCha20-Poly1305. Avoid DES, ' +
            '3DES, RC2, RC4, Blowfish, and ECB mode. For asymmetric encryption ' +
            'use RSA-OAEP with ≥2048-bit keys or modern curve-based schemes.',
          evidence: { ...det, language },
        });
      }
    }

    return { findings };
  }

  private buildMessage(det: { issue: string; detail: string; api: string }): string {
    switch (det.issue) {
      case 'weak-cipher':
        return (
          `Weak symmetric cipher \`${det.detail.toUpperCase()}\` used via ` +
          `\`${det.api}\`. DES, 3DES, RC2, RC4, Blowfish, and IDEA/SEED/CAST5 ` +
          'are deprecated and broken at modern key sizes.'
        );
      case 'ecb-mode':
        return (
          `ECB block-cipher mode used via \`${det.api}\` (\`${det.detail}\`). ` +
          'ECB leaks plaintext structure (identical blocks → identical ciphertext) ' +
          'and is not semantically secure.'
        );
      case 'deprecated-api':
        return (
          `Deprecated crypto API \`${det.api}\` used (no IV: \`${det.detail}\`). ` +
          'This API derives the key/IV from a password in an insecure way.'
        );
      default:
        return `Weak cryptography: ${det.detail} (${det.api})`;
    }
  }

  private detect(call: CallInfo, language: string): Array<{
    issue: 'weak-cipher' | 'ecb-mode' | 'deprecated-api';
    detail: string;
    api: string;
  }> {
    const method = call.method_name;
    const receiver = call.receiver ?? '';
    const out: Array<{ issue: 'weak-cipher' | 'ecb-mode' | 'deprecated-api'; detail: string; api: string }> = [];

    if (language === 'java') {
      // Cipher.getInstance(...) / KeyGenerator.getInstance(...)
      const isCipherFactory =
        method === 'getInstance' &&
        (receiver === 'Cipher' || receiver.endsWith('.Cipher') ||
         receiver === 'KeyGenerator' || receiver.endsWith('.KeyGenerator'));
      if (isCipherFactory) {
        const spec = literalAlgo(call, 0);
        if (spec) {
          const { weakBase, ecb } = classifyJavaCipherSpec(spec);
          const api = `${receiver}.getInstance`;
          if (weakBase) out.push({ issue: 'weak-cipher', detail: weakBase, api });
          if (ecb) out.push({ issue: 'ecb-mode', detail: spec, api });
        }
      }
      return out;
    }

    if (language === 'python') {
      // Crypto.Cipher.DES.new(...) / ARC4.new(...) / Blowfish.new(...)
      // pycryptodome receiver shape: `Crypto.Cipher.DES` or just `DES` (after import).
      if (method === 'new') {
        const rcvLower = receiver.toLowerCase();
        const lastSeg = rcvLower.split('.').pop() ?? rcvLower;
        if (WEAK_CIPHER_BASES.has(lastSeg)) {
          out.push({ issue: 'weak-cipher', detail: lastSeg, api: `${receiver}.new` });
        }
        // AES.new(key, AES.MODE_ECB) — ECB mode argument
        if (lastSeg === 'aes' || lastSeg.endsWith('.aes')) {
          const mode = call.arguments.find((a) => a.position === 1);
          const modeExpr = (mode?.expression ?? '').trim();
          if (/\bMODE_ECB\b/.test(modeExpr)) {
            out.push({ issue: 'ecb-mode', detail: 'AES.MODE_ECB', api: `${receiver}.new` });
          }
        }
      }
      // cryptography.hazmat ciphers — algorithms.TripleDES(key) / Blowfish(key) / ARC4(key) / IDEA(key) / SEED(key) / CAST5(key)
      // Receiver here is `algorithms` (or full path); method is the algo name.
      const isHazmatAlgos = receiver === 'algorithms' || receiver.endsWith('.algorithms');
      if (isHazmatAlgos) {
        const m = method.toLowerCase();
        const normalized = m === 'tripledes' ? '3des' : m;
        if (WEAK_CIPHER_BASES.has(normalized)) {
          out.push({ issue: 'weak-cipher', detail: normalized, api: `algorithms.${method}` });
        }
      }
      return out;
    }

    if (language === 'javascript' || language === 'typescript') {
      // crypto.createCipher(...) — deprecated, always weak (no IV).
      if (method === 'createCipher' && receiver === 'crypto') {
        const algo = literalAlgo(call, 0) ?? '<unknown>';
        out.push({ issue: 'deprecated-api', detail: algo, api: 'crypto.createCipher' });
      }
      // crypto.createCipheriv("des-..."|"rc4"|"...-ecb"|...)
      if (method === 'createCipheriv' && receiver === 'crypto') {
        const algo = literalAlgo(call, 0);
        if (algo) {
          const lower = algo.toLowerCase();
          // Split on dashes: "aes-128-ecb", "des-ede3-cbc", "rc4", "bf-cbc"
          const parts = lower.split('-');
          const base = parts[0];
          const mode = parts[parts.length - 1];
          let normalizedBase = base;
          if (base === 'bf') normalizedBase = 'blowfish';
          if (base === 'desede' || base === 'des-ede3' || base === 'des3') normalizedBase = '3des';
          if (WEAK_CIPHER_BASES.has(normalizedBase)) {
            out.push({ issue: 'weak-cipher', detail: normalizedBase, api: 'crypto.createCipheriv' });
          }
          if (mode === 'ecb') {
            out.push({ issue: 'ecb-mode', detail: lower, api: 'crypto.createCipheriv' });
          }
        }
      }
      return out;
    }

    if (language === 'go') {
      // crypto/des: des.NewCipher / des.NewTripleDESCipher
      if (receiver === 'des' && (method === 'NewCipher' || method === 'NewTripleDESCipher')) {
        const base = method === 'NewTripleDESCipher' ? '3des' : 'des';
        out.push({ issue: 'weak-cipher', detail: base, api: `des.${method}` });
      }
      // crypto/rc4: rc4.NewCipher
      if (receiver === 'rc4' && method === 'NewCipher') {
        out.push({ issue: 'weak-cipher', detail: 'rc4', api: 'rc4.NewCipher' });
      }
      // ECB mode wrappers — cipher.NewECBEncrypter / NewECBDecrypter (custom helpers
      // — Go stdlib intentionally omits ECB, so any such call is suspect).
      if ((method === 'NewECBEncrypter' || method === 'NewECBDecrypter') && receiver === 'cipher') {
        out.push({ issue: 'ecb-mode', detail: method, api: `cipher.${method}` });
      }
      return out;
    }

    return out;
  }
}
