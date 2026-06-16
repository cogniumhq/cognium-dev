/**
 * Pass: weak-crypto (CWE-327 / CWE-329 / CWE-321 / CWE-326, category: security)
 *
 * Pattern pass — flags use of cryptographically weak symmetric ciphers
 * (DES, 3DES, RC2, RC4, Blowfish), ECB mode, weak RSA key sizes (< 2048),
 * static/zero IVs (CWE-329), hardcoded symmetric keys (CWE-321), and weak
 * AES modes. Like weak-hash, the vulnerability is the *constant algorithm
 * string*, *constant IV bytes*, *literal key material*, or *key-size
 * argument*, not data flow.
 *
 * Detection per language:
 *   Java:
 *     - `Cipher.getInstance("DES"|"DES/...")` / `"RC4"` / `"RC2"` / `"Blowfish"`
 *     - `Cipher.getInstance(".../ECB/...")` — ECB mode
 *     - `KeyGenerator.getInstance("DES"|"RC4"|"Blowfish")`
 *     - `new IvParameterSpec(new byte[N])` / `new IvParameterSpec(literalBytes)`
 *       — static/zero IV (CWE-329, issue #87)
 *     - `new SecretKeySpec("literal".getBytes(), ...)` — hardcoded symmetric
 *       key (CWE-321, issue #87)
 *     - `KeyPairGenerator.initialize(<2048)` — weak RSA key size (CWE-326,
 *       issue #87). Detected by literal `< 2048` argument on `initialize`
 *       calls whose receiver is a `KeyPairGenerator` (best-effort: matches
 *       any `*.initialize(int)` where the literal is below 2048, since
 *       2048+ is also the minimum for DSA / DH and 256+ is correct for EC).
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

/**
 * Detect a static or zero IV passed to `new IvParameterSpec(...)`.
 *
 * Patterns flagged (returns a human-readable detail string):
 *   - `new byte[N]`               → "zero-filled byte[N]"
 *   - `new byte[]{0x00, 0x01,…}`  → "literal byte[] {…}"
 *   - `"literal".getBytes()`      → "literal string getBytes()"
 *   - bare string literal         → "literal string"
 *
 * Returns null when the IV argument is a variable / method call whose
 * value cannot be determined as a constant.
 */
function detectStaticIvJava(call: CallInfo): string | null {
  const arg = call.arguments.find((a) => a.position === 0);
  if (!arg) return null;
  const expr = (arg.literal ?? arg.expression ?? '').trim();
  if (!expr) return null;

  // `new byte[16]` / `new byte[BLOCK_SIZE]` — zero-initialised array literal.
  // Java initialises primitive arrays to zero, so a fresh `new byte[N]`
  // (without an immediate assignment of random bytes) is always a zero IV.
  if (/^new\s+byte\s*\[[^\]]*\]\s*$/.test(expr)) {
    return `zero-filled ${expr}`;
  }

  // `new byte[]{0x00, …}` — literal byte array initializer.
  if (/^new\s+byte\s*\[\s*\]\s*\{[^}]*\}\s*$/.test(expr)) {
    return `literal byte[] initializer`;
  }

  // `"…".getBytes()` / `"…".getBytes("UTF-8")` — constant string source.
  if (/^"[^"]*"\.getBytes\s*\(/.test(expr)) {
    return `literal string .getBytes()`;
  }

  // Bare string literal (rare for IvParameterSpec but possible via overload).
  if (/^"[^"]*"$/.test(expr)) {
    return `literal string`;
  }

  return null;
}

/**
 * Detect a hardcoded symmetric key passed to `new SecretKeySpec(...)`.
 *
 * Patterns flagged:
 *   - `"literalKey".getBytes()`   → "literal string .getBytes()"
 *   - `"literalKey".getBytes("…")`
 *   - `new byte[]{0x00, …}`       → "literal byte[] initializer"
 *   - bare string literal         → "literal string"
 *
 * Returns null when the key argument is a variable, method call, or any
 * other non-literal expression.
 */
/**
 * Recognise a Java constructor call to `new ClassName(...)`.
 *
 * The Java language plugin emits constructor calls as `CallInfo` with:
 *   method_name    === ClassName
 *   receiver       === null
 *   receiver_type  === ClassName (or FQN tail)
 *
 * Match on that shape, plus the explicit `is_constructor` flag when set.
 */
function isJavaCtor(call: CallInfo, className: string): boolean {
  if (call.is_constructor === true) return true;
  if (call.receiver) return false;
  if (call.receiver_type === className) return true;
  if ((call.receiver_type_fqn ?? '').endsWith('.' + className)) return true;
  return false;
}

function detectHardcodedKeyJava(call: CallInfo): string | null {
  const arg = call.arguments.find((a) => a.position === 0);
  if (!arg) return null;
  const expr = (arg.literal ?? arg.expression ?? '').trim();
  if (!expr) return null;

  if (/^"[^"]*"\.getBytes\s*\(/.test(expr)) return `literal string .getBytes()`;
  if (/^new\s+byte\s*\[\s*\]\s*\{[^}]*\}\s*$/.test(expr)) return `literal byte[] initializer`;
  if (/^"[^"]*"$/.test(expr)) return `literal string`;

  return null;
}

export type WeakCryptoIssue =
  | 'weak-cipher'      // CWE-327
  | 'ecb-mode'         // CWE-327
  | 'deprecated-api'   // CWE-327
  | 'static-iv'        // CWE-329 (zero / hardcoded IV)
  | 'hardcoded-key'    // CWE-321 (literal symmetric key material)
  | 'weak-rsa-key';    // CWE-326 (RSA key size < 2048)

/** Map issue kind → CWE identifier. */
const ISSUE_CWE: Record<WeakCryptoIssue, string> = {
  'weak-cipher': 'CWE-327',
  'ecb-mode': 'CWE-327',
  'deprecated-api': 'CWE-327',
  'static-iv': 'CWE-329',
  'hardcoded-key': 'CWE-321',
  'weak-rsa-key': 'CWE-326',
};

export interface WeakCryptoResult {
  findings: Array<{
    line: number;
    language: string;
    issue: WeakCryptoIssue;
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
          cwe: ISSUE_CWE[det.issue],
          severity: 'high',
          level: 'error',
          message,
          file,
          line,
          fix: this.buildFix(det.issue),
          evidence: { ...det, language },
        });
      }
    }

    return { findings };
  }

  private buildMessage(det: { issue: WeakCryptoIssue; detail: string; api: string }): string {
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
      case 'static-iv':
        return (
          `Static or zero-valued IV passed to \`${det.api}\` (\`${det.detail}\`). ` +
          'Reusing a fixed IV with CBC/CTR/GCM breaks confidentiality and, for ' +
          'GCM, can leak the authentication key.'
        );
      case 'hardcoded-key':
        return (
          `Hardcoded symmetric key material passed to \`${det.api}\` (\`${det.detail}\`). ` +
          'Keys embedded in source code are trivially recoverable from binaries ' +
          'and shared across deployments — they provide no confidentiality.'
        );
      case 'weak-rsa-key':
        return (
          `Weak RSA key size \`${det.detail}\` requested via \`${det.api}\`. ` +
          'RSA keys below 2048 bits are factorable and not compliant with ' +
          'NIST SP 800-57 / FIPS 186-5.'
        );
      default:
        return `Weak cryptography: ${det.detail} (${det.api})`;
    }
  }

  private buildFix(issue: WeakCryptoIssue): string {
    switch (issue) {
      case 'static-iv':
        return (
          'Generate a fresh random IV per message using SecureRandom: ' +
          '`byte[] iv = new byte[12]; SecureRandom.getInstanceStrong().nextBytes(iv); ' +
          'new IvParameterSpec(iv);` and prepend it to the ciphertext.'
        );
      case 'hardcoded-key':
        return (
          'Load the key from a secure key management system (HSM, KMS, ' +
          'Vault) or platform keystore. Never embed key material in source code.'
        );
      case 'weak-rsa-key':
        return (
          'Initialize KeyPairGenerator with at least 2048 bits (preferably ' +
          '3072 or 4096) for RSA, or switch to EC keys (P-256+).'
        );
      default:
        return (
          'Use AES-GCM (authenticated) or ChaCha20-Poly1305. Avoid DES, ' +
          '3DES, RC2, RC4, Blowfish, and ECB mode. For asymmetric encryption ' +
          'use RSA-OAEP with ≥2048-bit keys or modern curve-based schemes.'
        );
    }
  }

  private detect(call: CallInfo, language: string): Array<{
    issue: WeakCryptoIssue;
    detail: string;
    api: string;
  }> {
    const method = call.method_name;
    const receiver = call.receiver ?? '';
    const out: Array<{ issue: WeakCryptoIssue; detail: string; api: string }> = [];

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

      // new IvParameterSpec(...) — issue #87 (CWE-329 static IV)
      // Java constructor IR shape: method_name === 'IvParameterSpec',
      // receiver === null, receiver_type === 'IvParameterSpec'. The
      // is_constructor flag is not always populated by the Java plugin,
      // so detect by class-name match.
      if (method === 'IvParameterSpec' && isJavaCtor(call, 'IvParameterSpec')) {
        const ivDetail = detectStaticIvJava(call);
        if (ivDetail) {
          out.push({ issue: 'static-iv', detail: ivDetail, api: 'new IvParameterSpec' });
        }
      }

      // new SecretKeySpec(literal.getBytes(), "ALG") — issue #87 (CWE-321 hardcoded key)
      if (method === 'SecretKeySpec' && isJavaCtor(call, 'SecretKeySpec')) {
        const keyDetail = detectHardcodedKeyJava(call);
        if (keyDetail) {
          out.push({ issue: 'hardcoded-key', detail: keyDetail, api: 'new SecretKeySpec' });
        }
      }

      // kpg.initialize(<2048) — issue #87 (CWE-326 weak RSA key size)
      // KeyPairGenerator instance method. Receiver_type === 'KeyPairGenerator'
      // when the language plugin resolves it (post receiver-type matcher fix #52).
      if (method === 'initialize') {
        const isKpg =
          call.receiver_type === 'KeyPairGenerator' ||
          (call.receiver_type_fqn ?? '').endsWith('.KeyPairGenerator');
        if (isKpg) {
          const sizeArg = call.arguments.find((a) => a.position === 0);
          const expr = (sizeArg?.literal ?? sizeArg?.expression ?? '').trim();
          const n = parseInt(expr, 10);
          if (Number.isFinite(n) && n > 0 && n < 2048) {
            out.push({
              issue: 'weak-rsa-key',
              detail: String(n),
              api: 'KeyPairGenerator.initialize',
            });
          }
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
