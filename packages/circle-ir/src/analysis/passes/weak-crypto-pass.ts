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
 *     - `modes.ECB()` (cryptography.hazmat) — issue #87
 *     - `AES.new(b"literal", …)` / `algorithms.AES(b"literal")` — hardcoded
 *       symmetric key (CWE-321, issue #87). Detected for both inline byte
 *       literals and variables resolved via constant propagation.
 *     - `rsa.generate_private_key(key_size=<2048)` — weak RSA key size
 *       (CWE-326, issue #87)
 *   JavaScript / TypeScript:
 *     - `crypto.createCipher(...)` (deprecated; always weak)
 *     - `crypto.createCipheriv("des-..."|"rc4"|"bf-..."|"des-ede"|".*-ecb")`
 *   Go:
 *     - `des.NewCipher(...)` / `des.NewTripleDESCipher(...)` / `rc4.NewCipher(...)`
 *       (from `crypto/des` and `crypto/rc4`)
 *     - `cipher.NewECBEncrypter(...)` (custom ECB wrappers — best-effort)
 *     - `aes.NewCipher([]byte("literal"))` — hardcoded symmetric key
 *       (CWE-321, issue #87)
 *     - `rsa.GenerateKey(rand.Reader, <2048)` — weak RSA key size
 *       (CWE-326, issue #87)
 *
 * Aligned with: gosec G401/G405, Bandit B304/B305/B306, OWASP Benchmark `crypto` category.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import { isProtocolMandatedCryptoFile } from './_fp-allowlists.js';

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

/**
 * Detect a hardcoded symmetric key passed as the first positional argument
 * of a Python cipher constructor (`AES.new`, `DES.new`, `algorithms.AES(…)`,
 * etc.).
 *
 * Patterns flagged (returns a human-readable detail string):
 *   - inline bytes literal `b"…"` / `b'…'`
 *   - inline string literal `"…"` / `'…'` (legacy pycrypto style)
 *   - variable resolved by constant propagation to a string/bytes constant
 *
 * Returns null when the key argument is a runtime value (function call,
 * env-var lookup, parameter, etc.).
 */
function detectHardcodedKeyPython(
  call: CallInfo,
  constProp: ConstantPropagatorResult | null,
  literalBindings: Map<string, string>,
): string | null {
  const arg = call.arguments.find((a) => a.position === 0);
  if (!arg) return null;
  // Prefer `expression` over `literal` — the Python plugin's `literal`
  // field strips the trailing quote on bytes literals, breaking the
  // `^b"…"$` regex.
  const expr = (arg.expression ?? arg.literal ?? '').trim();
  if (!expr) return null;

  // Inline bytes literal: b"…" / b'…' / rb"…" / br"…"
  if (/^[bB][rR]?["'][^"']*["']$/.test(expr) || /^[rR][bB]["'][^"']*["']$/.test(expr)) {
    return `literal bytes ${expr.slice(0, 24)}${expr.length > 24 ? '…' : ''}`;
  }
  // Inline plain string literal: "…" / '…'
  if (/^["'][^"']*["']$/.test(expr)) {
    return `literal string ${expr.slice(0, 24)}${expr.length > 24 ? '…' : ''}`;
  }
  // Variable resolved by constant propagation (Java symbol table).
  if (arg.variable && constProp) {
    const sym = constProp.symbols.get(arg.variable);
    if (sym && sym.type === 'string' && typeof sym.value === 'string') {
      return `constant-propagated bytes from \`${arg.variable}\``;
    }
  }
  // Variable bound to a literal RHS earlier in the file (regex scan
  // fallback for languages whose const-prop pass does not yet track
  // string/bytes assignments).
  if (arg.variable) {
    const lit = literalBindings.get(arg.variable);
    if (lit) {
      return `literal-bound ${arg.variable} = ${lit.slice(0, 24)}${lit.length > 24 ? '…' : ''}`;
    }
  }
  return null;
}

/**
 * Detect a hardcoded symmetric key passed as the first positional argument
 * of a Go cipher constructor (`aes.NewCipher`, `des.NewCipher`, etc.).
 *
 * Patterns flagged:
 *   - inline `[]byte("literal")` conversion
 *   - inline `[]byte{0x00, 0x01, …}` composite literal
 *   - variable resolved by constant propagation to a string constant
 *
 * Returns null when the key argument is a runtime value.
 */
function detectHardcodedKeyGo(
  call: CallInfo,
  constProp: ConstantPropagatorResult | null,
  literalBindings: Map<string, string>,
): string | null {
  const arg = call.arguments.find((a) => a.position === 0);
  if (!arg) return null;
  const expr = (arg.literal ?? arg.expression ?? '').trim();
  if (!expr) return null;

  // []byte("literal") / []byte(`literal`)
  if (/^\[\s*\]\s*byte\s*\(\s*["'`][^"'`]*["'`]\s*\)$/.test(expr)) {
    return `literal []byte("…")`;
  }
  // []byte{0x00, 0x01, …}
  if (/^\[\s*\]\s*byte\s*\{[^}]*\}$/.test(expr)) {
    return `literal []byte{…} composite`;
  }
  // Variable resolved by constant propagation.
  if (arg.variable && constProp) {
    const sym = constProp.symbols.get(arg.variable);
    if (sym && sym.type === 'string' && typeof sym.value === 'string') {
      return `constant-propagated key from \`${arg.variable}\``;
    }
  }
  // Regex fallback: `var key = []byte("…")` / `key := []byte("…")` /
  // `const key = "…"` earlier in the same file.
  if (arg.variable) {
    const lit = literalBindings.get(arg.variable);
    if (lit) {
      return `literal-bound ${arg.variable} = ${lit.slice(0, 24)}${lit.length > 24 ? '…' : ''}`;
    }
  }
  return null;
}

/**
 * Extract a weak (< 2048) `key_size` argument from a Python
 * `…rsa.generate_private_key(...)` call.
 *
 * The Python plugin renders keyword arguments as `name=value` in
 * `argument.expression` and exposes the numeric RHS in `argument.literal`,
 * so we scan every positional and keyword argument for a `key_size=N`
 * spelling first, then fall back to a positional `key_size` (uncommon in
 * the cryptography API but accepted via `**kwargs`).
 */
function parseWeakRsaKeySizePython(call: CallInfo): number | null {
  for (const arg of call.arguments) {
    const expr = (arg.expression ?? '').trim();
    const lit = (arg.literal ?? '').trim();
    const m = expr.match(/^key_size\s*=\s*(-?\d+)\s*$/);
    if (m && m[1]) {
      const n = parseInt(m[1], 10);
      if (Number.isFinite(n) && n > 0 && n < 2048) return n;
      return null;
    }
    // Keyword arg where expression='key_size=…' but literal already isolated.
    if (/^key_size\s*=/.test(expr) && lit) {
      const n = parseInt(lit, 10);
      if (Number.isFinite(n) && n > 0 && n < 2048) return n;
    }
  }
  return null;
}

/**
 * Build a `<name> → <literal>` map by regex-scanning the file's source.
 *
 * Recognised forms per language (only inline literal RHSes — not function
 * calls, attribute lookups, parameters, etc.):
 *
 *   Python:
 *     `name = b"…"` / `name = b'…'`     (bytes literal)
 *     `name = "…"` / `name = '…'`        (string literal)
 *
 *   Go:
 *     `name := []byte("…")` / `var name = []byte("…")`
 *     `name := "…"` / `const name = "…"`
 *
 * Used by `detectHardcodedKeyPython` / `detectHardcodedKeyGo` to recognise
 * the common pattern `key = b"…"; AES.new(key, …)`. Returns an empty map
 * for unsupported languages or when the source is empty.
 */
function scanLiteralBindings(code: string, language: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!code) return out;

  if (language === 'python') {
    // `name = b"…"` (preferred form) or `name = "…"` (legacy / Python 2).
    const re = /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(b[rR]?["'][^"']*["']|[rR]?b["'][^"']*["']|["'][^"']*["'])\s*(?:$|#)/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      if (m[1] && m[2]) out.set(m[1], m[2]);
    }
    return out;
  }

  if (language === 'go') {
    // `name := []byte("…")` / `var name = []byte("…")` / `const name = "…"` /
    // `name := "…"`.
    const reByte = /^[ \t]*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(\[\s*\]\s*byte\s*\(\s*["'`][^"'`]*["'`]\s*\))/gm;
    let m: RegExpExecArray | null;
    while ((m = reByte.exec(code)) !== null) {
      if (m[1] && m[2]) out.set(m[1], m[2]);
    }
    const reStr = /^[ \t]*(?:var|const)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(["'`][^"'`]*["'`])/gm;
    while ((m = reStr.exec(code)) !== null) {
      if (m[1] && m[2]) out.set(m[1], m[2]);
    }
    const reShort = /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*(["'`][^"'`]*["'`])/gm;
    while ((m = reShort.exec(code)) !== null) {
      if (m[1] && m[2]) out.set(m[1], m[2]);
    }
    return out;
  }

  return out;
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
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;

    // #175 — suppress entirely when the file is a protocol-mandated
    // legacy-auth implementation (NTLM / Kerberos / SMB1 / SASL CRAM-MD5 /
    // HTTP Digest). DES/RC4/MD4/MD5 are hardcoded by the protocol spec;
    // switching algorithms would break interop with conformant peers.
    if (isProtocolMandatedCryptoFile(file, code)) {
      return { findings: [] };
    }

    const findings: WeakCryptoResult['findings'] = [];

    // Optional constant-propagation result — used to resolve a variable whose
    // assigned value is a literal bytes/string (Python `key = b"…"` → AES.new).
    const constProp = ctx.hasResult('constant-propagation')
      ? ctx.getResult<ConstantPropagatorResult>('constant-propagation')
      : null;

    // Lightweight per-language source scan for `<name> = <literal>`
    // bindings. Python's constant-propagation pass does not yet track
    // `name = b"…"` style assignments, and Go's does not track
    // `name := []byte("…")`. We do a one-pass regex over `ctx.code` to
    // build a `name → literal` map used by hardcoded-key detection.
    // This is a conservative augmentation — only inline literal RHSes
    // are recognised; runtime values stay invisible.
    const literalBindings = scanLiteralBindings(code, language);

    for (const call of graph.ir.calls) {
      const detections = this.detect(call, language, constProp, literalBindings);
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

  private detect(
    call: CallInfo,
    language: string,
    constProp: ConstantPropagatorResult | null,
    literalBindings: Map<string, string>,
  ): Array<{
    issue: WeakCryptoIssue;
    detail: string;
    api: string;
  }> {
    const method = call.method_name;
    const receiver = call.receiver ?? '';
    const out: Array<{ issue: WeakCryptoIssue; detail: string; api: string }> = [];

    if (language === 'java') {
      // Cipher.getInstance("ALG/MODE/PADDING") — both weak-base and ECB-mode
      // checks apply. ECB is meaningful here because Cipher actually performs
      // the encryption with the specified mode.
      const isCipherInstance =
        method === 'getInstance' &&
        (receiver === 'Cipher' || receiver.endsWith('.Cipher'));
      // KeyGenerator.getInstance("ALG") — only the weak-base check applies.
      // ECB is meaningless for KeyGenerator: it just generates key material
      // for the named algorithm; the cipher mode is chosen later by the
      // caller via Cipher.getInstance. `KeyGenerator.getInstance("AES")` is
      // the canonical, safe way to generate AES key material — flagging it
      // as ECB produces the bulk of CWE-327 FPs on OWASP Java benchmark
      // (cognium-dev #116, 93 FPs / 85% of all Java FPs in v3.67.0 snapshot).
      const isKeyGenInstance =
        method === 'getInstance' &&
        (receiver === 'KeyGenerator' || receiver.endsWith('.KeyGenerator'));
      if (isCipherInstance) {
        const spec = literalAlgo(call, 0);
        if (spec) {
          const { weakBase, ecb } = classifyJavaCipherSpec(spec);
          const api = `${receiver}.getInstance`;
          if (weakBase) out.push({ issue: 'weak-cipher', detail: weakBase, api });
          if (ecb) out.push({ issue: 'ecb-mode', detail: spec, api });
        }
      } else if (isKeyGenInstance) {
        const spec = literalAlgo(call, 0);
        if (spec) {
          const { weakBase } = classifyJavaCipherSpec(spec);
          const api = `${receiver}.getInstance`;
          if (weakBase) out.push({ issue: 'weak-cipher', detail: weakBase, api });
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
        // Hardcoded symmetric key — issue #87 (CWE-321). First arg is a bytes
        // literal `b"…"` either inline or via a constant-propagated variable.
        if (
          lastSeg === 'aes' || lastSeg.endsWith('.aes') ||
          WEAK_CIPHER_BASES.has(lastSeg)
        ) {
          const keyDetail = detectHardcodedKeyPython(call, constProp, literalBindings);
          if (keyDetail) {
            out.push({ issue: 'hardcoded-key', detail: keyDetail, api: `${receiver}.new` });
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
        // algorithms.AES(b"literal") — hardcoded key (CWE-321, issue #87).
        if (m === 'aes') {
          const keyDetail = detectHardcodedKeyPython(call, constProp, literalBindings);
          if (keyDetail) {
            out.push({ issue: 'hardcoded-key', detail: keyDetail, api: `algorithms.${method}` });
          }
        }
      }
      // cryptography.hazmat modes — modes.ECB() — issue #87 (CWE-327).
      // Receiver is `modes` (or full path ending in `.modes`); method is `ECB`.
      if (method === 'ECB' && (receiver === 'modes' || receiver.endsWith('.modes'))) {
        out.push({ issue: 'ecb-mode', detail: 'modes.ECB()', api: `${receiver}.ECB` });
      }
      // cryptography.hazmat asymmetric — rsa.generate_private_key(key_size=N)
      // / dsa.generate_private_key(key_size=N) — issue #87 (CWE-326).
      if (
        method === 'generate_private_key' &&
        (receiver === 'rsa' || receiver === 'dsa' ||
         receiver.endsWith('.rsa') || receiver.endsWith('.dsa'))
      ) {
        const n = parseWeakRsaKeySizePython(call);
        if (n !== null) {
          out.push({
            issue: 'weak-rsa-key',
            detail: String(n),
            api: `${receiver}.generate_private_key`,
          });
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
      // aes.NewCipher / des.NewCipher / des.NewTripleDESCipher hardcoded key —
      // issue #87 (CWE-321). First arg is `[]byte("literal")` or a variable
      // assigned from such a literal.
      if (
        (receiver === 'aes' && method === 'NewCipher') ||
        (receiver === 'des' && (method === 'NewCipher' || method === 'NewTripleDESCipher')) ||
        (receiver === 'rc4' && method === 'NewCipher')
      ) {
        const keyDetail = detectHardcodedKeyGo(call, constProp, literalBindings);
        if (keyDetail) {
          out.push({ issue: 'hardcoded-key', detail: keyDetail, api: `${receiver}.${method}` });
        }
      }
      // crypto/rsa: rsa.GenerateKey(rand.Reader, bits) — issue #87 (CWE-326).
      // Second positional arg is the key size in bits.
      if (receiver === 'rsa' && method === 'GenerateKey') {
        const bitsArg = call.arguments.find((a) => a.position === 1);
        const expr = (bitsArg?.literal ?? bitsArg?.expression ?? '').trim();
        const n = parseInt(expr, 10);
        if (Number.isFinite(n) && n > 0 && n < 2048) {
          out.push({
            issue: 'weak-rsa-key',
            detail: String(n),
            api: 'rsa.GenerateKey',
          });
        }
      }
      return out;
    }

    return out;
  }
}
