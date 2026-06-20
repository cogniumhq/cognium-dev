/**
 * Shared helpers for the credential / crypto rule family (Sprint 28).
 *
 * Used by:
 *   - weak-password-hash-pass.ts (CWE-916)
 *   - plaintext-password-storage-pass.ts (CWE-256)
 *   - cleartext-credential-transport-pass.ts (CWE-523)
 *   - weak-password-encoding-pass.ts (CWE-261)
 *
 * The credential-keyword regex is the same shape used by
 * scan-secrets-pass.ts (CWE-260, Sprint 26). Kept identifier-anchored:
 * `password`, `passwd`, `pwd`, `secret`, `api[_-]?key`, `auth[_-]?token`,
 * `private[_-]?key`, `access[_-]?key`, `credential`.
 */

import type { CallInfo, ArgumentInfo } from '../../types/index.js';

/** Identifier-name credential keywords. Case-insensitive substring match. */
const CRED_KEYWORD_RE =
  /(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key|credential)/i;

/** True if a bare identifier name carries a credential keyword. */
export function isCredentialIdentifier(name: string | null | undefined): boolean {
  if (!name) return false;
  // Reject very short / generic — `pwd` alone is fine, but reject obvious noise.
  if (name.length < 3) return false;
  return CRED_KEYWORD_RE.test(name);
}

/** True if any of the argument's variable / expression text carries a credential keyword. */
export function argLooksLikeCredential(arg: ArgumentInfo | undefined): boolean {
  if (!arg) return false;
  if (arg.variable && isCredentialIdentifier(arg.variable)) return true;
  const expr = (arg.expression ?? '').trim();
  if (!expr) return false;
  // Strip method-call tail (e.g. `password.getBytes()`, `pw.encode()`).
  const head = expr.split(/[.\s(]/, 1)[0] ?? '';
  return isCredentialIdentifier(head);
}

/** Strip surrounding quotes from a literal expression. */
export function stripQuotes(s: string): string {
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

/** Return the literal/value of an argument, with quotes stripped; null if not a literal. */
export function literalAt(call: CallInfo, position: number): string | null {
  const arg = call.arguments.find((a) => a.position === position);
  if (!arg) return null;
  const raw = arg.literal ?? arg.expression ?? '';
  const trimmed = raw.trim();
  if (
    trimmed.startsWith('"') ||
    trimmed.startsWith("'") ||
    trimmed.startsWith('`')
  ) {
    return stripQuotes(trimmed);
  }
  if (arg.literal) return stripQuotes(arg.literal);
  return null;
}

// ---------------------------------------------------------------------------
// Hash-function detection (used by plaintext-password-storage-pass)
// ---------------------------------------------------------------------------

/**
 * True if the call is a known cryptographic hash / KDF that "protects" a
 * credential value. Used by plaintext-storage detector to suppress when
 * the credential identifier has already been passed through a hash.
 *
 * Recognised:
 *   - Java: MessageDigest.update / .digest, DigestUtils.*, BCrypt.hashpw,
 *           PBKDF2*, Argon2*, SecretKeyFactory.generateSecret
 *   - Python: hashlib.*, bcrypt.hashpw / .hash, argon2.hash, passlib.hash
 *   - JS/TS: crypto.createHash().update / .digest, bcrypt.hash / .hashSync,
 *           argon2.hash, scrypt
 *   - Go: md5.Sum, sha*.Sum, bcrypt.GenerateFromPassword, argon2.*
 */
export function isHashFunctionCall(call: CallInfo): boolean {
  const method = call.method_name ?? '';
  const receiver = call.receiver ?? '';
  const recvLower = receiver.toLowerCase();

  // bcrypt across all langs
  if (recvLower === 'bcrypt' || recvLower.endsWith('.bcrypt')) {
    return (
      method === 'hashpw' || method === 'hash' || method === 'hashSync' ||
      method === 'GenerateFromPassword' || method === 'generate_password_hash'
    );
  }

  // argon2
  if (recvLower === 'argon2' || recvLower.endsWith('.argon2')) {
    return method === 'hash' || method === 'Hash' || method === 'PasswordHash';
  }

  // Python hashlib + passlib
  if (recvLower === 'hashlib') return true;
  if (recvLower === 'passlib' || recvLower.includes('passlib.hash')) return true;

  // Python pyca/cryptography PBKDF2HMAC
  if (method === 'PBKDF2HMAC' || method === 'derive') return true;

  // Node.js crypto
  if (recvLower === 'crypto') {
    return (
      method === 'createHash' || method === 'createHmac' ||
      method === 'pbkdf2' || method === 'pbkdf2Sync' ||
      method === 'scrypt' || method === 'scryptSync'
    );
  }

  // Java MessageDigest
  if (receiver === 'MessageDigest' || receiver.endsWith('.MessageDigest')) {
    return method === 'getInstance' || method === 'update' || method === 'digest';
  }

  // Java Apache Commons DigestUtils
  if (receiver === 'DigestUtils' || receiver.endsWith('.DigestUtils')) {
    return true;
  }

  // Java SecretKeyFactory / PBEKeySpec (PBKDF2 family)
  if (receiver === 'SecretKeyFactory' || receiver.endsWith('.SecretKeyFactory')) {
    return method === 'getInstance' || method === 'generateSecret';
  }
  if (method === 'PBEKeySpec') return true;

  // Go crypto/* hash packages
  if (
    receiver === 'md5' || receiver === 'sha1' || receiver === 'sha256' ||
    receiver === 'sha512' || receiver === 'sha3' ||
    receiver.endsWith('/md5') || receiver.endsWith('/sha1') ||
    receiver.endsWith('/sha256') || receiver.endsWith('/sha512')
  ) {
    return method === 'New' || method === 'Sum' || method === 'New224' || method === 'New384';
  }

  // Generic: anything literally named like a hash
  const m = method.toLowerCase();
  if (
    m === 'hash' || m === 'hashpw' || m === 'hashsync' ||
    m === 'pbkdf2' || m === 'pbkdf2sync' ||
    m === 'scrypt' || m === 'scryptsync'
  ) return true;

  return false;
}

/** True if the argument identifier was the target of a hash call earlier in `priorCalls`. */
export function priorHashOf(varName: string, priorCalls: CallInfo[]): boolean {
  for (const c of priorCalls) {
    if (!isHashFunctionCall(c)) continue;
    for (const a of c.arguments) {
      if (a.variable === varName) return true;
      const head = (a.expression ?? '').trim().split(/[.\s(]/, 1)[0];
      if (head === varName) return true;
    }
  }
  return false;
}
