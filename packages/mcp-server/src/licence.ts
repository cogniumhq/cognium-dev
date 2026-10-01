/**
 * Offline licence-token verification.
 *
 * A token is a compact, signed, self-describing string:
 *
 *   cognium-lic-v1.<base64url(JCS payload)>.<base64url(Ed25519 signature)>
 *
 * The signature covers the **canonical** payload (RFC 8785, `./jcs.ts`), not
 * the bytes the payload happened to arrive in, so a token survives being
 * re-encoded on the way. The same token is the api.cognium.net key and the
 * hosted proxy credential, so the format is a cross-surface contract: the
 * prefix is versioned, and a change to the shape is a prefix bump.
 *
 * `kid` names the key that signed it, so keys can be rotated without
 * invalidating tokens signed by the previous one — a verifier simply keeps
 * both. It is inside the payload, and therefore signed.
 *
 * Verification is **offline and read-only**: an Ed25519 public key, no
 * network, no cache, no state written anywhere. Nothing here phones home,
 * and nothing here is secret — a verification key is published on purpose.
 * The private half never appears in this repository or in any published
 * package.
 *
 * Deliberately *not* here: entitlement enforcement, metering and revocation.
 * Those live at the issuer and the hosted endpoints, never in a binary the
 * user runs.
 */

import { verify as verifySignature, createPublicKey, type KeyObject } from 'node:crypto';
import { canonicalBytes } from './jcs.js';

/** Token prefix. A version bump here is a format break, not a key rotation. */
export const TOKEN_PREFIX = 'cognium-lic-v1';

/** What a verified token asserts. Unknown fields are preserved but ignored. */
export interface LicencePayload {
  /** Identifies the signing key, so keys can be rotated. */
  readonly kid: string;
  /** Organisation the token was issued to. */
  readonly org: string;
  /** Issuer-defined tier name. The server never branches on this. */
  readonly tier: string;
  /** Issued-at, ISO-8601. */
  readonly iat: string;
  /** Expiry, ISO-8601. A date with no time is good through that whole UTC day. */
  readonly expiry: string;
  /** Issuer-defined entitlement names. The server never branches on these. */
  readonly entitlements?: readonly string[];
}

export type LicenceStatus =
  /** Signature checks out and the token is in date. */
  | 'valid'
  /** Signature checks out; `expiry` has passed. */
  | 'expired'
  /**
   * The signature did not verify. A token signed by a different key and a
   * token whose payload was altered are **indistinguishable** offline — both
   * land here, by construction, and no amount of local checking separates
   * them.
   */
  | 'invalid-signature'
  /** Not a token of this format: wrong prefix, bad base64url, or bad JSON. */
  | 'malformed'
  /** No key is known for this token's `kid`, so no verdict is possible. */
  | 'no-key'
  /** No token was configured at all. */
  | 'absent';

export interface LicenceVerdict {
  readonly status: LicenceStatus;
  /** Present for `valid` and `expired` only — never trust it otherwise. */
  readonly payload?: LicencePayload;
  /** One line, safe to print. Never contains the token or any key material. */
  readonly detail: string;
}

/**
 * The published verification keys, by `kid`, as base64url-encoded raw 32-byte
 * Ed25519 public keys.
 *
 * Empty until the production key pair exists. Generating it is a credential
 * operation, done by hand on the owner's machine — a placeholder that looked
 * real would be worse than none, so every token verifies to `no-key` until a
 * key is added here. Rotation adds a `kid` and keeps the old one as long as
 * tokens signed by it are still in date.
 *
 * `COGNIUM_LICENSE_PUBKEY` adds to this map at runtime, which is how a key is
 * rotated ahead of a release and how the tests supply a throwaway key.
 */
export const BUILTIN_PUBLIC_KEYS: Readonly<Record<string, string>> = Object.freeze({});

/**
 * A `kid` of `*` in the key map matches any token.
 *
 * For development and tests only: it defeats the point of `kid`, so it is
 * never written into `BUILTIN_PUBLIC_KEYS`.
 */
export const ANY_KID = '*';

const RAW_ED25519_PUBLIC_KEY_BYTES = 32;
/** DER prefix for an Ed25519 SubjectPublicKeyInfo wrapping a raw 32-byte key. */
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Parse `COGNIUM_LICENSE_PUBKEY`.
 *
 * Either `kid=key,kid=key` for real rotation, or a bare key, which registers
 * under `*` and matches any token — the development form.
 */
export function parsePublicKeyEnv(raw: string | undefined): Record<string, string> {
  if (!raw || raw.trim() === '') return {};
  const out: Record<string, string> = {};
  for (const part of raw.split(',')) {
    const entry = part.trim();
    if (entry === '') continue;
    const eq = entry.indexOf('=');
    if (eq === -1) out[ANY_KID] = entry;
    else out[entry.slice(0, eq).trim()] = entry.slice(eq + 1).trim();
  }
  return out;
}

function decodeBase64Url(segment: string): Buffer | null {
  // Reject anything outside the base64url alphabet up front: Buffer's decoder
  // is lenient and would silently accept padding and '+/' characters, which
  // would make two different strings decode to the same token.
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  const buf = Buffer.from(segment, 'base64url');
  if (buf.length === 0) return null;
  return buf;
}

/** Wrap a raw Ed25519 public key so `node:crypto` will accept it. */
function publicKeyFrom(encoded: string): KeyObject | null {
  const raw = decodeBase64Url(encoded);
  if (!raw || raw.length !== RAW_ED25519_PUBLIC_KEY_BYTES) return null;
  try {
    return createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return null;
  }
}

function isIsoDate(value: string): boolean {
  return !Number.isNaN(new Date(value).getTime());
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The first instant at which a token is no longer in date.
 *
 * A date-only `expiry` names a day, and the token is good for the whole of
 * it: `Date` reads `2026-10-15` as that day's UTC midnight, which would end
 * the licence a day before the date it prints. A full timestamp is the
 * instant it says.
 */
function expiryInstant(expiry: string): number {
  const at = new Date(expiry).getTime();
  return DATE_ONLY.test(expiry) ? at + DAY_MS : at;
}

/**
 * Read the payload segment.
 *
 * Returns the object **as parsed**, unknown members included: the signature
 * covers everything the issuer signed, so a field this version does not know
 * has to still be there when the canonical form is rebuilt. A known field of
 * the wrong shape is malformed rather than quietly dropped.
 */
function parsePayload(segment: string): LicencePayload | null {
  const raw = decodeBase64Url(segment);
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;

  const { kid, org, tier, iat, expiry, entitlements } = parsed as Record<string, unknown>;
  if (
    typeof kid !== 'string' || kid === '' ||
    typeof org !== 'string' ||
    typeof tier !== 'string' ||
    typeof iat !== 'string' ||
    typeof expiry !== 'string'
  ) {
    return null;
  }
  if (!isIsoDate(iat) || !isIsoDate(expiry)) return null;
  if (
    entitlements !== undefined &&
    !(Array.isArray(entitlements) && entitlements.every((e) => typeof e === 'string'))
  ) {
    return null;
  }

  return parsed as LicencePayload;
}

export interface VerifyOptions {
  /**
   * Verification keys by `kid`, base64url raw Ed25519. Merged over the
   * built-in map, so a caller can add a key without replacing the published
   * ones. Pass `{}` explicitly to verify against nothing.
   */
  readonly publicKeys?: Readonly<Record<string, string>>;
  /** Clock injection point for the expiry test. */
  readonly now?: Date;
}

/**
 * Verify a token. Never throws, never reaches the network, and returns one
 * line of detail that is always safe to print.
 */
export function verifyLicence(token: string | undefined, opts: VerifyOptions = {}): LicenceVerdict {
  if (!token || token.trim() === '') {
    return { status: 'absent', detail: 'no licence token configured' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) {
    return { status: 'malformed', detail: `not a ${TOKEN_PREFIX} token` };
  }
  const [, payloadSegment, signatureSegment] = parts;

  const payload = parsePayload(payloadSegment);
  if (!payload) {
    return { status: 'malformed', detail: 'licence payload is not readable' };
  }
  const signature = decodeBase64Url(signatureSegment);
  if (!signature) {
    return { status: 'malformed', detail: 'licence signature is not readable' };
  }

  const keys = { ...BUILTIN_PUBLIC_KEYS, ...(opts.publicKeys ?? {}) };
  const encodedKey = keys[payload.kid] ?? keys[ANY_KID];
  if (!encodedKey) {
    return {
      status: 'no-key',
      detail: `no verification key for licence key id "${payload.kid}"`,
    };
  }
  const key = publicKeyFrom(encodedKey);
  if (!key) {
    return {
      status: 'no-key',
      detail: `the verification key for key id "${payload.kid}" is unusable`,
    };
  }

  let signatureOk = false;
  try {
    // Over the canonical form of everything that arrived, not the segment's
    // own bytes and not just the fields this version reads.
    signatureOk = verifySignature(null, canonicalBytes(payload), key, signature);
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    return {
      status: 'invalid-signature',
      detail: 'licence signature did not verify (wrong key, or the token was altered)',
    };
  }

  const now = opts.now ?? new Date();
  if (expiryInstant(payload.expiry) <= now.getTime()) {
    return {
      status: 'expired',
      payload,
      detail: `licence for ${payload.org} expired on ${payload.expiry}`,
    };
  }

  return {
    status: 'valid',
    payload,
    detail: `licence for ${payload.org} (${payload.tier}) valid to ${payload.expiry}`,
  };
}

/**
 * Mint a token. Exported for the issuer and the tests; the server itself
 * never calls it, and the private key it needs lives only where tokens are
 * issued.
 */
export function encodeLicence(payload: LicencePayload, sign: (bytes: Buffer) => Buffer): string {
  const canonical = canonicalBytes(payload);
  const segment = canonical.toString('base64url');
  return `${TOKEN_PREFIX}.${segment}.${sign(canonical).toString('base64url')}`;
}
