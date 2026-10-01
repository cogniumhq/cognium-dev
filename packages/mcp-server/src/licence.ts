/**
 * Offline licence-token verification.
 *
 * A token is a compact, signed, self-describing string:
 *
 *   cognium-lic-v1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
 *
 * The signature covers the exact bytes of the payload segment as it appears
 * in the token, so verification never depends on re-serializing JSON.
 *
 * Verification is **offline and read-only**: an Ed25519 public key, no
 * network, no cache, no state written anywhere. Nothing here phones home,
 * and nothing here is secret — the private half of the key pair never
 * appears in this repository or in any published package.
 *
 * Deliberately *not* here: entitlement enforcement, metering and revocation.
 * Those live at the token issuer and the hosted endpoints, never in a binary
 * the user runs.
 */

import { verify as verifySignature, createPublicKey, type KeyObject } from 'node:crypto';

/** Token prefix. A version bump here is a format break, not a key rotation. */
export const TOKEN_PREFIX = 'cognium-lic-v1';

/** What a verified token asserts. Unknown fields are preserved but ignored. */
export interface LicencePayload {
  /** Organisation the token was issued to. */
  readonly org: string;
  /** Issuer-defined tier name. The server never branches on this. */
  readonly tier: string;
  /** Expiry as an ISO-8601 date or date-time. */
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
  /** No verification key is configured, so no verdict is possible. */
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
 * The verification key, as a base64url-encoded raw 32-byte Ed25519 public
 * key. `null` until the production key pair exists: generating and publishing
 * it is a credential operation, so it is the owner's to do, and shipping a
 * placeholder that looked real would be worse than shipping none.
 *
 * `COGNIUM_LICENSE_PUBKEY` overrides it — which is also how the tests supply
 * a throwaway key.
 */
export const BUILTIN_PUBLIC_KEY: string | null = null;

const RAW_ED25519_PUBLIC_KEY_BYTES = 32;
/** DER prefix for an Ed25519 SubjectPublicKeyInfo wrapping a raw 32-byte key. */
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function decodeBase64Url(segment: string): Buffer | null {
  // Reject anything outside the base64url alphabet up front: Buffer's decoder
  // is lenient and would silently accept padding and '+/' characters, which
  // would make two different strings verify as the same token.
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

function parsePayload(segment: string): LicencePayload | null {
  const raw = decodeBase64Url(segment);
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const { org, tier, expiry } = parsed as Record<string, unknown>;
  if (typeof org !== 'string' || typeof tier !== 'string' || typeof expiry !== 'string') {
    return null;
  }
  const entitlements = (parsed as Record<string, unknown>).entitlements;
  return {
    org,
    tier,
    expiry,
    ...(Array.isArray(entitlements) && entitlements.every((e) => typeof e === 'string')
      ? { entitlements: entitlements as string[] }
      : {}),
  };
}

export interface VerifyOptions {
  /** base64url raw Ed25519 public key. Defaults to the built-in key. */
  readonly publicKey?: string | null;
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

  const encodedKey = opts.publicKey === undefined ? BUILTIN_PUBLIC_KEY : opts.publicKey;
  if (!encodedKey) {
    return { status: 'no-key', detail: 'no licence verification key is configured' };
  }
  const key = publicKeyFrom(encodedKey);
  if (!key) {
    return { status: 'no-key', detail: 'the configured licence verification key is unusable' };
  }

  let signatureOk = false;
  try {
    signatureOk = verifySignature(null, Buffer.from(payloadSegment, 'utf8'), key, signature);
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    return {
      status: 'invalid-signature',
      detail: 'licence signature did not verify (wrong key, or the token was altered)',
    };
  }

  const expiry = new Date(payload.expiry);
  if (Number.isNaN(expiry.getTime())) {
    return { status: 'malformed', detail: 'licence expiry is not a date' };
  }
  const now = opts.now ?? new Date();
  if (expiry.getTime() <= now.getTime()) {
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
