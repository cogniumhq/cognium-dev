/**
 * Minting helpers for the licence tests.
 *
 * Keys are generated per call and thrown away. No key material is committed,
 * and the production key pair does not exist yet by design.
 */

import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { encodeLicence, type LicencePayload } from '../../src/licence.js';

/** The DER SubjectPublicKeyInfo prefix in front of a raw Ed25519 key. */
const SPKI_PREFIX_BYTES = 12;

export interface TestKey {
  readonly kid: string;
  /** base64url raw 32-byte public key, the form the key map takes. */
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

export function testKey(kid = 'test-1'): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return { kid, publicKey: der.subarray(SPKI_PREFIX_BYTES).toString('base64url'), privateKey };
}

export function payloadFor(key: TestKey, over: Partial<LicencePayload> = {}): LicencePayload {
  return {
    kid: key.kid,
    org: 'Example Ltd',
    tier: 'team',
    iat: '2026-10-01T00:00:00.000Z',
    expiry: '2027-01-01',
    entitlements: ['commercial-use'],
    ...over,
  };
}

/** A token signed by `key`. */
export function mint(key: TestKey, over: Partial<LicencePayload> = {}): string {
  return encodeLicence(payloadFor(key, over), (bytes) => sign(null, bytes, key.privateKey));
}

/** The key map a verifier would hold for these keys. */
export function keyMap(...keys: TestKey[]): Record<string, string> {
  return Object.fromEntries(keys.map((k) => [k.kid, k.publicKey]));
}
