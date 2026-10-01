/**
 * Licence verification — the four cases `spec.md` §7 names (valid, expired,
 * wrong key, tampered), plus the ones a user hits by accident.
 *
 * Keys are generated here and thrown away. No key material is committed, and
 * the production key does not exist yet by design.
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { verifyLicence, TOKEN_PREFIX, BUILTIN_PUBLIC_KEY } from '../src/licence.js';

/** The DER SubjectPublicKeyInfo prefix in front of a raw Ed25519 key. */
const SPKI_PREFIX_BYTES = 12;

function keypair(): { publicKey: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: der.subarray(SPKI_PREFIX_BYTES).toString('base64url'),
    privateKey,
  };
}

function mint(payload: unknown, privateKey: KeyObject): string {
  const segment = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = sign(null, Buffer.from(segment, 'utf8'), privateKey).toString('base64url');
  return `${TOKEN_PREFIX}.${segment}.${signature}`;
}

const PAYLOAD = {
  org: 'Example Ltd',
  tier: 'team',
  expiry: '2027-01-01',
  entitlements: ['commercial-use'],
};

describe('verifyLicence', () => {
  it('accepts a token signed by the configured key', () => {
    const { publicKey, privateKey } = keypair();
    const verdict = verifyLicence(mint(PAYLOAD, privateKey), {
      publicKey,
      now: new Date('2026-10-01'),
    });
    expect(verdict.status).toBe('valid');
    expect(verdict.payload?.org).toBe('Example Ltd');
    expect(verdict.payload?.tier).toBe('team');
  });

  it('reports a well-signed token past its expiry as expired, not invalid', () => {
    const { publicKey, privateKey } = keypair();
    const verdict = verifyLicence(mint({ ...PAYLOAD, expiry: '2026-09-01' }, privateKey), {
      publicKey,
      now: new Date('2026-10-01'),
    });
    expect(verdict.status).toBe('expired');
    // The payload is still trustworthy — the signature verified.
    expect(verdict.payload?.org).toBe('Example Ltd');
    expect(verdict.detail).toContain('2026-09-01');
  });

  it('treats the expiry boundary as expired', () => {
    const { publicKey, privateKey } = keypair();
    const verdict = verifyLicence(mint({ ...PAYLOAD, expiry: '2026-10-01T00:00:00.000Z' }, privateKey), {
      publicKey,
      now: new Date('2026-10-01T00:00:00.000Z'),
    });
    expect(verdict.status).toBe('expired');
  });

  it('rejects a token signed by a different key', () => {
    const { privateKey } = keypair();
    const other = keypair();
    const verdict = verifyLicence(mint(PAYLOAD, privateKey), {
      publicKey: other.publicKey,
      now: new Date('2026-10-01'),
    });
    expect(verdict.status).toBe('invalid-signature');
    expect(verdict.payload).toBeUndefined();
  });

  it('rejects a token whose payload was altered after signing', () => {
    const { publicKey, privateKey } = keypair();
    const token = mint(PAYLOAD, privateKey);
    const [prefix, , signature] = token.split('.');
    const forged = Buffer.from(
      JSON.stringify({ ...PAYLOAD, org: 'Someone Else', expiry: '2099-01-01' }),
      'utf8',
    ).toString('base64url');

    const verdict = verifyLicence(`${prefix}.${forged}.${signature}`, {
      publicKey,
      now: new Date('2026-10-01'),
    });
    // Offline, a wrong key and an altered payload are the same observation.
    // The test asserts the honest outcome rather than a distinction the
    // verifier cannot make.
    expect(verdict.status).toBe('invalid-signature');
  });

  it.each([
    ['empty', ''],
    ['no prefix', 'abc.def'],
    ['wrong prefix', 'cognium-lic-v9.abc.def'],
    ['non-base64url payload', `${TOKEN_PREFIX}.not+valid/base64.AAAA`],
    ['payload that is not JSON', `${TOKEN_PREFIX}.${Buffer.from('nope').toString('base64url')}.AAAA`],
    [
      'payload missing required fields',
      `${TOKEN_PREFIX}.${Buffer.from(JSON.stringify({ org: 'x' })).toString('base64url')}.AAAA`,
    ],
  ])('refuses a %s token before looking at any key', (_label, token) => {
    const verdict = verifyLicence(token, { publicKey: keypair().publicKey });
    expect(['malformed', 'absent']).toContain(verdict.status);
    expect(verdict.payload).toBeUndefined();
  });

  it('says so when no token is configured', () => {
    expect(verifyLicence(undefined).status).toBe('absent');
    expect(verifyLicence('   ').status).toBe('absent');
  });

  it('cannot give a verdict with no verification key, and says that instead of guessing', () => {
    const { privateKey } = keypair();
    const verdict = verifyLicence(mint(PAYLOAD, privateKey), { publicKey: null });
    expect(verdict.status).toBe('no-key');
  });

  it('rejects a key of the wrong length rather than throwing', () => {
    const { privateKey } = keypair();
    const verdict = verifyLicence(mint(PAYLOAD, privateKey), {
      publicKey: Buffer.alloc(16).toString('base64url'),
    });
    expect(verdict.status).toBe('no-key');
  });

  it('ships no built-in key yet, so a real token cannot be forged against a placeholder', () => {
    // Generating and publishing the production key pair is a credential
    // operation and therefore the owner's. Until it exists, the honest
    // verdict for any token is `no-key`.
    expect(BUILTIN_PUBLIC_KEY).toBeNull();
  });

  it('never throws, whatever it is handed', () => {
    const inputs = ['.', '..', `${TOKEN_PREFIX}..`, `${TOKEN_PREFIX}.a.`, 'x'.repeat(10_000)];
    for (const input of inputs) {
      expect(() => verifyLicence(input, { publicKey: keypair().publicKey })).not.toThrow();
    }
  });
});
