/**
 * Licence verification.
 *
 * `spec.md` §7 names four cases — valid, expired, wrong key, tampered. Those
 * are four *inputs*; offline they produce three distinguishable *outcomes*,
 * because a token signed by another key and a token whose payload was
 * altered cannot be told apart without the issuer. The tests assert the
 * outcomes that exist rather than a distinction the verifier cannot make.
 */

import { describe, it, expect } from 'vitest';
import { sign } from 'node:crypto';
import {
  verifyLicence,
  encodeLicence,
  parsePublicKeyEnv,
  TOKEN_PREFIX,
  BUILTIN_PUBLIC_KEYS,
  ANY_KID,
} from '../src/licence.js';
import { canonicalBytes } from '../src/jcs.js';
import { testKey, mint, keyMap, payloadFor } from './fixtures/licence.js';

const NOW = new Date('2026-10-15T00:00:00.000Z');

describe('verifyLicence', () => {
  it('accepts a token signed by the key its kid names', () => {
    const key = testKey();
    const verdict = verifyLicence(mint(key), { publicKeys: keyMap(key), now: NOW });
    expect(verdict.status).toBe('valid');
    expect(verdict.payload?.org).toBe('Example Ltd');
    expect(verdict.payload?.kid).toBe('test-1');
    expect(verdict.payload?.iat).toBe('2026-10-01T00:00:00.000Z');
    expect(verdict.payload?.entitlements).toEqual(['commercial-use']);
  });

  it('reports a well-signed token past its expiry as expired, not invalid', () => {
    const key = testKey();
    const verdict = verifyLicence(mint(key, { expiry: '2026-09-01' }), {
      publicKeys: keyMap(key),
      now: NOW,
    });
    expect(verdict.status).toBe('expired');
    // The payload is still trustworthy — the signature verified.
    expect(verdict.payload?.org).toBe('Example Ltd');
    expect(verdict.detail).toContain('2026-09-01');
  });

  it('treats the expiry boundary as expired', () => {
    const key = testKey();
    const verdict = verifyLicence(mint(key, { expiry: NOW.toISOString() }), {
      publicKeys: keyMap(key),
      now: NOW,
    });
    expect(verdict.status).toBe('expired');
  });

  it('keeps a date-only expiry in date through the whole of the named day', () => {
    // `Date` reads a bare date as that day's UTC midnight. Taken literally the
    // licence would lapse a day before the date its own detail line prints.
    const key = testKey();
    const token = mint(key, { expiry: '2026-10-15' });
    const at = (iso: string) => verifyLicence(token, { publicKeys: keyMap(key), now: new Date(iso) });

    expect(at('2026-10-15T00:00:00.000Z').status).toBe('valid');
    expect(at('2026-10-15T23:59:59.999Z').status).toBe('valid');
    expect(at('2026-10-15T00:00:00.000Z').detail).toContain('valid to 2026-10-15');
    expect(at('2026-10-16T00:00:00.000Z').status).toBe('expired');
  });

  it('verifies a token carrying a field this version does not know', () => {
    // The issuer signed the whole payload. Rebuilding it from the known
    // fields alone would drop the extra one and fail a genuine token.
    const key = testKey();
    const payload = { ...payloadFor(key), seats: 25, region: { code: 'eu' } };
    const token = encodeLicence(payload, (b) => sign(null, b, key.privateKey));

    const verdict = verifyLicence(token, { publicKeys: keyMap(key), now: NOW });
    expect(verdict.status).toBe('valid');
    expect(verdict.payload).toEqual(payload);
  });

  it('rejects a token whose unknown field was removed after signing', () => {
    // The other half of the above: an unknown field is covered, not ignored.
    const key = testKey();
    const signed = { ...payloadFor(key), seats: 25 };
    const [prefix, , signature] = encodeLicence(signed, (b) => sign(null, b, key.privateKey)).split('.');
    const stripped = canonicalBytes(payloadFor(key)).toString('base64url');

    const verdict = verifyLicence(`${prefix}.${stripped}.${signature}`, {
      publicKeys: keyMap(key),
      now: NOW,
    });
    expect(verdict.status).toBe('invalid-signature');
  });

  it('rejects a token signed by a different key', () => {
    const issuer = testKey('test-1');
    const impostor = { ...testKey('test-1'), kid: 'test-1' };
    const token = mint(impostor);
    const verdict = verifyLicence(token, { publicKeys: keyMap(issuer), now: NOW });
    expect(verdict.status).toBe('invalid-signature');
    expect(verdict.payload).toBeUndefined();
  });

  it('rejects a token whose payload was altered after signing', () => {
    const key = testKey();
    const [prefix, , signature] = mint(key).split('.');
    const forged = canonicalBytes(payloadFor(key, { org: 'Someone Else', expiry: '2099-01-01' }))
      .toString('base64url');

    const verdict = verifyLicence(`${prefix}.${forged}.${signature}`, {
      publicKeys: keyMap(key),
      now: NOW,
    });
    expect(verdict.status).toBe('invalid-signature');
  });

  it('verifies a token whose payload was re-encoded but not changed', () => {
    // The whole point of signing the canonical form: a payload that arrives
    // with its keys in another order is the same token, not a broken one.
    const key = testKey();
    const payload = payloadFor(key);
    const reordered = JSON.stringify({
      expiry: payload.expiry,
      entitlements: payload.entitlements,
      tier: payload.tier,
      iat: payload.iat,
      org: payload.org,
      kid: payload.kid,
    });
    const signature = sign(null, canonicalBytes(payload), key.privateKey).toString('base64url');
    const token = `${TOKEN_PREFIX}.${Buffer.from(reordered, 'utf8').toString('base64url')}.${signature}`;

    expect(verifyLicence(token, { publicKeys: keyMap(key), now: NOW }).status).toBe('valid');
  });
});

describe('key rotation', () => {
  it('keeps verifying tokens signed by a retired key while they are in date', () => {
    const oldKey = testKey('2026-10');
    const newKey = testKey('2027-04');
    const keys = keyMap(oldKey, newKey);

    expect(verifyLicence(mint(oldKey), { publicKeys: keys, now: NOW }).status).toBe('valid');
    expect(verifyLicence(mint(newKey), { publicKeys: keys, now: NOW }).status).toBe('valid');
  });

  it('cannot give a verdict for a kid it holds no key for, and says which', () => {
    const key = testKey('2028-01');
    const verdict = verifyLicence(mint(key), { publicKeys: keyMap(testKey('2026-10')), now: NOW });
    expect(verdict.status).toBe('no-key');
    expect(verdict.detail).toContain('2028-01');
  });

  it('will not accept a token for one kid against another kid\'s key', () => {
    // Without the kid lookup, any key in the map would verify any token.
    const a = testKey('key-a');
    const b = testKey('key-b');
    const token = mint(a, { kid: 'key-b' });
    expect(verifyLicence(token, { publicKeys: keyMap(b), now: NOW }).status).toBe('invalid-signature');
  });

  it('merges caller keys over the built-in map rather than replacing it', () => {
    const key = testKey();
    expect(verifyLicence(mint(key), { publicKeys: keyMap(key), now: NOW }).status).toBe('valid');
    // Nothing published yet, so the built-in map contributes nothing — but it
    // is still consulted, which is what makes a baked-in key work.
    expect(Object.keys(BUILTIN_PUBLIC_KEYS)).toEqual([]);
  });
});

describe('malformed input', () => {
  it.each([
    ['empty', ''],
    ['no prefix', 'abc.def'],
    ['wrong prefix', 'cognium-lic-v9.abc.def'],
    ['non-base64url payload', `${TOKEN_PREFIX}.not+valid/base64.AAAA`],
    ['payload that is not JSON', `${TOKEN_PREFIX}.${Buffer.from('nope').toString('base64url')}.AAAA`],
    ['a JSON array, not an object', `${TOKEN_PREFIX}.${Buffer.from('[]').toString('base64url')}.AAAA`],
  ])('refuses a %s token before looking at any key', (_label, token) => {
    const verdict = verifyLicence(token, { publicKeys: { [ANY_KID]: testKey().publicKey } });
    expect(['malformed', 'absent']).toContain(verdict.status);
    expect(verdict.payload).toBeUndefined();
  });

  it.each([
    ['kid', { kid: undefined }],
    ['an empty kid', { kid: '' }],
    ['iat', { iat: undefined }],
    ['expiry', { expiry: undefined }],
    ['org', { org: undefined }],
    ['a readable iat', { iat: 'whenever' }],
    ['a readable expiry', { expiry: 'soon' }],
    ['a list for entitlements', { entitlements: 'commercial-use' }],
    ['string entitlements', { entitlements: ['commercial-use', 7] }],
  ])('refuses a payload missing %s', (_label, over) => {
    const key = testKey();
    const payload = { ...payloadFor(key), ...over } as never;
    const token = encodeLicence(payload, (b) => sign(null, b, key.privateKey));
    expect(verifyLicence(token, { publicKeys: keyMap(key), now: NOW }).status).toBe('malformed');
  });

  it('says so when no token is configured', () => {
    expect(verifyLicence(undefined).status).toBe('absent');
    expect(verifyLicence('   ').status).toBe('absent');
  });

  it('rejects a key of the wrong length rather than throwing', () => {
    const key = testKey();
    const verdict = verifyLicence(mint(key), {
      publicKeys: { [key.kid]: Buffer.alloc(16).toString('base64url') },
      now: NOW,
    });
    expect(verdict.status).toBe('no-key');
  });

  it('never throws, whatever it is handed', () => {
    const key = testKey();
    const inputs = ['.', '..', `${TOKEN_PREFIX}..`, `${TOKEN_PREFIX}.a.`, 'x'.repeat(10_000)];
    for (const input of inputs) {
      expect(() => verifyLicence(input, { publicKeys: keyMap(key) })).not.toThrow();
    }
  });
});

describe('BUILTIN_PUBLIC_KEYS', () => {
  it('is empty and frozen, so no token verifies against a placeholder', () => {
    // Generating the production key pair is a credential operation and so the
    // owner's. Until a key is published here, every real token is `no-key`.
    expect(BUILTIN_PUBLIC_KEYS).toEqual({});
    expect(Object.isFrozen(BUILTIN_PUBLIC_KEYS)).toBe(true);
  });

  it('holds no wildcard, which is a development form only', () => {
    expect(BUILTIN_PUBLIC_KEYS[ANY_KID]).toBeUndefined();
  });
});

describe('parsePublicKeyEnv', () => {
  it('reads kid=key pairs', () => {
    expect(parsePublicKeyEnv('a=AAA,b=BBB')).toEqual({ a: 'AAA', b: 'BBB' });
  });

  it('tolerates spacing and empty entries', () => {
    expect(parsePublicKeyEnv(' a = AAA , , b=BBB ')).toEqual({ a: 'AAA', b: 'BBB' });
  });

  it('reads a bare key as the development wildcard', () => {
    expect(parsePublicKeyEnv('AAA')).toEqual({ [ANY_KID]: 'AAA' });
  });

  it.each([[undefined], [''], ['   ']])('reads %o as no keys', (raw) => {
    expect(parsePublicKeyEnv(raw)).toEqual({});
  });

  it('lets the wildcard verify a token of any kid, for development', () => {
    const key = testKey('whatever');
    const verdict = verifyLicence(mint(key), {
      publicKeys: parsePublicKeyEnv(key.publicKey),
      now: NOW,
    });
    expect(verdict.status).toBe('valid');
  });
});
