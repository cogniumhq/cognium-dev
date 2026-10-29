import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { sha256Bytes, sha256Digest } from '../../src/remedy-class/sha256.js';

const hex = (b: Uint8Array): string => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

describe('sha256', () => {
  it('matches the FIPS 180-4 examples', () => {
    const enc = new TextEncoder();
    expect(hex(sha256Bytes(enc.encode('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(hex(sha256Bytes(enc.encode('')))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(hex(sha256Bytes(enc.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))))
      .toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  it('agrees with node:crypto across padding boundaries', () => {
    for (const len of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 1000, 4097]) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 31 + 7) % 256;
      expect(hex(sha256Bytes(bytes))).toBe(createHash('sha256').update(bytes).digest('hex'));
    }
  });

  it('prints sha256:<hex> and hashes a string as its UTF-8 bytes', () => {
    const text = 'naïve — ü\n';
    const expected = `sha256:${createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex')}`;
    expect(sha256Digest(text)).toBe(expected);
    expect(sha256Digest(new TextEncoder().encode(text))).toBe(expected);
  });
});
