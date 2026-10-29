import { describe, it, expect } from 'vitest';
import { blake3, base32, digest128 } from '../../src/stable-ids/hash.js';

const hex = (b: Uint8Array): string => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

/** The published BLAKE3 test-vector input: byte i is i mod 251. */
function vectorInput(len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = i % 251;
  return out;
}

describe('blake3', () => {
  it('matches the published vectors', () => {
    const cases: [number, string][] = [
      [0, 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'],
      [1, '2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213'],
      [1024, '42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7'],
      [1025, 'd00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444'],
      [2048, 'e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a'],
    ];
    for (const [len, want] of cases) expect(hex(blake3(vectorInput(len))), `len ${len}`).toBe(want);
  });

  it('hashes "abc"', () => {
    expect(hex(blake3(new TextEncoder().encode('abc')))).toBe(
      '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
    );
  });
});

describe('base32', () => {
  it('follows RFC 4648 (lowercase, unpadded)', () => {
    const enc = (s: string) => base32(new TextEncoder().encode(s));
    expect(enc('')).toBe('');
    expect(enc('f')).toBe('my');
    expect(enc('fo')).toBe('mzxq');
    expect(enc('foo')).toBe('mzxw6');
    expect(enc('foobar')).toBe('mzxw6ytboi');
  });
});

describe('digest128', () => {
  it('is 26 base32 characters and separates parts', () => {
    const d = digest128(['ab', 'c']);
    expect(d).toMatch(/^[a-z2-7]{26}$/);
    expect(d).not.toBe(digest128(['a', 'bc']));
    expect(d).toBe(digest128(['ab', 'c']));
  });
});
