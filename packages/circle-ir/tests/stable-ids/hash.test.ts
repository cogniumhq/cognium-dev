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
      // Block boundaries and every tree shape up to eight chunks, plus the longer published inputs.
      [63, 'e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b'],
      [64, '4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98'],
      [65, 'de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee'],
      [2049, '5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030'],
      [3072, 'b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2'],
      [3073, '7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3'],
      [4096, '015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969'],
      [5120, '9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833'],
      [6144, '3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205'],
      [7168, '61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a'],
      [8192, 'aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63'],
      [8193, 'bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b'],
      [31744, '62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47'],
      [102400, 'bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085'],
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
