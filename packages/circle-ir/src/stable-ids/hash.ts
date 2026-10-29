/**
 * BLAKE3 (unkeyed hash mode, 32-byte output) and the 128-bit base32 digest the
 * stable-id scheme prints.
 *
 * A dependency-free implementation so the library keeps its two dependencies
 * and runs unchanged in Node.js, browsers and Workers. It is the plain
 * reference algorithm (no SIMD, no incremental API): ids hash short strings —
 * a qualified name, a signature, one function body — so throughput is not the
 * constraint, and determinism across hosts is. Checked against the published
 * BLAKE3 test vectors in `tests/stable-ids/hash.test.ts`.
 */

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;

const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function g(s: Uint32Array, a: number, b: number, c: number, d: number, mx: number, my: number): void {
  s[a] = (s[a] + s[b] + mx) >>> 0;
  s[d] = rotr(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotr(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + my) >>> 0;
  s[d] = rotr(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotr(s[b] ^ s[c], 7);
}

function round(s: Uint32Array, m: Uint32Array): void {
  g(s, 0, 4, 8, 12, m[0], m[1]);
  g(s, 1, 5, 9, 13, m[2], m[3]);
  g(s, 2, 6, 10, 14, m[4], m[5]);
  g(s, 3, 7, 11, 15, m[6], m[7]);
  g(s, 0, 5, 10, 15, m[8], m[9]);
  g(s, 1, 6, 11, 12, m[10], m[11]);
  g(s, 2, 7, 8, 13, m[12], m[13]);
  g(s, 3, 4, 9, 14, m[14], m[15]);
}

/** The compression function; returns the first 8 output words. */
function compress(
  cv: Uint32Array,
  block: Uint32Array,
  counter: number,
  blockLen: number,
  flags: number,
): Uint32Array {
  const s = new Uint32Array(16);
  s.set(cv, 0);
  s.set(IV.subarray(0, 4), 8);
  s[12] = counter >>> 0;
  // Counters here never exceed 2^53 (a JS number); the high word is exact.
  s[13] = Math.floor(counter / 0x100000000) >>> 0;
  s[14] = blockLen;
  s[15] = flags;
  let m = Uint32Array.from(block);
  for (let r = 0; r < 7; r++) {
    round(s, m);
    if (r < 6) {
      const p = new Uint32Array(16);
      for (let i = 0; i < 16; i++) p[i] = m[MSG_PERMUTATION[i]];
      m = p;
    }
  }
  const out = new Uint32Array(8);
  for (let i = 0; i < 8; i++) out[i] = (s[i] ^ s[i + 8]) >>> 0;
  return out;
}

function blockWords(bytes: Uint8Array, offset: number, len: number): Uint32Array {
  const w = new Uint32Array(16);
  for (let i = 0; i < len; i++) {
    w[i >> 2] |= bytes[offset + i] << ((i & 3) * 8);
  }
  return w;
}

/** The pending compression of a chunk's last block or of a parent node. */
interface Output {
  cv: Uint32Array;
  block: Uint32Array;
  counter: number;
  blockLen: number;
  flags: number;
}

function chainingValue(o: Output): Uint32Array {
  return compress(o.cv, o.block, o.counter, o.blockLen, o.flags);
}

function chunkOutput(input: Uint8Array, start: number, end: number, chunkCounter: number): Output {
  let cv: Uint32Array = IV;
  let offset = start;
  let blocksDone = 0;
  // Every block but the last is compressed straight into the chaining value.
  while (end - offset > BLOCK_LEN) {
    const flags = blocksDone === 0 ? CHUNK_START : 0;
    cv = compress(cv, blockWords(input, offset, BLOCK_LEN), chunkCounter, BLOCK_LEN, flags);
    offset += BLOCK_LEN;
    blocksDone++;
  }
  const len = end - offset;
  return {
    cv,
    block: blockWords(input, offset, len),
    counter: chunkCounter,
    blockLen: len,
    flags: (blocksDone === 0 ? CHUNK_START : 0) | CHUNK_END,
  };
}

function parentOutput(left: Uint32Array, right: Uint32Array): Output {
  const block = new Uint32Array(16);
  block.set(left, 0);
  block.set(right, 8);
  return { cv: IV, block, counter: 0, blockLen: BLOCK_LEN, flags: PARENT };
}

/** BLAKE3 of `input`, the default 32-byte output. */
export function blake3(input: Uint8Array): Uint8Array {
  const chunkCount = Math.max(1, Math.ceil(input.length / CHUNK_LEN));
  const stack: Uint32Array[] = [];
  for (let i = 0; i < chunkCount - 1; i++) {
    let cv = chainingValue(chunkOutput(input, i * CHUNK_LEN, (i + 1) * CHUNK_LEN, i));
    // Merge completed subtrees: one merge per trailing zero bit of the count.
    let total = i + 1;
    while ((total & 1) === 0) {
      cv = chainingValue(parentOutput(stack.pop() as Uint32Array, cv));
      total >>= 1;
    }
    stack.push(cv);
  }
  const last = chunkCount - 1;
  let output = chunkOutput(input, last * CHUNK_LEN, input.length, last);
  while (stack.length > 0) {
    output = parentOutput(stack.pop() as Uint32Array, chainingValue(output));
  }
  const words = compress(output.cv, output.block, 0, output.blockLen, output.flags | ROOT);
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    bytes[i * 4] = words[i] & 0xff;
    bytes[i * 4 + 1] = (words[i] >>> 8) & 0xff;
    bytes[i * 4 + 2] = (words[i] >>> 16) & 0xff;
    bytes[i * 4 + 3] = (words[i] >>> 24) & 0xff;
  }
  return bytes;
}

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

/** RFC 4648 base32, lowercase, unpadded. */
export function base32(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 31];
  return out;
}

const encoder = new TextEncoder();

/**
 * The digest every stable id is built from: BLAKE3 of the parts (UTF-8, each
 * part followed by a NUL so `["ab","c"]` and `["a","bc"]` differ), truncated
 * to 128 bits, printed as 26 base32 characters.
 */
export function digest128(parts: readonly string[]): string {
  let s = '';
  for (const p of parts) s += p + '\u0000';
  return base32(blake3(encoder.encode(s)).subarray(0, 16));
}
