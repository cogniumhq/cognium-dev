/**
 * BLAKE3 (unkeyed hash mode, 32-byte output) and the 128-bit base32 digest the
 * stable-id scheme prints.
 *
 * A dependency-free implementation so the library keeps its two dependencies
 * and runs unchanged in Node.js, browsers and Workers. It is the plain
 * reference algorithm (no SIMD, no incremental API) with an allocation-free
 * compression function: ids hash short strings — a qualified name, a
 * signature, one function body — but the `facts@1` emitter also digests
 * every IPC file it writes (tens of MB), so the inner loop matters. Checked
 * against the published BLAKE3 test vectors in `tests/stable-ids/hash.test.ts`.
 */

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/** `SCHEDULE[r][i]`: which message word round `r` reads at position `i` (the permutation applied `r` times). */
const SCHEDULE: Uint8Array[] = [];
{
  let perm = Array.from({ length: 16 }, (_, i) => i);
  for (let r = 0; r < 7; r++) {
    SCHEDULE.push(Uint8Array.from(perm));
    perm = MSG_PERMUTATION.map(i => perm[i]);
  }
}

const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;

const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

// The message block of the compression in flight, shared by every call (the
// function is synchronous and not re-entrant): no allocation per block, which
// is what makes hashing a 50 MB IPC file cost tens of milliseconds, not
// seconds.
const M = new Uint32Array(16);

/**
 * The compression function on `cv` (8 words at `cvOffset`) and the block in
 * `M`; writes the first 8 output words to `out[outOffset..]`, or all 16 (root
 * output) when `full` is set. The state lives in locals and the eight G
 * steps of a round are written out: the quarter-round mixing is the whole
 * cost of the hash, and a G helper over a state array spends it on loads.
 */
function compress(cv: Uint32Array, cvOffset: number, counter: number, blockLen: number, flags: number, out: Uint32Array, outOffset: number, full = false): void {
  let v0 = cv[cvOffset];
  let v1 = cv[cvOffset + 1];
  let v2 = cv[cvOffset + 2];
  let v3 = cv[cvOffset + 3];
  let v4 = cv[cvOffset + 4];
  let v5 = cv[cvOffset + 5];
  let v6 = cv[cvOffset + 6];
  let v7 = cv[cvOffset + 7];
  let v8 = IV[0];
  let v9 = IV[1];
  let v10 = IV[2];
  let v11 = IV[3];
  let v12 = counter >>> 0;
  // Counters here never exceed 2^53 (a JS number); the high word is exact.
  let v13 = Math.floor(counter / 0x100000000) >>> 0;
  let v14 = blockLen;
  let v15 = flags;
  for (let r = 0; r < 7; r++) {
    const p = SCHEDULE[r];
    v0 = (v0 + v4 + M[p[0]]) >>> 0;
    v12 ^= v0; v12 = ((v12 >>> 16) | (v12 << 16)) >>> 0;
    v8 = (v8 + v12) >>> 0;
    v4 ^= v8; v4 = ((v4 >>> 12) | (v4 << 20)) >>> 0;
    v0 = (v0 + v4 + M[p[1]]) >>> 0;
    v12 ^= v0; v12 = ((v12 >>> 8) | (v12 << 24)) >>> 0;
    v8 = (v8 + v12) >>> 0;
    v4 ^= v8; v4 = ((v4 >>> 7) | (v4 << 25)) >>> 0;
    v1 = (v1 + v5 + M[p[2]]) >>> 0;
    v13 ^= v1; v13 = ((v13 >>> 16) | (v13 << 16)) >>> 0;
    v9 = (v9 + v13) >>> 0;
    v5 ^= v9; v5 = ((v5 >>> 12) | (v5 << 20)) >>> 0;
    v1 = (v1 + v5 + M[p[3]]) >>> 0;
    v13 ^= v1; v13 = ((v13 >>> 8) | (v13 << 24)) >>> 0;
    v9 = (v9 + v13) >>> 0;
    v5 ^= v9; v5 = ((v5 >>> 7) | (v5 << 25)) >>> 0;
    v2 = (v2 + v6 + M[p[4]]) >>> 0;
    v14 ^= v2; v14 = ((v14 >>> 16) | (v14 << 16)) >>> 0;
    v10 = (v10 + v14) >>> 0;
    v6 ^= v10; v6 = ((v6 >>> 12) | (v6 << 20)) >>> 0;
    v2 = (v2 + v6 + M[p[5]]) >>> 0;
    v14 ^= v2; v14 = ((v14 >>> 8) | (v14 << 24)) >>> 0;
    v10 = (v10 + v14) >>> 0;
    v6 ^= v10; v6 = ((v6 >>> 7) | (v6 << 25)) >>> 0;
    v3 = (v3 + v7 + M[p[6]]) >>> 0;
    v15 ^= v3; v15 = ((v15 >>> 16) | (v15 << 16)) >>> 0;
    v11 = (v11 + v15) >>> 0;
    v7 ^= v11; v7 = ((v7 >>> 12) | (v7 << 20)) >>> 0;
    v3 = (v3 + v7 + M[p[7]]) >>> 0;
    v15 ^= v3; v15 = ((v15 >>> 8) | (v15 << 24)) >>> 0;
    v11 = (v11 + v15) >>> 0;
    v7 ^= v11; v7 = ((v7 >>> 7) | (v7 << 25)) >>> 0;
    v0 = (v0 + v5 + M[p[8]]) >>> 0;
    v15 ^= v0; v15 = ((v15 >>> 16) | (v15 << 16)) >>> 0;
    v10 = (v10 + v15) >>> 0;
    v5 ^= v10; v5 = ((v5 >>> 12) | (v5 << 20)) >>> 0;
    v0 = (v0 + v5 + M[p[9]]) >>> 0;
    v15 ^= v0; v15 = ((v15 >>> 8) | (v15 << 24)) >>> 0;
    v10 = (v10 + v15) >>> 0;
    v5 ^= v10; v5 = ((v5 >>> 7) | (v5 << 25)) >>> 0;
    v1 = (v1 + v6 + M[p[10]]) >>> 0;
    v12 ^= v1; v12 = ((v12 >>> 16) | (v12 << 16)) >>> 0;
    v11 = (v11 + v12) >>> 0;
    v6 ^= v11; v6 = ((v6 >>> 12) | (v6 << 20)) >>> 0;
    v1 = (v1 + v6 + M[p[11]]) >>> 0;
    v12 ^= v1; v12 = ((v12 >>> 8) | (v12 << 24)) >>> 0;
    v11 = (v11 + v12) >>> 0;
    v6 ^= v11; v6 = ((v6 >>> 7) | (v6 << 25)) >>> 0;
    v2 = (v2 + v7 + M[p[12]]) >>> 0;
    v13 ^= v2; v13 = ((v13 >>> 16) | (v13 << 16)) >>> 0;
    v8 = (v8 + v13) >>> 0;
    v7 ^= v8; v7 = ((v7 >>> 12) | (v7 << 20)) >>> 0;
    v2 = (v2 + v7 + M[p[13]]) >>> 0;
    v13 ^= v2; v13 = ((v13 >>> 8) | (v13 << 24)) >>> 0;
    v8 = (v8 + v13) >>> 0;
    v7 ^= v8; v7 = ((v7 >>> 7) | (v7 << 25)) >>> 0;
    v3 = (v3 + v4 + M[p[14]]) >>> 0;
    v14 ^= v3; v14 = ((v14 >>> 16) | (v14 << 16)) >>> 0;
    v9 = (v9 + v14) >>> 0;
    v4 ^= v9; v4 = ((v4 >>> 12) | (v4 << 20)) >>> 0;
    v3 = (v3 + v4 + M[p[15]]) >>> 0;
    v14 ^= v3; v14 = ((v14 >>> 8) | (v14 << 24)) >>> 0;
    v9 = (v9 + v14) >>> 0;
    v4 ^= v9; v4 = ((v4 >>> 7) | (v4 << 25)) >>> 0;
  }
  out[outOffset] = (v0 ^ v8) >>> 0;
  out[outOffset + 1] = (v1 ^ v9) >>> 0;
  out[outOffset + 2] = (v2 ^ v10) >>> 0;
  out[outOffset + 3] = (v3 ^ v11) >>> 0;
  out[outOffset + 4] = (v4 ^ v12) >>> 0;
  out[outOffset + 5] = (v5 ^ v13) >>> 0;
  out[outOffset + 6] = (v6 ^ v14) >>> 0;
  out[outOffset + 7] = (v7 ^ v15) >>> 0;
  if (full) {
    out[outOffset + 8] = (v8 ^ cv[cvOffset]) >>> 0;
    out[outOffset + 9] = (v9 ^ cv[cvOffset + 1]) >>> 0;
    out[outOffset + 10] = (v10 ^ cv[cvOffset + 2]) >>> 0;
    out[outOffset + 11] = (v11 ^ cv[cvOffset + 3]) >>> 0;
    out[outOffset + 12] = (v12 ^ cv[cvOffset + 4]) >>> 0;
    out[outOffset + 13] = (v13 ^ cv[cvOffset + 5]) >>> 0;
    out[outOffset + 14] = (v14 ^ cv[cvOffset + 6]) >>> 0;
    out[outOffset + 15] = (v15 ^ cv[cvOffset + 7]) >>> 0;
  }
}

/** Load `len` bytes at `offset` into `M` as little-endian words, zero-padded. */
function loadBlock(bytes: Uint8Array, offset: number, len: number): void {
  if (len === BLOCK_LEN) {
    for (let i = 0, o = offset; i < 16; i++, o += 4) {
      M[i] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
    }
    return;
  }
  M.fill(0);
  for (let i = 0; i < len; i++) M[i >> 2] |= bytes[offset + i] << ((i & 3) * 8);
}

/** The pending compression of a chunk's last block or of a parent node. */
interface Output {
  cv: Uint32Array;
  block: Uint32Array;
  counter: number;
  blockLen: number;
  flags: number;
}

/**
 * Compress the whole chunk `[start, end)` (not the final one) and write its
 * chaining value to `out[outOffset..]`.
 */
function chunkChainingValue(input: Uint8Array, start: number, end: number, chunkCounter: number, out: Uint32Array, outOffset: number): void {
  const cv = new Uint32Array(8);
  cv.set(IV);
  let offset = start;
  let blocksDone = 0;
  while (end - offset > BLOCK_LEN) {
    loadBlock(input, offset, BLOCK_LEN);
    compress(cv, 0, chunkCounter, BLOCK_LEN, blocksDone === 0 ? CHUNK_START : 0, cv, 0);
    offset += BLOCK_LEN;
    blocksDone++;
  }
  const len = end - offset;
  loadBlock(input, offset, len);
  compress(cv, 0, chunkCounter, len, (blocksDone === 0 ? CHUNK_START : 0) | CHUNK_END, out, outOffset);
}

/** The final chunk's pending output (its last block is compressed with the root flag later). */
function finalChunkOutput(input: Uint8Array, start: number, end: number, chunkCounter: number): Output {
  const cv = new Uint32Array(8);
  cv.set(IV);
  let offset = start;
  let blocksDone = 0;
  while (end - offset > BLOCK_LEN) {
    loadBlock(input, offset, BLOCK_LEN);
    compress(cv, 0, chunkCounter, BLOCK_LEN, blocksDone === 0 ? CHUNK_START : 0, cv, 0);
    offset += BLOCK_LEN;
    blocksDone++;
  }
  const len = end - offset;
  loadBlock(input, offset, len);
  return { cv, block: Uint32Array.from(M), counter: chunkCounter, blockLen: len, flags: (blocksDone === 0 ? CHUNK_START : 0) | CHUNK_END };
}

const IV_CV = new Uint32Array(IV);

/** Parent node of two chaining values (`left` at `stack[leftOffset..]`, `right` at `rightOffset`) as a pending output. */
function parentOutput(stack: Uint32Array, leftOffset: number, right: Uint32Array, rightOffset: number): Output {
  const block = new Uint32Array(16);
  for (let i = 0; i < 8; i++) {
    block[i] = stack[leftOffset + i];
    block[8 + i] = right[rightOffset + i];
  }
  return { cv: IV_CV, block, counter: 0, blockLen: BLOCK_LEN, flags: PARENT };
}

/** BLAKE3 of `input`, the default 32-byte output. */
export function blake3(input: Uint8Array): Uint8Array {
  const chunkCount = Math.max(1, Math.ceil(input.length / CHUNK_LEN));
  // The chaining-value stack: at most 54 subtrees for any JS-sized input.
  const stack = new Uint32Array(8 * 54);
  let depth = 0;
  const cv = new Uint32Array(8);
  for (let i = 0; i < chunkCount - 1; i++) {
    chunkChainingValue(input, i * CHUNK_LEN, (i + 1) * CHUNK_LEN, i, cv, 0);
    // Merge completed subtrees: one merge per trailing zero bit of the count.
    let total = i + 1;
    while ((total & 1) === 0) {
      depth--;
      for (let k = 0; k < 8; k++) {
        M[k] = stack[depth * 8 + k];
        M[8 + k] = cv[k];
      }
      compress(IV_CV, 0, 0, BLOCK_LEN, PARENT, cv, 0);
      total >>= 1;
    }
    stack.set(cv, depth * 8);
    depth++;
  }
  const last = chunkCount - 1;
  let output = finalChunkOutput(input, last * CHUNK_LEN, input.length, last);
  while (depth > 0) {
    M.set(output.block);
    compress(output.cv, 0, output.counter, output.blockLen, output.flags, cv, 0);
    depth--;
    output = parentOutput(stack, depth * 8, cv, 0);
  }
  M.set(output.block);
  const words = new Uint32Array(8);
  compress(output.cv, 0, 0, output.blockLen, output.flags | ROOT, words, 0);
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
