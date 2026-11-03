/**
 * The `file` kind of `ids@0.1` (stable-ids decision 6): a function of the
 * path alone, the `digest128` construction of every other id, and an input
 * that never coincides with a declaration id's or a node id's.
 */

import { describe, it, expect } from 'vitest';
import { STABLE_FILE_KIND, fileId, fileIdBytes } from '../../src/stable-ids/files.js';
import { base32, digest128, digest128Bytes } from '../../src/stable-ids/hash.js';
import { STABLE_ID_SCHEME } from '../../src/stable-ids/types.js';
import { fileKey } from '../../src/facts/schema2.js';

const hex = (b: Uint8Array): string => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

describe('ids@0.1 file kind', () => {
  it('is digest128(["ids@0.1", "file", path]) and reproduces the facts@2 test vector', () => {
    const path = 'src/main/java/org/example/App.java';
    expect(STABLE_FILE_KIND).toBe('file');
    expect(hex(fileIdBytes(path))).toBe('d26d79b82b9a2df38e9b9ccd3946a3e8');
    expect(fileId(path)).toBe('2jwxtobltiw7hdu3ttgtsrvd5a');
    expect(fileIdBytes(path)).toEqual(digest128Bytes([STABLE_ID_SCHEME, 'file', path]));
    expect(fileId(path)).toBe(digest128([STABLE_ID_SCHEME, 'file', path]));
  });

  it('prints as 26 base32 characters of 16 bytes, and facts@2 fileKey is the same bytes', () => {
    for (const path of ['a.ts', 'src/x/Y.java', 'dir with space/é.py', '']) {
      const bytes = fileIdBytes(path);
      expect(bytes).toHaveLength(16);
      expect(fileId(path)).toMatch(/^[a-z2-7]{26}$/);
      expect(base32(bytes)).toBe(fileId(path));
      expect(fileKey(path)).toEqual(bytes);
    }
  });

  it('depends on the path alone, exactly as written (no normalization)', () => {
    expect(fileId('src/A.java')).toBe(fileId('src/A.java'));
    expect(fileId('src/A.java')).not.toBe(fileId('src/B.java'));
    expect(fileId('src/A.java')).not.toBe(fileId('./src/A.java'));
    expect(fileId('src/A.java')).not.toBe(fileId('src\\A.java'));
  });

  it('never shares its digest input with a declaration id or a node id', () => {
    // A declaration id's second part is a language; a node id's is "node". "file" is neither.
    expect(['java', 'typescript', 'javascript', 'python', 'go', 'node']).not.toContain(STABLE_FILE_KIND);
    expect(fileId('x')).not.toBe(digest128([STABLE_ID_SCHEME, 'node', 'x']));
    expect(fileId('x')).not.toBe(digest128([STABLE_ID_SCHEME, 'java', 'x']));
  });
});
