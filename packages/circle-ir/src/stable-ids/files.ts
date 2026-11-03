/**
 * The `file` kind of `ids@0.1` (stable-ids decision 6).
 *
 * A file key is `digest128(["ids@0.1", "file", path])`: BLAKE3 of the UTF-8
 * parts, each followed by NUL, first 16 bytes, printed as 26 base32
 * characters like every other `ids@0.1` id. `path` is the repository-relative,
 * `/`-separated path exactly as `facts@2` writes `files.path`; it is used as
 * given, with no normalization, so the caller decides the path once.
 *
 * The second part is the literal `file`, which is not a language name, so a
 * file key never shares its input with a declaration id
 * (`["ids@0.1", <language>, <kind>, …]`) or a node id
 * (`["ids@0.1", "node", …]`). A file is named by its path, not by its import
 * name: moving or renaming a file re-keys that file and nothing else.
 */

import { base32, digest128Bytes } from './hash.js';
import { STABLE_ID_SCHEME } from './types.js';

/** The second part of every file key's digest input. */
export const STABLE_FILE_KIND = 'file' as const;

/** The 16 raw bytes of a file key (what a `fixed16` column holds). */
export function fileIdBytes(path: string): Uint8Array {
  return digest128Bytes([STABLE_ID_SCHEME, STABLE_FILE_KIND, path]);
}

/** A file key printed as 26 lowercase base32 characters. */
export function fileId(path: string): string {
  return base32(fileIdBytes(path));
}
