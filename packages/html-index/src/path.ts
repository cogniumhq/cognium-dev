/**
 * Whether a path lies inside a root folder (or is the root itself). A bare `file.startsWith(root)`
 * is not that check: `/tmp/pageEvil/x.css` starts with `/tmp/page`. Both sides are resolved, so a
 * relative root, a trailing separator or a `..` segment cannot change the answer; a name that only
 * begins with two dots (`..x.css`) is still inside.
 *
 * `isUnder` is lexical: it does not touch the disk, so it does not follow symlinks. Subject trees
 * are untrusted and a link inside the root (`site/x -> /etc`) passes `isUnder`, so anything
 * that reads or serves a file from a subject tree checks `isUnderReal` as well.
 */
import { lstatSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export function isUnder(root: string, file: string): boolean {
  const rel = relative(resolve(root), resolve(file));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * `isUnder` after following symlinks on both sides: the file must exist, and its real path must lie
 * inside the root's real path. A missing file, a dangling link or a link that resolves outside the
 * root is false; a link that stays inside the root is fine. The root is resolved as well, so
 * a root reached through a symlink (macOS `/var` -> `/private/var`) still works.
 */
export function isUnderReal(root: string, file: string): boolean {
  let r: string, f: string;
  try { r = realpathSync(root); f = realpathSync(file); } catch { return false; }
  return isUnder(r, f);
}

/**
 * One entry of a directory walk over a subject tree: a directory to descend into (with its real
 * path), a file to read, or something to skip. A symlink is followed only when it resolves inside
 * the root; a dangling or escaping link is skipped, never thrown on. `ancestors` holds
 * the real paths of the directories on the current walk path, so a link back up the tree is skipped
 * rather than looped on, while a link to a sibling folder inside the root is still followed.
 */
export function walkEntry(root: string, full: string, ancestors: Set<string>): { kind: 'dir'; real: string } | { kind: 'file' | 'skip' } {
  let st;
  try { st = lstatSync(full); } catch { return { kind: 'skip' }; }
  if (st.isSymbolicLink()) {
    if (!isUnderReal(root, full)) return { kind: 'skip' };
    try { st = statSync(full); } catch { return { kind: 'skip' }; }
  }
  if (st.isDirectory()) {
    let real: string;
    try { real = realpathSync(full); } catch { return { kind: 'skip' }; }
    return ancestors.has(real) ? { kind: 'skip' } : { kind: 'dir', real };
  }
  return { kind: st.isFile() ? 'file' : 'skip' };
}
