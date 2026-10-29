/**
 * Compare two `ids@0.1` id sets (two versions of the same files).
 *
 * A declaration is *unchanged* when its `decl` id and `body` id both match,
 * *body changed* when only the `decl` id matches, and otherwise *added* or
 * *removed*. Move and rename matching between removed and added
 * declarations is a separate step; this comparison never pairs them.
 */

import type { StableDecl, StableIdFile } from './types.js';

export interface StableIdDiff {
  unchanged: StableDecl[];
  /** `[before, after]` pairs sharing a `decl` id. */
  body_changed: [StableDecl, StableDecl][];
  added: StableDecl[];
  removed: StableDecl[];
}

function byId(files: readonly StableIdFile[]): Map<string, StableDecl> {
  const m = new Map<string, StableDecl>();
  for (const f of files) {
    if (f.scheme !== 'ids@0.1') throw new Error(`stable-ids: unsupported scheme ${String(f.scheme)}`);
    for (const d of f.decls) m.set(d.id, d);
  }
  return m;
}

export function diffStableIds(before: readonly StableIdFile[], after: readonly StableIdFile[]): StableIdDiff {
  const a = byId(before);
  const b = byId(after);
  const out: StableIdDiff = { unchanged: [], body_changed: [], added: [], removed: [] };
  for (const [id, old] of a) {
    const now = b.get(id);
    if (!now) out.removed.push(old);
    else if (now.body_id === old.body_id) out.unchanged.push(now);
    else out.body_changed.push([old, now]);
  }
  for (const [id, now] of b) if (!a.has(id)) out.added.push(now);
  return out;
}
