/**
 * SR-G2 `removal-reach` (`removal-reach@0.1`): for each declaration removed
 * between a base and a head, whether the base could reach it.
 *
 * Removed = `diffStableIds(base, head)` minus settled moves and renames
 * (`detectMoves`): a declaration that moved is not a removal. A removal that
 * only a move *candidate* explains stays a removal and carries the candidate.
 *
 * Per removed declaration, at the **base**: one strong path if any, one weak
 * path if any, and the unresolved sites that could reach it. The consumer
 * decides: a strong path means live code was removed; no strong path but a
 * weak path or an unresolved site means "may be live"; nothing means the
 * removal was unreachable. Files that do not parse at either pin are listed
 * in `partial[]`.
 */

import { digest128 } from '../stable-ids/hash.js';
import { detectMoves, type MoveCandidate, type MoveOptions } from '../stable-ids/moves.js';
import type { StableIdFile } from '../stable-ids/types.js';
import type { EntryKind } from '../navigation/ts-entry-tables.js';
import { ALL_ENTRY_KINDS, reach, type CouldReachSite, type ReachInput, type ReachPath } from './reach.js';

export const REMOVAL_REACH_SCHEME = 'removal-reach@0.1' as const;

export interface RemovedDeclaration {
  id: string;
  qualified_name: string;
  kind: string;
  file: string;
  strong: ReachPath | null;
  weak: ReachPath | null;
  unresolved: CouldReachSite[];
  unresolvedCount: number;
  /** Move or rename candidates (signal) that could explain the removal. */
  moveCandidates: MoveCandidateRef[];
}

export interface MoveCandidateRef {
  to: string;
  relation: MoveCandidate['relation'];
  evidence: MoveCandidate['evidence'];
  similarity: number;
}

export interface RemovalReachOptions {
  /** Root kinds at the base. Default: every kind except `test`. */
  rootKinds?: readonly EntryKind[];
  /** Passed to `detectMoves`. */
  moves?: MoveOptions;
  /** Most unresolved sites listed per declaration. Default 5. */
  maxUnresolved?: number;
}

export interface RemovalReachResult {
  scheme: typeof REMOVAL_REACH_SCHEME;
  ids: 'ids@0.1';
  rootKinds: EntryKind[];
  /** Digest of the base's entry index (sorted entries), so a record can name what it was decided against. */
  entryIndexDigest: string;
  /** Files that do not parse at the base or the head. */
  partial: string[];
  /** Declarations that moved or were renamed (not removals), as `from → to` ids. */
  moved: { from: string; to: string; relation: string; evidence: string }[];
  removed: RemovedDeclaration[];
}

/** A stable digest of an entry list: order-independent, 26 base32 characters. */
export function entryIndexDigest(entries: ReachInput['entries']): string {
  const rows = entries
    .map(e => [e.id, e.kind, e.certainty, e.method ?? '', e.path ?? '', e.file, String(e.line)].join('\u0001'))
    .sort();
  return digest128(['entry-index@0.1', ...rows]);
}

/**
 * `base` is the reach input at the base pin (e.g. `buildTsCallGraph` over
 * the base files); `head` is the stable ids at the head pin.
 */
export function removalReach(
  base: ReachInput,
  head: readonly StableIdFile[],
  options: RemovalReachOptions = {},
): RemovalReachResult {
  const rootKinds = [...(options.rootKinds ?? ALL_ENTRY_KINDS.filter(k => k !== 'test'))];
  const moves = detectMoves(base.files, head, options.moves);
  const removedIds = moves.diff.removed.map(d => d.id);
  const facts = reach(base, { rootKinds, targets: removedIds, maxUnresolved: options.maxUnresolved });
  const candidates = new Map<string, MoveCandidateRef[]>();
  for (const c of moves.candidates) {
    const list = candidates.get(c.from.id) ?? [];
    list.push({ evidence: c.evidence, relation: c.relation, similarity: c.similarity, to: c.to.id });
    candidates.set(c.from.id, list);
  }
  const partial = [...new Set([...base.partial, ...head.filter(f => f.partial).map(f => f.file)])].sort();
  return {
    scheme: REMOVAL_REACH_SCHEME,
    ids: 'ids@0.1',
    rootKinds,
    entryIndexDigest: entryIndexDigest(base.entries),
    partial,
    moved: moves.moves.map(m => ({ from: m.from.id, to: m.to.id, relation: m.relation, evidence: m.evidence })),
    removed: facts.facts.map(f => ({
      id: f.id,
      qualified_name: f.qualified_name,
      kind: f.kind,
      file: f.file,
      strong: f.strong,
      weak: f.weak,
      unresolved: f.unresolved,
      unresolvedCount: f.unresolvedCount,
      moveCandidates: candidates.get(f.id) ?? [],
    })),
  };
}
