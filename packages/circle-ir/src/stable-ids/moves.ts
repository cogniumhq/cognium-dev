/**
 * Moves and renames between two versions, as facts (`ids@0.1`).
 *
 * `diffStableIds` leaves a moved or renamed declaration as one removal plus
 * one addition. This pairs them, in three steps over what is still unpaired:
 *
 * 1. **Equal body hash** — settles. The pair must be unique on both sides
 *    (one removed and one added declaration of the same kind with that
 *    hash) and the body must have at least `minTokens` normalized tokens;
 *    a smaller or shared body is reported as a candidate, never a fact —
 *    unless a settled pair vouches for it: a container settles when one of
 *    its members settled into the counterpart (`members`), and a member
 *    follows its settled container when the counterpart has the same local
 *    name, kind, signature and body (`enclosing`).
 * 2. **Same kind and qualified name, new signature** — settles as
 *    `signature-changed` when exactly one removed and one added
 *    declaration share them (declarations flagged `unstable:duplicate` are
 *    left out).
 * 3. **Similar body** — candidates only (signal): token-bigram similarity at
 *    or above `similarityBar`, with the caller sets compared when the caller
 *    supplies them. A candidate whose caller sets differ is dropped.
 *
 * Anything not paired stays removed and added, so a missed move costs a
 * "removed + added", never a wrong match.
 */

import { diffStableIds, type StableIdDiff } from './diff.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableIdFile, type StableIdScheme } from './types.js';

export type MoveRelation = 'moved' | 'renamed' | 'moved-renamed' | 'signature-changed';

/** Why a pair settled. */
export type MoveEvidence =
  /** Equal body hash, unique on both sides, body of at least `minTokens` tokens. */
  | 'body-hash'
  /** A small equal-hash pair one of whose members settled into the other. */
  | 'members'
  /** Its enclosing declaration settled; same local name, kind, signature and body under the new one. */
  | 'enclosing'
  /** Same kind and qualified name, new signature. */
  | 'qualified-name';

/** Why a pair is only a candidate. */
export type CandidateEvidence = 'body-hash-small' | 'body-hash-ambiguous' | 'similar-body';

export interface StableIdMove {
  scheme: StableIdScheme;
  relation: MoveRelation;
  evidence: MoveEvidence;
  from: StableDecl;
  to: StableDecl;
  /** The two commits, when the caller named them. */
  base?: string;
  head?: string;
}

export interface MoveCandidate {
  relation: MoveRelation;
  evidence: CandidateEvidence;
  from: StableDecl;
  to: StableDecl;
  /** Token-bigram Dice similarity of the two bodies, 0–1, rounded to 4 places (1 for equal hashes). */
  similarity: number;
  /** `equal` when both caller sets were supplied and match; `unknown` when either was not supplied. */
  callers: 'equal' | 'unknown';
}

export interface MoveOptions {
  /** Bodies with fewer normalized tokens never settle by hash alone. Default 12. */
  minTokens?: number;
  /**
   * Bar for similar-body candidates, 0–1. Default 0.8. It is a placeholder
   * until measured on a seeded set: candidates are signal whatever it is.
   */
  similarityBar?: number;
  /** Callers of each declaration at the base version, by declaration id. */
  callersBefore?: ReadonlyMap<string, readonly string[]>;
  /** Callers of each declaration at the head version, by declaration id. */
  callersAfter?: ReadonlyMap<string, readonly string[]>;
  base?: string;
  head?: string;
}

export interface MoveDetection {
  /** `diffStableIds`, with every settled pair taken out of `removed` and `added`. */
  diff: StableIdDiff;
  moves: StableIdMove[];
  /** Signal only, sorted by similarity (highest first), then by ids. */
  candidates: MoveCandidate[];
}

/** The qualified name of the enclosing scope: everything before the declaration's own name. */
function enclosing(d: StableDecl): string {
  const q = d.qualified_name.replace(/#\d+$/, '');
  if (d.parent === null) return '';
  const at = q.lastIndexOf(d.name);
  return at > 0 ? q.slice(0, at) : q;
}

function relationOf(from: StableDecl, to: StableDecl): MoveRelation {
  // A module is named by its path: a new name is a move of the file.
  if (from.kind === 'module' && from.parent === null) return 'moved';
  const renamed = from.name !== to.name;
  const moved = enclosing(from) !== enclosing(to);
  if (renamed && moved) return 'moved-renamed';
  if (renamed) return 'renamed';
  if (moved) return 'moved';
  return 'signature-changed';
}

function groupBy(decls: readonly StableDecl[], key: (d: StableDecl) => string): Map<string, StableDecl[]> {
  const m = new Map<string, StableDecl[]>();
  for (const d of decls) {
    const k = key(d);
    const list = m.get(k);
    if (list) list.push(d);
    else m.set(k, [d]);
  }
  return m;
}

function bigrams(tokens: readonly string[]): Map<string, number> {
  const m = new Map<string, number>();
  for (let i = 0; i + 1 < tokens.length; i++) {
    const k = tokens[i] + '\u0000' + tokens[i + 1];
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return m;
}

/** Dice coefficient over token-bigram multisets. */
export function bodySimilarity(a: readonly string[], b: readonly string[]): number {
  if (a.length < 2 || b.length < 2) return a.length === b.length && a.every((t, i) => t === b[i]) ? 1 : 0;
  const x = bigrams(a);
  const y = bigrams(b);
  let shared = 0;
  for (const [k, n] of x) shared += Math.min(n, y.get(k) ?? 0);
  return (2 * shared) / (a.length - 1 + (b.length - 1));
}

/** Shared-body groups larger than this (removed × added) yield no candidates. */
const MAX_AMBIGUOUS = 25;

const round4 = (n: number): number => Math.round(n * 10000) / 10000;

function byIds(a: { from: StableDecl; to: StableDecl }, b: { from: StableDecl; to: StableDecl }): number {
  return a.from.id < b.from.id ? -1 : a.from.id > b.from.id ? 1 : a.to.id < b.to.id ? -1 : a.to.id > b.to.id ? 1 : 0;
}

/** Pair the removed and added declarations of two versions. */
export function detectMoves(
  before: readonly StableIdFile[],
  after: readonly StableIdFile[],
  options: MoveOptions = {},
): MoveDetection {
  const minTokens = options.minTokens ?? 12;
  const bar = options.similarityBar ?? 0.8;
  const diff = diffStableIds(before, after);
  const removed = new Set(diff.removed);
  const added = new Set(diff.added);
  const moves: StableIdMove[] = [];
  const candidates: MoveCandidate[] = [];
  const settle = (from: StableDecl, to: StableDecl, evidence: MoveEvidence): void => {
    removed.delete(from);
    added.delete(to);
    const move: StableIdMove = { scheme: STABLE_ID_SCHEME, relation: relationOf(from, to), evidence, from, to };
    if (options.base !== undefined) move.base = options.base;
    if (options.head !== undefined) move.head = options.head;
    moves.push(move);
  };

  // 1. Equal body hash, unique on both sides.
  const hashKey = (d: StableDecl) => `${d.kind}\u0000${d.body_hash}`;
  const removedByHash = groupBy([...removed], hashKey);
  const addedByHash = groupBy([...added], hashKey);
  const hashPaired = new Set<StableDecl>();
  const small: MoveCandidate[] = [];
  const ambiguous: MoveCandidate[] = [];
  for (const [k, olds] of removedByHash) {
    const news = addedByHash.get(k);
    if (!news) continue;
    if (olds.length === 1 && news.length === 1) {
      const [from] = olds;
      const [to] = news;
      if (from.token_count >= minTokens) settle(from, to, 'body-hash');
      else small.push({ relation: relationOf(from, to), evidence: 'body-hash-small', from, to, similarity: 1, callers: 'unknown' });
      hashPaired.add(from).add(to);
      continue;
    }
    // Shared bodies (often trivial ones): every pairing is a candidate, up
    // to a bound; later steps may still settle one of them.
    if (olds.length * news.length > MAX_AMBIGUOUS) continue;
    for (const from of olds) {
      for (const to of news) {
        ambiguous.push({ relation: relationOf(from, to), evidence: 'body-hash-ambiguous', from, to, similarity: 1, callers: 'unknown' });
      }
    }
  }

  // 1b. Settled pairs carry their surroundings, to a fixpoint: a small
  // equal-hash pair settles when a member of one settled into the other
  // (a container's body is mostly member placeholders), and a declaration
  // whose enclosing declaration settled follows it when the counterpart
  // under the new parent has the same local name, kind, signature and body.
  const declById = new Map<string, StableDecl>();
  for (const f of [...before, ...after]) for (const d of f.decls) declById.set(d.id, d);
  const local = (d: StableDecl): string => {
    const p = d.parent === null ? undefined : declById.get(d.parent);
    return p && d.qualified_name.startsWith(p.qualified_name) ? d.qualified_name.slice(p.qualified_name.length) : d.qualified_name;
  };
  const addedByParent = groupBy([...added], d => d.parent ?? '');
  for (let changed = true; changed;) {
    changed = false;
    const settledTo = new Map<string, string>(moves.map(m => [m.from.id, m.to.id]));
    for (const c of small) {
      if (!removed.has(c.from) || !added.has(c.to)) continue;
      if (moves.some(m => m.from.parent === c.from.id && m.to.parent === c.to.id)) {
        settle(c.from, c.to, 'members');
        changed = true;
      }
    }
    for (const from of [...removed]) {
      const newParent = from.parent === null ? undefined : settledTo.get(from.parent);
      if (newParent === undefined) continue;
      const match = (addedByParent.get(newParent) ?? []).filter(
        to => added.has(to) && to.kind === from.kind && to.signature === from.signature
          && to.body_hash === from.body_hash && local(to) === local(from),
      );
      if (match.length === 1) {
        settle(from, match[0], 'enclosing');
        changed = true;
      }
    }
  }

  // 2. Same kind and qualified name, new signature.
  const stable = (d: StableDecl) => !d.flags.includes('unstable:duplicate');
  const nameKey = (d: StableDecl) => `${d.kind}\u0000${d.qualified_name}`;
  const removedByName = groupBy([...removed].filter(stable), nameKey);
  const addedByName = groupBy([...added].filter(stable), nameKey);
  for (const [k, olds] of removedByName) {
    const news = addedByName.get(k);
    if (olds.length === 1 && news?.length === 1 && !hashPaired.has(olds[0]) && !hashPaired.has(news[0])) {
      settle(olds[0], news[0], 'qualified-name');
    }
  }

  for (const c of [...small, ...ambiguous]) {
    if (!removed.has(c.from) || !added.has(c.to)) continue;
    candidates.push(c);
    hashPaired.add(c.from).add(c.to);
  }

  // 3. Similar bodies (signal), over what steps 1 and 2 did not pair.
  const mapped = new Map<string, string>(moves.map(m => [m.from.id, m.to.id]));
  const callerSet = (ids: readonly string[], map: boolean): string =>
    [...new Set(ids.map(id => (map ? mapped.get(id) ?? id : id)))].sort().join('\u0000');
  for (const from of removed) {
    if (hashPaired.has(from) || !from.body_tokens) continue;
    for (const to of added) {
      if (hashPaired.has(to) || !to.body_tokens || to.kind !== from.kind) continue;
      const similarity = round4(bodySimilarity(from.body_tokens, to.body_tokens));
      if (similarity < bar) continue;
      const cb = options.callersBefore?.get(from.id);
      const ca = options.callersAfter?.get(to.id);
      let callers: MoveCandidate['callers'] = 'unknown';
      if (cb && ca) {
        if (callerSet(cb, true) !== callerSet(ca, false)) continue;
        callers = 'equal';
      }
      candidates.push({ relation: relationOf(from, to), evidence: 'similar-body', from, to, similarity, callers });
    }
  }

  moves.sort(byIds);
  candidates.sort((a, b) => b.similarity - a.similarity || byIds(a, b));
  return {
    diff: { ...diff, removed: diff.removed.filter(d => removed.has(d)), added: diff.added.filter(d => added.has(d)) },
    moves,
    candidates,
  };
}
