/**
 * The dead-code answer (`dead-code@0.1`): per declaration, whether any
 * entry point can reach it, how strongly, and whether a test does.
 *
 * - `live` — a strong path exists.
 * - `may-be-live` — no strong path, but a weak path, an unresolved site that
 *   could reach it, or a file that did not parse and could reach it (its
 *   calls are missing: anything in it, in a module it imports, or reachable
 *   from those over any edge).
 *   `reasons` says which; the paths and sites are on the fact.
 * - `dead` — none of these. Only this verdict claims anything.
 *
 * Test reach is computed separately from `test` roots: code that only tests
 * reach is dead product code (`reachedByTest` tells the caller which tests
 * exercise it). Declarations in test files, and declarations that exist only
 * for the type checker, are left out of the answer.
 */

import type { EntryKind } from '../navigation/ts-entry-tables.js';
import { ALL_ENTRY_KINDS, ReachGraph, entryRoots, reach, reachedIds, walkFrom, type PartialFile, type ReachFact, type ReachInput } from './reach.js';

export const DEAD_CODE_SCHEME = 'dead-code@0.1' as const;

export type DeadCodeVerdict = 'live' | 'may-be-live' | 'dead';

export type MayBeLiveReason = 'weak-path' | 'unresolved-sites' | 'partial-files';

export interface DeadCodeFact extends ReachFact {
  verdict: DeadCodeVerdict;
  reasons: MayBeLiveReason[];
  reachedByTest: boolean;
  /** The test entry whose walk first reached it (shortest), when `reachedByTest`. */
  test?: string;
}

export interface DeadCodeOptions {
  /** Product roots. Default: every entry kind except `test`. */
  rootKinds?: readonly EntryKind[];
  /** Files that are tests; their declarations are not reported. Default: none beyond `testFiles` of the input. */
  testFile?: RegExp;
  /** Declaration ids that exist only for the type checker; not reported. */
  typeOnly?: readonly string[];
  /** Most unresolved sites listed per declaration. Default 5. */
  maxUnresolved?: number;
  /** See `ReachOptions.boundRegistrations`. Default off. */
  boundRegistrations?: boolean;
}

export interface DeadCodeResult {
  scheme: typeof DEAD_CODE_SCHEME;
  ids: 'ids@0.1';
  rootKinds: EntryKind[];
  partial: string[];
  /** One row per `partial` file: where its first blocking parse error is. */
  partialFiles: PartialFile[];
  facts: DeadCodeFact[];
  summary: Record<DeadCodeVerdict, number> & { reachedByTestOnly: number };
}

function verdictRank(v: DeadCodeVerdict): number {
  return v === 'dead' ? 0 : v === 'may-be-live' ? 1 : 2;
}

function buildDeclParentChildren(input: ReachInput): { parent: Map<string, string | null>; children: Map<string, string[]> } {
  const parent = new Map<string, string | null>();
  const children = new Map<string, string[]>();
  for (const f of input.files) {
    for (const d of f.decls) {
      parent.set(d.id, d.parent);
      if (d.parent) {
        const list = children.get(d.parent) ?? [];
        list.push(d.id);
        children.set(d.parent, list);
      }
    }
  }
  return { parent, children };
}

function descendantIds(root: string, children: Map<string, string[]>): string[] {
  const out: string[] = [];
  const stack = [...(children.get(root) ?? [])];
  while (stack.length > 0) {
    const id = stack.pop()!;
    out.push(id);
    stack.push(...(children.get(id) ?? []));
  }
  return out;
}

/**
 * A module or type cannot be `dead` when a member is `may-be-live` or `live` (#1288).
 * Fields on a type with a `may-be-live` method follow the type when dynamic `this` may touch them.
 */
function promoteMemberConsistentVerdicts(facts: DeadCodeFact[], input: ReachInput): void {
  const byId = new Map(facts.map(f => [f.id, f]));
  const { parent, children } = buildDeclParentChildren(input);

  for (const fact of facts) {
    if ((fact.kind !== 'module' && fact.kind !== 'type') || fact.verdict !== 'dead') continue;
    for (const did of descendantIds(fact.id, children)) {
      const child = byId.get(did);
      if (child && verdictRank(child.verdict) > 0) {
        fact.verdict = 'may-be-live';
        const reason: MayBeLiveReason =
          child.reasons.includes('unresolved-sites') ? 'unresolved-sites' : 'weak-path';
        if (!fact.reasons.includes(reason)) fact.reasons.push(reason);
        break;
      }
    }
  }

  for (const fact of facts) {
    if (fact.kind !== 'field' || fact.verdict !== 'dead') continue;
    const parentId = parent.get(fact.id);
    if (!parentId) continue;
    const typeFact = byId.get(parentId);
    if (!typeFact || typeFact.kind !== 'type') continue;
    const hasMayBeLiveMethod = (children.get(parentId) ?? []).some(sid => {
      const s = byId.get(sid);
      return (
        s !== undefined &&
        (s.kind === 'method' || s.kind === 'function') &&
        s.verdict === 'may-be-live'
      );
    });
    if (hasMayBeLiveMethod) {
      fact.verdict = 'may-be-live';
      if (!fact.reasons.includes('unresolved-sites')) fact.reasons.push('unresolved-sites');
    }
  }
}

function resummary(facts: readonly DeadCodeFact[]): DeadCodeResult['summary'] {
  const summary = { live: 0, 'may-be-live': 0, dead: 0, reachedByTestOnly: 0 };
  for (const f of facts) {
    summary[f.verdict]++;
    if (f.verdict === 'dead' && f.reachedByTest) summary.reachedByTestOnly++;
  }
  return summary;
}

/** Container ids reported dead while a descendant is not dead (#1288 invariant). */
export function deadCodeConsistencyViolations(
  facts: readonly DeadCodeFact[],
  input: ReachInput,
): string[] {
  const byId = new Map(facts.map(f => [f.id, f]));
  const { children } = buildDeclParentChildren(input);
  const violations: string[] = [];
  for (const fact of facts) {
    if (fact.kind !== 'module' && fact.kind !== 'type') continue;
    if (fact.verdict !== 'dead') continue;
    for (const did of descendantIds(fact.id, children)) {
      const child = byId.get(did);
      if (child && child.verdict !== 'dead') {
        violations.push(fact.id);
        break;
      }
    }
  }
  return violations;
}

export function deadCode(input: ReachInput & { typeOnly?: readonly string[] }, options: DeadCodeOptions = {}): DeadCodeResult {
  const product = reach(input, { rootKinds: options.rootKinds ?? ALL_ENTRY_KINDS.filter(k => k !== 'test'), maxUnresolved: options.maxUnresolved, boundRegistrations: options.boundRegistrations });
  // Test reach: every path class counts — a test that reaches it only through an inferred call still exercises it.
  const g = new ReachGraph(input);
  const testRoots = input.entries.filter(e => e.kind === 'test');
  const testSeeds = entryRoots(testRoots);
  const testVisits = walkFrom(g, testSeeds.roots, testSeeds.rootIndex);
  const byTest = reachedIds(testVisits);
  const firstTest = (id: string): string | undefined => {
    const v = testVisits.get(`0${id}`) ?? testVisits.get(`1${id}`);
    return v ? testRoots[v.root].id : undefined;
  };
  const typeOnly = new Set([...(options.typeOnly ?? []), ...(input.typeOnly ?? [])]);
  const testFiles = new Set(input.entries.filter(e => e.kind === 'test').map(e => e.file));
  const isTestFile = (file: string): boolean => testFiles.has(file) || (options.testFile?.test(file) ?? false);
  const partialReach = partialScope(g, input);
  const facts: DeadCodeFact[] = [];
  const summary = { live: 0, 'may-be-live': 0, dead: 0, reachedByTestOnly: 0 };
  for (const f of product.facts) {
    if (typeOnly.has(f.id) || isTestFile(f.file)) continue;
    const reasons: MayBeLiveReason[] = [];
    if (!f.strong) {
      if (f.weak) reasons.push('weak-path');
      if (f.unresolvedCount > 0) reasons.push('unresolved-sites');
      if (partialReach.has(f.id)) reasons.push('partial-files');
    }
    const verdict: DeadCodeVerdict = f.strong ? 'live' : reasons.length > 0 ? 'may-be-live' : 'dead';
    const reachedByTest = byTest.has(f.id);
    const fact: DeadCodeFact = { ...f, verdict, reasons, reachedByTest };
    const t = reachedByTest ? firstTest(f.id) : undefined;
    if (t) fact.test = t;
    facts.push(fact);
    summary[verdict]++;
    if (verdict === 'dead' && reachedByTest) summary.reachedByTestOnly++;
  }
  promoteMemberConsistentVerdicts(facts, input);
  const finalSummary = resummary(facts);
  return {
    scheme: DEAD_CODE_SCHEME,
    ids: 'ids@0.1',
    rootKinds: product.rootKinds,
    partial: product.partial,
    partialFiles: product.partialFiles,
    facts,
    summary: finalSummary,
  };
}

/**
 * What files that did not parse could reach: their own declarations, the
 * modules they import or load, and everything reachable from those over any
 * edge. A missing call site can only run what its file can name, so the rest
 * of the tree keeps its verdict.
 */
export function partialScope(g: ReachGraph, input: ReachInput): Set<string> {
  if (input.partial.length === 0) return new Set();
  const partial = new Set(input.partial);
  const declFile = new Map<string, string>();
  for (const f of input.files) for (const d of f.decls) declFile.set(d.id, f.file);
  const seedFiles = new Set(partial);
  for (const i of [...(input.imports ?? []), ...(input.loads ?? [])]) {
    const from = declFile.get(i.from);
    const to = declFile.get(i.to);
    if (from && to && partial.has(from)) seedFiles.add(to);
  }
  const seeds: { id: string; weak: boolean }[] = [];
  for (const f of input.files) if (seedFiles.has(f.file)) for (const d of f.decls) seeds.push({ id: d.id, weak: true });
  return reachedIds(walkFrom(g, seeds));
}
