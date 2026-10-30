/**
 * Known-vulnerability matching of a resolved dependency set against advisory
 * records in the OSV schema (https://ossf.github.io/osv-schema/).
 *
 * The library ships no advisory data and fetches none: the caller parses the
 * records of a snapshot it chose (for example the unzipped per-ecosystem
 * export of OSV.dev) and passes them in, so the same set, records and engine
 * version always give the same answer. Facts only: which advisory affects
 * which coordinate, by which range, and which later versions are fixed.
 * Severity is copied from the record; nothing is ranked or scored here.
 *
 * Ecosystems with an ordering (see {@link ADVISORY_ECOSYSTEMS}): `Maven`
 * (Maven's `ComparableVersion` order, `ECOSYSTEM` ranges) and `npm` (SemVer
 * 2.0 precedence, `SEMVER` ranges). Any other ecosystem name keeps the
 * original behaviour: Maven order over `ECOSYSTEM` ranges, names as given.
 */

import type { Dependency, Ecosystem } from './sbom.js';
import { compareMavenVersions } from './maven-version.js';
import { compareSemver, parseSemver } from './semver-version.js';

// ---------------------------------------------------------------------------
// Ecosystem rules
// ---------------------------------------------------------------------------

/** How one OSV ecosystem orders versions and names packages. */
export interface AdvisoryEcosystem {
  /** OSV's ecosystem name (`affected[].package.ecosystem`). */
  osv: string;
  /** The `Dependency.ecosystem` it matches. */
  dependency: Ecosystem;
  /** Version order for ranges, fixed lists and deltas. */
  compare: (a: string, b: string) => number;
  /** OSV range types evaluated (others are ignored). */
  rangeTypes: readonly string[];
  /** A version the matcher may place in that order. */
  isVersion: (version: string) => boolean;
  /** Canonical package name, applied to OSV names and dependency names alike. */
  normalizeName: (name: string) => string;
}

const asIs = (n: string): string => n;

/** The ecosystems this library can order, keyed by OSV name. */
export const ADVISORY_ECOSYSTEMS: Readonly<Record<string, AdvisoryEcosystem>> = {
  Maven: {
    osv: 'Maven',
    dependency: 'maven',
    compare: compareMavenVersions,
    rangeTypes: ['ECOSYSTEM'],
    isVersion: () => true,
    normalizeName: asIs,
  },
  npm: {
    osv: 'npm',
    dependency: 'npm',
    compare: compareSemver,
    rangeTypes: ['SEMVER', 'ECOSYSTEM'],
    isVersion: (v) => parseSemver(v) !== null,
    normalizeName: asIs,
  },
};

/** Rules for an index; unknown ecosystems keep the original Maven behaviour. */
function rulesFor(ecosystem: string): AdvisoryEcosystem & { filterDependencies: boolean } {
  const known = ADVISORY_ECOSYSTEMS[ecosystem];
  if (known) return { ...known, filterDependencies: known.osv !== 'Maven' };
  return { ...ADVISORY_ECOSYSTEMS.Maven, osv: ecosystem, filterDependencies: false };
}

/** Version order for a dependency's ecosystem (Maven order when unknown). */
function compareForDependency(eco: Ecosystem): (a: string, b: string) => number {
  for (const r of Object.values(ADVISORY_ECOSYSTEMS)) if (r.dependency === eco) return r.compare;
  return compareMavenVersions;
}

// ---------------------------------------------------------------------------
// OSV record (the subset matching needs)
// ---------------------------------------------------------------------------

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: string;
  events: OsvEvent[];
}

export interface OsvAffected {
  package: { ecosystem: string; name: string; purl?: string };
  ranges?: OsvRange[];
  versions?: string[];
}

export interface OsvRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  published?: string;
  modified: string;
  withdrawn?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: OsvAffected[];
  references?: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string } & Record<string, unknown>;
}

/**
 * Read one OSV record from JSON text or an already-parsed value. Returns null
 * for anything that is not a record (no string `id` or `modified`), so a
 * stray file in a snapshot directory is skipped rather than fatal.
 */
export function parseOsvRecord(input: string | unknown): OsvRecord | null {
  let value: unknown = input;
  if (typeof input === 'string') {
    try {
      value = JSON.parse(input);
    } catch {
      return null;
    }
  }
  if (!value || typeof value !== 'object') return null;
  const r = value as Record<string, unknown>;
  if (typeof r.id !== 'string' || typeof r.modified !== 'string') return null;
  return r as unknown as OsvRecord;
}

// ---------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------

/** One vulnerability after alias merge: the records that describe it. */
export interface AdvisoryGroup {
  /** The group's id: its `GHSA-…` id if any, else the lowest id. */
  id: string;
  /** Every other id and alias of the group, CVE ids first. */
  aliases: string[];
  records: OsvRecord[];
}

export interface AdvisoryIndex {
  /** Ecosystem the index was built for (OSV name, e.g. `Maven`). */
  ecosystem: string;
  /** Live (non-withdrawn) records read. */
  records: number;
  /** The greatest `modified` across all records read: the data's own date. */
  snapshotDate: string | null;
  /** Withdrawn records, never matched: id, aliases and withdrawal time. */
  withdrawn: Array<{ id: string; aliases: string[]; withdrawnAt: string }>;
  /** Package name → groups with an `affected` entry for it. */
  byPackage: Map<string, AdvisoryGroup[]>;
}

function aliasOrder(a: string, b: string): number {
  const rank = (s: string): number => (s.startsWith('CVE-') ? 0 : s.startsWith('GHSA-') ? 1 : 2);
  return rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0);
}

/**
 * Build the matching index for one ecosystem. Records whose ids or aliases
 * intersect are merged into one group, so a vulnerability published under two
 * ids is reported once. Withdrawn records are listed and never matched.
 */
export function buildAdvisoryIndex(records: OsvRecord[], ecosystem = 'Maven'): AdvisoryIndex {
  const rules = rulesFor(ecosystem);
  let snapshotDate: string | null = null;
  const withdrawn: AdvisoryIndex['withdrawn'] = [];
  const live: OsvRecord[] = [];
  for (const r of records) {
    if (snapshotDate === null || r.modified > snapshotDate) snapshotDate = r.modified;
    if (r.withdrawn) {
      withdrawn.push({ id: r.id, aliases: [...(r.aliases ?? [])].sort(aliasOrder), withdrawnAt: r.withdrawn });
      continue;
    }
    if (r.affected?.some((a) => a.package?.ecosystem === ecosystem)) live.push(r);
  }
  withdrawn.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // Union-find over every id and alias.
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root) as string;
    let cur = x;
    while (parent.get(cur) !== root) {
      const next = parent.get(cur) as string;
      parent.set(cur, root);
      cur = next;
    }
    return root;
  };
  const add = (x: string): void => {
    if (!parent.has(x)) parent.set(x, x);
  };
  const union = (a: string, b: string): void => {
    add(a);
    add(b);
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  for (const r of live) {
    add(r.id);
    for (const al of r.aliases ?? []) union(r.id, al);
  }

  const groups = new Map<string, OsvRecord[]>();
  for (const r of live) {
    const root = find(r.id);
    const list = groups.get(root) ?? [];
    list.push(r);
    groups.set(root, list);
  }

  const byPackage = new Map<string, AdvisoryGroup[]>();
  for (const recs of groups.values()) {
    recs.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const ids = new Set<string>();
    for (const r of recs) {
      ids.add(r.id);
      for (const al of r.aliases ?? []) ids.add(al);
    }
    const sorted = [...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const recordIds = new Set(recs.map((r) => r.id));
    const id = sorted.find((x) => x.startsWith('GHSA-') && recordIds.has(x)) ?? [...recordIds].sort()[0];
    const group: AdvisoryGroup = { id, aliases: sorted.filter((x) => x !== id).sort(aliasOrder), records: recs };
    const names = new Set<string>();
    for (const r of recs) for (const a of r.affected ?? []) if (a.package.ecosystem === ecosystem) names.add(rules.normalizeName(a.package.name));
    for (const n of names) {
      const list = byPackage.get(n) ?? [];
      list.push(group);
      byPackage.set(n, list);
    }
  }
  for (const list of byPackage.values()) list.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  return { ecosystem, records: live.length, snapshotDate, withdrawn, byPackage };
}

// ---------------------------------------------------------------------------
// Range evaluation
// ---------------------------------------------------------------------------

export interface AffectedInterval {
  /** Inclusive lower bound; `"0"` means from the first version. */
  introduced: string;
  /** Exclusive upper bound. */
  fixed?: string;
  /** Inclusive upper bound. */
  lastAffected?: string;
}

const cmp = compareMavenVersions;

/**
 * Turn one range's events into intervals, in version order (Maven order unless
 * another `compare` is given).
 */
export function rangeIntervals(range: OsvRange, compare: (a: string, b: string) => number = cmp): AffectedInterval[] {
  const events = range.events
    .filter((e) => e.introduced !== undefined || e.fixed !== undefined || e.last_affected !== undefined)
    .map((e) => {
      const v = (e.introduced ?? e.fixed ?? e.last_affected) as string;
      return { e, v };
    })
    .sort((a, b) => {
      if (a.v === '0' || b.v === '0') return a.v === b.v ? 0 : a.v === '0' ? -1 : 1;
      return compare(a.v, b.v);
    });
  const out: AffectedInterval[] = [];
  let open: AffectedInterval | null = null;
  for (const { e, v } of events) {
    if (e.introduced !== undefined) {
      if (!open) open = { introduced: v };
    } else if (open) {
      if (e.fixed !== undefined) open.fixed = v;
      else open.lastAffected = v;
      out.push(open);
      open = null;
    }
  }
  if (open) out.push(open);
  return out;
}

function inInterval(version: string, iv: AffectedInterval, compare: (a: string, b: string) => number): boolean {
  if (iv.introduced !== '0' && compare(version, iv.introduced) < 0) return false;
  if (iv.fixed !== undefined) return compare(version, iv.fixed) < 0;
  if (iv.lastAffected !== undefined) return compare(version, iv.lastAffected) <= 0;
  return true;
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

export interface AdvisoryRef {
  id: string;
  aliases: string[];
  summary?: string;
  published?: string;
  modified: string;
  /** Copied from the records (CVSS vectors and the like), never computed. */
  severity: Array<{ type: string; score: string }>;
  /** The record's own `database_specific.severity` (e.g. GHSA's HIGH), copied. */
  databaseSeverity?: string;
  references: string[];
}

export interface AdvisoryMatch {
  dependency: Dependency;
  advisory: AdvisoryRef;
  affected: { ranges: AffectedInterval[]; viaVersionsList: boolean };
  /** Every `fixed` bound above the dependency's version, ascending. */
  fixedIn: string[];
}

function advisoryRef(g: AdvisoryGroup): AdvisoryRef {
  const first = g.records[0];
  const severity: AdvisoryRef['severity'] = [];
  const seenSev = new Set<string>();
  let databaseSeverity: string | undefined;
  let modified = first.modified;
  let published: string | undefined;
  let summary: string | undefined;
  const references = new Set<string>();
  for (const r of g.records) {
    for (const s of r.severity ?? []) {
      const k = `${s.type}|${s.score}`;
      if (!seenSev.has(k)) {
        seenSev.add(k);
        severity.push({ type: s.type, score: s.score });
      }
    }
    if (!databaseSeverity && typeof r.database_specific?.severity === 'string') databaseSeverity = r.database_specific.severity;
    if (r.modified > modified) modified = r.modified;
    if (r.published && (!published || r.published < published)) published = r.published;
    if (!summary && r.summary) summary = r.summary;
    for (const ref of r.references ?? []) references.add(ref.url);
  }
  return {
    id: g.id,
    aliases: g.aliases,
    ...(summary ? { summary } : {}),
    ...(published ? { published } : {}),
    modified,
    severity,
    ...(databaseSeverity ? { databaseSeverity } : {}),
    references: [...references].sort(),
  };
}

/**
 * Match each dependency against the index. A dependency whose version is not
 * concrete (`unknown`, a range, an unresolved property) is never matched: the
 * caller reports it as unresolved. One match per (dependency, vulnerability).
 */
export function matchAdvisories(deps: Dependency[], index: AdvisoryIndex): AdvisoryMatch[] {
  const rules = rulesFor(index.ecosystem);
  const c = rules.compare;
  const out: AdvisoryMatch[] = [];
  for (const d of deps) {
    if (rules.filterDependencies && d.ecosystem !== rules.dependency) continue;
    if (!isConcreteVersion(d.version) || !rules.isVersion(d.version)) continue;
    const name = rules.normalizeName(d.name);
    const groups = index.byPackage.get(name);
    if (!groups) continue;
    for (const g of groups) {
      const ranges: AffectedInterval[] = [];
      const fixed = new Set<string>();
      let hitRange = false;
      let hitList = false;
      for (const r of g.records) {
        for (const a of r.affected ?? []) {
          if (a.package.ecosystem !== index.ecosystem || rules.normalizeName(a.package.name) !== name) continue;
          if (a.versions?.includes(d.version)) hitList = true;
          for (const range of a.ranges ?? []) {
            if (!rules.rangeTypes.includes(range.type)) continue;
            for (const iv of rangeIntervals(range, c)) {
              if (!inInterval(d.version, iv, c)) continue;
              hitRange = true;
              if (!ranges.some((x) => x.introduced === iv.introduced && x.fixed === iv.fixed && x.lastAffected === iv.lastAffected)) ranges.push(iv);
              if (iv.fixed !== undefined) fixed.add(iv.fixed);
            }
          }
        }
      }
      if (!hitRange && !hitList) continue;
      // Later fixed bounds of the same package (other branches) are fix candidates too.
      for (const r of g.records) {
        for (const a of r.affected ?? []) {
          if (a.package.ecosystem !== index.ecosystem || rules.normalizeName(a.package.name) !== name) continue;
          for (const range of a.ranges ?? []) {
            if (!rules.rangeTypes.includes(range.type)) continue;
            for (const iv of rangeIntervals(range, c)) if (iv.fixed !== undefined && c(iv.fixed, d.version) > 0) fixed.add(iv.fixed);
          }
        }
      }
      out.push({
        dependency: d,
        advisory: advisoryRef(g),
        affected: { ranges, viaVersionsList: hitList && !hitRange },
        fixedIn: [...fixed].filter((f) => c(f, d.version) > 0).sort(c),
      });
    }
  }
  return out;
}

/** A version the matcher may compare: one token, no range or unresolved reference. */
export function isConcreteVersion(version: string): boolean {
  return /^[0-9A-Za-z][\w.+-]*$/.test(version) && version !== 'unknown';
}

// ---------------------------------------------------------------------------
// Delta between two pins
// ---------------------------------------------------------------------------

export interface DeltaMatch extends AdvisoryMatch {
  baselineVersions: string[];
  headVersions: string[];
}

export interface AdvisoryDelta {
  /** Matched at baseline, not at head (keyed by package name and advisory id). */
  removed: DeltaMatch[];
  /** Matched at head, not at baseline. */
  added: DeltaMatch[];
  /** Matched at both. */
  persisting: DeltaMatch[];
}

export interface DependencyDelta {
  added: Dependency[];
  removed: Dependency[];
  changed: Array<{ name: string; from: string[]; to: string[]; head: Dependency[] }>;
}

const byKey = (m: AdvisoryMatch): string => `${m.dependency.ecosystem}\u0000${m.dependency.name}\u0000${m.advisory.id}`;

function group(matches: AdvisoryMatch[]): Map<string, AdvisoryMatch[]> {
  const out = new Map<string, AdvisoryMatch[]>();
  for (const m of matches) {
    const k = byKey(m);
    const list = out.get(k) ?? [];
    list.push(m);
    out.set(k, list);
  }
  return out;
}

const versionsOf = (ms: AdvisoryMatch[] | undefined): string[] =>
  ms ? [...new Set(ms.map((m) => m.dependency.version))].sort(compareForDependency(ms[0].dependency.ecosystem)) : [];

/**
 * Advisory delta between two pins matched under the same records. Each entry
 * is a full match (the head side for `added` and `persisting`, the baseline
 * side for `removed`) carrying the versions seen on both sides.
 */
export function diffAdvisoryMatches(baseline: AdvisoryMatch[], head: AdvisoryMatch[]): AdvisoryDelta {
  const b = group(baseline);
  const h = group(head);
  const delta: AdvisoryDelta = { removed: [], added: [], persisting: [] };
  const keys = [...new Set([...b.keys(), ...h.keys()])].sort();
  for (const k of keys) {
    const bs = b.get(k);
    const hs = h.get(k);
    const base = (hs ?? bs) as AdvisoryMatch[];
    const entry: DeltaMatch = { ...base[0], baselineVersions: versionsOf(bs), headVersions: versionsOf(hs) };
    if (bs && hs) delta.persisting.push(entry);
    else if (bs) delta.removed.push(entry);
    else delta.added.push(entry);
  }
  return delta;
}

/** Resolved-set drift between two pins, by package name. */
export function diffDependencySets(baseline: Dependency[], head: Dependency[]): DependencyDelta {
  const index = (deps: Dependency[]): Map<string, Dependency[]> => {
    const m = new Map<string, Dependency[]>();
    for (const d of deps) {
      const k = `${d.ecosystem}\u0000${d.name}`;
      m.set(k, [...(m.get(k) ?? []), d]);
    }
    return m;
  };
  const b = index(baseline);
  const h = index(head);
  const out: DependencyDelta = { added: [], removed: [], changed: [] };
  for (const key of [...new Set([...b.keys(), ...h.keys()])].sort()) {
    const bs = b.get(key);
    const hs = h.get(key);
    if (!bs) out.added.push(...(hs as Dependency[]));
    else if (!hs) out.removed.push(...bs);
    else {
      const order = compareForDependency(hs[0].ecosystem);
      const from = [...new Set(bs.map((d) => d.version))].sort(order);
      const to = [...new Set(hs.map((d) => d.version))].sort(order);
      if (from.join('\u0000') !== to.join('\u0000')) out.changed.push({ name: hs[0].name, from, to, head: hs });
    }
  }
  return out;
}
