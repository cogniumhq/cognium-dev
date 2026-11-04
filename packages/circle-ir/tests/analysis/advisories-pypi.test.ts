/**
 * PyPI advisory matching over hand-written OSV records (tests/fixtures/osv-pypi).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  parseOsvRecord,
  buildAdvisoryIndex,
  matchAdvisories,
  diffAdvisoryMatches,
  type OsvRecord,
} from '../../src/analysis/advisories.js';
import { parsePoetryLockDependencies, type Dependency } from '../../src/analysis/sbom.js';

const DIR = fileURLToPath(new URL('../fixtures/osv-pypi/', import.meta.url));
const RECORDS: OsvRecord[] = readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => parseOsvRecord(readFileSync(DIR + f, 'utf-8')))
  .filter((r): r is OsvRecord => r !== null);
const INDEX = buildAdvisoryIndex(RECORDS, 'PyPI');

const py = (name: string, version: string): Dependency => ({
  name, version, ecosystem: 'pypi', scope: 'required', purl: `pkg:pypi/${name}@${version}`,
});
const ids = (deps: Dependency[]): string[] =>
  matchAdvisories(deps, INDEX).map((m) => `${m.dependency.name}@${m.dependency.version} ${m.advisory.id}`);

describe('PyPI index', () => {
  it('keeps only PyPI records, under PEP 503 names', () => {
    expect(INDEX.records).toBe(4); // TEST-NPM-0002 is npm
    expect([...INDEX.byPackage.keys()].sort()).toEqual(['flask', 'listed-pkg', 'requests', 'zope-interface']);
  });
});

describe('matchAdvisories (PyPI)', () => {
  it('matches ECOSYSTEM ranges in PEP 440 order', () => {
    const m = matchAdvisories([py('requests', '2.28.1')], INDEX);
    expect(m.map((x) => x.advisory.id)).toEqual(['GHSA-j8r2-6x86-q33q']);
    expect(m[0].fixedIn).toEqual(['2.31.0']);
    expect(m[0].advisory.aliases).toEqual(['CVE-2023-32681']);
    expect(ids([py('requests', '2.31.0'), py('requests', '2.31'), py('requests', '2.2.9')])).toEqual([]);
    expect(ids([py('requests', '2.30.0')])).toEqual(['requests@2.30.0 GHSA-j8r2-6x86-q33q']); // 2.30 > 2.3 numerically
  });
  it('evaluates multi-branch ranges and normalises names on both sides', () => {
    expect(matchAdvisories([py('Flask', '2.2.4')], INDEX).map((m) => m.fixedIn)).toEqual([['2.2.5', '2.3.2']]);
    expect(ids([py('Flask', '2.2.5'), py('flask', '2.3.2')])).toEqual([]);
    expect(ids([py('FLASK', '2.3.1')])).toEqual(['FLASK@2.3.1 GHSA-m2qf-hxjv-5gpq']);
  });
  it('places pre- and post-releases', () => {
    expect(ids([py('zope.interface', '5.0b9')])).toEqual([]);
    expect(ids([py('zope.interface', '5.0rc1')])).toEqual(['zope.interface@5.0rc1 TEST-PEP-0001']);
    expect(ids([py('zope_interface', '5.0')])).toEqual(['zope_interface@5.0 TEST-PEP-0001']);
    expect(ids([py('Zope-Interface', '5.0.post1')])).toEqual([]);
  });
  it('honours explicit version lists under normalised names', () => {
    const m = matchAdvisories([py('Listed.Pkg', '1.0.0')], INDEX);
    expect(m).toEqual([]); // the list holds "1.0" literally; lists are exact strings, as OSV defines them
    expect(matchAdvisories([py('Listed.Pkg', '1.0')], INDEX)[0].affected.viaVersionsList).toBe(true);
  });
  it('never matches specifiers, non-versions or other ecosystems', () => {
    expect(ids([py('requests', '>=2.0'), py('requests', 'unknown'), py('requests', 'latest')])).toEqual([]);
    const npmRequests: Dependency = { name: 'requests', version: '2.28.1', ecosystem: 'npm', scope: 'required', purl: 'pkg:npm/requests@2.28.1' };
    expect(ids([npmRequests])).toEqual([]);
  });
  it('matches the exact versions of a poetry.lock', () => {
    const lock = ['[[package]]', 'name = "requests"', 'version = "2.25.1"', '', '[[package]]', 'name = "Flask"', 'version = "2.3.3"'].join('\n');
    expect(ids(parsePoetryLockDependencies(lock))).toEqual(['requests@2.25.1 GHSA-j8r2-6x86-q33q']);
  });
});

describe('deltas (PyPI)', () => {
  it('orders versions by PEP 440 on both sides', () => {
    const base = matchAdvisories([py('requests', '2.9.0'), py('requests', '2.10.0')], INDEX);
    const d = diffAdvisoryMatches(base, matchAdvisories([py('requests', '2.31.0')], INDEX));
    expect(d.removed).toHaveLength(1);
    expect(d.removed[0].baselineVersions).toEqual(['2.9.0', '2.10.0']);
  });
});
