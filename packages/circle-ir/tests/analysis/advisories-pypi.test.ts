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
import {
  parsePoetryLockDependencies,
  parsePypiDependencies,
  parsePyprojectDependencies,
  type Dependency,
} from '../../src/analysis/sbom.js';

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
  it('honours explicit version lists under normalised names, by PEP 440 equality (#1127)', () => {
    // The list holds "1.0"; PEP 440 calls 1.0, 1.0.0 and 1 the same version.
    for (const v of ['1.0', '1.0.0', '1', '0!1.0', 'v1.0']) {
      expect([v, matchAdvisories([py('Listed.Pkg', v)], INDEX)[0]?.affected.viaVersionsList]).toEqual([v, true]);
    }
    expect(ids([py('Listed.Pkg', '1.0.post1'), py('Listed.Pkg', '1.0+local'), py('Listed.Pkg', '1.0rc1')])).toEqual([]);
  });
  it('never matches specifiers, non-versions or other ecosystems', () => {
    expect(ids([py('requests', '>=2.0'), py('requests', 'unknown'), py('requests', 'latest')])).toEqual([]);
    const npmRequests: Dependency = { name: 'requests', version: '2.28.1', ecosystem: 'npm', scope: 'required', purl: 'pkg:npm/requests@2.28.1' };
    expect(ids([npmRequests])).toEqual([]);
  });
  it('never takes a declared lower bound for the installed version (#1127)', () => {
    const req = ['requests>=2.0', 'requests~=2.28', 'requests>=2.28,<3', 'requests==2.*', 'requests==2.28.1'].join('\n');
    expect(ids(parsePypiDependencies(req))).toEqual(['requests@2.28.1 GHSA-j8r2-6x86-q33q']);
    const pyproject = ['[project]', 'dependencies = [', '  "flask>=2.0",', '  "requests (>=2.0)",', ']'].join('\n');
    expect(ids(parsePyprojectDependencies(pyproject))).toEqual([]);
  });
  it('matches pins in a hashed requirements file (#1131 review)', () => {
    const req = [
      'requests==2.28.1 \\',
      '    --hash=sha256:abc \\',
      '    --hash=sha256:def',
      'requests == 2.28.1 --hash=sha256:abc',
      'requests==2.28.1 ; python_version >= "3.8"  # pinned',
    ].join('\n');
    expect(ids(parsePypiDependencies(req))).toEqual([
      'requests@2.28.1 GHSA-j8r2-6x86-q33q',
      'requests@2.28.1 GHSA-j8r2-6x86-q33q',
      'requests@2.28.1 GHSA-j8r2-6x86-q33q',
    ]);
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

describe('epochs and edge bounds (PyPI, #1127)', () => {
  const rec = (id: string, name: string, events: Array<Record<string, string>>, versions?: string[]): OsvRecord => ({
    id,
    modified: '2024-05-01T00:00:00Z',
    affected: [{ package: { ecosystem: 'PyPI', name }, ranges: [{ type: 'ECOSYSTEM', events }], ...(versions ? { versions } : {}) }],
  });
  const idx = buildAdvisoryIndex(
    [
      rec('TEST-EP-1', 'ep', [{ introduced: '0' }, { fixed: '1!1.0' }]),
      rec('TEST-LA-1', 'la', [{ introduced: '1.0' }, { last_affected: '2.0' }]),
      rec('TEST-IN-1', 'intro', [{ introduced: '2.0' }, { fixed: '3.0' }]),
      { id: 'TEST-VL-2', modified: '2024-05-01T00:00:00Z', affected: [{ package: { ecosystem: 'PyPI', name: 'pre' }, versions: ['1.0rc1'] }] },
    ],
    'PyPI',
  );
  const hit = (name: string, version: string): string[] => matchAdvisories([py(name, version)], idx).map((m) => m.advisory.id);

  it('matches a dependency with an epoch', () => {
    expect(hit('ep', '1!0.5')).toEqual(['TEST-EP-1']);
    expect(hit('ep', '0!2.0')).toEqual(['TEST-EP-1']); // epoch 0 is the default, below 1!
    expect(hit('ep', '2.0')).toEqual(['TEST-EP-1']);
    expect(hit('ep', '1!1.0')).toEqual([]);
    expect(hit('ep', '1!0.0.post1')).toEqual(['TEST-EP-1']);
    expect(matchAdvisories([py('ep', '1!0.5')], idx)[0].fixedIn).toEqual(['1!1.0']);
  });
  it('compares a versions list by PEP 440 equality, whatever the spelling', () => {
    for (const v of ['1.0rc1', '1.0c1', '1.0.0rc1', '1.0RC1', '1.0-rc.1', '1.0.0-c1']) expect([v, hit('pre', v)]).toEqual([v, ['TEST-VL-2']]);
    expect(hit('pre', '1.0rc2')).toEqual([]);
    expect(hit('pre', '1.0')).toEqual([]);
  });
  it('excludes a post or local version above last_affected', () => {
    expect(hit('la', '2.0')).toEqual(['TEST-LA-1']);
    expect(hit('la', '2.0.0')).toEqual(['TEST-LA-1']);
    expect(hit('la', '2.0.post1')).toEqual([]);
    expect(hit('la', '2.0+local')).toEqual([]);
  });
  it('excludes a dev or pre release just below introduced', () => {
    expect(hit('intro', '2.0.dev1')).toEqual([]);
    expect(hit('intro', '2.0rc1')).toEqual([]);
    expect(hit('intro', '2.0')).toEqual(['TEST-IN-1']);
    expect(hit('intro', '3.0.dev1')).toEqual(['TEST-IN-1']); // a dev release of the fix is still before it
  });
  it('never matches a version with whitespace or a specifier operator', () => {
    expect(hit('ep', ' 1.0')).toEqual([]);
    expect(hit('ep', '1.0 ')).toEqual([]);
    expect(hit('ep', '!1.0')).toEqual([]);
    expect(hit('ep', '==1.0')).toEqual([]);
  });
});
