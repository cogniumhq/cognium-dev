/**
 * npm advisory matching over hand-written OSV records (tests/fixtures/osv-npm).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  parseOsvRecord,
  buildAdvisoryIndex,
  matchAdvisories,
  diffAdvisoryMatches,
  diffDependencySets,
  ADVISORY_ECOSYSTEMS,
  type OsvRecord,
} from '../../src/analysis/advisories.js';
import { parseNpmLockDependencies, type Dependency } from '../../src/analysis/sbom.js';

const DIR = fileURLToPath(new URL('../fixtures/osv-npm/', import.meta.url));
const RECORDS: OsvRecord[] = readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => parseOsvRecord(readFileSync(DIR + f, 'utf-8')))
  .filter((r): r is OsvRecord => r !== null);
const INDEX = buildAdvisoryIndex(RECORDS, 'npm');

const npm = (name: string, version: string, extra: Partial<Dependency> = {}): Dependency => ({
  name, version, ecosystem: 'npm', scope: 'required', purl: `pkg:npm/${name}@${version}`, ...extra,
});
const ids = (deps: Dependency[]): string[] =>
  matchAdvisories(deps, INDEX).map((m) => `${m.dependency.name}@${m.dependency.version} ${m.advisory.id}`);

describe('npm index', () => {
  it('keeps only npm records and dates the snapshot', () => {
    expect(INDEX.ecosystem).toBe('npm');
    expect(INDEX.records).toBe(6); // TEST-MVN-0001 is Maven
    expect(INDEX.snapshotDate).toBe('2024-04-04T00:00:00Z');
    expect([...INDEX.byPackage.keys()].sort()).toEqual(['@scope/pre', 'la-pkg', 'listed', 'lodash', 'semver']);
  });
  it('lists the npm rules', () => {
    expect(ADVISORY_ECOSYSTEMS.npm.rangeTypes).toContain('SEMVER');
    expect(ADVISORY_ECOSYSTEMS.npm.isVersion('1.2.3')).toBe(true);
    expect(ADVISORY_ECOSYSTEMS.npm.isVersion('^1.2.3')).toBe(false);
  });
});

describe('matchAdvisories (npm)', () => {
  it('matches SEMVER ranges in SemVer order, with fixed versions ascending', () => {
    const m = matchAdvisories([npm('lodash', '4.17.15')], INDEX);
    expect(m.map((x) => x.advisory.id)).toEqual(['GHSA-35jh-r3h4-6jhm', 'GHSA-p6mc-m468-83gw']);
    expect(m[0].fixedIn).toEqual(['4.17.21']);
    expect(m[0].advisory.aliases).toEqual(['CVE-2021-23337']);
    expect(m[0].advisory.databaseSeverity).toBe('HIGH');
    expect(m[1].fixedIn).toEqual(['4.17.19']);
  });
  it('does not match at or above the fixed version', () => {
    expect(ids([npm('lodash', '4.17.21')])).toEqual([]);
    expect(ids([npm('lodash', '4.17.19')])).toEqual(['lodash@4.17.19 GHSA-35jh-r3h4-6jhm']);
    expect(ids([npm('lodash', '3.6.9')])).toEqual(['lodash@3.6.9 GHSA-35jh-r3h4-6jhm']);
  });
  it('evaluates multi-branch ranges and offers later fixes', () => {
    const at = (v: string) => matchAdvisories([npm('semver', v)], INDEX);
    expect(at('5.7.1').map((m) => m.fixedIn)).toEqual([['5.7.2', '6.3.1', '7.5.2']]);
    expect(at('5.7.2')).toEqual([]);
    expect(at('6.3.0').map((m) => m.affected.ranges)).toEqual([[{ introduced: '6.0.0', fixed: '6.3.1' }]]);
    expect(at('7.5.2')).toEqual([]);
    expect(at('10.0.0')).toEqual([]); // numeric, not text, order
  });
  it('orders pre-releases before their release', () => {
    expect(ids([npm('@scope/pre', '2.0.0-alpha.0')])).toEqual([]);
    expect(ids([npm('@scope/pre', '2.0.0-beta.3')])).toEqual(['@scope/pre@2.0.0-beta.3 TEST-PRE-0001']);
    expect(ids([npm('@scope/pre', '2.0.0-rc.2')])).toEqual([]);
    expect(ids([npm('@scope/pre', '2.0.0')])).toEqual([]);
  });
  it('honours last_affected and explicit version lists', () => {
    expect(ids([npm('la-pkg', '1.4.0')])).toEqual(['la-pkg@1.4.0 TEST-LA-0002']);
    expect(ids([npm('la-pkg', '1.4.1')])).toEqual([]);
    const listed = matchAdvisories([npm('listed', '0.9.1')], INDEX);
    expect(listed[0].affected.viaVersionsList).toBe(true);
    expect(ids([npm('listed', '0.9.2')])).toEqual([]);
  });
  it('never matches ranges, tags or other ecosystems', () => {
    expect(ids([npm('lodash', '^4.17.0'), npm('lodash', 'latest'), npm('lodash', 'unknown')])).toEqual([]);
    const mavenLodash: Dependency = { name: 'lodash', version: '1.0.0', ecosystem: 'maven', scope: 'required', purl: 'pkg:maven/x/lodash@1.0.0' };
    expect(ids([mavenLodash])).toEqual([]);
  });
  it('matches the exact versions of a package-lock', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { name: 'app' }, 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/semver': { version: '7.5.4' } },
    });
    expect(ids(parseNpmLockDependencies(lock))).toEqual(['lodash@4.17.20 GHSA-35jh-r3h4-6jhm']);
  });
});

describe('deltas (npm)', () => {
  it('reports the fix and keeps versions in SemVer order', () => {
    const base = matchAdvisories([npm('lodash', '4.17.9'), npm('lodash', '4.17.10')], INDEX);
    const head = matchAdvisories([npm('lodash', '4.17.21')], INDEX);
    const d = diffAdvisoryMatches(base, head);
    expect(d.removed.map((x) => x.advisory.id)).toEqual(['GHSA-35jh-r3h4-6jhm', 'GHSA-p6mc-m468-83gw']);
    expect(d.removed[0].baselineVersions).toEqual(['4.17.9', '4.17.10']);
    expect(d.added).toEqual([]);
  });
  it('keeps npm and Maven coordinates of the same name apart', () => {
    const mvnDep: Dependency = { name: 'lodash', version: '1.0.0', ecosystem: 'maven', scope: 'required', purl: 'pkg:maven/x/lodash@1.0.0' };
    const delta = diffDependencySets([npm('lodash', '4.17.9'), mvnDep], [npm('lodash', '4.17.10'), mvnDep]);
    expect(delta.changed).toHaveLength(1);
    expect(delta.changed[0]).toMatchObject({ name: 'lodash', from: ['4.17.9'], to: ['4.17.10'] });
    expect(delta.added).toEqual([]);
    expect(delta.removed).toEqual([]);
  });
});
