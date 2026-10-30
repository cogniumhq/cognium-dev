/**
 * Advisory matching over hand-written OSV records (tests/fixtures/osv-maven).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  parseOsvRecord,
  buildAdvisoryIndex,
  matchAdvisories,
  rangeIntervals,
  diffAdvisoryMatches,
  diffDependencySets,
  isConcreteVersion,
  type OsvRecord,
} from '../../src/analysis/advisories.js';
import { parseMavenResolvedDependencies, type Dependency } from '../../src/analysis/sbom.js';

const DIR = fileURLToPath(new URL('../fixtures/osv-maven/', import.meta.url));
const RECORDS: OsvRecord[] = readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => parseOsvRecord(readFileSync(DIR + f, 'utf-8')))
  .filter((r): r is OsvRecord => r !== null);
const INDEX = buildAdvisoryIndex(RECORDS);

const mvn = (name: string, version: string, extra: Partial<Dependency> = {}): Dependency => ({
  name, version, ecosystem: 'maven', scope: 'required', purl: `pkg:maven/${name.replace(':', '/')}@${version}`, ...extra,
});
const ids = (deps: Dependency[]): string[] => matchAdvisories(deps, INDEX).map((m) => `${m.dependency.name}@${m.dependency.version} ${m.advisory.id}`);

describe('parseOsvRecord', () => {
  it('accepts text or a parsed value and rejects non-records', () => {
    expect(parseOsvRecord('{"id":"X","modified":"2024-01-01T00:00:00Z"}')?.id).toBe('X');
    expect(parseOsvRecord({ id: 'Y', modified: '2024' })?.id).toBe('Y');
    expect(parseOsvRecord('not json')).toBeNull();
    expect(parseOsvRecord({ id: 'Z' })).toBeNull();
    expect(parseOsvRecord(null)).toBeNull();
  });
});

describe('buildAdvisoryIndex', () => {
  it('counts live Maven records, dates the snapshot by its data, lists withdrawn ids', () => {
    expect(INDEX.records).toBe(8); // 10 records − 1 withdrawn − 1 npm
    expect(INDEX.snapshotDate).toBe('2025-03-01T00:00:00Z');
    expect(INDEX.withdrawn).toEqual([{ id: 'TEST-WD-0001', aliases: ['CVE-2099-0001'], withdrawnAt: '2025-03-01T00:00:00Z' }]);
    expect(INDEX.byPackage.has('left-pad')).toBe(false);
  });

  it('merges records that share an alias into one vulnerability, GHSA id first', () => {
    const log4j = INDEX.byPackage.get('org.apache.logging.log4j:log4j-core') ?? [];
    const g = log4j.find((x) => x.aliases.includes('CVE-2021-44228'));
    expect(g?.id).toBe('GHSA-jfh8-c2jp-5v3q');
    expect(g?.aliases).toEqual(['CVE-2021-44228', 'TEST-ALIAS-0001']);
    expect(g?.records).toHaveLength(2);
  });
});

describe('rangeIntervals', () => {
  it('pairs events in version order, whatever order they are written in', () => {
    expect(rangeIntervals({ type: 'ECOSYSTEM', events: [{ fixed: '2.0' }, { introduced: '0' }] })).toEqual([{ introduced: '0', fixed: '2.0' }]);
    expect(rangeIntervals({ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }] })).toEqual([{ introduced: '1.0' }]);
    expect(rangeIntervals({ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { last_affected: '1.2' }, { limit: '9' }] })).toEqual([{ introduced: '1.0', lastAffected: '1.2' }]);
  });
});

describe('matchAdvisories', () => {
  it('matches log4j-core 2.14.1 to the three Log4Shell-era advisories, once each', () => {
    const matches = matchAdvisories([mvn('org.apache.logging.log4j:log4j-core', '2.14.1')], INDEX);
    expect(matches.map((m) => m.advisory.id)).toEqual(['GHSA-7rjr-3q55-vv33', 'GHSA-8489-44mv-ggj8', 'GHSA-jfh8-c2jp-5v3q']);
    const shell = matches.find((m) => m.advisory.id === 'GHSA-jfh8-c2jp-5v3q');
    expect(shell?.advisory.aliases[0]).toBe('CVE-2021-44228');
    expect(shell?.advisory.databaseSeverity).toBe('CRITICAL');
    expect(shell?.advisory.severity[0].type).toBe('CVSS_V3');
    expect(shell?.affected).toEqual({ ranges: [{ introduced: '2.13.0', fixed: '2.15.0' }], viaVersionsList: false });
    expect(shell?.fixedIn).toEqual(['2.15.0']);
    expect(shell?.advisory.references).toEqual(['https://example.org/alias', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228']);
  });

  it('lists every later fixed bound as a fix candidate', () => {
    const [m] = matchAdvisories([mvn('org.apache.logging.log4j:log4j-core', '2.11.0')], INDEX).filter((x) => x.advisory.id === 'GHSA-jfh8-c2jp-5v3q');
    expect(m.fixedIn).toEqual(['2.12.2', '2.15.0']);
  });

  it('treats introduced as inclusive and fixed as exclusive, in Maven order', () => {
    expect(ids([mvn('org.apache.logging.log4j:log4j-core', '2.15.0')])).toEqual([
      'org.apache.logging.log4j:log4j-core@2.15.0 GHSA-7rjr-3q55-vv33',
      'org.apache.logging.log4j:log4j-core@2.15.0 GHSA-8489-44mv-ggj8',
    ]);
    expect(ids([mvn('org.apache.logging.log4j:log4j-core', '2.17.1')])).toEqual([]); // and the withdrawn record never matches
    expect(ids([mvn('org.apache.logging.log4j:log4j-core', '2.0-beta9')])).toHaveLength(3);
    expect(ids([mvn('org.apache.logging.log4j:log4j-core', '2.0-beta8')])).toEqual(['org.apache.logging.log4j:log4j-core@2.0-beta8 GHSA-8489-44mv-ggj8']);
    expect(ids([mvn('org.apache.logging.log4j:log4j-core', '2.15.0-rc1')])).toHaveLength(3); // rc1 sorts before 2.15.0
  });

  it('reads qualifier versions and an introduced "0"', () => {
    expect(ids([mvn('io.netty:netty-codec-http', '4.1.100.Final')])).toHaveLength(1);
    expect(ids([mvn('io.netty:netty-codec-http', '4.1.108.Final')])).toEqual([]);
    expect(ids([mvn('org.yaml:snakeyaml', '1.33')])).toHaveLength(1);
    expect(ids([mvn('org.yaml:snakeyaml', '2.0')])).toEqual([]);
  });

  it('closes a range with last_affected inclusively', () => {
    expect(ids([mvn('com.fasterxml.jackson.core:jackson-databind', '2.13.2')])).toHaveLength(1);
    expect(ids([mvn('com.fasterxml.jackson.core:jackson-databind', '2.13.2.1')])).toEqual([]);
    const [m] = matchAdvisories([mvn('com.fasterxml.jackson.core:jackson-databind', '2.13.1')], INDEX);
    expect(m.fixedIn).toEqual([]);
  });

  it('matches an explicit versions list', () => {
    const [m] = matchAdvisories([mvn('org.example:listed', '1.0.1')], INDEX);
    expect(m.affected.viaVersionsList).toBe(true);
    expect(ids([mvn('org.example:listed', '1.0.2')])).toEqual([]);
  });

  it('never matches a version that is not concrete', () => {
    expect(ids([mvn('org.yaml:snakeyaml', 'unknown'), mvn('org.yaml:snakeyaml', '${snakeyaml.version}'), mvn('org.yaml:snakeyaml', '[1.0,2.0)')])).toEqual([]);
    expect(isConcreteVersion('1.33')).toBe(true);
    expect(isConcreteVersion('unknown')).toBe(false);
  });
});

const tree = (log4j: string, extra = ''): string => `[INFO] com.example:demo:jar:1.0
[INFO] +- org.apache.logging.log4j:log4j-core:jar:${log4j}:compile
[INFO] |  \\- org.apache.logging.log4j:log4j-api:jar:${log4j}:compile
[INFO] +- io.netty:netty-codec-http:jar:4.1.108.Final:compile${extra}
[INFO] \\- junit:junit:jar:4.13.2:test
`;

describe('the proof pair', () => {
  it('a bump to 2.17.1 removes all three advisories and adds none', () => {
    const base = parseMavenResolvedDependencies(tree('2.14.1'));
    const head = parseMavenResolvedDependencies(tree('2.17.1'));
    const delta = diffAdvisoryMatches(matchAdvisories(base, INDEX), matchAdvisories(head, INDEX));
    expect(delta.removed.map((m) => m.advisory.id)).toEqual(['GHSA-7rjr-3q55-vv33', 'GHSA-8489-44mv-ggj8', 'GHSA-jfh8-c2jp-5v3q']);
    expect(delta.added).toEqual([]);
    expect(delta.persisting).toEqual([]);
    const shell = delta.removed.find((m) => m.advisory.id === 'GHSA-jfh8-c2jp-5v3q');
    expect(shell?.advisory.aliases).toContain('CVE-2021-44228');
    expect(shell?.baselineVersions).toEqual(['2.14.1']);
    expect(shell?.headVersions).toEqual([]);
    expect(shell?.dependency.direct).toBe(true);
  });

  it('a bump to 2.16.0 that pulls in snakeyaml shows persisting and added, with paths', () => {
    const base = parseMavenResolvedDependencies(tree('2.14.1'));
    const head = parseMavenResolvedDependencies(
      tree('2.16.0', '\n[INFO] |  \\- org.yaml:snakeyaml:jar:1.33:compile'),
    );
    const delta = diffAdvisoryMatches(matchAdvisories(base, INDEX), matchAdvisories(head, INDEX));
    expect(delta.removed.map((m) => m.advisory.id)).toEqual(['GHSA-7rjr-3q55-vv33', 'GHSA-jfh8-c2jp-5v3q']);
    expect(delta.persisting.map((m) => [m.advisory.id, m.baselineVersions, m.headVersions])).toEqual([
      ['GHSA-8489-44mv-ggj8', ['2.14.1'], ['2.16.0']],
    ]);
    expect(delta.added).toHaveLength(1);
    expect(delta.added[0].advisory.aliases).toEqual(['CVE-2022-1471']);
    expect(delta.added[0].dependency.via).toEqual(['io.netty:netty-codec-http']);
    expect(delta.added[0].dependency.direct).toBe(false);

    const drift = diffDependencySets(base, head);
    expect(drift.added.map((d) => d.name)).toEqual(['org.yaml:snakeyaml']);
    expect(drift.removed).toEqual([]);
    expect(drift.changed.map((c) => [c.name, c.from, c.to])).toEqual([
      ['org.apache.logging.log4j:log4j-api', ['2.14.1'], ['2.16.0']],
      ['org.apache.logging.log4j:log4j-core', ['2.14.1'], ['2.16.0']],
    ]);
  });

  it('removing the vulnerable coordinate altogether is a removal', () => {
    const delta = diffAdvisoryMatches(matchAdvisories([mvn('org.yaml:snakeyaml', '1.33')], INDEX), []);
    expect(delta.removed.map((m) => m.advisory.id)).toEqual(['GHSA-mjmj-j48q-9wg2']);
    expect(diffDependencySets([mvn('org.yaml:snakeyaml', '1.33')], []).removed).toHaveLength(1);
  });
});
