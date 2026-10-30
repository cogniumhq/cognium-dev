/**
 * pnpm-lock.yaml (5.x / 6.0 / 9.0) and yarn.lock v1 → exact resolved npm
 * dependencies, with scope by reachability and `direct` (DT4).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  parsePnpmLockDependencies,
  parseYarnLockDependencies,
  pnpmLockImporters,
  collectDependencies,
  type Dependency,
} from '../../src/analysis/sbom.js';
import { buildAdvisoryIndex, matchAdvisories, parseOsvRecord, type OsvRecord } from '../../src/analysis/advisories.js';

const DIR = fileURLToPath(new URL('../fixtures/js-lockfiles/', import.meta.url));
const read = (f: string): string => readFileSync(DIR + f, 'utf-8');
const row = (d: Dependency): string => `${d.name}@${d.version} ${d.scope}${d.direct === undefined ? '' : d.direct ? ' direct' : ''}`;

describe('parsePnpmLockDependencies', () => {
  it('reads a v9 workspace lockfile: importers, snapshots, aliases, links, peers', () => {
    const deps = parsePnpmLockDependencies(read('pnpm-v9.yaml'));
    expect(deps.map(row)).toEqual([
      '@scope/pre@1.0.0 required direct',
      'fsevents@2.3.3 optional direct',
      'lodash@4.17.15 required direct',
      'loose-envify@1.4.0 required',
      'react-dom@18.2.0 required direct',
      'react@18.2.0 required',
      'semver@7.5.1 required direct',
      'string-width@4.2.3 required direct',
      'tinyspy@2.2.0 dev',
      'vitest@1.0.0 dev direct',
    ]);
    expect(deps.every((d) => d.ecosystem === 'npm')).toBe(true);
    expect(deps.find((d) => d.name === '@scope/pre')?.purl).toBe('pkg:npm/%40scope/pre@1.0.0');
    expect(deps.some((d) => d.name === '@acme/lib')).toBe(false); // workspace link is our own code
  });

  it('reads a v6 single-project lockfile and keeps pnpm\'s own dev flag for unreached packages', () => {
    expect(parsePnpmLockDependencies(read('pnpm-v6.yaml')).map(row)).toEqual([
      'lodash@4.17.15 required direct',
      'loose-envify@1.4.0 required',
      'orphan@0.1.0 dev',
      'react-dom@18.2.0 required direct',
      'react@18.2.0 required',
      'tinyspy@2.2.0 dev',
      'vitest@1.0.0 dev direct',
    ]);
  });

  it('reads a v5 lockfile (slash keys, underscore peer suffix)', () => {
    expect(parsePnpmLockDependencies(read('pnpm-v5.yaml')).map(row)).toEqual([
      '@scope/pre@1.0.0 required direct',
      'lodash@4.17.15 required direct',
      'semver@7.5.1 required',
    ]);
  });

  it('collapses peer variants of one version into one entry', () => {
    const lock = [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      a: {specifier: 1.0.0, version: 1.0.0(react@17.0.0)}',
      '      b: {specifier: 1.0.0, version: 1.0.0(react@18.0.0)}',
      'packages:',
      '  a@1.0.0: {}',
      '  b@1.0.0: {}',
      'snapshots:',
      '  a@1.0.0(react@17.0.0): {}',
      '  a@1.0.0(react@18.0.0): {}',
      '  b@1.0.0(react@18.0.0): {}',
    ].join('\n');
    expect(parsePnpmLockDependencies(lock).map(row)).toEqual(['a@1.0.0 required direct', 'b@1.0.0 required direct']);
  });

  it('returns [] for empty or malformed input', () => {
    expect(parsePnpmLockDependencies('')).toEqual([]);
    expect(parsePnpmLockDependencies('a: [unclosed')).toEqual([]);
    expect(parsePnpmLockDependencies('- just\n- a list')).toEqual([]);
  });
});

describe('pnpmLockImporters', () => {
  it('lists workspace importers, or the root for a single project', () => {
    expect(pnpmLockImporters(read('pnpm-v9.yaml'))).toEqual(['.', 'packages/app', 'packages/lib']);
    expect(pnpmLockImporters(read('pnpm-v6.yaml'))).toEqual(['.']);
    expect(pnpmLockImporters('')).toEqual([]);
    expect(pnpmLockImporters('a: [unclosed')).toEqual([]);
  });
});

describe('parseYarnLockDependencies', () => {
  it('without package.json: every package required, direct unknown', () => {
    const deps = parseYarnLockDependencies(read('yarn-v1.lock'));
    expect(deps.map(row)).toEqual([
      '@scope/pre@1.0.0 required',
      'lodash@4.17.15 required',
      'loose-envify@1.4.0 required',
      'react@18.2.0 required',
      'tinyspy@2.2.0 required',
      'vitest@1.0.0 required',
    ]);
    expect(deps.every((d) => d.direct === undefined)).toBe(true);
  });

  it('with package.json: scope and direct by reachability; one entry for several ranges', () => {
    expect(parseYarnLockDependencies(read('yarn-v1.lock'), read('yarn-package.json')).map(row)).toEqual([
      '@scope/pre@1.0.0 required direct',
      'lodash@4.17.15 dev direct',
      'loose-envify@1.4.0 required',
      'react@18.2.0 required direct',
      'tinyspy@2.2.0 dev',
      'vitest@1.0.0 dev direct',
    ]);
  });

  it('skips Yarn Berry files and tolerates bad input', () => {
    expect(parseYarnLockDependencies('__metadata:\n  version: 6\n')).toEqual([]);
    expect(parseYarnLockDependencies('')).toEqual([]);
    expect(parseYarnLockDependencies('garbage line\n  version "1.0.0"\n')).toEqual([]);
    expect(parseYarnLockDependencies(read('yarn-v1.lock'), '{not json').every((d) => d.direct === undefined)).toBe(true);
  });
});

describe('collectDependencies (js precedence, DT4)', () => {
  const pkg = read('yarn-package.json');
  it('pnpm lock > package-lock > yarn lock > package.json', () => {
    const names = (deps: Dependency[]): string[] => deps.map((d) => `${d.name}@${d.version}`).sort();
    expect(names(collectDependencies({ js: { packageJson: pkg, pnpmLock: read('pnpm-v5.yaml'), yarnLock: read('yarn-v1.lock') } })))
      .toEqual(['@scope/pre@1.0.0', 'lodash@4.17.15', 'semver@7.5.1']);
    expect(names(collectDependencies({ js: { packageJson: pkg, yarnLock: read('yarn-v1.lock') } }))).toContain('tinyspy@2.2.0');
    expect(collectDependencies({ js: { packageJson: pkg } }).map((d) => d.version)).toContain('^18.2.0');
  });
  it('is unchanged when no lockfile is supplied', () => {
    expect(collectDependencies({ js: { packageJson: pkg } })).toEqual(collectDependencies({ js: { packageJson: pkg } }));
    expect(collectDependencies({ js: { packageJson: pkg } }).every((d) => d.direct === undefined)).toBe(true);
  });
});

describe('advisory matching over a pnpm lockfile', () => {
  it('matches exact pnpm versions against the npm fixture snapshot', () => {
    const osvDir = fileURLToPath(new URL('../fixtures/osv-npm/', import.meta.url));
    const records: OsvRecord[] = readdirSync(osvDir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => parseOsvRecord(readFileSync(osvDir + f, 'utf-8')))
      .filter((r): r is OsvRecord => r !== null);
    const index = buildAdvisoryIndex(records, 'npm');
    const hits = matchAdvisories(parsePnpmLockDependencies(read('pnpm-v9.yaml')), index);
    expect(hits.some((h) => h.dependency.name === 'lodash' && h.dependency.version === '4.17.15')).toBe(true);
  });
});
