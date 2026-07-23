/**
 * Tests for cognium-dev #261 (npm slice, plumbing) —
 * `resolveDepFromPackageJson`.
 *
 * Parser-only unit tests. No gate consumes this helper today; when a
 * JS deserialization-safety gate is added (deferred pending a real
 * FP-driving JS use case), it will consume this resolver via
 * `AnalyzerOptions.dependencyContext.js.packageJson`.
 */

import { describe, it, expect } from 'vitest';
import { resolveDepFromPackageJson } from '../../src/analysis/dependency-versions.js';

describe('#261 npm slice — resolveDepFromPackageJson', () => {
  it('returns null on empty input', () => {
    expect(resolveDepFromPackageJson('', 'express')).toBeNull();
  });

  it('returns null on empty dep name', () => {
    expect(
      resolveDepFromPackageJson('{"dependencies":{"a":"1"}}', ''),
    ).toBeNull();
  });

  it('returns null on invalid JSON', () => {
    expect(resolveDepFromPackageJson('{ not json', 'x')).toBeNull();
  });

  it('parses from `dependencies` (caret range)', () => {
    const pkg = JSON.stringify({
      name: 'x',
      dependencies: { 'node-serialize': '^0.0.4' },
    });
    expect(resolveDepFromPackageJson(pkg, 'node-serialize')).toEqual({
      version: '^0.0.4',
      section: 'dependencies',
    });
  });

  it('parses from `devDependencies`', () => {
    const pkg = JSON.stringify({
      name: 'x',
      devDependencies: { typescript: '~5.4.5' },
    });
    expect(resolveDepFromPackageJson(pkg, 'typescript')).toEqual({
      version: '~5.4.5',
      section: 'devDependencies',
    });
  });

  it('parses from `peerDependencies`', () => {
    const pkg = JSON.stringify({
      name: 'x',
      peerDependencies: { react: '>=18 <20' },
    });
    expect(resolveDepFromPackageJson(pkg, 'react')).toEqual({
      version: '>=18 <20',
      section: 'peerDependencies',
    });
  });

  it('parses from `optionalDependencies`', () => {
    const pkg = JSON.stringify({
      name: 'x',
      optionalDependencies: { fsevents: '^2.3.3' },
    });
    expect(resolveDepFromPackageJson(pkg, 'fsevents')).toEqual({
      version: '^2.3.3',
      section: 'optionalDependencies',
    });
  });

  it('prefers `dependencies` over `devDependencies` when a dep appears in both', () => {
    const pkg = JSON.stringify({
      name: 'x',
      dependencies: { lodash: '4.17.21' },
      devDependencies: { lodash: 'latest' },
    });
    expect(resolveDepFromPackageJson(pkg, 'lodash')).toEqual({
      version: '4.17.21',
      section: 'dependencies',
    });
  });

  it('handles exact version pins', () => {
    const pkg = JSON.stringify({
      dependencies: { express: '4.19.2' },
    });
    expect(resolveDepFromPackageJson(pkg, 'express')).toEqual({
      version: '4.19.2',
      section: 'dependencies',
    });
  });

  it('handles dist-tag values like `latest`', () => {
    const pkg = JSON.stringify({
      dependencies: { react: 'latest' },
    });
    expect(resolveDepFromPackageJson(pkg, 'react')).toEqual({
      version: 'latest',
      section: 'dependencies',
    });
  });

  it('returns null for git+ URL sources (no version to compare)', () => {
    const pkg = JSON.stringify({
      dependencies: {
        mypkg: 'git+https://github.com/example/mypkg.git#v1.0.0',
      },
    });
    expect(resolveDepFromPackageJson(pkg, 'mypkg')).toBeNull();
  });

  it('returns null for github: shorthand sources', () => {
    const pkg = JSON.stringify({
      dependencies: { mypkg: 'github:example/mypkg' },
    });
    expect(resolveDepFromPackageJson(pkg, 'mypkg')).toBeNull();
  });

  it('returns null for file: sources', () => {
    const pkg = JSON.stringify({
      dependencies: { localpkg: 'file:../localpkg' },
    });
    expect(resolveDepFromPackageJson(pkg, 'localpkg')).toBeNull();
  });

  it('returns null for workspace: sources', () => {
    const pkg = JSON.stringify({
      dependencies: { shared: 'workspace:*' },
    });
    expect(resolveDepFromPackageJson(pkg, 'shared')).toBeNull();
  });

  it('returns null when the dep is absent', () => {
    const pkg = JSON.stringify({
      dependencies: { express: '4.19.2' },
    });
    expect(resolveDepFromPackageJson(pkg, 'lodash')).toBeNull();
  });

  it('returns null when dependencies is not an object (defensive)', () => {
    const pkg = JSON.stringify({ dependencies: 'not-an-object' });
    expect(resolveDepFromPackageJson(pkg, 'x')).toBeNull();
  });

  it('handles scoped packages like `@types/node`', () => {
    const pkg = JSON.stringify({
      devDependencies: { '@types/node': '20.11.30' },
    });
    expect(resolveDepFromPackageJson(pkg, '@types/node')).toEqual({
      version: '20.11.30',
      section: 'devDependencies',
    });
  });
});
