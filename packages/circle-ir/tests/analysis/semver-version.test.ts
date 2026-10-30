import { describe, it, expect } from 'vitest';
import { compareSemver, parseSemver } from '../../src/analysis/semver-version.js';

describe('parseSemver', () => {
  it('parses full, short and prefixed versions', () => {
    expect(parseSemver('1.2.3')).toEqual({ major: 1, minor: 2, patch: 3, prerelease: [] });
    expect(parseSemver('v2.0.0-rc.1+build.5')).toEqual({ major: 2, minor: 0, patch: 0, prerelease: ['rc', '1'] });
    expect(parseSemver('=1.2')).toEqual({ major: 1, minor: 2, patch: 0, prerelease: [] });
    expect(parseSemver('3')).toEqual({ major: 3, minor: 0, patch: 0, prerelease: [] });
  });
  it('rejects ranges, tags and leading zeros', () => {
    for (const v of ['^1.2.3', '>=1.0.0', 'latest', '1.x', '01.2.3', '1.2.3-', 'npm:foo@1.0.0', '']) {
      expect(parseSemver(v)).toBeNull();
    }
  });
});

describe('compareSemver', () => {
  // The precedence example of semver.org §11, in ascending order.
  const ORDERED = [
    '1.0.0-alpha',
    '1.0.0-alpha.1',
    '1.0.0-alpha.beta',
    '1.0.0-beta',
    '1.0.0-beta.2',
    '1.0.0-beta.11',
    '1.0.0-rc.1',
    '1.0.0',
    '1.0.1',
    '1.1.0',
    '2.0.0',
    '10.0.0',
  ];
  it('orders the specification example', () => {
    for (let i = 0; i < ORDERED.length; i++) {
      for (let j = 0; j < ORDERED.length; j++) {
        expect(Math.sign(compareSemver(ORDERED[i], ORDERED[j]))).toBe(Math.sign(i - j));
      }
    }
  });
  it('ignores build metadata and a leading v', () => {
    expect(compareSemver('1.0.0+a', '1.0.0+b')).toBe(0);
    expect(compareSemver('v1.2.3', '1.2.3')).toBe(0);
    expect(compareSemver('1.2', '1.2.0')).toBe(0);
  });
  it('sorts non-SemVer strings first, as text among themselves', () => {
    expect(compareSemver('latest', '0.0.1')).toBeLessThan(0);
    expect(compareSemver('0.0.1', 'latest')).toBeGreaterThan(0);
    expect(compareSemver('a', 'b')).toBeLessThan(0);
    expect(compareSemver('b', 'b')).toBe(0);
  });
});
