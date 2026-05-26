/**
 * Tests for Semver Version Matching
 */

import { describe, it, expect } from 'vitest';
import {
  parseVersion,
  compareVersions,
  semverSatisfies,
  isVersionVulnerable,
} from '../../src/analysis/semver.js';

describe('Semver', () => {
  describe('parseVersion', () => {
    it('should parse simple versions', () => {
      expect(parseVersion('1.2.3')).toEqual({
        major: 1,
        minor: 2,
        patch: 3,
        prerelease: undefined,
      });
    });

    it('should parse versions with leading v', () => {
      expect(parseVersion('v1.2.3')).toEqual({
        major: 1,
        minor: 2,
        patch: 3,
        prerelease: undefined,
      });
    });

    it('should parse prerelease versions', () => {
      expect(parseVersion('1.2.3-alpha')).toEqual({
        major: 1,
        minor: 2,
        patch: 3,
        prerelease: 'alpha',
      });

      expect(parseVersion('2.0.0-beta.1')).toEqual({
        major: 2,
        minor: 0,
        patch: 0,
        prerelease: 'beta.1',
      });
    });

    it('should handle partial versions', () => {
      expect(parseVersion('1')).toEqual({
        major: 1,
        minor: 0,
        patch: 0,
        prerelease: undefined,
      });

      expect(parseVersion('1.2')).toEqual({
        major: 1,
        minor: 2,
        patch: 0,
        prerelease: undefined,
      });
    });

    it('should handle versions with whitespace', () => {
      expect(parseVersion('  1.2.3  ')).toEqual({
        major: 1,
        minor: 2,
        patch: 3,
        prerelease: undefined,
      });
    });
  });

  describe('compareVersions', () => {
    it('should compare major versions', () => {
      expect(compareVersions('2.0.0', '1.0.0')).toBe(1);
      expect(compareVersions('1.0.0', '2.0.0')).toBe(-1);
    });

    it('should compare minor versions', () => {
      expect(compareVersions('1.2.0', '1.1.0')).toBe(1);
      expect(compareVersions('1.1.0', '1.2.0')).toBe(-1);
    });

    it('should compare patch versions', () => {
      expect(compareVersions('1.0.2', '1.0.1')).toBe(1);
      expect(compareVersions('1.0.1', '1.0.2')).toBe(-1);
    });

    it('should return 0 for equal versions', () => {
      expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    });

    it('should handle prerelease vs release', () => {
      // Prerelease is lower than release
      expect(compareVersions('1.0.0-alpha', '1.0.0')).toBe(-1);
      expect(compareVersions('1.0.0', '1.0.0-alpha')).toBe(1);
    });

    it('should compare prerelease versions alphabetically', () => {
      expect(compareVersions('1.0.0-alpha', '1.0.0-beta')).toBe(-1);
      expect(compareVersions('1.0.0-beta', '1.0.0-alpha')).toBe(1);
    });
  });

  describe('semverSatisfies', () => {
    describe('caret range (^)', () => {
      it('should match same major version', () => {
        expect(semverSatisfies('1.2.3', '^1.0.0')).toBe(true);
        expect(semverSatisfies('1.9.9', '^1.0.0')).toBe(true);
      });

      it('should not match different major version', () => {
        expect(semverSatisfies('2.0.0', '^1.0.0')).toBe(false);
        expect(semverSatisfies('0.9.9', '^1.0.0')).toBe(false);
      });

      it('should respect minimum minor/patch', () => {
        expect(semverSatisfies('1.2.0', '^1.2.3')).toBe(false);
        expect(semverSatisfies('1.2.3', '^1.2.3')).toBe(true);
        expect(semverSatisfies('1.2.4', '^1.2.3')).toBe(true);
        expect(semverSatisfies('1.3.0', '^1.2.3')).toBe(true);
      });
    });

    describe('tilde range (~)', () => {
      it('should match same minor version', () => {
        expect(semverSatisfies('1.2.3', '~1.2.0')).toBe(true);
        expect(semverSatisfies('1.2.9', '~1.2.0')).toBe(true);
      });

      it('should not match different minor version', () => {
        expect(semverSatisfies('1.3.0', '~1.2.0')).toBe(false);
        expect(semverSatisfies('1.1.9', '~1.2.0')).toBe(false);
      });

      it('should respect minimum patch', () => {
        expect(semverSatisfies('1.2.2', '~1.2.3')).toBe(false);
        expect(semverSatisfies('1.2.3', '~1.2.3')).toBe(true);
        expect(semverSatisfies('1.2.4', '~1.2.3')).toBe(true);
      });
    });

    describe('comparison operators', () => {
      it('should handle >= comparison', () => {
        expect(semverSatisfies('1.0.0', '>=1.0.0')).toBe(true);
        expect(semverSatisfies('2.0.0', '>=1.0.0')).toBe(true);
        expect(semverSatisfies('0.9.9', '>=1.0.0')).toBe(false);
      });

      it('should handle > comparison', () => {
        expect(semverSatisfies('1.0.1', '>1.0.0')).toBe(true);
        expect(semverSatisfies('1.0.0', '>1.0.0')).toBe(false);
        expect(semverSatisfies('0.9.9', '>1.0.0')).toBe(false);
      });

      it('should handle <= comparison', () => {
        expect(semverSatisfies('1.0.0', '<=1.0.0')).toBe(true);
        expect(semverSatisfies('0.9.9', '<=1.0.0')).toBe(true);
        expect(semverSatisfies('1.0.1', '<=1.0.0')).toBe(false);
      });

      it('should handle < comparison', () => {
        expect(semverSatisfies('0.9.9', '<1.0.0')).toBe(true);
        expect(semverSatisfies('1.0.0', '<1.0.0')).toBe(false);
        expect(semverSatisfies('1.0.1', '<1.0.0')).toBe(false);
      });

      it('should handle = comparison', () => {
        expect(semverSatisfies('1.0.0', '=1.0.0')).toBe(true);
        expect(semverSatisfies('1.0.1', '=1.0.0')).toBe(false);
      });
    });

    describe('range syntax', () => {
      it('should handle range with dash', () => {
        expect(semverSatisfies('1.5.0', '1.0.0 - 2.0.0')).toBe(true);
        expect(semverSatisfies('1.0.0', '1.0.0 - 2.0.0')).toBe(true);
        expect(semverSatisfies('2.0.0', '1.0.0 - 2.0.0')).toBe(true);
        expect(semverSatisfies('0.9.9', '1.0.0 - 2.0.0')).toBe(false);
        expect(semverSatisfies('2.0.1', '1.0.0 - 2.0.0')).toBe(false);
      });
    });

    describe('wildcards', () => {
      it('should match any version with *', () => {
        expect(semverSatisfies('0.0.1', '*')).toBe(true);
        expect(semverSatisfies('99.99.99', '*')).toBe(true);
      });

      it('should match any version with x', () => {
        expect(semverSatisfies('0.0.1', 'x')).toBe(true);
        expect(semverSatisfies('99.99.99', 'x')).toBe(true);
      });
    });

    describe('exact match', () => {
      it('should match exact version', () => {
        expect(semverSatisfies('1.2.3', '1.2.3')).toBe(true);
        expect(semverSatisfies('1.2.4', '1.2.3')).toBe(false);
      });
    });
  });

  describe('isVersionVulnerable', () => {
    it('should return true when version is not patched or unaffected', () => {
      expect(isVersionVulnerable('1.0.0')).toBe(true);
      expect(isVersionVulnerable('1.0.0', [], [])).toBe(true);
    });

    it('should return false when version is in patched range', () => {
      expect(isVersionVulnerable('1.5.0', ['>=1.4.0'])).toBe(false);
      expect(isVersionVulnerable('1.3.0', ['>=1.4.0'])).toBe(true);
    });

    it('should return false when version is in unaffected range', () => {
      expect(isVersionVulnerable('0.9.0', undefined, ['<1.0.0'])).toBe(false);
      expect(isVersionVulnerable('1.0.0', undefined, ['<1.0.0'])).toBe(true);
    });

    it('should check both patched and unaffected', () => {
      // Version 0.5.0 is unaffected (before vuln was introduced)
      expect(isVersionVulnerable('0.5.0', ['>=2.0.0'], ['<1.0.0'])).toBe(false);

      // Version 2.1.0 is patched
      expect(isVersionVulnerable('2.1.0', ['>=2.0.0'], ['<1.0.0'])).toBe(false);

      // Version 1.5.0 is vulnerable (after 1.0.0, before patch)
      expect(isVersionVulnerable('1.5.0', ['>=2.0.0'], ['<1.0.0'])).toBe(true);
    });

    it('should handle multiple patched ranges', () => {
      // Patched in 1.x line at 1.5.0, in 2.x line at 2.3.0
      const patched = ['>=1.5.0', '>=2.3.0'];

      expect(isVersionVulnerable('1.4.0', patched)).toBe(true);  // Before patch
      expect(isVersionVulnerable('1.5.0', patched)).toBe(false); // Patched
      expect(isVersionVulnerable('2.2.0', patched)).toBe(false); // >= 1.5.0
      expect(isVersionVulnerable('2.3.0', patched)).toBe(false); // Patched
    });
  });
});
