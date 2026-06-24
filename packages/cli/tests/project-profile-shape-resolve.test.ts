/**
 * Unit tests for `resolveShape` — signal precedence + hybrid policy
 * (3.106.0, #169, ADR-008). Pillar I: no LLM identifiers.
 *
 * Precedence (locked):
 *   spring-boot > war/ear > maven-plugin/gradle-plugin
 *     > application plugin > main()
 *     > java-library/JPMS/SPI (gated by public-registry distribution)
 *     > unknown
 */

import { describe, test, expect } from 'bun:test';
import { resolveShape } from '../src/project-profile-detect/shape-resolve.js';
import type { BuildModule, ModuleSignals } from '../src/project-profile-detect/types.js';

const emptySignals: ModuleSignals = {
  plugins: [],
  distributionUrls: [],
  hasJpmsModuleInfo: false,
  hasSpiServices: false,
  hasMainMethod: false,
};

const mod = (overrides: Partial<ModuleSignals>): BuildModule => ({
  root: '/repo/mod',
  buildSystem: 'maven',
  buildFile: '/repo/mod/pom.xml',
  signals: { ...emptySignals, ...overrides },
});

describe('resolveShape — single-signal cases', () => {
  test('spring-boot → server', () => {
    const r = resolveShape(mod({ plugins: ['spring-boot'] }));
    expect(r.shape).toBe('server');
    expect(r.reasons.join(',')).toContain('spring-boot');
  });

  test('war packaging → server', () => {
    const r = resolveShape(mod({ plugins: ['war'] }));
    expect(r.shape).toBe('server');
  });

  test('ear packaging → server', () => {
    const r = resolveShape(mod({ plugins: ['ear'] }));
    expect(r.shape).toBe('server');
  });

  test('maven-plugin packaging → plugin', () => {
    const r = resolveShape(mod({ plugins: ['maven-plugin'] }));
    expect(r.shape).toBe('plugin');
  });

  test('gradle-plugin → plugin', () => {
    const r = resolveShape(mod({ plugins: ['gradle-plugin'] }));
    expect(r.shape).toBe('plugin');
  });

  test('application plugin → cli', () => {
    const r = resolveShape(mod({ plugins: ['application'] }));
    expect(r.shape).toBe('cli');
  });

  test('main() only → application (not cli)', () => {
    const r = resolveShape(mod({ hasMainMethod: true }));
    expect(r.shape).toBe('application');
    expect(r.reasons.join(',')).toContain('main(String[])');
  });

  test('no signals → unknown', () => {
    const r = resolveShape(mod({}));
    expect(r.shape).toBe('unknown');
  });
});

describe('resolveShape — library hybrid gate', () => {
  test('java-library + public registry → library', () => {
    const r = resolveShape(mod({
      plugins: ['java-library'],
      distributionUrls: ['https://repo1.maven.org/maven2/'],
    }));
    expect(r.shape).toBe('library');
    expect(r.reasons.join(',')).toContain('public-registry');
  });

  test('java-library + no public registry → application (internal helper)', () => {
    const r = resolveShape(mod({ plugins: ['java-library'] }));
    expect(r.shape).toBe('application');
    expect(r.reasons.join(',')).toContain('internal helper');
  });

  test('java-library + corporate Nexus only → application (Nexus is not public)', () => {
    const r = resolveShape(mod({
      plugins: ['java-library'],
      distributionUrls: ['https://nexus.acme.internal/repo/'],
    }));
    expect(r.shape).toBe('application');
  });

  test('JPMS module-info alone, no publication → application', () => {
    const r = resolveShape(mod({ hasJpmsModuleInfo: true }));
    expect(r.shape).toBe('application');
  });

  test('JPMS module-info + public registry → library', () => {
    const r = resolveShape(mod({
      hasJpmsModuleInfo: true,
      distributionUrls: ['https://repo.maven.apache.org/maven2/'],
    }));
    expect(r.shape).toBe('library');
  });

  test('SPI services + public registry → library', () => {
    const r = resolveShape(mod({
      hasSpiServices: true,
      distributionUrls: ['https://plugins.gradle.org/m2/'],
    }));
    expect(r.shape).toBe('library');
  });
});

describe('resolveShape — precedence ordering', () => {
  test('spring-boot beats java-library + main()', () => {
    const r = resolveShape(mod({
      plugins: ['spring-boot', 'java-library'],
      hasMainMethod: true,
      distributionUrls: ['https://repo1.maven.org/maven2/'],
    }));
    expect(r.shape).toBe('server');
  });

  test('war beats application plugin', () => {
    const r = resolveShape(mod({ plugins: ['war', 'application'] }));
    expect(r.shape).toBe('server');
  });

  test('application plugin beats main()', () => {
    const r = resolveShape(mod({
      plugins: ['application'],
      hasMainMethod: true,
    }));
    expect(r.shape).toBe('cli');
  });

  test('main() beats java-library (since library signal requires hybrid gate)', () => {
    const r = resolveShape(mod({
      plugins: ['java-library'],
      hasMainMethod: true,
      distributionUrls: ['https://repo1.maven.org/maven2/'],
    }));
    expect(r.shape).toBe('application');
  });

  test('maven-plugin beats application plugin', () => {
    const r = resolveShape(mod({ plugins: ['maven-plugin', 'application'] }));
    expect(r.shape).toBe('plugin');
  });
});

describe('resolveShape — Pillar I guard', () => {
  test('reasons never contain LLM-themed words', () => {
    const r = resolveShape(mod({
      plugins: ['spring-boot', 'java-library', 'application'],
      hasJpmsModuleInfo: true,
      hasSpiServices: true,
      hasMainMethod: true,
      distributionUrls: ['https://repo.maven.apache.org/'],
    }));
    for (const reason of r.reasons) {
      expect(reason).not.toMatch(/llm|ai|verify/i);
    }
  });
});
