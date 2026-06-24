/**
 * Unit tests for `isPubliclyPublished` — strict public-registry allowlist
 * (3.106.0, #169). Pillar I: no LLM identifiers. Corporate Nexus /
 * Artifactory must NOT count as public per ADR-008.
 */

import { describe, test, expect } from 'bun:test';
import {
  isPubliclyPublished,
  PUBLIC_REGISTRY_HOSTS_LIST,
} from '../src/publication-detect.js';

describe('isPubliclyPublished', () => {
  test('empty input → false', () => {
    expect(isPubliclyPublished([])).toBe(false);
  });

  test('Maven Central → true', () => {
    expect(isPubliclyPublished(['https://repo.maven.apache.org/maven2/'])).toBe(true);
    expect(isPubliclyPublished(['https://repo1.maven.org/maven2/'])).toBe(true);
  });

  test('Sonatype OSSRH → true', () => {
    expect(isPubliclyPublished(['https://oss.sonatype.org/content/repositories/snapshots/'])).toBe(true);
    expect(isPubliclyPublished(['https://s01.oss.sonatype.org/content/repositories/releases/'])).toBe(true);
    expect(isPubliclyPublished(['https://central.sonatype.com/'])).toBe(true);
  });

  test('Gradle Plugins Portal → true', () => {
    expect(isPubliclyPublished(['https://plugins.gradle.org/m2/'])).toBe(true);
  });

  test('Legacy Bintray jcenter → true', () => {
    expect(isPubliclyPublished(['https://jcenter.bintray.com/'])).toBe(true);
  });

  test('corporate Nexus → false (key threat-model invariant)', () => {
    expect(isPubliclyPublished(['https://nexus.acme.internal/repository/maven-releases/'])).toBe(false);
  });

  test('corporate Artifactory → false', () => {
    expect(isPubliclyPublished(['https://artifactory.example.com/libs-release/'])).toBe(false);
  });

  test('GitHub Packages → false (not in strict allowlist)', () => {
    expect(isPubliclyPublished(['https://maven.pkg.github.com/owner/repo'])).toBe(false);
  });

  test('case-insensitive host matching', () => {
    expect(isPubliclyPublished(['https://Repo.Maven.Apache.Org/maven2/'])).toBe(true);
  });

  test('malformed URLs are silently skipped', () => {
    expect(isPubliclyPublished(['not a url', 'https://repo.maven.apache.org/'])).toBe(true);
    expect(isPubliclyPublished(['not a url at all'])).toBe(false);
  });

  test('mixed URLs: any public match wins', () => {
    expect(isPubliclyPublished([
      'https://nexus.internal/repo/',
      'https://repo1.maven.org/maven2/',
    ])).toBe(true);
  });

  test('exposed PUBLIC_REGISTRY_HOSTS_LIST contains the canonical set', () => {
    expect(PUBLIC_REGISTRY_HOSTS_LIST.has('repo.maven.apache.org')).toBe(true);
    expect(PUBLIC_REGISTRY_HOSTS_LIST.has('plugins.gradle.org')).toBe(true);
    // Pillar I: must NOT contain LLM-themed hosts.
    for (const h of PUBLIC_REGISTRY_HOSTS_LIST) {
      expect(h).not.toMatch(/llm|ai|verify/i);
    }
  });
});
