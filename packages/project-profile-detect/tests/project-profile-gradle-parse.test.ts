/**
 * Unit tests for `parseGradleBuild` — regex-based Gradle/Kotlin-DSL parser
 * (3.106.0, #169). Pillar I: no LLM identifiers.
 */

import { describe, test, expect } from 'bun:test';
import { parseGradleBuild } from '../src/gradle-parse.js';
import type { ModuleSignals } from '../src/types.js';

const emptyDirSignals: ModuleSignals = {
  plugins: [],
  distributionUrls: [],
  hasJpmsModuleInfo: false,
  hasSpiServices: false,
  hasMainMethod: false,
};

describe('parseGradleBuild — Groovy DSL', () => {
  test('detects plugins via plugins { id ... } block', () => {
    const text = `
plugins {
  id 'java-library'
  id 'maven-publish'
}
group = 'com.example'
version = '1.0.0'
`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toContain('java-library');
    expect(m.signals.plugins).toContain('maven-publish');
    expect(m.groupId).toBe('com.example');
    expect(m.version).toBe('1.0.0');
    expect(m.buildSystem).toBe('gradle');
  });

  test('detects legacy apply plugin syntax', () => {
    const text = `apply plugin: 'java-library'\napply plugin: 'application'`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toContain('java-library');
    expect(m.signals.plugins).toContain('application');
  });

  test('spring-boot plugin → spring-boot tag', () => {
    const text = `plugins { id 'org.springframework.boot' version '3.2.0' }`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toContain('spring-boot');
  });

  test('war plugin → war tag', () => {
    const text = `plugins { id 'war' }`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toContain('war');
  });

  test('java-gradle-plugin → gradle-plugin tag', () => {
    const text = `plugins { id 'java-gradle-plugin' }`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toContain('gradle-plugin');
  });

  test('extracts publishing repository URLs', () => {
    const text = `
publishing {
  repositories {
    maven {
      url = uri('https://oss.sonatype.org/service/local/staging/deploy/maven2/')
    }
  }
}`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.distributionUrls).toContain('https://oss.sonatype.org/service/local/staging/deploy/maven2/');
  });

  test('artifactId falls back to module directory name', () => {
    const m = parseGradleBuild('', '/repo/my-module', '/repo/my-module/build.gradle', 'gradle', emptyDirSignals);
    expect(m.artifactId).toBe('my-module');
  });

  test('unknown plugin ids are silently ignored', () => {
    const text = `plugins { id 'com.example.unknown-plugin' }`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toEqual([]);
  });

  test('plugin inside block comment is ignored', () => {
    const text = `
/*
plugins { id 'spring-boot' }
*/
plugins { id 'java-library' }
`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle', 'gradle', emptyDirSignals);
    expect(m.signals.plugins).toContain('java-library');
    expect(m.signals.plugins).not.toContain('spring-boot');
  });
});

describe('parseGradleBuild — Kotlin DSL', () => {
  test('detects plugins via id("...") syntax', () => {
    const text = `
plugins {
  id("java-library")
  id("maven-publish")
}
group = "com.example"
version = "2.0.0"
`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle.kts', 'gradle-kts', emptyDirSignals);
    expect(m.signals.plugins).toContain('java-library');
    expect(m.signals.plugins).toContain('maven-publish');
    expect(m.groupId).toBe('com.example');
    expect(m.version).toBe('2.0.0');
    expect(m.buildSystem).toBe('gradle-kts');
  });

  test('Kotlin-DSL Spring Boot plugin', () => {
    const text = `plugins { id("org.springframework.boot") version "3.2.0" }`;
    const m = parseGradleBuild(text, '/r', '/r/build.gradle.kts', 'gradle-kts', emptyDirSignals);
    expect(m.signals.plugins).toContain('spring-boot');
  });

  test('directory signals are merged through', () => {
    const dirSig: ModuleSignals = {
      plugins: ['from-dir'],
      distributionUrls: ['https://from-dir.example.com'],
      hasJpmsModuleInfo: true,
      hasSpiServices: false,
      hasMainMethod: true,
    };
    const m = parseGradleBuild('', '/r', '/r/build.gradle', 'gradle', dirSig);
    expect(m.signals.plugins).toContain('from-dir');
    expect(m.signals.hasJpmsModuleInfo).toBe(true);
    expect(m.signals.hasMainMethod).toBe(true);
    expect(m.signals.distributionUrls).toContain('https://from-dir.example.com');
  });
});
