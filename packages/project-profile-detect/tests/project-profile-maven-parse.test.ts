/**
 * Unit tests for `parseMavenPom` — regex-based pom.xml extractor
 * (3.106.0, #169). Pillar I: no LLM identifiers.
 */

import { describe, test, expect } from 'bun:test';
import { parseMavenPom } from '../src/maven-parse.js';
import type { ModuleSignals } from '../src/types.js';

const emptyDirSignals: ModuleSignals = {
  plugins: [],
  distributionUrls: [],
  hasJpmsModuleInfo: false,
  hasSpiServices: false,
  hasMainMethod: false,
};

describe('parseMavenPom', () => {
  test('extracts groupId / artifactId / version', () => {
    const xml = `<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-lib</artifactId>
  <version>1.2.3</version>
</project>`;
    const m = parseMavenPom(xml, '/repo', '/repo/pom.xml', emptyDirSignals);
    expect(m.groupId).toBe('com.example');
    expect(m.artifactId).toBe('my-lib');
    expect(m.version).toBe('1.2.3');
    expect(m.buildSystem).toBe('maven');
    expect(m.root).toBe('/repo');
  });

  test('parent block does not shadow module coords', () => {
    const xml = `<project>
  <parent>
    <groupId>org.parent</groupId>
    <artifactId>parent-pom</artifactId>
    <version>99.99.99</version>
  </parent>
  <groupId>com.child</groupId>
  <artifactId>child-mod</artifactId>
  <version>1.0.0</version>
</project>`;
    const m = parseMavenPom(xml, '/repo', '/repo/pom.xml', emptyDirSignals);
    expect(m.groupId).toBe('com.child');
    expect(m.artifactId).toBe('child-mod');
    expect(m.version).toBe('1.0.0');
  });

  test('detects spring-boot via spring-boot-starter-parent', () => {
    const xml = `<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>my-app</artifactId>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.plugins).toContain('spring-boot');
  });

  test('detects spring-boot via spring-boot-maven-plugin', () => {
    const xml = `<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.plugins).toContain('spring-boot');
  });

  test('packaging=war → war plugin tag', () => {
    const xml = `<project>
  <packaging>war</packaging>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.packaging).toBe('war');
    expect(m.signals.plugins).toContain('war');
  });

  test('packaging=ear → ear plugin tag', () => {
    const xml = `<project><packaging>ear</packaging></project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.plugins).toContain('ear');
  });

  test('packaging=maven-plugin → maven-plugin tag', () => {
    const xml = `<project><packaging>maven-plugin</packaging></project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.plugins).toContain('maven-plugin');
  });

  test('exec-maven-plugin → application tag', () => {
    const xml = `<project>
  <build><plugins>
    <plugin><artifactId>exec-maven-plugin</artifactId></plugin>
  </plugins></build>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.plugins).toContain('application');
  });

  test('distributionManagement URLs are extracted', () => {
    const xml = `<project>
  <distributionManagement>
    <repository>
      <id>central</id>
      <url>https://repo1.maven.org/maven2/</url>
    </repository>
    <snapshotRepository>
      <id>oss</id>
      <url>https://oss.sonatype.org/content/repositories/snapshots/</url>
    </snapshotRepository>
  </distributionManagement>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.distributionUrls).toContain('https://repo1.maven.org/maven2/');
    expect(m.signals.distributionUrls).toContain('https://oss.sonatype.org/content/repositories/snapshots/');
  });

  test('unknown plugin artifactIds are silently ignored', () => {
    const xml = `<project>
  <build><plugins>
    <plugin><artifactId>random-plugin</artifactId></plugin>
  </plugins></build>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.plugins).toEqual([]);
  });

  test('directory signals are merged through', () => {
    const dirSig: ModuleSignals = {
      plugins: ['java-library'],
      distributionUrls: [],
      hasJpmsModuleInfo: true,
      hasSpiServices: true,
      hasMainMethod: false,
    };
    const m = parseMavenPom('<project><packaging>jar</packaging></project>', '/r', '/r/pom.xml', dirSig);
    expect(m.signals.hasJpmsModuleInfo).toBe(true);
    expect(m.signals.hasSpiServices).toBe(true);
    expect(m.signals.plugins).toContain('java-library');
  });

  test('malformed XML returns partial result without throwing', () => {
    const m = parseMavenPom('not xml at all', '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.root).toBe('/r');
    expect(m.buildSystem).toBe('maven');
    expect(m.groupId).toBeUndefined();
  });
});
