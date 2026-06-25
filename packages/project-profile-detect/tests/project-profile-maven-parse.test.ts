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

  test('central-publishing-maven-plugin synthesizes a Sonatype Central URL', () => {
    const xml = `<project>
  <build><plugins>
    <plugin>
      <groupId>org.sonatype.central</groupId>
      <artifactId>central-publishing-maven-plugin</artifactId>
      <version>0.10.0</version>
    </plugin>
  </plugins></build>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.distributionUrls).toContain('https://central.sonatype.com/');
  });

  test('nexus-staging-maven-plugin synthesizes an OSSRH URL', () => {
    const xml = `<project>
  <build><plugins>
    <plugin>
      <groupId>org.sonatype.plugins</groupId>
      <artifactId>nexus-staging-maven-plugin</artifactId>
    </plugin>
  </plugins></build>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.signals.distributionUrls).toContain('https://oss.sonatype.org/');
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

describe('parseMavenPom — parentRef extraction (#192, 1.1.0)', () => {
  test('extracts groupId/artifactId/version/relativePath from <parent>', () => {
    const xml = `<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-pom</artifactId>
    <version>1.2.3</version>
    <relativePath>../parent/pom.xml</relativePath>
  </parent>
  <artifactId>child</artifactId>
</project>`;
    const m = parseMavenPom(xml, '/r/child', '/r/child/pom.xml', emptyDirSignals);
    expect(m.parentRef).toBeDefined();
    expect(m.parentRef!.groupId).toBe('com.example');
    expect(m.parentRef!.artifactId).toBe('parent-pom');
    expect(m.parentRef!.version).toBe('1.2.3');
    expect(m.parentRef!.relativePath).toBe('../parent/pom.xml');
    expect(m.parentRef!.emptyRelativePath).toBe(false);
  });

  test('self-closing <relativePath/> marks emptyRelativePath true', () => {
    const xml = `<project>
  <parent>
    <groupId>g</groupId>
    <artifactId>a</artifactId>
    <version>1</version>
    <relativePath/>
  </parent>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.parentRef).toBeDefined();
    expect(m.parentRef!.emptyRelativePath).toBe(true);
    expect(m.parentRef!.relativePath).toBeUndefined();
  });

  test('empty <relativePath></relativePath> marks emptyRelativePath true', () => {
    const xml = `<project>
  <parent>
    <groupId>g</groupId>
    <artifactId>a</artifactId>
    <version>1</version>
    <relativePath></relativePath>
  </parent>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.parentRef!.emptyRelativePath).toBe(true);
  });

  test('missing <relativePath> tag defaults (caller resolves to ../pom.xml)', () => {
    const xml = `<project>
  <parent>
    <groupId>g</groupId>
    <artifactId>a</artifactId>
    <version>1</version>
  </parent>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.parentRef).toBeDefined();
    expect(m.parentRef!.relativePath).toBeUndefined();
    expect(m.parentRef!.emptyRelativePath).toBe(false);
  });

  test('no <parent> block → parentRef undefined', () => {
    const xml = `<project>
  <artifactId>standalone</artifactId>
</project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', emptyDirSignals);
    expect(m.parentRef).toBeUndefined();
  });
});
