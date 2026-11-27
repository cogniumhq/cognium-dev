/**
 * Maven `<packaging>` decides each module's shape on its own.
 *
 * A two-module reactor: an aggregator parent (`pom`) that manages
 * `maven-plugin-plugin` and runs an assembly plugin, a `jar` library, and a
 * `maven-plugin` module. Before, every module took the parent's plugin tags
 * and all three resolved to `plugin`.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdir, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { detectProjectProfiles } from '../src/index.js';
import { parseMavenPom } from '../src/maven-parse.js';
import { resolveShape } from '../src/shape-resolve.js';
import type { BuildModule, ModuleSignals } from '../src/types.js';

const dirSig = (): ModuleSignals => ({
  plugins: [], distributionUrls: [],
  hasJpmsModuleInfo: false, hasSpiServices: false, hasMainMethod: false,
});

const PARENT = `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.acme</groupId>
  <artifactId>tools-parent</artifactId>
  <version>1.3</version>
  <packaging>pom</packaging>
  <modules><module>library</module><module>plugin</module></modules>
  <build>
    <pluginManagement>
      <plugins>
        <plugin><artifactId>maven-plugin-plugin</artifactId><version>3.16.0</version></plugin>
        <plugin><artifactId>maven-war-plugin</artifactId><version>3.4.0</version></plugin>
      </plugins>
    </pluginManagement>
    <plugins>
      <plugin><artifactId>maven-assembly-plugin</artifactId></plugin>
    </plugins>
  </build>
</project>`;

const LIBRARY = `<project>
  <artifactId>tools-lib</artifactId>
  <packaging>jar</packaging>
  <parent><groupId>org.acme</groupId><artifactId>tools-parent</artifactId><version>1.3</version></parent>
</project>`;

const PLUGIN = `<project>
  <artifactId>tools-maven-plugin</artifactId>
  <packaging>maven-plugin</packaging>
  <parent><groupId>org.acme</groupId><artifactId>tools-parent</artifactId><version>1.3</version></parent>
  <dependencies>
    <dependency><groupId>org.apache.maven</groupId><artifactId>maven-plugin-api</artifactId><version>3.9.9</version></dependency>
  </dependencies>
</project>`;

const MOJO = `package org.acme.tools;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;
@Mojo(name = "report")
public class ReportMojo extends AbstractMojo {
  public void execute() {}
}
`;

describe('parseMavenPom: packaging and coordinates', () => {
  test('a missing <packaging> is jar', () => {
    const m = parseMavenPom('<project><artifactId>a</artifactId></project>', '/r', '/r/pom.xml', dirSig());
    expect(m.signals.packaging).toBe('jar');
  });

  test('<pluginManagement> applies no plugin', () => {
    const m = parseMavenPom(PARENT, '/r', '/r/pom.xml', dirSig());
    expect(m.signals.packaging).toBe('pom');
    expect(m.signals.plugins).not.toContain('maven-plugin');
    expect(m.signals.plugins).not.toContain('war');
    expect(m.signals.plugins).toContain('application');
  });

  test('a profile\'s build plugins are not the module\'s', () => {
    const xml = `<project><artifactId>a</artifactId>
      <profiles><profile><id>p</id><build><plugins><plugin><artifactId>maven-war-plugin</artifactId></plugin></plugins></build></profile></profiles>
    </project>`;
    const m = parseMavenPom(xml, '/r', '/r/pom.xml', dirSig());
    expect(m.signals.plugins).not.toContain('war');
  });

  test('coordinates come from the project, then the parent; never a dependency', () => {
    const m = parseMavenPom(PLUGIN, '/r/plugin', '/r/plugin/pom.xml', dirSig());
    expect(m.groupId).toBe('org.acme');
    expect(m.artifactId).toBe('tools-maven-plugin');
    expect(m.version).toBe('1.3');
    expect(m.signals.packaging).toBe('maven-plugin');
  });

  test('packaging is read case-insensitively and a commented-out one is ignored', () => {
    const m = parseMavenPom('<project><!-- <packaging>war</packaging> --><packaging>Maven-Plugin</packaging></project>', '/r', '/r/pom.xml', dirSig());
    expect(m.signals.packaging).toBe('maven-plugin');
  });
});

describe('resolveShape: Maven packaging decides first', () => {
  const mod = (packaging: string, plugins: string[] = []): BuildModule => ({
    root: '/r', buildSystem: 'maven', buildFile: '/r/pom.xml',
    signals: { ...dirSig(), plugins, packaging },
  });

  test('pom → no shape (aggregator)', () => {
    const r = resolveShape(mod('pom', ['spring-boot', 'application']));
    expect(r.shape).toBe('unknown');
    expect(r.reasons[0]).toContain('pom packaging');
  });
  test('maven-plugin → plugin', () => {
    expect(resolveShape(mod('maven-plugin', ['application'])).shape).toBe('plugin');
  });
  test('war → server, ear → server', () => {
    expect(resolveShape(mod('war')).shape).toBe('server');
    expect(resolveShape(mod('ear')).shape).toBe('server');
  });
  test('jar goes on to the other signals', () => {
    expect(resolveShape(mod('jar', ['application'])).shape).toBe('cli');
    expect(resolveShape(mod('jar')).shape).toBe('unknown');
  });
});

describe('detectProjectProfiles: two-module reactor', () => {
  let root: string;

  beforeAll(async () => {
    root = join(tmpdir(), `cognium-maven-packaging-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(join(root, 'library', 'src', 'main', 'java', 'org', 'acme'), { recursive: true });
    await mkdir(join(root, 'plugin', 'src', 'main', 'java', 'org', 'acme', 'tools'), { recursive: true });
    await mkdir(join(root, 'scripts'), { recursive: true });
    await writeFile(join(root, 'pom.xml'), PARENT);
    await writeFile(join(root, 'library', 'pom.xml'), LIBRARY);
    await writeFile(join(root, 'plugin', 'pom.xml'), PLUGIN);
    await writeFile(join(root, 'library', 'src', 'main', 'java', 'org', 'acme', 'Util.java'), 'package org.acme;\npublic class Util {}\n');
    await writeFile(join(root, 'plugin', 'src', 'main', 'java', 'org', 'acme', 'tools', 'ReportMojo.java'), MOJO);
    await writeFile(join(root, 'scripts', 'run.sh'), '#!/bin/sh\necho hi\n');
  });

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  test('each module keeps its own packaging', async () => {
    const r = await detectProjectProfiles(root);
    const byRoot = new Map(r.modules.map(m => [m.module.root, m]));
    expect(byRoot.get(root)?.profile).toBe('unknown');
    // The library is a jar: it inherits neither maven-plugin (managed only)
    // nor the parent's assembly plugin, and has no main of its own.
    const lib = byRoot.get(join(root, 'library'))!;
    expect(lib.module.signals.plugins).not.toContain('maven-plugin');
    expect(lib.module.signals.plugins).not.toContain('application');
    expect(lib.profile).not.toMatch(/^plugin\//);
    expect(byRoot.get(join(root, 'plugin'))?.profile).toMatch(/^plugin\//);
    expect(r.profileByFile.get(join(root, 'plugin', 'src', 'main', 'java', 'org', 'acme', 'tools', 'ReportMojo.java'))).toBe('plugin/production');
    expect(r.profileByFile.get(join(root, 'scripts', 'run.sh'))).toBe('unknown');
  });

  test('a child still inherits the parent\'s spring-boot plugin', async () => {
    const dir = join(root, 'sb');
    await mkdir(join(dir, 'app'), { recursive: true });
    await writeFile(join(dir, 'pom.xml'), '<project><artifactId>sb-parent</artifactId><packaging>pom</packaging><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>');
    await writeFile(join(dir, 'app', 'pom.xml'), '<project><artifactId>app</artifactId><parent><artifactId>sb-parent</artifactId></parent></project>');
    const r = await detectProjectProfiles(dir);
    const app = r.modules.find(m => m.module.root === join(dir, 'app'))!;
    expect(app.profile).toMatch(/^server\//);
  });
});
