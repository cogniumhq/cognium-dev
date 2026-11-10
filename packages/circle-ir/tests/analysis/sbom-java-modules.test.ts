/**
 * E02 (cognium-dev#1219): resolved Java dependency sets per module. A reactor
 * `mvn dependency:tree` prints one tree per module; Gradle keeps one lockfile
 * per project. The flat parsers merge them and keep only the first of equal
 * entries, so a later module loses its own; these keep one set per module.
 */
import { describe, it, expect } from 'vitest';
import {
  parseMavenModuleDependencies,
  parseMavenResolvedDependencies,
  parseGradleProjectDependencies,
} from '../../src/analysis/sbom.js';
import { buildAdvisoryIndex, matchAdvisories } from '../../src/analysis/advisories.js';

const REACTOR_TREE = `[INFO] --- dependency:3.6.1:tree (default-cli) @ shop-parent ---
[INFO] org.example:shop-parent:pom:1.0.0
[INFO]
[INFO] --- dependency:3.6.1:tree (default-cli) @ shop-core ---
[INFO] org.example:shop-core:jar:1.0.0
[INFO] +- com.nimbusds:nimbus-jose-jwt:jar:9.37.3:compile
[INFO] |  \\- com.github.stephenc.jcip:jcip-annotations:jar:1.0-1:compile
[INFO] \\- junit:junit:jar:4.13.2:test
[INFO]    \\- org.hamcrest:hamcrest-core:jar:1.3:test
[INFO]
[INFO] --- dependency:3.6.1:tree (default-cli) @ shop-web ---
[INFO] org.example:shop-web:war:1.0.0
[INFO] +- org.example:shop-core:jar:1.0.0:compile
[INFO] |  \\- com.nimbusds:nimbus-jose-jwt:jar:9.37.3:compile
[INFO] |     \\- com.github.stephenc.jcip:jcip-annotations:jar:1.0-1:compile
[INFO] \\- org.apache.commons:commons-lang3:jar:3.17.0:compile
`;

describe('parseMavenModuleDependencies', () => {
  it("reads one set per reactor module, with each module's own direct / via", () => {
    const mods = parseMavenModuleDependencies(REACTOR_TREE);
    expect(mods.map(m => `${m.module}@${m.version}:${m.packaging} ${m.dependencies.length}`)).toEqual([
      'org.example:shop-parent@1.0.0:pom 0',
      'org.example:shop-core@1.0.0:jar 4',
      'org.example:shop-web@1.0.0:war 4',
    ]);
    const web = mods[2].dependencies;
    const nimbus = web.find(d => d.name === 'com.nimbusds:nimbus-jose-jwt')!;
    expect(nimbus.direct).toBe(false);
    expect(nimbus.via).toEqual(['org.example:shop-core']);
    const core = mods[1].dependencies.find(d => d.name === 'com.nimbusds:nimbus-jose-jwt')!;
    expect(core.direct).toBe(true);
    expect(core.via).toEqual([]);
  });

  it("keeps what the flat parser drops: the second module's copy of an equal entry", () => {
    const flat = parseMavenResolvedDependencies(REACTOR_TREE).filter(d => d.name === 'com.nimbusds:nimbus-jose-jwt');
    expect(flat).toHaveLength(1);
    const perModule = parseMavenModuleDependencies(REACTOR_TREE)
      .filter(m => m.dependencies.some(d => d.name === 'com.nimbusds:nimbus-jose-jwt'))
      .map(m => m.module);
    expect(perModule).toEqual(['org.example:shop-core', 'org.example:shop-web']);
  });

  it('an advisory match per module says which modules it reaches', () => {
    const index = buildAdvisoryIndex([{
      id: 'GHSA-test-nimbus',
      modified: '2026-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'Maven', name: 'com.nimbusds:nimbus-jose-jwt' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '9.37.4' }] }] }],
    }]);
    const reached = parseMavenModuleDependencies(REACTOR_TREE)
      .filter(m => matchAdvisories(m.dependencies, index).length > 0)
      .map(m => m.module);
    expect(reached).toEqual(['org.example:shop-core', 'org.example:shop-web']);
  });

  it('reads dependency:list output, where only the plugin header names the module', () => {
    const list = `[INFO] --- dependency:3.6.1:list (default-cli) @ a ---
[INFO]
[INFO] The following files have been resolved:
[INFO]    org.slf4j:slf4j-api:jar:2.0.9:compile
[INFO]    junit:junit:jar:4.13.2:test
[INFO]
[INFO] --- dependency:3.6.1:list (default-cli) @ b ---
[INFO]
[INFO] The following files have been resolved:
[INFO]    org.slf4j:slf4j-api:jar:2.0.9:compile
`;
    const mods = parseMavenModuleDependencies(list);
    expect(mods.map(m => [m.module, m.dependencies.map(d => `${d.name}:${d.scope}`)])).toEqual([
      ['a', ['org.slf4j:slf4j-api:required', 'junit:junit:dev']],
      ['b', ['org.slf4j:slf4j-api:required']],
    ]);
  });

  it('reads a root line with the module suffix newer plugins print', () => {
    const mods = parseMavenModuleDependencies('org.example:app:jar:1.0 -- module app\n\\- org.slf4j:slf4j-api:jar:2.0.9:compile -- module org.slf4j\n');
    expect(mods.map(m => [m.module, m.version, m.dependencies.map(d => d.name)])).toEqual([['org.example:app', '1.0', ['org.slf4j:slf4j-api']]]);
  });

  it('a single tree is one module; text with no module boundary is one unnamed set', () => {
    const one = parseMavenModuleDependencies('org.example:app:jar:1.0\n+- org.slf4j:slf4j-api:jar:2.0.9:compile\n');
    expect(one.map(m => m.module)).toEqual(['org.example:app']);
    const bare = parseMavenModuleDependencies('   org.slf4j:slf4j-api:jar:2.0.9:compile\n');
    expect(bare).toEqual([{ module: '', dependencies: parseMavenResolvedDependencies('   org.slf4j:slf4j-api:jar:2.0.9:compile\n') }]);
  });

  it('negative: empty input, prose, malformed lines and conflict-omitted entries give nothing extra', () => {
    expect(parseMavenModuleDependencies('')).toEqual([]);
    expect(parseMavenModuleDependencies('[INFO] BUILD SUCCESS\n[INFO] Total time: 2 s\nnot:a:coordinate\n')).toEqual([]);
    const verbose = `org.example:app:jar:1.0
+- org.a:x:jar:1.0:compile
|  \\- (org.b:y:jar:1.0:compile - omitted for conflict with 2.0)
\\- org.b:y:jar:2.0:compile
`;
    const [m] = parseMavenModuleDependencies(verbose);
    expect(m.dependencies.map(d => `${d.name}@${d.version}`)).toEqual(['org.a:x@1.0', 'org.b:y@2.0']);
  });
});

describe('parseGradleProjectDependencies', () => {
  const LOCK = (lines: string[]) => `# This is a Gradle generated file for dependency locking.\n${lines.join('\n')}\nempty=\n`;

  it('one set per project directory, in path order', () => {
    const projects = parseGradleProjectDependencies([
      { path: 'web/gradle.lockfile', text: LOCK(['org.apache.commons:commons-lang3:3.17.0=runtimeClasspath']) },
      { path: 'gradle.lockfile', text: LOCK(['com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath']) },
      { path: 'core/gradle.lockfile', text: LOCK(['com.nimbusds:nimbus-jose-jwt:9.37.3=runtimeClasspath', 'junit:junit:4.13.2=testRuntimeClasspath']) },
    ]);
    expect(projects.map(p => [p.project, p.lockfiles, p.dependencies.map(d => `${d.name}@${d.version}:${d.scope}`)])).toEqual([
      ['.', ['gradle.lockfile'], ['com.google.guava:guava@33.0.0-jre:required']],
      ['core', ['core/gradle.lockfile'], ['com.nimbusds:nimbus-jose-jwt@9.37.3:required', 'junit:junit@4.13.2:dev']],
      ['web', ['web/gradle.lockfile'], ['org.apache.commons:commons-lang3@3.17.0:required']],
    ]);
  });

  it('the older per-configuration layout: the file name is the configuration, dev only when every one is a test one', () => {
    const [p] = parseGradleProjectDependencies([
      { path: 'svc/gradle/dependency-locks/runtimeClasspath.lockfile', text: 'org.slf4j:slf4j-api:2.0.9\n' },
      { path: 'svc/gradle/dependency-locks/testRuntimeClasspath.lockfile', text: 'org.slf4j:slf4j-api:2.0.9\njunit:junit:4.13.2\n' },
    ]);
    expect(p.project).toBe('svc');
    expect(p.lockfiles).toEqual(['svc/gradle/dependency-locks/runtimeClasspath.lockfile', 'svc/gradle/dependency-locks/testRuntimeClasspath.lockfile']);
    expect(Object.fromEntries(p.dependencies.map(d => [d.name, d.scope]))).toEqual({ 'org.slf4j:slf4j-api': 'required', 'junit:junit': 'dev' });
  });

  it('gradle.lockfile wins over legacy files of the same project', () => {
    const [p] = parseGradleProjectDependencies([
      { path: 'app/gradle/dependency-locks/runtimeClasspath.lockfile', text: 'old:dep:1.0\n' },
      { path: 'app/gradle.lockfile', text: LOCK(['new:dep:2.0=runtimeClasspath']) },
    ]);
    expect(p.lockfiles).toEqual(['app/gradle.lockfile']);
    expect(p.dependencies.map(d => d.name)).toEqual(['new:dep']);
  });

  it('negative: other files, buildscript lockfiles and malformed content give no project entries', () => {
    expect(parseGradleProjectDependencies([])).toEqual([]);
    expect(parseGradleProjectDependencies([
      { path: 'buildscript-gradle.lockfile', text: 'com.example:plugin:1.0=classpath\n' },
      { path: 'settings.gradle', text: 'include "a"\n' },
    ])).toEqual([]);
    const [p] = parseGradleProjectDependencies([{ path: 'x/gradle.lockfile', text: 'not a coordinate\n:::\nempty=\n' }]);
    expect(p).toEqual({ project: 'x', lockfiles: ['x/gradle.lockfile'], dependencies: [] });
  });
});
