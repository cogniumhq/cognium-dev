/**
 * SBOM — resolved Java dependency sets: Gradle lockfiles and Maven
 * `dependency:list` / `dependency:tree` output (direct + transitive).
 */

import { describe, it, expect } from 'vitest';
import {
  parseGradleLockfile,
  parseMavenResolvedDependencies,
  collectDependencies,
  toCycloneDx,
} from '../../src/analysis/sbom.js';

const GRADLE_LOCKFILE = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.fasterxml.jackson.core:jackson-annotations:2.13.0=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
com.fasterxml.jackson.core:jackson-databind:2.13.0=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
org.apiguardian:apiguardian-api:1.1.2=testCompileClasspath
org.junit.jupiter:junit-jupiter-api:5.9.0=testCompileClasspath,testRuntimeClasspath
org.example:it-only:1.0=integrationTestRuntimeClasspath
org.projectlombok:lombok:1.18.30=annotationProcessor,compileClasspath
empty=testAnnotationProcessor
`;

describe('parseGradleLockfile', () => {
  it('reads every resolved coordinate with its exact version', () => {
    const deps = parseGradleLockfile(GRADLE_LOCKFILE);
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual([
      'com.fasterxml.jackson.core:jackson-annotations@2.13.0',
      'com.fasterxml.jackson.core:jackson-databind@2.13.0',
      'org.apiguardian:apiguardian-api@1.1.2',
      'org.junit.jupiter:junit-jupiter-api@5.9.0',
      'org.example:it-only@1.0',
      'org.projectlombok:lombok@1.18.30',
    ]);
    expect(deps.every((d) => d.ecosystem === 'maven')).toBe(true);
  });

  it('marks a dependency dev only when every configuration is a test one', () => {
    const scope = Object.fromEntries(parseGradleLockfile(GRADLE_LOCKFILE).map((d) => [d.name, d.scope]));
    expect(scope['com.fasterxml.jackson.core:jackson-databind']).toBe('required');
    expect(scope['org.apiguardian:apiguardian-api']).toBe('dev');
    expect(scope['org.junit.jupiter:junit-jupiter-api']).toBe('dev');
    expect(scope['org.example:it-only']).toBe('dev');
    expect(scope['org.projectlombok:lombok']).toBe('required');
  });

  it('builds an exact purl', () => {
    const [first] = parseGradleLockfile('com.google.guava:guava:31.1-jre=runtimeClasspath');
    expect(first.purl).toBe('pkg:maven/com.google.guava/guava@31.1-jre');
  });

  it('reads the older per-configuration layout, scoped by the configuration passed', () => {
    const legacy = '# comment\norg.slf4j:slf4j-api:1.7.36\njunit:junit:4.13.2\n';
    expect(parseGradleLockfile(legacy).every((d) => d.scope === 'required')).toBe(true);
    expect(parseGradleLockfile(legacy, 'testRuntimeClasspath').every((d) => d.scope === 'dev')).toBe(true);
  });

  it('skips the empty= line, malformed lines and empty input', () => {
    expect(parseGradleLockfile('')).toEqual([]);
    expect(parseGradleLockfile('empty=compileClasspath\nnot-a-coordinate\na:b=x\n::1=y')).toEqual([]);
  });
});

const MAVEN_TREE = `[INFO] --- maven-dependency-plugin:3.6.1:tree (default-cli) @ demo ---
[INFO] com.example:demo:jar:1.0-SNAPSHOT
[INFO] +- org.springframework:spring-core:jar:5.3.20:compile
[INFO] |  \\- org.springframework:spring-jcl:jar:5.3.20:compile
[INFO] +- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
[INFO] |  \\- (org.apache.logging.log4j:log4j-api:jar:2.13.0:compile - omitted for conflict with 2.14.1)
[INFO] +- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile
[INFO] +- javax.servlet:javax.servlet-api:jar:4.0.1:provided
[INFO] +- io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100.Final:runtime
[INFO] +- com.h2database:h2:jar:2.1.214:compile (optional)
[INFO] \\- junit:junit:jar:4.13.2:test
[INFO]    \\- (org.springframework:spring-jcl:jar:5.3.20:compile - omitted for duplicate)
[INFO] BUILD SUCCESS
`;

const MAVEN_LIST = `The following files have been resolved:
   org.apache.commons:commons-text:jar:1.9:compile -- module org.apache.commons.text [auto]
   org.apache.commons:commons-lang3:jar:3.11:compile -- module org.apache.commons.lang3
   org.hamcrest:hamcrest-core:jar:1.3:test
`;

describe('parseMavenResolvedDependencies', () => {
  it('reads a dependency:tree, direct and transitive, skipping the root and conflicts', () => {
    const deps = parseMavenResolvedDependencies(MAVEN_TREE);
    expect(deps.map((d) => `${d.name}@${d.version}:${d.scope}`)).toEqual([
      'org.springframework:spring-core@5.3.20:required',
      'org.springframework:spring-jcl@5.3.20:required',
      'org.apache.logging.log4j:log4j-core@2.14.1:required',
      'org.apache.logging.log4j:log4j-api@2.14.1:required',
      'javax.servlet:javax.servlet-api@4.0.1:dev',
      'io.netty:netty-transport-native-epoll@4.1.100.Final:required',
      'com.h2database:h2@2.1.214:optional',
      'junit:junit@4.13.2:dev',
    ]);
  });

  it('never reports the version Maven mediated away', () => {
    const deps = parseMavenResolvedDependencies(MAVEN_TREE);
    expect(deps.some((d) => d.name === 'org.apache.logging.log4j:log4j-api' && d.version === '2.13.0')).toBe(false);
  });

  it('reads a dependency:list written to a file, with module suffixes', () => {
    const deps = parseMavenResolvedDependencies(MAVEN_LIST);
    expect(deps.map((d) => `${d.name}@${d.version}:${d.scope}`)).toEqual([
      'org.apache.commons:commons-text@1.9:required',
      'org.apache.commons:commons-lang3@3.11:required',
      'org.hamcrest:hamcrest-core@1.3:dev',
    ]);
    expect(deps[0].purl).toBe('pkg:maven/org.apache.commons/commons-text@1.9');
  });

  it('returns nothing for empty or unrelated text', () => {
    expect(parseMavenResolvedDependencies('')).toEqual([]);
    expect(parseMavenResolvedDependencies('[INFO] BUILD SUCCESS\n[INFO] com.example:demo:jar:1.0')).toEqual([]);
  });
});

describe('collectDependencies with resolved Java sets', () => {
  it('lets a Gradle lockfile supersede build.gradle', () => {
    const deps = collectDependencies({
      java: {
        buildGradle: "implementation 'com.google.guava:guava:31.0-jre'",
        gradleLockfile: 'com.google.guava:guava:31.1-jre=runtimeClasspath\ncom.google.guava:failureaccess:1.0.1=runtimeClasspath',
      },
    });
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual([
      'com.google.guava:guava@31.1-jre',
      'com.google.guava:failureaccess@1.0.1',
    ]);
  });

  it('lets Maven resolved output supersede pom.xml', () => {
    const deps = collectDependencies({
      java: {
        pomXml: '<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>${junit.version}</version></dependency>',
        mavenResolved: MAVEN_LIST,
      },
    });
    expect(deps.map((d) => d.name)).toEqual([
      'org.apache.commons:commons-text',
      'org.apache.commons:commons-lang3',
      'org.hamcrest:hamcrest-core',
    ]);
  });

  it('feeds the emitters unchanged', () => {
    const bom = toCycloneDx(parseGradleLockfile('org.yaml:snakeyaml:1.33=runtimeClasspath')) as {
      components: Array<{ purl: string }>;
    };
    expect(bom.components[0].purl).toBe('pkg:maven/org.yaml/snakeyaml@1.33');
  });
});
