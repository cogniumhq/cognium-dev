/**
 * controldeck#729 — a `<dependency>` whose version is a `${property}` declared in
 * the same pom's `<properties>` was recorded as `unknown`, so the BOM had no version
 * for it. It now takes the declared value; anything not resolvable here stays `unknown`.
 */
import { describe, it, expect } from 'vitest';
import { parseMavenDependencies } from '../../src/analysis/sbom.js';

const pom = `<project>
  <parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
  <properties>
    <jackson.version>2.21.2</jackson.version>
    <derived>\${jackson.version}</derived>
  </properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>\${jackson.version}</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>\${jackson.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-core</artifactId><version>\${jackson.version}</version><scope>test</scope></dependency>
    <dependency><groupId>org.x</groupId><artifactId>from-parent</artifactId><version>\${parent.only}</version></dependency>
    <dependency><groupId>org.x</groupId><artifactId>chained</artifactId><version>\${derived}</version></dependency>
    <dependency><groupId>org.x</groupId><artifactId>partial</artifactId><version>1.0-\${jackson.version}</version></dependency>
    <dependency><groupId>org.x</groupId><artifactId>literal</artifactId><version>3.4.5</version></dependency>
    <dependency><groupId>org.x</groupId><artifactId>none</artifactId></dependency>
  </dependencies>
</project>`;

const keys = (ds: { name: string; version: string; scope: string }[]) => ds.map(d => `${d.name}@${d.version}/${d.scope}`).sort();

describe('controldeck#729 pom property versions', () => {
  it('resolves a dependency ${property} version from the pom\'s own <properties>', () => {
    const deps = parseMavenDependencies(pom);
    const databind = deps.find(d => d.name === 'com.fasterxml.jackson.core:jackson-databind');
    expect(databind?.version).toBe('2.21.2');
    expect(databind?.purl).toBe('pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.21.2');
    const ds = keys(deps);
    expect(ds).toContain('com.fasterxml.jackson.core:jackson-core@2.21.2/dev');
    expect(ds).toContain('com.fasterxml.jackson:jackson-bom@2.21.2/required');
    expect(ds).toContain('org.x:literal@3.4.5/required');
    // a property defined by another property resolves through it
    expect(ds).toContain('org.x:chained@2.21.2/required');
  });

  it('leaves what it cannot resolve as unknown, never guessed', () => {
    const ds = keys(parseMavenDependencies(pom));
    // defined in a parent pom, embedded in other text, absent
    expect(ds).toContain('org.x:from-parent@unknown/required');
    expect(ds).toContain('org.x:partial@unknown/required');
    expect(ds).toContain('org.x:none@unknown/required');
  });
});
