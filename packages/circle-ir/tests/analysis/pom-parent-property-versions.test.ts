/**
 * A `<dependency>` version `${property}` defined in a parent pom (a multi-module
 * build: the root pom holds the versions, the modules use them). The parser
 * takes the parent chain's properties as `inherited`; the pom's own value wins.
 * `mavenParentRef` and `mavenArtifactId` let a caller find that chain on disk.
 */
import { describe, it, expect } from 'vitest';
import { mavenArtifactId, mavenParentRef, mavenPomProperties, parseMavenDependencies } from '../../src/analysis/sbom.js';

const root = `<project>
  <groupId>org.example</groupId><artifactId>shop-parent</artifactId><version>1.0</version><packaging>pom</packaging>
  <properties>
    <jackson.version>2.21.2</jackson.version>
    <junit.version>6.0.3</junit.version>
    <!-- <old.version>0.1</old.version> -->
  </properties>
</project>`;

const mod = `<project>
  <parent><groupId>org.example</groupId><artifactId>shop-parent</artifactId><version>1.0</version></parent>
  <artifactId>shop-core</artifactId>
  <properties><junit.version>5.11.0</junit.version></properties>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>\${jackson.version}</version></dependency>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>\${junit.version}</version><scope>test</scope></dependency>
    <dependency><groupId>org.x</groupId><artifactId>nowhere</artifactId><version>\${missing.version}</version></dependency>
  </dependencies>
</project>`;

const versions = (ds: { name: string; version: string }[]) => Object.fromEntries(ds.map(d => [d.name, d.version]));

describe('pom ${property} versions from the parent pom', () => {
  it('resolves a version from the inherited properties; the pom\'s own value wins; the rest stay unknown', () => {
    const v = versions(parseMavenDependencies(mod, undefined, mavenPomProperties(root)));
    expect(v['com.fasterxml.jackson.core:jackson-databind']).toBe('2.21.2');
    expect(v['org.junit.jupiter:junit-jupiter']).toBe('5.11.0');
    expect(v['org.x:nowhere']).toBe('unknown');
  });

  it('without the parent chain it is unknown, as before', () => {
    expect(versions(parseMavenDependencies(mod))['com.fasterxml.jackson.core:jackson-databind']).toBe('unknown');
  });

  it('reads a commented-out property as absent', () => {
    expect(mavenPomProperties(root).has('old.version')).toBe(false);
    expect(mavenPomProperties(root).get('jackson.version')).toBe('2.21.2');
  });

  it('mavenParentRef: default ../pom.xml, an explicit path, an empty relativePath, no parent', () => {
    expect(mavenParentRef(mod)).toEqual({ artifactId: 'shop-parent', relativePath: '../pom.xml' });
    expect(mavenParentRef(mod.replace('</parent>', '<relativePath>../build/parent</relativePath></parent>')))
      .toEqual({ artifactId: 'shop-parent', relativePath: '../build/parent' });
    expect(mavenParentRef(mod.replace('</parent>', '<relativePath/></parent>')))
      .toEqual({ artifactId: 'shop-parent', relativePath: null });
    expect(mavenParentRef(root)).toBeNull();
  });

  it('resolves properties defined by other properties, after the parent chain is merged', () => {
    const parent = `<project><artifactId>p</artifactId><properties>
      <major>2</major><minor>21</minor>
      <jackson.version>\${major}.\${minor}.2</jackson.version>
      <jackson.databind.version>\${jackson.version}</jackson.databind.version>
      <from.project>\${project.version}</from.project>
      <loop.a>\${loop.b}</loop.a><loop.b>\${loop.a}</loop.b><self>\${self}</self>
    </properties></project>`;
    const child = (props: string) => `<project><artifactId>c</artifactId><properties>${props}</properties><dependencies>
      <dependency><groupId>g</groupId><artifactId>databind</artifactId><version>\${jackson.databind.version}</version></dependency>
      <dependency><groupId>g</groupId><artifactId>project</artifactId><version>\${from.project}</version></dependency>
      <dependency><groupId>g</groupId><artifactId>loop</artifactId><version>\${loop.a}</version></dependency>
      <dependency><groupId>g</groupId><artifactId>self</artifactId><version>\${self}</version></dependency>
    </dependencies></project>`;
    const v = versions(parseMavenDependencies(child(''), undefined, mavenPomProperties(parent)));
    expect(v['g:databind']).toBe('2.21.2');
    // a reference to a property defined nowhere given, or a cycle, stays unknown
    expect(v['g:project']).toBe('unknown');
    expect(v['g:loop']).toBe('unknown');
    expect(v['g:self']).toBe('unknown');
    // the child's own value is used inside the parent's derived properties, as in Maven
    expect(versions(parseMavenDependencies(child('<minor>22</minor>'), undefined, mavenPomProperties(parent)))['g:databind']).toBe('2.22.2');
  });

  it('mavenParentRef: a relativePath padded with whitespace is trimmed; whitespace only means the default', () => {
    expect(mavenParentRef(mod.replace('</parent>', '<relativePath>\n  ../build/parent  \n</relativePath></parent>')))
      .toEqual({ artifactId: 'shop-parent', relativePath: '../build/parent' });
    expect(mavenParentRef(mod.replace('</parent>', '<relativePath>   </relativePath></parent>')))
      .toEqual({ artifactId: 'shop-parent', relativePath: null });
  });

  it('mavenArtifactId: the pom\'s own, not its parent\'s or a dependency\'s', () => {
    expect(mavenArtifactId(mod)).toBe('shop-core');
    expect(mavenArtifactId(root)).toBe('shop-parent');
  });
});
