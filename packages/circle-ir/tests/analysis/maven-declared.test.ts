/**
 * Declared Maven versions and their origin over a module → parent POM chain.
 */

import { describe, it, expect } from 'vitest';
import { MavenDeclaredIndex } from '../../src/analysis/maven-declared.js';

const PARENT = `<project>
  <groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0</version><packaging>pom</packaging>
  <properties><log4j.version>2.14.1</log4j.version><slf4j.version>1.7.36</slf4j.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.33</version></dependency>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.version}</version></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-framework-bom</artifactId><version>5.3.20</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>\${slf4j.version}</version></dependency>
  </dependencies>
  <build><plugins><plugin><artifactId>x</artifactId><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>0.1</version></dependency>
  </dependencies></plugin></plugins></build>
</project>`;

const CHILD = `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
  <artifactId>app</artifactId>
  <!-- <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>9.9</version></dependency> -->
  <properties><log4j.version>2.17.1</log4j.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.13.4.2</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId></dependency>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>2.0</version></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></dependency>
    <dependency><groupId>com.example</groupId><artifactId>sibling</artifactId><version>\${project.version}</version></dependency>
  </dependencies>
</project>`;

const SIBLING = `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
  <artifactId>sibling</artifactId>
  <dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency></dependencies>
</project>`;

const BOOT = `<project>
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.1.0</version><relativePath/></parent>
  <artifactId>boot-app</artifactId>
  <dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency></dependencies>
</project>`;

const index = new MavenDeclaredIndex([
  { path: 'pom.xml', content: PARENT },
  { path: 'app/pom.xml', content: CHILD },
  { path: 'sibling/pom.xml', content: SIBLING },
  { path: 'boot/pom.xml', content: BOOT },
]);

describe('MavenDeclaredIndex', () => {
  it('reads a literal version on the module dependency as direct, over the parent pin', () => {
    expect(index.declared('app/pom.xml', 'org.yaml:snakeyaml')).toEqual({ version: '2.0', origin: 'direct', file: 'app/pom.xml' });
  });

  it('follows a versionless dependency to the parent dependencyManagement, resolving the property child-first', () => {
    expect(index.declared('app/pom.xml', 'org.apache.logging.log4j:log4j-core')).toEqual({
      version: '2.17.1', origin: 'parent-dependencyManagement', file: 'pom.xml', property: 'log4j.version',
    });
  });

  it('shows where a sibling that does not get the bump still takes the parent pin', () => {
    expect(index.declared('sibling/pom.xml', 'org.yaml:snakeyaml')).toEqual({ version: '1.33', origin: 'parent-dependencyManagement', file: 'pom.xml' });
    expect(index.declared('sibling/pom.xml', 'org.apache.logging.log4j:log4j-core')).toEqual({
      version: '2.14.1', origin: 'parent-dependencyManagement', file: 'pom.xml', property: 'log4j.version',
    });
  });

  it('reports a transitive pin in the module own dependencyManagement', () => {
    expect(index.declared('app/pom.xml', 'com.fasterxml.jackson.core:jackson-databind')).toEqual({
      version: '2.13.4.2', origin: 'dependencyManagement', file: 'app/pom.xml',
    });
  });

  it('reads an inherited dependency and a property origin', () => {
    expect(index.declared('app/pom.xml', 'org.slf4j:slf4j-api')).toEqual({ version: '1.7.36', origin: 'property', file: 'pom.xml', property: 'slf4j.version' });
    expect(index.declared('app/pom.xml', 'com.example:sibling')).toEqual({ version: '1.0', origin: 'property', file: 'app/pom.xml', property: 'project.version' });
  });

  it('names the BOM when a versionless dependency is managed outside the tree', () => {
    expect(index.declared('app/pom.xml', 'org.springframework:spring-core')).toEqual({
      version: null, origin: 'bom', file: 'app/pom.xml', boms: ['org.springframework:spring-framework-bom:5.3.20'],
    });
  });

  it('names an external parent, and fills the version from an effective POM when given', () => {
    expect(index.declared('boot/pom.xml', 'org.yaml:snakeyaml')).toEqual({
      version: null, origin: 'external-parent', file: 'boot/pom.xml', parent: 'org.springframework.boot:spring-boot-starter-parent:3.1.0',
    });
    const withEffective = new MavenDeclaredIndex(
      [{ path: 'boot/pom.xml', content: BOOT }],
      '<project><dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.33</version></dependency></dependencies></project>',
    );
    expect(withEffective.declared('boot/pom.xml', 'org.yaml:snakeyaml')?.version).toBe('1.33');
  });

  it('returns null for a coordinate no POM in the chain names, and for an unknown module', () => {
    expect(index.declared('app/pom.xml', 'org.example:transitive-only')).toBeNull();
    expect(index.declared('nope/pom.xml', 'org.yaml:snakeyaml')).toBeNull();
  });

  it('ignores plugin dependencies and comments', () => {
    const only = new MavenDeclaredIndex([{ path: 'pom.xml', content: PARENT }]);
    expect(only.declared('pom.xml', 'org.yaml:snakeyaml')?.version).toBe('1.33');
  });
});
