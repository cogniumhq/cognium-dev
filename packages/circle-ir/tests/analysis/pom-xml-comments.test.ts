/**
 * controldeck#727, controldeck#728 — `parseMavenDependencies` read `<dependency>` blocks
 * inside XML comments. A commented-out sample declaration whose comment closes as
 * `</dependency -->` (no real end tag) opened a block that ran on to the next real
 * `</dependency>`: the commented coordinate was listed (#727) and the active dependency
 * after the comment was dropped (#728). Comments are now removed before reading.
 */
import { describe, it, expect } from 'vitest';
import { parseMavenDependencies } from '../../src/analysis/sbom.js';

const keys = (ds: { name: string; version: string; scope: string }[]) => ds.map(d => `${d.name}@${d.version}/${d.scope}`).sort();

// The shape of the pom in both issues: a sample declaration inside a comment, closed as
// `</dependency -->`, then the active dependency straight after it.
const issuePom = `<project>
  <dependencies>
        <dependency>
            <groupId>org.yaml</groupId>
            <artifactId>snakeyaml</artifactId>
            <version>2.6</version>
        </dependency>

        <!-- The following dependency might be an upgrade/replacement for jaxb.xml.bind.JAXBContext,
            but it looks like it requires Java 11.
            <dependency>
            <groupId>jakarta.xml.bind</groupId>
            <artifactId>jakarta.xml.bind-api</artifactId>
            <version>4.0.0</version>
            </dependency -->

        <dependency>
            <groupId>javax.validation</groupId>
            <artifactId>validation-api</artifactId>
            <version>2.0.1.Final</version>
        </dependency>

        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.1</version>
        </dependency>
  </dependencies>
</project>`;

describe('XML comments in pom.xml (controldeck#727, #728)', () => {
  it('#727: a dependency declared only inside a comment is not listed; the active jaxb-api is kept', () => {
    const ds = keys(parseMavenDependencies(issuePom));
    expect(ds.some(d => d.startsWith('jakarta.xml.bind:'))).toBe(false);
    expect(ds).toContain('javax.xml.bind:jaxb-api@2.3.1/required');
  });

  it('#728: the active dependency right after a comment holding a sample declaration is listed, exact version', () => {
    expect(keys(parseMavenDependencies(issuePom))).toEqual([
      'javax.validation:validation-api@2.0.1.Final/required',
      'javax.xml.bind:jaxb-api@2.3.1/required',
      'org.yaml:snakeyaml@2.6/required',
    ]);
  });

  it('a whole commented-out <dependency> block (properly closed), single- or multi-line, is skipped', () => {
    const pom = `<project><dependencies>
      <!-- <dependency><groupId>com.old</groupId><artifactId>one-line</artifactId><version>1</version></dependency> -->
      <!--
      <dependency>
        <groupId>com.old</groupId>
        <artifactId>multi-line</artifactId>
        <version>2</version>
      </dependency>
      --><dependency><groupId>com.live</groupId><artifactId>right-after</artifactId><version>3</version></dependency>
    </dependencies></project>`;
    expect(keys(parseMavenDependencies(pom))).toEqual(['com.live:right-after@3/required']);
  });

  it('a comment inside an active dependency does not change its coordinate, version or scope', () => {
    const pom = `<project><dependencies><dependency>
      <groupId>com.live</groupId>
      <!-- <groupId>com.wrong</groupId> -->
      <artifactId>lib</artifactId>
      <!-- <version>0.0.1</version> -->
      <version>4.5</version>
      <!-- <scope>test</scope> -->
    </dependency></dependencies></project>`;
    expect(keys(parseMavenDependencies(pom))).toEqual(['com.live:lib@4.5/required']);
  });

  it('a commented-out property does not resolve a version; the active one does', () => {
    const pom = `<project>
      <properties>
        <!-- <lib.version>9.9</lib.version> -->
        <other.version>1.2</other.version>
      </properties>
      <dependencies>
        <dependency><groupId>d</groupId><artifactId>dep-commented</artifactId><version>\${lib.version}</version></dependency>
        <dependency><groupId>d</groupId><artifactId>dep-active</artifactId><version>\${other.version}</version></dependency>
      </dependencies>
      <build><plugins><plugin><artifactId>maven-dependency-plugin</artifactId><configuration><artifactItems>
        <artifactItem><groupId>g</groupId><artifactId>uses-commented</artifactId><version>\${lib.version}</version></artifactItem>
        <artifactItem><groupId>g</groupId><artifactId>uses-active</artifactId><version>\${other.version}</version></artifactItem>
        <!-- <artifactItem><groupId>g</groupId><artifactId>commented-item</artifactId><version>1</version></artifactItem> -->
      </artifactItems></configuration></plugin></plugins></build>
    </project>`;
    expect(keys(parseMavenDependencies(pom))).toEqual([
      'd:dep-active@1.2/required',
      'd:dep-commented@unknown/required',
      'g:uses-active@1.2/required',
      'g:uses-commented@unknown/required',
    ]);
  });

  it('an unterminated comment comments out the rest of the file', () => {
    const pom = `<project><dependencies>
      <dependency><groupId>com.live</groupId><artifactId>before</artifactId><version>1</version></dependency>
      <!-- never closed
      <dependency><groupId>com.gone</groupId><artifactId>after</artifactId><version>2</version></dependency>
    </dependencies></project>`;
    expect(keys(parseMavenDependencies(pom))).toEqual(['com.live:before@1/required']);
  });
});
