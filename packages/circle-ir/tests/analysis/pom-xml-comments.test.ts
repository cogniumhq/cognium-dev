/**
 * controldeck#727, controldeck#728 — `parseMavenDependencies` read `<dependency>` blocks
 * inside XML comments. A commented-out sample declaration whose comment closes as
 * `</dependency -->` (no real end tag) opened a block that ran on to the next real
 * `</dependency>`: the commented coordinate was listed (#727) and the active dependency
 * after the comment was dropped (#728). Comments are now removed before reading, in one
 * left-to-right pass that recognises CDATA, so a `<!--` inside CDATA is text (#1398 review).
 */
import { describe, it, expect } from 'vitest';
import { parseMavenDependencies, parseTychoTargetDependencies } from '../../src/analysis/sbom.js';

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

  it('an unterminated comment runs to the end of the file and is reported, with its line', () => {
    const pom = `<project><dependencies>
      <dependency><groupId>com.live</groupId><artifactId>before</artifactId><version>1</version></dependency>
      <!-- never closed
      <dependency><groupId>com.gone</groupId><artifactId>after</artifactId><version>2</version></dependency>
    </dependencies></project>`;
    const warnings: string[] = [];
    expect(keys(parseMavenDependencies(pom, w => warnings.push(w)))).toEqual(['com.live:before@1/required']);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^unterminated XML comment at line 3 /);
  });

  it('well-formed comments and CDATA produce no warning', () => {
    const warnings: string[] = [];
    parseMavenDependencies(issuePom, w => warnings.push(w));
    parseMavenDependencies(`<project><x><![CDATA[ <!-- ]]></x><!-- ok --></project>`, w => warnings.push(w));
    expect(warnings).toEqual([]);
  });
});

// A `<!--` inside a CDATA section is text, not a comment opener (e.g. an antrun
// `<script>`). Before the single-pass scan it deleted real dependencies.
describe('CDATA in pom.xml and *.target', () => {
  const dep = (a: string, v: string) =>
    `<dependency><groupId>g</groupId><artifactId>${a}</artifactId><version>${v}</version></dependency>`;
  const cdataPlugin = `<build><plugins><plugin><artifactId>maven-antrun-plugin</artifactId>
      <configuration><target><echo><![CDATA[ echo "<!--" ]]></echo></target></configuration>
    </plugin></plugins></build>`;

  it('with no `-->` anywhere after it, the dependencies after the CDATA are kept', () => {
    const pom = `<project>
      <dependencies>${dep('a', '1')}</dependencies>
      ${cdataPlugin}
      <profiles><profile><dependencies>${dep('b', '2')}</dependencies></profile></profiles>
    </project>`;
    const warnings: string[] = [];
    expect(keys(parseMavenDependencies(pom, w => warnings.push(w)))).toEqual(['g:a@1/required', 'g:b@2/required']);
    expect(warnings).toEqual([]);
  });

  it('with a real comment later, nothing between the CDATA and that comment is removed', () => {
    const pom = `<project>
      <x><![CDATA[ <!-- ]]></x>
      <dependencies>${dep('a', '1')}
      <!-- note -->
      ${dep('b', '2')}</dependencies>
    </project>`;
    expect(keys(parseMavenDependencies(pom))).toEqual(['g:a@1/required', 'g:b@2/required']);
  });

  it('CDATA content is left intact: a `-->` inside CDATA does not close an earlier comment', () => {
    const pom = `<project><dependencies>
      <!-- <![CDATA[ --> ${dep('in-comment', '9')}
      <x><![CDATA[ --> ]]></x>
      ${dep('live', '1')}
    </dependencies></project>`;
    // The comment opens first, so its own `-->` (right after `<![CDATA[`) closes it; the
    // later `<![CDATA[ --> ]]>` is a CDATA section and stays as text.
    expect(keys(parseMavenDependencies(pom))).toEqual(['g:in-comment@9/required', 'g:live@1/required']);
  });

  it('a `<![CDATA[` inside a comment is part of the comment', () => {
    const pom = `<project><dependencies>
      <!-- sample: <![CDATA[ ${dep('gone', '9')} -->
      ${dep('live', '1')}
    </dependencies></project>`;
    expect(keys(parseMavenDependencies(pom))).toEqual(['g:live@1/required']);
  });

  it('Tycho: a `<!--` inside CDATA does not hide the Maven location after it', () => {
    const target = `<?xml version="1.0"?><target name="t"><locations>
      <location type="InstallableUnit"><repository location="x"/><![CDATA[<!--]]></location>
      <location includeDependencyScope="compile" type="Maven">
        <dependencies>${dep('tycho-a', '1.0')}</dependencies>
      </location>
      <!-- <location type="Maven"><dependencies>${dep('tycho-commented', '2')}</dependencies></location> -->
    </locations></target>`;
    const warnings: string[] = [];
    expect(keys(parseTychoTargetDependencies(target, w => warnings.push(w)))).toEqual(['g:tycho-a@1.0/required']);
    expect(warnings).toEqual([]);
  });

  it('Tycho: CDATA is still dropped, so a coordinate inside it is not listed', () => {
    const target = `<target><locations><location type="Maven"><![CDATA[${dep('in-cdata', '9')}]]>
      <dependencies>${dep('live', '1')}</dependencies></location></locations></target>`;
    expect(keys(parseTychoTargetDependencies(target))).toEqual(['g:live@1/required']);
  });

  it('Tycho: an unterminated comment is reported', () => {
    const warnings: string[] = [];
    const target = `<target><locations><location type="Maven">${dep('a', '1')}</location>\n<!-- open`;
    expect(keys(parseTychoTargetDependencies(target, w => warnings.push(w)))).toEqual(['g:a@1/required']);
    expect(warnings).toEqual([expect.stringMatching(/^unterminated XML comment at line 2 /)]);
  });
});
