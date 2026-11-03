/**
 * cognium-dev#1077 — the dependency census missed the two places an Eclipse/Tycho
 * project (iDempiere) declares third-party versions: `maven-dependency-plugin`
 * `<artifactItem>`s in poms, and `<location type="Maven">` entries of `*.target` files.
 */
import { describe, it, expect } from 'vitest';
import { parseMavenDependencies, parseTychoTargetDependencies, collectDependencies } from '../../src/analysis/sbom.js';

const pom = `<project>
  <properties><zk.version>10.3.0.1</zk.version><derived>\${zk.version}</derived></properties>
  <dependencies>
    <dependency><groupId>org.idempiere</groupId><artifactId>org.adempiere.base</artifactId><version>\${revision}</version></dependency>
  </dependencies>
  <build><plugins><plugin>
    <artifactId>maven-dependency-plugin</artifactId>
    <executions><execution><goals><goal>copy</goal></goals><configuration><artifactItems>
      <artifactItem><groupId>com.nimbusds</groupId><artifactId>nimbus-jose-jwt</artifactId><version>9.37.3</version></artifactItem>
      <artifactItem><groupId>org.zkoss.theme</groupId><artifactId>breeze</artifactId><version>\${zk.version}</version></artifactItem>
      <artifactItem><groupId>org.x</groupId><artifactId>from-parent</artifactId><version>\${parent.only}</version></artifactItem>
      <artifactItem><groupId>org.x</groupId><artifactId>chained</artifactId><version>\${derived}</version></artifactItem>
    </artifactItems></configuration></execution></executions>
  </plugin></plugins></build>
</project>`;

const target = `<?xml version="1.0"?>
<target name="t"><locations>
  <!-- <location type="Maven"><groupId>com.old</groupId><artifactId>commented</artifactId><version>1</version></location> -->
  <location includeSource="true" missingManifest="generate" type="Maven">
    <groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version><type>jar</type>
    <instructions><![CDATA[Bundle-Name: <groupId>not.this</groupId>]]></instructions>
  </location>
  <location type="Maven" missingManifest="error">
    <dependencies>
      <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId><version>5.3.27</version><type>jar</type></dependency>
      <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>5.3.27</version><type>jar</type></dependency>
    </dependencies>
  </location>
  <location type="InstallableUnit"><unit id="org.eclipse.equinox" version="0.0.0"/></location>
</locations></target>`;

const keys = (ds: { name: string; version: string; scope: string }[]) => ds.map(d => `${d.name}@${d.version}/${d.scope}`).sort();

describe('#1077 artifactItems in poms', () => {
  it('reads artifactItems as required declarations, resolving same-pom properties', () => {
    const ds = keys(parseMavenDependencies(pom));
    expect(ds).toContain('com.nimbusds:nimbus-jose-jwt@9.37.3/required');
    expect(ds).toContain('org.zkoss.theme:breeze@10.3.0.1/required');
    // a property from a parent pom, or one defined by another property, is not resolved here
    expect(ds).toContain('org.x:from-parent@unknown/required');
    expect(ds).toContain('org.x:chained@unknown/required');
    // the ordinary <dependency> row is unchanged
    expect(ds).toContain('org.idempiere:org.adempiere.base@unknown/required');
  });
});

describe('#1077 Tycho *.target Maven locations', () => {
  it('reads the flat and the <dependencies> forms; ignores comments, CDATA and non-Maven locations', () => {
    expect(keys(parseTychoTargetDependencies(target))).toEqual([
      'org.apache.commons:commons-lang3@3.12.0/required',
      'org.springframework:spring-core@5.3.27/required',
      'org.springframework:spring-web@5.3.27/required',
    ]);
    expect(parseTychoTargetDependencies('')).toEqual([]);
  });

  it('collectDependencies reads java.targetPlatforms beside the pom', () => {
    const ds = keys(collectDependencies({ java: { pomXml: pom, targetPlatforms: [target] } }));
    expect(ds).toContain('org.apache.commons:commons-lang3@3.12.0/required');
    expect(ds).toContain('com.nimbusds:nimbus-jose-jwt@9.37.3/required');
  });
});
