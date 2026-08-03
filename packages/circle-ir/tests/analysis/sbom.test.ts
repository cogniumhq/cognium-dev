/**
 * SBOM generation — deterministic CycloneDX 1.5 / SPDX 2.3 from manifests.
 */

import { describe, it, expect } from 'vitest';
import {
  parseNpmDependencies,
  parseNpmLockDependencies,
  parsePypiDependencies,
  parseMavenDependencies,
  parseCargoDependencies,
  parseGoDependencies,
  parsePyprojectDependencies,
  parseGradleDependencies,
  collectDependencies,
  toCycloneDx,
  toSpdx,
  type Dependency,
} from '../../src/analysis/sbom.js';

describe('SBOM manifest parsing', () => {
  it('parses npm package.json across dependency sections with correct scopes', () => {
    const pkg = JSON.stringify({
      name: 'demo',
      dependencies: { 'circle-ir': '^3.201.0', '@scope/pkg': '1.0.0' },
      devDependencies: { vitest: '4.1.7' },
      optionalDependencies: { fsevents: '~2.3.0' },
    });
    const deps = parseNpmDependencies(pkg);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['circle-ir'].scope).toBe('required');
    expect(byName['circle-ir'].purl).toBe('pkg:npm/circle-ir@3.201.0');
    expect(byName['vitest'].scope).toBe('dev');
    expect(byName['fsevents'].scope).toBe('optional');
    // scoped name: '@' is percent-encoded, '/' preserved
    expect(byName['@scope/pkg'].purl).toBe('pkg:npm/%40scope/pkg@1.0.0');
  });

  it('returns empty list (not throw) on malformed package.json', () => {
    expect(parseNpmDependencies('{ not valid json')).toEqual([]);
  });

  it('parses package-lock v3 packages map with exact versions + transitive deps', () => {
    const lock = JSON.stringify({
      name: 'demo',
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo', version: '1.0.0' }, // root, skipped
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/@scope/pkg': { version: '2.1.0' },
        'node_modules/vitest': { version: '4.1.7', dev: true },
        'node_modules/lodash/node_modules/nested': { version: '0.1.0', optional: true },
      },
    });
    const deps = parseNpmLockDependencies(lock);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['lodash'].purl).toBe('pkg:npm/lodash@4.17.21'); // exact, not a range
    expect(byName['@scope/pkg'].purl).toBe('pkg:npm/%40scope/pkg@2.1.0');
    expect(byName['vitest'].scope).toBe('dev');
    expect(byName['nested'].scope).toBe('optional'); // deep transitive, name after final node_modules/
    expect(byName['demo']).toBeUndefined(); // root "" skipped
  });

  it('parses legacy package-lock v1 nested dependencies tree', () => {
    const lock = JSON.stringify({
      name: 'demo',
      lockfileVersion: 1,
      dependencies: {
        express: { version: '4.18.2', requires: { 'body-parser': '1.20.1' }, dependencies: { 'body-parser': { version: '1.20.1' } } },
        mocha: { version: '10.2.0', dev: true },
      },
    });
    const deps = parseNpmLockDependencies(lock);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['express'].version).toBe('4.18.2');
    expect(byName['body-parser'].version).toBe('1.20.1'); // nested transitive
    expect(byName['mocha'].scope).toBe('dev');
  });

  it('malformed package-lock returns empty (no throw)', () => {
    expect(parseNpmLockDependencies('not json')).toEqual([]);
  });

  it('parses requirements.txt with comparators, extras, markers, comments', () => {
    const req = [
      '# a comment',
      'Flask==2.3.0',
      'requests>=2.28,<3   # trailing comment',
      'urllib3',
      'uvicorn[standard]==0.23.2',
      'django ; python_version >= "3.8"',
      '-r other.txt',
      'https://example.com/pkg.whl',
    ].join('\n');
    const deps = parsePypiDependencies(req);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(Object.keys(byName).sort()).toEqual(['Flask', 'django', 'requests', 'urllib3', 'uvicorn']);
    expect(byName['Flask'].purl).toBe('pkg:pypi/Flask@2.3.0');
    expect(byName['requests'].version).toBe('2.28'); // first comparator clause
    expect(byName['urllib3'].version).toBe('unknown'); // no version → purl carries no @
    expect(byName['urllib3'].purl).toBe('pkg:pypi/urllib3');
    expect(byName['uvicorn'].purl).toBe('pkg:pypi/uvicorn@0.23.2'); // extras stripped
  });

  it('parses pom.xml with groupId:artifactId names and scope mapping', () => {
    const pom = `
      <project><dependencies>
        <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.0</version></dependency>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
        <dependency><groupId>x.y</groupId><artifactId>z</artifactId><version>\${z.version}</version></dependency>
      </dependencies></project>`;
    const deps = parseMavenDependencies(pom);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['com.google.guava:guava'].purl).toBe('pkg:maven/com.google.guava/guava@32.1.0');
    expect(byName['junit:junit'].scope).toBe('dev');
    expect(byName['x.y:z'].version).toBe('unknown'); // unresolved ${...}
    expect(byName['x.y:z'].purl).toBe('pkg:maven/x.y/z');
  });

  it('parses Cargo.toml string and inline-table forms with section scopes', () => {
    const toml = [
      '[dependencies]',
      'serde = "1.0.188"',
      'tokio = { version = "1.32", features = ["full"] }',
      '[dev-dependencies]',
      'proptest = "1.2"',
      '[package]',
      'name = "notadep"',
    ].join('\n');
    const deps = parseCargoDependencies(toml);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['serde'].purl).toBe('pkg:cargo/serde@1.0.188');
    expect(byName['tokio'].version).toBe('1.32');
    expect(byName['proptest'].scope).toBe('dev');
    expect(byName['name']).toBeUndefined(); // [package] table is not a dep table
  });

  it('parses go.mod grouped + single-line require, keeps the v-prefix, marks indirect', () => {
    const goMod = [
      'module example.com/m',
      'go 1.21',
      'require (',
      '\tgithub.com/gin-gonic/gin v1.9.1',
      '\tgithub.com/stretchr/testify v1.8.4 // indirect',
      ')',
      'require github.com/single/dep v0.4.0',
    ].join('\n');
    const deps = parseGoDependencies(goMod);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['github.com/gin-gonic/gin'].purl).toBe('pkg:golang/github.com/gin-gonic/gin@v1.9.1');
    expect(byName['github.com/gin-gonic/gin'].version).toBe('v1.9.1'); // v-prefix kept
    expect(byName['github.com/stretchr/testify'].scope).toBe('optional'); // // indirect
    expect(byName['github.com/single/dep'].purl).toBe('pkg:golang/github.com/single/dep@v0.4.0');
  });

  it('parses pyproject.toml — PEP 621 multi-line array + optional groups', () => {
    const toml = [
      '[project]',
      'name = "demo"',
      'dependencies = [',
      '  "flask>=2.0",',
      '  "requests==2.28.1",',
      ']',
      '[project.optional-dependencies]',
      'test = ["pytest>=7.0"]',
    ].join('\n');
    const deps = parsePyprojectDependencies(toml);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['flask'].purl).toBe('pkg:pypi/flask@2.0');
    expect(byName['requests'].version).toBe('2.28.1');
    expect(byName['pytest'].scope).toBe('optional');
  });

  it('parses pyproject.toml — Poetry tables, skipping the python pin, dev group', () => {
    const toml = [
      '[tool.poetry.dependencies]',
      'python = "^3.11"',
      'flask = "^2.3.0"',
      'httpx = { version = "0.25.0", optional = true }',
      '[tool.poetry.group.dev.dependencies]',
      'pytest = "^7.4"',
    ].join('\n');
    const deps = parsePyprojectDependencies(toml);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['python']).toBeUndefined(); // python pin skipped
    expect(byName['flask'].purl).toBe('pkg:pypi/flask@2.3.0'); // ^ stripped
    expect(byName['httpx'].version).toBe('0.25.0'); // inline table
    expect(byName['pytest'].scope).toBe('dev');
  });

  it('parses build.gradle deps (Groovy + Kotlin forms), test* → dev, platform skipped', () => {
    const gradle = [
      "implementation 'com.google.guava:guava:32.1.0'",
      'api("org.slf4j:slf4j-api:2.0.9")',
      "testImplementation 'junit:junit:4.13.2'",
      "implementation platform('org.springframework.boot:spring-boot-dependencies:3.1.0')",
    ].join('\n');
    const deps = parseGradleDependencies(gradle);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName['com.google.guava:guava'].purl).toBe('pkg:maven/com.google.guava/guava@32.1.0');
    expect(byName['org.slf4j:slf4j-api'].version).toBe('2.0.9'); // Kotlin DSL
    expect(byName['junit:junit'].scope).toBe('dev'); // testImplementation
    // platform(...) BOM import declares no concrete artifact
    expect(byName['org.springframework.boot:spring-boot-dependencies']).toBeUndefined();
  });

  it('collectDependencies now also reads pyproject.toml and build.gradle from the context', () => {
    const deps = collectDependencies({
      python: { pyprojectToml: '[project]\ndependencies = ["flask==2.3.0"]' },
      java: { buildGradle: "implementation 'com.google.guava:guava:32.1.0'" },
    });
    expect(deps.map((d) => d.purl).sort()).toEqual([
      'pkg:maven/com.google.guava/guava@32.1.0',
      'pkg:pypi/flask@2.3.0',
    ]);
  });

  it('collectDependencies aggregates across ecosystems and de-dupes', () => {
    const deps = collectDependencies({
      js: { packageJson: JSON.stringify({ dependencies: { lodash: '4.17.21' } }) },
      python: { requirementsTxt: 'flask==2.3.0' },
      rust: { cargoToml: '[dependencies]\nserde = "1.0"' },
    });
    expect(deps.map((d) => d.ecosystem).sort()).toEqual(['cargo', 'npm', 'pypi']);
    // idempotent de-dup
    const dupd = collectDependencies({
      js: { packageJson: JSON.stringify({ dependencies: { a: '1.0.0' }, optionalDependencies: {} }) },
    });
    expect(dupd.length).toBe(1);
  });
});

describe('SBOM emitters', () => {
  const deps: Dependency[] = [
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm', scope: 'required', purl: 'pkg:npm/lodash@4.17.21' },
    { name: 'vitest', version: '4.1.7', ecosystem: 'npm', scope: 'dev', purl: 'pkg:npm/vitest@4.1.7' },
  ];

  it('emits a valid CycloneDX 1.5 skeleton with components and purls', () => {
    const bom = toCycloneDx(deps, { name: 'demo', version: '1.0.0' });
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    const components = bom.components as Array<Record<string, unknown>>;
    expect(components).toHaveLength(2);
    expect(components[0]).toMatchObject({ type: 'library', name: 'lodash', purl: 'pkg:npm/lodash@4.17.21', 'bom-ref': 'pkg:npm/lodash@4.17.21' });
    expect(components[1].scope).toBe('excluded'); // dev → excluded
  });

  it('emits a valid SPDX 2.3 skeleton with unique SPDXIDs and purl externalRefs', () => {
    const doc = toSpdx(deps, { name: 'demo' });
    expect(doc.spdxVersion).toBe('SPDX-2.3');
    expect(doc.SPDXID).toBe('SPDXRef-DOCUMENT');
    const packages = doc.packages as Array<Record<string, unknown>>;
    const ids = packages.map((p) => p.SPDXID);
    expect(new Set(ids).size).toBe(ids.length); // unique
    expect((packages[0].externalRefs as Array<Record<string, unknown>>)[0].referenceLocator).toBe('pkg:npm/lodash@4.17.21');
    const rels = doc.relationships as Array<Record<string, unknown>>;
    expect(rels.every((r) => r.relationshipType === 'DESCRIBES')).toBe(true);
  });

  it('is deterministic: no injected metadata → byte-identical repeated output', () => {
    expect(JSON.stringify(toCycloneDx(deps))).toBe(JSON.stringify(toCycloneDx(deps)));
    expect(JSON.stringify(toSpdx(deps))).toBe(JSON.stringify(toSpdx(deps)));
    // no serialNumber/timestamp leak into a metadata-free CycloneDX
    expect(toCycloneDx(deps).serialNumber).toBeUndefined();
  });

  it('sanitizes SPDXID characters from scoped/coordinate names', () => {
    const scoped: Dependency[] = [
      { name: '@scope/pkg', version: '1.0.0', ecosystem: 'npm', scope: 'required', purl: 'pkg:npm/%40scope/pkg@1.0.0' },
    ];
    const doc = toSpdx(scoped);
    const id = (doc.packages as Array<Record<string, unknown>>)[0].SPDXID as string;
    expect(id).toMatch(/^[A-Za-z0-9.\-]+$/); // only legal SPDXID chars
  });
});
