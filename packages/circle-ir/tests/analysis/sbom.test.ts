/**
 * SBOM generation — deterministic CycloneDX 1.5 / SPDX 2.3 from manifests.
 */

import { describe, it, expect } from 'vitest';
import {
  parseNpmDependencies,
  parsePypiDependencies,
  parseMavenDependencies,
  parseCargoDependencies,
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
