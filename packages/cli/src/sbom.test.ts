/**
 * `cognium-dev sbom` command — end-to-end.
 *
 * The manifest parsers + emitters are unit-tested in circle-ir; these cover
 * the CLI's own logic: manifest discovery, cross-manifest aggregation/de-dup,
 * metadata injection, format dispatch, and exit codes. Run the built source
 * as a subprocess against a temp fixture.
 */
import { test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const CLI = join(import.meta.dir, 'cli.ts');
let fixture: string;

beforeAll(() => {
  fixture = mkdtempSync(join(tmpdir(), 'sbom-'));
  writeFileSync(
    join(fixture, 'package.json'),
    JSON.stringify({
      name: 'demo-app',
      version: '2.1.0',
      dependencies: { lodash: '4.17.21', '@scope/x': '^1.0.0' },
      devDependencies: { vitest: '4.1.7' },
    }),
  );
  writeFileSync(join(fixture, 'requirements.txt'), 'Flask==2.3.0\nurllib3\n');
  mkdirSync(join(fixture, 'sub'));
  writeFileSync(join(fixture, 'sub', 'Cargo.toml'), '[dependencies]\nserde = "1.0.188"\n');
  writeFileSync(join(fixture, 'go.mod'), 'module example.com/m\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.1\n');
  writeFileSync(join(fixture, 'pyproject.toml'), '[project]\ndependencies = ["httpx==0.25.0"]\n');
  writeFileSync(join(fixture, 'build.gradle'), "dependencies {\n  implementation 'com.google.guava:guava:32.1.0'\n}\n");
  // must be skipped by discovery
  mkdirSync(join(fixture, 'node_modules', 'x'), { recursive: true });
  writeFileSync(join(fixture, 'node_modules', 'x', 'package.json'), JSON.stringify({ dependencies: { evil: '1.0.0' } }));
});

afterAll(() => {
  rmSync(fixture, { recursive: true, force: true });
});

async function runCli(args: string[]): Promise<{ out: string; err: string; code: number }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const out = await new Response(proc.stdout).text();
  const err = await new Response(proc.stderr).text();
  const code = await proc.exited;
  return { out, err, code };
}

test('sbom: CycloneDX aggregates manifests, encodes purls, skips node_modules', async () => {
  const { out, code } = await runCli(['sbom', fixture, '-f', 'cyclonedx', '--deterministic']);
  expect(code).toBe(0);
  const bom = JSON.parse(out);
  expect(bom.bomFormat).toBe('CycloneDX');
  expect(bom.specVersion).toBe('1.5');
  expect(bom.metadata.component.name).toBe('demo-app'); // from package.json
  const purls = bom.components.map((c: { purl: string }) => c.purl);
  expect(purls).toContain('pkg:npm/lodash@4.17.21');
  expect(purls).toContain('pkg:npm/%40scope/x@1.0.0'); // scoped name encoded
  expect(purls).toContain('pkg:pypi/Flask@2.3.0');
  expect(purls).toContain('pkg:cargo/serde@1.0.188'); // nested sub/Cargo.toml found
  expect(purls).toContain('pkg:golang/github.com/gin-gonic/gin@v1.9.1'); // go.mod, v-prefix kept
  expect(purls).toContain('pkg:pypi/httpx@0.25.0'); // pyproject.toml
  expect(purls).toContain('pkg:maven/com.google.guava/guava@32.1.0'); // build.gradle
  expect(purls.some((p: string) => p.includes('evil'))).toBe(false); // node_modules skipped
});

test('sbom: --deterministic omits volatile metadata (reproducible)', async () => {
  const a = await runCli(['sbom', fixture, '--deterministic']);
  const b = await runCli(['sbom', fixture, '--deterministic']);
  expect(a.out).toBe(b.out); // byte-identical
  const bom = JSON.parse(a.out);
  expect(bom.serialNumber).toBeUndefined();
  expect(bom.metadata.timestamp).toBeUndefined();
});

test('sbom: default (non-deterministic) injects urn:uuid serialNumber + timestamp', async () => {
  const { out } = await runCli(['sbom', fixture]);
  const bom = JSON.parse(out);
  expect(bom.serialNumber).toMatch(/^urn:uuid:/);
  expect(typeof bom.metadata.timestamp).toBe('string');
});

test('sbom: SPDX 2.3 has unique SPDXIDs and purl externalRefs', async () => {
  const { out, code } = await runCli(['sbom', fixture, '-f', 'spdx', '--deterministic']);
  expect(code).toBe(0);
  const doc = JSON.parse(out);
  expect(doc.spdxVersion).toBe('SPDX-2.3');
  const ids = doc.packages.map((p: { SPDXID: string }) => p.SPDXID);
  expect(new Set(ids).size).toBe(ids.length);
  expect(doc.packages[0].externalRefs[0].referenceType).toBe('purl');
  expect(doc.relationships.every((r: { relationshipType: string }) => r.relationshipType === 'DESCRIBES')).toBe(true);
});

test('sbom: package-lock.json supersedes package.json (exact + transitive, no range dupes)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-lock-'));
  try {
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'locked', dependencies: { lodash: '^4.0.0' } }),
    );
    writeFileSync(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'locked',
        lockfileVersion: 3,
        packages: {
          '': { name: 'locked', version: '1.0.0' },
          'node_modules/lodash': { version: '4.17.21' },
          'node_modules/ms': { version: '2.1.3' }, // transitive, not in package.json
        },
      }),
    );
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = JSON.parse(out).components.map((c: { purl: string }) => c.purl);
    expect(purls).toContain('pkg:npm/lodash@4.17.21'); // exact from lock
    expect(purls).toContain('pkg:npm/ms@2.1.3'); // transitive included
    expect(purls).not.toContain('pkg:npm/lodash@4.0.0'); // range form NOT double-listed
    expect(purls.some((p: string) => p.startsWith('pkg:npm/lodash'))).toBe(true);
    // exactly one lodash entry
    expect(purls.filter((p: string) => p.startsWith('pkg:npm/lodash')).length).toBe(1);
    expect(JSON.parse(out).metadata.component.name).toBe('locked'); // name still from package.json
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: Cargo.lock supersedes Cargo.toml (exact + transitive crate graph)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-cargo-'));
  try {
    writeFileSync(join(dir, 'Cargo.toml'), '[dependencies]\nserde = "1"\n');
    writeFileSync(
      join(dir, 'Cargo.lock'),
      ['[[package]]', 'name = "serde"', 'version = "1.0.188"', '', '[[package]]', 'name = "serde_derive"', 'version = "1.0.188"'].join('\n'),
    );
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = JSON.parse(out).components.map((c: { purl: string }) => c.purl);
    expect(purls).toContain('pkg:cargo/serde@1.0.188'); // exact from lock
    expect(purls).toContain('pkg:cargo/serde_derive@1.0.188'); // transitive
    expect(purls).not.toContain('pkg:cargo/serde@1'); // range form from Cargo.toml dropped
    expect(purls.filter((p: string) => p === 'pkg:cargo/serde@1.0.188').length).toBe(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: root license (package.json) + per-dep license (package-lock) surface', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-lic-'));
  try {
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'licproj', license: 'Apache-2.0', dependencies: { lodash: '^4.0.0' } }),
    );
    writeFileSync(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'licproj',
        lockfileVersion: 3,
        packages: {
          '': { name: 'licproj', version: '1.0.0' },
          'node_modules/lodash': { version: '4.17.21', license: 'MIT' },
        },
      }),
    );
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const bom = JSON.parse(out);
    expect(bom.metadata.component.licenses).toEqual([{ license: { name: 'Apache-2.0' } }]); // root
    const lodash = bom.components.find((c: { name: string }) => c.name === 'lodash');
    expect(lodash.licenses).toEqual([{ license: { name: 'MIT' } }]); // per-dep from lock
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: --prod-only drops dev dependencies', async () => {
  const full = JSON.parse((await runCli(['sbom', fixture, '--deterministic'])).out);
  const prod = JSON.parse((await runCli(['sbom', fixture, '--prod-only', '--deterministic'])).out);
  expect(full.components.some((c: { name: string }) => c.name === 'vitest')).toBe(true);
  expect(prod.components.some((c: { name: string }) => c.name === 'vitest')).toBe(false);
});

test('sbom: unknown format exits 1', async () => {
  const { code } = await runCli(['sbom', fixture, '-f', 'bogus']);
  expect(code).toBe(1);
});

test('sbom: missing path exits 2', async () => {
  const { code } = await runCli(['sbom', join(fixture, 'does-not-exist')]);
  expect(code).toBe(2);
});

// ─── Resolved Java sets (DT4: resolved > lockfile > declared) ────────────────

const purlsOf = (out: string): string[] =>
  JSON.parse(out).components.map((c: { purl: string }) => c.purl);

test('sbom: gradle.lockfile supersedes build.gradle (exact + transitive)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-gradle-lock-'));
  try {
    writeFileSync(join(dir, 'build.gradle'), "dependencies {\n  implementation 'com.google.guava:guava:32.+'\n}\n");
    writeFileSync(
      join(dir, 'gradle.lockfile'),
      [
        '# This is a Gradle generated file for dependency locking.',
        'com.google.guava:failureaccess:1.0.1=compileClasspath,runtimeClasspath',
        'com.google.guava:guava:32.1.3-jre=compileClasspath,runtimeClasspath',
        'junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath',
        'empty=annotationProcessor',
      ].join('\n'),
    );
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = purlsOf(out);
    expect(purls).toContain('pkg:maven/com.google.guava/guava@32.1.3-jre');
    expect(purls).toContain('pkg:maven/com.google.guava/failureaccess@1.0.1'); // transitive
    expect(purls.filter((p) => p.startsWith('pkg:maven/com.google.guava/guava@')).length).toBe(1); // declared range dropped
    const prod = purlsOf((await runCli(['sbom', dir, '--prod-only', '--deterministic'])).out);
    expect(prod.some((p) => p.includes('junit'))).toBe(false); // test-only configuration is dev
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: gradle/dependency-locks/*.lockfile supersedes the project build.gradle.kts', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-gradle-locks-'));
  try {
    writeFileSync(join(dir, 'build.gradle.kts'), 'dependencies {\n  implementation("org.slf4j:slf4j-api:2.+")\n}\n');
    mkdirSync(join(dir, 'gradle', 'dependency-locks'), { recursive: true });
    writeFileSync(join(dir, 'gradle', 'dependency-locks', 'runtimeClasspath.lockfile'), 'org.slf4j:slf4j-api:2.0.9\n');
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = purlsOf(out);
    expect(purls).toContain('pkg:maven/org.slf4j/slf4j-api@2.0.9');
    expect(purls.filter((p) => p.startsWith('pkg:maven/org.slf4j/slf4j-api@')).length).toBe(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: Maven dependency-tree.txt supersedes pom.xml (resolved, transitive)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-mvn-tree-'));
  try {
    writeFileSync(
      join(dir, 'pom.xml'),
      '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency></dependencies></project>',
    );
    writeFileSync(
      join(dir, 'dependency-tree.txt'),
      [
        'com.example:app:jar:1.0.0',
        '+- org.apache.logging.log4j:log4j-core:jar:2.17.1:compile',
        '|  \\- org.apache.logging.log4j:log4j-api:jar:2.17.1:compile',
        '\\- junit:junit:jar:4.13.2:test',
      ].join('\n'),
    );
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = purlsOf(out);
    expect(purls).toContain('pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1');
    expect(purls).toContain('pkg:maven/org.apache.logging.log4j/log4j-api@2.17.1'); // transitive
    expect(purls.some((p) => p.includes('$'))).toBe(false); // unresolved declared version dropped
    expect(purls.filter((p) => p.includes('log4j-core')).length).toBe(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: Maven resolved output without a sibling pom.xml is ignored', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-mvn-orphan-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'orphan', dependencies: { ms: '2.1.3' } }));
    writeFileSync(join(dir, 'dependency-list.txt'), '   org.example:stray:jar:1.0:compile\n');
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = purlsOf(out);
    expect(purls).toContain('pkg:npm/ms@2.1.3');
    expect(purls.some((p) => p.includes('stray'))).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: only an orphan resolved file → no supported manifests (exit 1)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-mvn-only-orphan-'));
  try {
    writeFileSync(join(dir, 'dependency-tree.txt'), '+- org.example:stray:jar:1.0:compile\n');
    const { code } = await runCli(['sbom', dir]);
    expect(code).toBe(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: a pnpm workspace lockfile supersedes every importer\'s package.json (DT4)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-pnpm-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'mono', dependencies: { lodash: '^4.17.0' } }));
    mkdirSync(join(dir, 'packages', 'app'), { recursive: true });
    writeFileSync(join(dir, 'packages', 'app', 'package.json'), JSON.stringify({ name: 'app', dependencies: { semver: '^7.5.0' } }));
    writeFileSync(join(dir, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      lodash: {specifier: ^4.17.0, version: 4.17.15}',
      '  packages/app:',
      '    dependencies:',
      '      semver: {specifier: ^7.5.0, version: 7.5.1}',
      'packages:',
      '  lodash@4.17.15: {}',
      '  semver@7.5.1: {}',
      'snapshots:',
      '  lodash@4.17.15: {}',
      '  semver@7.5.1: {}',
      '',
    ].join('\n'));
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const purls = purlsOf(out);
    expect(purls).toContain('pkg:npm/lodash@4.17.15');
    expect(purls).toContain('pkg:npm/semver@7.5.1');
    expect(purls.some((p) => p.includes('%5E') || p.includes('^'))).toBe(false); // no declared ranges left
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: yarn.lock supersedes package.json and reads it for dev scope', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-yarn-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'y', dependencies: { ms: '^2.1.0' }, devDependencies: { tap: '^1.0.0' } }));
    writeFileSync(join(dir, 'yarn.lock'), [
      '# yarn lockfile v1',
      '',
      'ms@^2.1.0:',
      '  version "2.1.3"',
      '',
      'tap@^1.0.0:',
      '  version "1.0.2"',
      '',
    ].join('\n'));
    const { out, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    expect(purlsOf(out)).toEqual(expect.arrayContaining(['pkg:npm/ms@2.1.3', 'pkg:npm/tap@1.0.2']));
    expect(out).not.toContain('^2.1.0');
    const prod = await runCli(['sbom', dir, '--prod-only', '--deterministic']);
    expect(purlsOf(prod.out)).toContain('pkg:npm/ms@2.1.3');
    expect(purlsOf(prod.out).some((p) => p.includes('tap'))).toBe(false); // dev by reachability from package.json
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function pnpmLicenceFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-lic-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'mono', dependencies: { lodash: '^4.17.0', '@scope/y': '^1.0.0', zod: '^3.0.0' } }));
  writeFileSync(join(dir, 'pnpm-lock.yaml'), [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      lodash: {specifier: ^4.17.0, version: 4.17.21}',
    "      '@scope/y': {specifier: ^1.0.0, version: 1.2.0}",
    '      zod: {specifier: ^3.0.0, version: 3.22.0}',
    'packages:',
    '  lodash@4.17.21: {}',
    "  '@scope/y@1.2.0': {}",
    '  zod@3.22.0: {}',
    'snapshots:',
    '  lodash@4.17.21: {}',
    "  '@scope/y@1.2.0': {}",
    '  zod@3.22.0: {}',
    '',
  ].join('\n'));
  // pnpm store layout for lodash and the scoped package (name `/` → `+`)
  const store = (n: string, v: string) => join(dir, 'node_modules', '.pnpm', `${n.replace(/\//g, '+')}@${v}`, 'node_modules', n);
  mkdirSync(store('lodash', '4.17.21'), { recursive: true });
  writeFileSync(join(store('lodash', '4.17.21'), 'package.json'), JSON.stringify({ name: 'lodash', version: '4.17.21', license: 'MIT' }));
  mkdirSync(store('@scope/y', '1.2.0'), { recursive: true });
  writeFileSync(join(store('@scope/y', '1.2.0'), 'package.json'), JSON.stringify({ name: '@scope/y', version: '1.2.0', licenses: [{ type: 'Apache-2.0' }] }));
  // a hoisted zod of another version must not lend its licence
  mkdirSync(join(dir, 'node_modules', 'zod'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'zod', 'package.json'), JSON.stringify({ name: 'zod', version: '3.0.0', license: 'WRONG' }));
  return dir;
}

function licencesOf(out: string): Record<string, string | undefined> {
  const bom = JSON.parse(out) as { components: { name: string; licenses?: { license: { name: string } }[] }[] };
  return Object.fromEntries(bom.components.map((c) => [c.name, c.licenses?.[0]?.license.name]));
}

test('sbom: licences come from installed node_modules (pnpm store), offline; a hoisted copy of another version is ignored', async () => {
  const dir = pnpmLicenceFixture();
  try {
    const { out, err, code } = await runCli(['sbom', dir, '--deterministic']);
    expect(code).toBe(0);
    const lic = licencesOf(out);
    expect(lic.lodash).toBe('MIT');
    expect(lic['@scope/y']).toBe('Apache-2.0');
    expect(lic.zod).toBeUndefined();
    expect(err).toContain('licences: 2 known, 1 unknown');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: --license-map fills the rest; node_modules wins; SPDX keeps NOASSERTION for unknown', async () => {
  const dir = pnpmLicenceFixture();
  try {
    const map = join(dir, 'licences.json');
    writeFileSync(map, JSON.stringify({ 'zod@3.22.0': 'MIT', lodash: 'GPL-3.0' }));
    const { out, code } = await runCli(['sbom', dir, '--deterministic', '--license-map', map]);
    expect(code).toBe(0);
    const lic = licencesOf(out);
    expect(lic.zod).toBe('MIT');
    expect(lic.lodash).toBe('MIT'); // from node_modules, not overwritten by the map
    const spdx = await runCli(['sbom', dir, '--deterministic', '-f', 'spdx']);
    const doc = JSON.parse(spdx.out) as { packages: { name: string; licenseDeclared: string }[] };
    expect(doc.packages.find((p) => p.name === 'zod')?.licenseDeclared).toBe('NOASSERTION');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sbom: a --license-map that is not a JSON object of strings is refused (exit 1)', async () => {
  const dir = pnpmLicenceFixture();
  try {
    const map = join(dir, 'bad.json');
    writeFileSync(map, JSON.stringify(['MIT']));
    const r = await runCli(['sbom', dir, '--license-map', map]);
    expect(r.code).toBe(1);
    expect(r.err).toContain('--license-map');
    const r2 = await runCli(['sbom', dir, '--license-map']);
    expect(r2.code).toBe(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
