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
