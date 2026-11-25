/** `cognium-dev sbom` resolves a module pom's `${property}` versions from its parent poms on disk. */
import { test, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');

const dep = (g: string, a: string, v: string) => `<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></dependency>`;
const parent = (a: string, extra = '') => `<parent><groupId>org.example</groupId><artifactId>${a}</artifactId><version>1.0</version>${extra}</parent>`;

test('sbom: module poms take ${property} versions from the parent chain; what it cannot find stays unknown', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sbom-pom-parent-'));
  try {
    // root (grandparent) → build/parent (parent, by relativePath to a directory) → plugin; lib → root by default.
    writeFileSync(join(root, 'pom.xml'), `<project><groupId>org.example</groupId><artifactId>shop-root</artifactId><version>1.0</version>
      <properties><jackson.version>2.21.2</jackson.version><eclipselink.version>2.7.15</eclipselink.version></properties></project>`);
    mkdirSync(join(root, 'build', 'parent'), { recursive: true });
    writeFileSync(join(root, 'build', 'parent', 'pom.xml'), `<project>${parent('shop-root', '<relativePath>../../pom.xml</relativePath>')}<artifactId>shop-parent</artifactId>
      <properties><eclipselink.version>2.7.16</eclipselink.version><fluido.version>2.1.0</fluido.version></properties></project>`);
    mkdirSync(join(root, 'plugin'));
    writeFileSync(join(root, 'plugin', 'pom.xml'), `<project>${parent('shop-parent', '<relativePath>../build/parent</relativePath>')}<artifactId>shop-plugin</artifactId><dependencies>
      ${dep('com.fasterxml.jackson.core', 'jackson-databind', '${jackson.version}')}
      ${dep('org.eclipse.persistence', 'eclipselink', '${eclipselink.version}')}
      ${dep('org.apache.maven.skins', 'maven-fluido-skin', '${fluido.version}')}
      </dependencies></project>`);
    mkdirSync(join(root, 'lib'));
    writeFileSync(join(root, 'lib', 'pom.xml'), `<project>${parent('shop-root')}<artifactId>shop-lib</artifactId><dependencies>
      ${dep('com.fasterxml.jackson.core', 'jackson-core', '${jackson.version}')}
      </dependencies></project>`);
    // The parent named is not the file at the default path: not used (Maven would look in a repository).
    mkdirSync(join(root, 'other'));
    writeFileSync(join(root, 'other', 'pom.xml'), `<project>${parent('someone-else')}<artifactId>other</artifactId><dependencies>
      ${dep('org.x', 'from-elsewhere', '${jackson.version}')}
      </dependencies></project>`);
    // An empty relativePath: Maven does not look on disk.
    mkdirSync(join(root, 'detached'));
    writeFileSync(join(root, 'detached', 'pom.xml'), `<project>${parent('shop-root', '<relativePath/>')}<artifactId>detached</artifactId><dependencies>
      ${dep('org.x', 'detached-dep', '${jackson.version}')}
      </dependencies></project>`);

    const proc = Bun.spawn(['bun', 'run', CLI, 'sbom', root, '--deterministic'], { cwd: root, stdout: 'pipe', stderr: 'pipe' });
    const out = await new Response(proc.stdout).text();
    expect(await proc.exited).toBe(0);
    const v = Object.fromEntries((JSON.parse(out).components as Array<{ group?: string; name: string; version: string }>)
      .map(c => [`${c.group ? c.group + ':' : ''}${c.name}`, c.version]));
    expect(v['com.fasterxml.jackson.core:jackson-databind']).toBe('2.21.2'); // from the grandparent
    expect(v['org.eclipse.persistence:eclipselink']).toBe('2.7.16'); // the nearer parent wins
    expect(v['org.apache.maven.skins:maven-fluido-skin']).toBe('2.1.0'); // parent by a directory relativePath
    expect(v['com.fasterxml.jackson.core:jackson-core']).toBe('2.21.2'); // default ../pom.xml
    expect(v['org.x:from-elsewhere']).toBe('unknown');
    expect(v['org.x:detached-dep']).toBe('unknown');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 60_000);

test('sbom: a parent pom outside the scan root is not read', async () => {
  const outer = mkdtempSync(join(tmpdir(), 'sbom-pom-root-'));
  try {
    // outer/pom.xml is the parent of outer/scan/mod; only outer/scan is scanned.
    writeFileSync(join(outer, 'pom.xml'), `<project><groupId>org.example</groupId><artifactId>outer-root</artifactId><version>1.0</version>
      <properties><jackson.version>2.21.2</jackson.version></properties></project>`);
    const scan = join(outer, 'scan');
    mkdirSync(join(scan, 'mod'), { recursive: true });
    mkdirSync(join(scan, 'abs'));
    writeFileSync(join(scan, 'mod', 'pom.xml'), `<project>${parent('outer-root', '<relativePath>../../pom.xml</relativePath>')}<artifactId>mod</artifactId><dependencies>
      ${dep('org.x', 'climbs-out', '${jackson.version}')}
      </dependencies></project>`);
    writeFileSync(join(scan, 'abs', 'pom.xml'), `<project>${parent('outer-root', `<relativePath>${join(outer, 'pom.xml')}</relativePath>`)}<artifactId>abs</artifactId><dependencies>
      ${dep('org.x', 'absolute', '${jackson.version}')}
      </dependencies></project>`);
    // A symlink inside the root that points at the outside parent is not followed either.
    mkdirSync(join(scan, 'linked'));
    symlinkSync(join(outer, 'pom.xml'), join(scan, 'parent-link.xml'));
    writeFileSync(join(scan, 'linked', 'pom.xml'), `<project>${parent('outer-root', '<relativePath>../parent-link.xml</relativePath>')}<artifactId>linked</artifactId><dependencies>
      ${dep('org.x', 'through-link', '${jackson.version}')}
      </dependencies></project>`);

    const run = async (target: string) => {
      const proc = Bun.spawn(['bun', 'run', CLI, 'sbom', target, '--deterministic'], { cwd: outer, stdout: 'pipe', stderr: 'pipe' });
      const out = await new Response(proc.stdout).text();
      expect(await proc.exited).toBe(0);
      return Object.fromEntries((JSON.parse(out).components as Array<{ group?: string; name: string; version: string }>)
        .map(c => [`${c.group ? c.group + ':' : ''}${c.name}`, c.version]));
    };
    const inner = await run(scan);
    expect(inner['org.x:climbs-out']).toBe('unknown');
    expect(inner['org.x:absolute']).toBe('unknown');
    expect(inner['org.x:through-link']).toBe('unknown');
    // Scanning from the outer directory, the same parent is inside the root and is used.
    expect((await run(outer))['org.x:climbs-out']).toBe('2.21.2');
  } finally {
    rmSync(outer, { recursive: true, force: true });
  }
}, 60_000);
