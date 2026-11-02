/** cognium-dev#1077 — `cognium-dev sbom` reads Tycho `*.target` files and pom `<artifactItem>`s. */
import { test, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');

test('sbom lists .target Maven locations and pom artifactItems', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sbom-tycho-'));
  try {
    mkdirSync(join(root, 'tp'));
    writeFileSync(join(root, 'tp', 'maven.locations.target'), `<target><locations><location type="Maven"><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version></location></locations></target>`);
    mkdirSync(join(root, 'bundle'));
    writeFileSync(join(root, 'bundle', 'pom.xml'), `<project><build><plugins><plugin><artifactId>maven-dependency-plugin</artifactId><configuration><artifactItems><artifactItem><groupId>com.nimbusds</groupId><artifactId>nimbus-jose-jwt</artifactId><version>9.37.3</version></artifactItem></artifactItems></configuration></plugin></plugins></build></project>`);
    const proc = Bun.spawn(['bun', 'run', CLI, 'sbom', root, '--deterministic'], { cwd: root, stdout: 'pipe', stderr: 'pipe' });
    const out = await new Response(proc.stdout).text();
    expect(await proc.exited).toBe(0);
    const names = (JSON.parse(out).components as Array<{ group?: string; name: string; version: string }>).map(c => `${c.group ? c.group + ':' : ''}${c.name}@${c.version}`).sort();
    expect(names).toEqual(['com.nimbusds:nimbus-jose-jwt@9.37.3', 'org.apache.commons:commons-lang3@3.12.0']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 60_000);
