/**
 * Unit tests for `mergeMavenInheritance` — parent-pom inheritance walk
 * (#192, 1.1.0). Builds temporary multi-module Maven trees on disk and
 * validates the inherited `distributionUrls` + `plugins` end up on the
 * child module's signals.
 *
 * Pillar I: no LLM identifiers.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdir, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { discoverBuildModules } from '../src/walk.js';

const CENTRAL = 'https://central.sonatype.com/repository/maven-snapshots/';
const REPO1 = 'https://repo1.maven.org/maven2/';

function pom(opts: {
  artifactId: string;
  parent?: { artifactId: string; relativePath?: string; emptyRelativePath?: boolean };
  distUrl?: string;
  pluginArtifact?: string;
}): string {
  const parentBlock = opts.parent
    ? `<parent>
  <groupId>g</groupId>
  <artifactId>${opts.parent.artifactId}</artifactId>
  <version>1</version>
  ${opts.parent.emptyRelativePath
    ? '<relativePath/>'
    : opts.parent.relativePath
      ? `<relativePath>${opts.parent.relativePath}</relativePath>`
      : ''}
</parent>`
    : '';
  const distBlock = opts.distUrl
    ? `<distributionManagement><repository><id>r</id><url>${opts.distUrl}</url></repository></distributionManagement>`
    : '';
  const pluginBlock = opts.pluginArtifact
    ? `<build><plugins><plugin><artifactId>${opts.pluginArtifact}</artifactId></plugin></plugins></build>`
    : '';
  return `<project>
  ${parentBlock}
  <groupId>g</groupId>
  <artifactId>${opts.artifactId}</artifactId>
  <version>1</version>
  ${distBlock}
  ${pluginBlock}
</project>`;
}

let tmpRoot: string;

beforeAll(async () => {
  tmpRoot = join(tmpdir(), `cognium-inherit-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(tmpRoot, { recursive: true });
});

afterAll(async () => {
  await rm(tmpRoot, { recursive: true, force: true });
});

async function mkScenario(name: string): Promise<string> {
  const root = join(tmpRoot, name);
  await mkdir(root, { recursive: true });
  return root;
}

describe('mergeMavenInheritance — distributionManagement', () => {
  test('two-level chain: child inherits parent dist URL (explicit relativePath)', async () => {
    const root = await mkScenario('two-level-explicit');
    await mkdir(join(root, 'parent'), { recursive: true });
    await mkdir(join(root, 'child'), { recursive: true });
    await writeFile(join(root, 'parent', 'pom.xml'),
      pom({ artifactId: 'parent', distUrl: CENTRAL }));
    await writeFile(join(root, 'child', 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'parent', relativePath: '../parent/pom.xml' } }));

    const mods = await discoverBuildModules(root);
    const child = mods.find(m => m.root === join(root, 'child'))!;
    expect(child.signals.distributionUrls).toContain(CENTRAL);
  });

  test('default <relativePath> (omitted) resolves to ../pom.xml', async () => {
    // parent at root, child at root/child — default ../pom.xml works.
    const root = await mkScenario('default-relpath');
    await mkdir(join(root, 'child'), { recursive: true });
    await writeFile(join(root, 'pom.xml'),
      pom({ artifactId: 'parent', distUrl: CENTRAL }));
    await writeFile(join(root, 'child', 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'parent' } }));

    const mods = await discoverBuildModules(root);
    const child = mods.find(m => m.root === join(root, 'child'))!;
    expect(child.signals.distributionUrls).toContain(CENTRAL);
  });

  test('three-level chain: grandparent dist URL propagates to child', async () => {
    const root = await mkScenario('three-level');
    await mkdir(join(root, 'grand'), { recursive: true });
    await mkdir(join(root, 'parent'), { recursive: true });
    await mkdir(join(root, 'child'), { recursive: true });
    await writeFile(join(root, 'grand', 'pom.xml'),
      pom({ artifactId: 'grand', distUrl: CENTRAL }));
    await writeFile(join(root, 'parent', 'pom.xml'),
      pom({ artifactId: 'parent', parent: { artifactId: 'grand', relativePath: '../grand/pom.xml' } }));
    await writeFile(join(root, 'child', 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'parent', relativePath: '../parent/pom.xml' } }));

    const mods = await discoverBuildModules(root);
    const child = mods.find(m => m.root === join(root, 'child'))!;
    expect(child.signals.distributionUrls).toContain(CENTRAL);
  });

  test('empty <relativePath/> stops the chain (no inheritance)', async () => {
    const root = await mkScenario('empty-relpath');
    await mkdir(join(root, 'parent'), { recursive: true });
    await mkdir(join(root, 'child'), { recursive: true });
    await writeFile(join(root, 'parent', 'pom.xml'),
      pom({ artifactId: 'parent', distUrl: CENTRAL }));
    await writeFile(join(root, 'child', 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'parent', emptyRelativePath: true } }));

    const mods = await discoverBuildModules(root);
    const child = mods.find(m => m.root === join(root, 'child'))!;
    expect(child.signals.distributionUrls).not.toContain(CENTRAL);
    expect(child.signals.distributionUrls).toEqual([]);
  });

  test('parent outside scanRoot: chain walk stops at boundary', async () => {
    // Top-level scanRoot only contains the child. The parent lives one
    // directory above scanRoot. The walker never discovers it and the
    // boundary check rejects the candidate path.
    const outer = await mkScenario('outside-scanroot');
    const scanRoot = join(outer, 'inside');
    await mkdir(scanRoot, { recursive: true });
    await writeFile(join(outer, 'pom.xml'),
      pom({ artifactId: 'outer-parent', distUrl: CENTRAL }));
    await writeFile(join(scanRoot, 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'outer-parent', relativePath: '../pom.xml' } }));

    const mods = await discoverBuildModules(scanRoot);
    const child = mods.find(m => m.root === scanRoot)!;
    expect(child.signals.distributionUrls).not.toContain(CENTRAL);
    expect(child.signals.distributionUrls).toEqual([]);
  });

  test('parent not discovered (parent dir missing): walk stops', async () => {
    const root = await mkScenario('missing-parent');
    await mkdir(join(root, 'child'), { recursive: true });
    // No parent pom written anywhere.
    await writeFile(join(root, 'child', 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'ghost', relativePath: '../ghost/pom.xml' } }));

    const mods = await discoverBuildModules(root);
    const child = mods.find(m => m.root === join(root, 'child'))!;
    expect(child.signals.distributionUrls).toEqual([]);
  });
});

describe('mergeMavenInheritance — plugin inheritance', () => {
  test('child inherits spring-boot-maven-plugin tag from parent', async () => {
    const root = await mkScenario('plugin-inherit');
    await mkdir(join(root, 'parent'), { recursive: true });
    await mkdir(join(root, 'child'), { recursive: true });
    await writeFile(join(root, 'parent', 'pom.xml'),
      pom({ artifactId: 'parent', pluginArtifact: 'spring-boot-maven-plugin' }));
    await writeFile(join(root, 'child', 'pom.xml'),
      pom({ artifactId: 'child', parent: { artifactId: 'parent', relativePath: '../parent/pom.xml' } }));

    const mods = await discoverBuildModules(root);
    const child = mods.find(m => m.root === join(root, 'child'))!;
    expect(child.signals.plugins).toContain('spring-boot');
  });
});

describe('mergeMavenInheritance — safety', () => {
  test('cycle between two poms terminates (does not hang)', async () => {
    // a points to b; b points to a. The merge should run to completion.
    const root = await mkScenario('cycle');
    await mkdir(join(root, 'a'), { recursive: true });
    await mkdir(join(root, 'b'), { recursive: true });
    await writeFile(join(root, 'a', 'pom.xml'),
      pom({ artifactId: 'a', parent: { artifactId: 'b', relativePath: '../b/pom.xml' }, distUrl: REPO1 }));
    await writeFile(join(root, 'b', 'pom.xml'),
      pom({ artifactId: 'b', parent: { artifactId: 'a', relativePath: '../a/pom.xml' }, distUrl: CENTRAL }));

    const mods = await discoverBuildModules(root);
    const a = mods.find(m => m.root === join(root, 'a'))!;
    const b = mods.find(m => m.root === join(root, 'b'))!;
    // Each gets the *other*'s URL via one hop, then walk stops on cycle.
    expect(a.signals.distributionUrls).toContain(CENTRAL);
    expect(b.signals.distributionUrls).toContain(REPO1);
  });

  test('depth cap: 10-level chain stops at depth 6', async () => {
    const root = await mkScenario('depth-cap');
    // Build chain root/d0/pom.xml -> root/d1/pom.xml -> … -> root/d9/pom.xml
    // d9 declares the dist URL. With cap=6, only d0..d5 chain reaches the
    // URL via d6 — but the test only checks d0 (the leaf-most child).
    for (let i = 0; i < 10; i++) {
      await mkdir(join(root, `d${i}`), { recursive: true });
    }
    // d9 is the top-most ancestor.
    await writeFile(join(root, 'd9', 'pom.xml'),
      pom({ artifactId: 'd9', distUrl: CENTRAL }));
    for (let i = 8; i >= 0; i--) {
      await writeFile(join(root, `d${i}`, 'pom.xml'),
        pom({ artifactId: `d${i}`, parent: { artifactId: `d${i+1}`, relativePath: `../d${i+1}/pom.xml` } }));
    }

    const mods = await discoverBuildModules(root);
    const leaf = mods.find(m => m.root === join(root, 'd0'))!;
    // d0 → d1 → d2 → d3 → d4 → d5 → d6 (6 hops). d6 has no dist URL.
    // d9 is 9 hops away from d0 → never reached.
    expect(leaf.signals.distributionUrls).not.toContain(CENTRAL);
  });
});
