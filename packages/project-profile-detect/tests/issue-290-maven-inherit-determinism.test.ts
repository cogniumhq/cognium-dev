/**
 * cognium-dev #290 — `mergeMavenInheritance` must be order-independent, and
 * `MAX_DEPTH` must be a real horizon.
 *
 * `walkParents` read the LIVE `parent.signals` arrays, which the same merge
 * loop mutates. A module processed early absorbed its own ancestors' values and
 * wrote them into its signals; a module processed later walked into it and
 * inherited those too. Effect: the depth cap bounded nothing, and the result
 * depended on filesystem discovery order — the same project could produce
 * different `distributionUrls` on different machines.
 *
 * These tests drive `mergeMavenInheritance` directly with a hand-built module
 * list, so they are independent of directory-iteration order (the reason the
 * pre-existing `depth cap` test was flaky rather than reliably red).
 */

import { describe, test, expect } from 'bun:test';
import { join } from 'path';
import { mergeMavenInheritance } from '../src/maven-inherit.js';
import type { BuildModule } from '../src/types.js';

const CENTRAL = 'https://central.sonatype.com/repository/maven-snapshots/';
const ROOT = join('/tmp', 'issue-290-root');

/** d0 → d1 → … → d9, only d9 declaring a distribution URL. */
function chain(): BuildModule[] {
  const mods: BuildModule[] = [];
  for (let i = 0; i < 10; i++) {
    const isTop = i === 9;
    mods.push({
      root: join(ROOT, `d${i}`),
      buildSystem: 'maven',
      buildFile: join(ROOT, `d${i}`, 'pom.xml'),
      artifactId: `d${i}`,
      signals: {
        plugins: [],
        distributionUrls: isTop ? [CENTRAL] : [],
      },
      ...(isTop
        ? {}
        : {
            parentRef: {
              artifactId: `d${i + 1}`,
              relativePath: join('..', `d${i + 1}`, 'pom.xml'),
              emptyRelativePath: false,
            },
          }),
    });
  }
  return mods;
}

const urlsByArtifact = (mods: BuildModule[]) =>
  Object.fromEntries(
    mods.map(m => [m.artifactId!, [...m.signals.distributionUrls].sort()]),
  );

describe('#290 mergeMavenInheritance determinism + depth horizon', () => {
  test('depth cap is a real horizon: d0 is 9 hops from the URL and does not inherit it', () => {
    const mods = chain();
    mergeMavenInheritance(mods, ROOT);
    const d0 = mods.find(m => m.artifactId === 'd0')!;
    expect(d0.signals.distributionUrls).not.toContain(CENTRAL);
  });

  test('modules within MAX_DEPTH of the URL still inherit it (recall)', () => {
    const mods = chain();
    mergeMavenInheritance(mods, ROOT);
    // d3 → d4 … → d9 is 6 hops, exactly the cap.
    const d3 = mods.find(m => m.artifactId === 'd3')!;
    expect(d3.signals.distributionUrls).toContain(CENTRAL);
    // d8 is one hop away — the nearest child of the declaring module.
    const d8 = mods.find(m => m.artifactId === 'd8')!;
    expect(d8.signals.distributionUrls).toContain(CENTRAL);
  });

  test('result does not depend on module processing order', () => {
    const forward = chain();
    mergeMavenInheritance(forward, ROOT);

    const reversed = chain().reverse();
    mergeMavenInheritance(reversed, ROOT);

    // An order that provoked the read-after-write bug in the original report:
    // d6 first, so it absorbs d7/d8/d9 before d0 walks through it.
    const provoking = chain();
    const order = [6, 5, 8, 7, 9, 2, 3, 0, 1, 4];
    const shuffled = order.map(i => provoking.find(m => m.artifactId === `d${i}`)!);
    mergeMavenInheritance(shuffled, ROOT);

    expect(urlsByArtifact(reversed)).toEqual(urlsByArtifact(forward));
    expect(urlsByArtifact(shuffled)).toEqual(urlsByArtifact(forward));
  });
});
