/**
 * SR-G2 `removal-reach`: per removed declaration, the base's strong and weak
 * paths and the unresolved sites that could reach it; moves are not removals.
 */

import { describe, it, expect } from 'vitest';
import { buildTsCallGraph, type TsCallGraph } from '../../src/navigation/index.js';
import { entryIndexDigest, removalReach } from '../../src/graph-facts/index.js';
import * as publicApi from '../../src/index.js';
import { APP, PACKAGE_JSON } from './fixture.js';

const REG = 'const registry = [hidden];\nfunction hidden() { return 1; }\nexport function run() { registry.forEach(f => f()); }';

const build = (files: Record<string, string>): Promise<TsCallGraph> =>
  buildTsCallGraph(
    Object.entries(files).map(([path, code]) => ({ path, code, ids: { packageName: 'svc', keepBodyTokens: true } })),
    { packages: [{ root: '', packageJson: PACKAGE_JSON }], exportRoots: ['src/reg.ts'] },
  );

const BASE = { ...APP, 'src/reg.ts': REG };

describe('removalReach', () => {
  it('classifies removals by what reached them at the base, and leaves moves out', async () => {
    const base = await build(BASE);
    const head = await build({
      ...BASE,
      'src/repo.ts': APP['src/repo.ts']
        .replace('  legacy() { return 1; }\n', '')
        .replace('  find(id: string) { return this.rows.find(r => r === id); }\n', ''),
      // formatName moves to its own file (same body): a move, not a removal.
      'src/users.ts': APP['src/users.ts'].replace('function formatName(s: string) { return s.toUpperCase(); }', "import { formatName } from './fmt';"),
      'src/fmt.ts': 'export function formatName(s: string) { return s.toUpperCase(); }',
      'src/reg.ts': 'const registry: any[] = [];\nexport function run() { registry.forEach(f => f()); }',
    });
    const r = removalReach(base, head.files);
    const byName = Object.fromEntries(r.removed.map(d => [d.qualified_name, d]));
    // Live code removed: the CLI and a route reach Repo.find through getUser.
    expect(byName['svc/repo:Repo.find'].strong?.entry.certainty).toBe('declared');
    expect(byName['svc/repo:Repo.find'].strong?.steps.map(s => s.via)).toContain('call');
    // Unreachable: no path, nothing unresolved.
    expect(byName['svc/repo:Repo.legacy'].strong).toBeNull();
    expect(byName['svc/repo:Repo.legacy'].weak).toBeNull();
    expect(byName['svc/repo:Repo.legacy'].unresolvedCount).toBe(0);
    // May be live: only a value reference (the registry array) reaches it.
    expect(byName['svc/reg:hidden'].strong).toBeNull();
    expect(byName['svc/reg:hidden'].weak?.steps.at(-1)?.via).toBe('reference');
    // The move is reported, not removed.
    expect(byName['svc/users:formatName']).toBeUndefined();
    expect(r.moved.some(m => m.relation === 'moved')).toBe(true);
    expect(r.scheme).toBe('removal-reach@0.1');
    expect(r.rootKinds).not.toContain('test');
    expect(r.entryIndexDigest).toMatch(/^[a-z2-7]{26}$/);
    expect(r.partial).toEqual([]);
  });

  it('a removal only a move candidate explains stays removed and carries the candidate', async () => {
    const base = await build(BASE);
    const head = await build({ ...BASE, 'src/users.ts': APP['src/users.ts'].replace('function formatName(s: string) { return s.toUpperCase(); }', 'function fmtName(s: string) { return s.toUpperCase() + ""; }') });
    const r = removalReach(base, head.files, { moves: { similarityBar: 0.5 } });
    const f = r.removed.find(d => d.qualified_name === 'svc/users:formatName');
    expect(f?.moveCandidates.map(c => c.evidence)).toEqual(['similar-body']);
  });

  it('lists files that do not parse at either pin; root kinds are an input', async () => {
    const base = await build(BASE);
    const head = await build({ ...BASE, 'src/broken.ts': 'function x( {' });
    const r = removalReach(base, head.files, { rootKinds: ['export'] });
    expect(r.partial).toEqual(['src/broken.ts']);
    expect(r.rootKinds).toEqual(['export']);
  });

  it('the entry-index digest is order-independent and changes with the entries', async () => {
    const g = await build(BASE);
    expect(entryIndexDigest([...g.entries].reverse())).toBe(entryIndexDigest(g.entries));
    expect(entryIndexDigest(g.entries.slice(1))).not.toBe(entryIndexDigest(g.entries));
    expect(publicApi.removalReach).toBe(removalReach);
  });
});
