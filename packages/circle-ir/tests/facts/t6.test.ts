/**
 * Graph-store T6 on `facts@2`, walked by the producer (`T6Graph`), against
 * circle-ir's own graph walk (`reach`, `blastRadius`, `impactedTests` over the
 * same `JavaGraph`). The rules a store runs must give the `T6Graph` answers;
 * this pins those answers to the reach core's.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { blastRadius, impactedTests, reach, ReachGraph, walkFrom, reachedIds } from '../../src/graph-facts/index.js';
import { T6Graph, t6RowsFromArrow, type T6Rows } from '../../src/facts/t6.js';
import type { Facts2Arrow } from '../../src/facts/arrow.js';
import { JAVA_APP } from '../graph-facts/java-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
const SERVICES = [{ path: 'src/main/resources/META-INF/services/app.plugins.Plugin', text: '# plugins\napp.plugins.Spi\n' }];

const sorted = (m: Map<string, string>) => [...m.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

/** circle-ir `reach()` as a tier map. */
function reachTiers(graph: JavaGraph, stripConstructors: boolean): Map<string, 'strong' | 'weak'> {
  const input = stripConstructors ? { ...graph, entries: graph.entries.map(({ constructors: _c, ...e }) => e) } : graph;
  const out = new Map<string, 'strong' | 'weak'>();
  for (const f of reach(input).facts) {
    if (f.strong) out.set(f.id, 'strong');
    else if (f.weak) out.set(f.id, 'weak');
  }
  return out;
}

let graph: JavaGraph;
let t6: T6Graph;

beforeAll(async () => {
  graph = await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES, emitFacts: 'arrow', factsScheme: 'facts@2' });
  t6 = new T6Graph(await t6RowsFromArrow(graph.facts as Facts2Arrow));
}, 120_000);

describe('T6 on facts@2 equals circle-ir\'s graph walk', () => {
  it('the facts hold every declaration of the graph, and every edge kind is present', () => {
    const graphIds = graph.files.flatMap(f => f.decls.map(d => d.id)).sort();
    expect([...t6.ids].sort()).toEqual([...new Set(graphIds)].sort());
    expect(t6.edges.callStrong).toBeGreaterThan(0);
    expect(t6.edges.contains).toBeGreaterThan(0);
    expect(t6.edges.loadsModule).toBeGreaterThan(0);
  });

  it('blast radius: every declaration as the seed, and seed pairs', () => {
    const ids = [...t6.ids];
    const sets: string[][] = ids.map(id => [id]);
    for (let i = 0; i + 1 < ids.length; i += 3) sets.push([ids[i], ids[i + 1]]);
    let nonEmpty = 0;
    for (const seeds of sets) {
      const mine = t6.blastRadius(seeds);
      expect(sorted(mine), seeds.join(',')).toEqual(sorted(blastRadius(graph, seeds)));
      if (mine.size > 0) nonEmpty++;
    }
    expect(nonEmpty).toBeGreaterThan(0);
  });

  it('impacted tests: every declaration as the seed', () => {
    let hits = 0;
    for (const id of t6.ids) {
      const mine = t6.impactedTests([id]);
      expect(sorted(mine), id).toEqual(sorted(impactedTests(graph, [id])));
      hits += mine.size;
    }
    expect(hits).toBeGreaterThan(0);
  });

  it('reach from declared entries: equal to reach() once entry constructors are left out', () => {
    expect(sorted(t6.reached())).toEqual(sorted(reachTiers(graph, true)));
  });

  it('with constructors, reach() adds only what the constructor roots reach (facts@2 has no constructors column)', () => {
    const full = reachTiers(graph, false);
    const mine = t6.reached();
    const extra = [...full.keys()].filter(id => !mine.has(id) || (full.get(id) === 'strong' && mine.get(id) === 'weak'));
    for (const id of mine.keys()) expect(full.has(id), id).toBe(true);
    const fromCtors = reachedIds(walkFrom(new ReachGraph(graph), graph.entries.flatMap(e => (e.constructors ?? []).map(c => ({ id: c, weak: e.certainty === 'inferred' })))));
    for (const id of extra) expect(fromCtors.has(id), id).toBe(true);
  });
});

describe('T6Graph tiers (hand-built facts)', () => {
  const D = (id: string, kind = 'method', parentId: string | null = null) => ({ id, kind, file: 'f', parentId, contained: false, loadsParent: false });
  const rows: T6Rows = {
    decl: [D('m', 'module'), D('a'), D('b'), D('c'), D('d'), D('t')],
    call: [
      { callerId: 'a', calleeId: 'b', tier: 'exact' },
      { callerId: 'b', calleeId: 'c', tier: 'inferred' },
      { callerId: 't', calleeId: 'a', tier: 'polymorphic' },
    ],
    ref: [{ fromId: 'd', toId: 'b' }],
    entries: [
      { declId: 'a', kind: 'route', certainty: 'declared' },
      { declId: 'd', kind: 'main', certainty: 'inferred' },
      { declId: 't', kind: 'test', certainty: 'declared' },
    ],
  };
  const g = new T6Graph(rows);

  it('a weak edge or an inferred entry makes the tier weak; test entries are not reach roots', () => {
    const r = g.reached();
    expect(r.get('a')).toBe('strong');
    expect(r.get('b')).toBe('strong');
    expect(r.get('c')).toBe('weak'); // only through the inferred call
    expect(r.get('d')).toBe('weak'); // an inferred entry
    expect(r.get('m')).toBe('strong'); // every declaration loads its module
    expect(r.has('t')).toBe(false);
  });

  it('blast radius excludes the seeds; impacted tests include a changed test', () => {
    expect(sorted(g.blastRadius(['b']))).toEqual([['a', 'strong'], ['d', 'weak'], ['t', 'strong']]);
    expect(sorted(g.blastRadius(['c']))).toEqual([['a', 'weak'], ['b', 'weak'], ['d', 'weak'], ['t', 'weak']]);
    expect(sorted(g.impactedTests(['b']))).toEqual([['t', 'strong']]);
    expect(sorted(g.impactedTests(['c']))).toEqual([['t', 'weak']]);
    expect(sorted(g.impactedTests(['t']))).toEqual([['t', 'strong']]);
    expect(sorted(g.impactedTests(['m']))).toEqual([['t', 'strong']]); // every declaration loads its module
    expect(g.impactedTests(['d']).size).toBe(0); // no test reaches d
  });
});
