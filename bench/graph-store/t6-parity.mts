#!/usr/bin/env bun
/**
 * Graph-store T6 parity on a real Java tree: the `facts@2` producer walk
 * (`T6Graph`, the answers a store's T6 rules must give) against circle-ir's
 * own graph walk (`reach`, `blastRadius`, `impactedTests`) on the same graph.
 *
 *   bun bench/graph-store/t6-parity.mts <java-tree> [--seeds 50] [--rng 1] [--out result.json]
 *
 * The graph is built the way `cognium-dev entries --facts-arrow` builds it
 * (service and registering files included). Seeds are `method` declarations
 * drawn with a fixed PRNG, so a rerun on the same tree draws the same seeds.
 * Prints a summary and writes the full result as JSON. Exit 1 on any
 * blast-radius, impacted-test or (constructor-free) reach difference.
 * Needs the built packages: `npm run build`.
 */
import { writeFileSync } from 'node:fs';
import { buildGraph } from '../../packages/cli/src/graph-facts.ts';
// One circle-ir instance for the CLI's graph builder and for the walks: the built package (`npm run build -w packages/circle-ir` first).
import { blastRadius, impactedTests, initAnalyzer, reach, ReachGraph, T6Graph, t6RowsFromArrow } from 'circle-ir';
import type { Facts2Arrow, ReachInput } from 'circle-ir';

const argv = process.argv.slice(2);
const opt = (name: string, dflt: string): string => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : dflt; };
const tree = argv.find(a => !a.startsWith('--') && argv[argv.indexOf(a) - 1]?.startsWith('--') !== true);
if (!tree) { console.error('usage: bun bench/graph-store/t6-parity.mts <java-tree> [--seeds 50] [--rng 1] [--out result.json]'); process.exit(2); }
const nSeeds = Number(opt('--seeds', '50'));
const out = opt('--out', '');

/** mulberry32: a small fixed PRNG so seed draws repeat. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const ms = (t: number): number => Math.round(performance.now() - t);
const sameTiers = (a: Map<string, string>, b: Map<string, string>): boolean => a.size === b.size && [...a].every(([k, v]) => b.get(k) === v);
const median = (xs: number[]): number => { const s = [...xs].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : 0; };

await initAnalyzer();
let t = performance.now();
const graph = await buildGraph(tree, 'java', { emitFacts: 'arrow', factsScheme: 'facts@2' }) as ReachInput & { facts: Facts2Arrow };
const buildMs = ms(t);
t = performance.now();
const rows = await t6RowsFromArrow(graph.facts);
const t6 = new T6Graph(rows);
const loadMs = ms(t);

const graphIds = new Set(graph.files.flatMap(f => f.decls.map(d => d.id)));
const factsOnly = t6.ids.filter(id => !graphIds.has(id)).length; // re-keyed duplicates (`qualified_name#n`)
const t6Ids = new Set(t6.ids);
const methods = graph.files.flatMap(f => f.decls.filter(d => d.kind === 'method' && t6Ids.has(d.id)).map(d => d.id)).sort();
const reachGraph = new ReachGraph(graph);
const rand = prng(Number(opt('--rng', '1')));
const seeds: string[] = [];
const pool = [...new Set(methods)];
while (seeds.length < Math.min(nSeeds, pool.length)) seeds.push(pool.splice(Math.floor(rand() * pool.length), 1)[0]);

const perSeed: { seed: string; radius: number; radiusWeak: number; tests: number; blastEqual: boolean; testsEqual: boolean; t6Ms: number; walkMs: number }[] = [];
for (const s of seeds) {
  let q = performance.now();
  const mine = t6.blastRadius([s]);
  const mineTests = t6.impactedTests([s]);
  const t6Ms = ms(q);
  q = performance.now();
  const theirs = blastRadius(graph, [s], reachGraph);
  const theirTests = impactedTests(graph, [s], reachGraph);
  const walkMs = ms(q);
  perSeed.push({
    seed: s,
    radius: mine.size,
    radiusWeak: [...mine.values()].filter(v => v === 'weak').length,
    tests: mineTests.size,
    blastEqual: sameTiers(mine, theirs),
    testsEqual: sameTiers(mineTests, theirTests),
    t6Ms,
    walkMs,
  });
}

t = performance.now();
const mineReach = t6.reached();
const reachT6Ms = ms(t);
const tiers = (input: ReachInput): Map<string, string> => {
  const m = new Map<string, string>();
  for (const f of reach(input).facts) { if (f.strong) m.set(f.id, 'strong'); else if (f.weak) m.set(f.id, 'weak'); }
  return m;
};
t = performance.now();
const noCtors = tiers({ ...graph, entries: graph.entries.map(({ constructors: _c, ...e }) => e) });
const reachWalkMs = ms(t);
const full = tiers(graph);
const ctorRoots = graph.entries.flatMap(e => (e.constructors ?? []).map(c => ({ id: c, weak: e.certainty === 'inferred' })));
// What the constructor roots alone reach: entries made of them, through the same walk.
const ctorEntries = ctorRoots.map(r => ({ id: r.id, kind: 'main' as const, certainty: r.weak ? 'inferred' as const : 'declared' as const, file: '', line: 0 }));
const fromCtors = new Set(reach({ ...graph, entries: ctorEntries }).facts.filter(f => f.strong || f.weak).map(f => f.id));
const gap = [...full.keys()].filter(id => !mineReach.has(id));
const gapUpgraded = [...full.keys()].filter(id => full.get(id) === 'strong' && mineReach.get(id) === 'weak');

const result = {
  tree,
  date: new Date().toISOString().slice(0, 10),
  graph: { files: graph.files.length, decls: graphIds.size, factsDecls: t6.ids.length, factsOnlyIds: factsOnly, entries: graph.entries.length, partial: graph.partial.length },
  rows: { decl: rows.decl.length, call: rows.call.length, ref: rows.ref.length, entries: rows.entries.length },
  edges: t6.edges,
  maxRssMiB: Math.round(process.resourceUsage().maxRSS / 1024),
  timingsMs: { buildGraphAndFacts: buildMs, decodeAndIndex: loadMs, reachT6: reachT6Ms, reachCircleIr: reachWalkMs, seedQueryT6P50: median(perSeed.map(p => p.t6Ms)), seedQueryCircleIrP50: median(perSeed.map(p => p.walkMs)) },
  blast: {
    seeds: perSeed.length,
    equal: perSeed.filter(p => p.blastEqual).length,
    radiusMedian: median(perSeed.map(p => p.radius)),
    radiusMax: Math.max(0, ...perSeed.map(p => p.radius)),
    radiusShareOfDeclsMedian: t6.ids.length ? Number((median(perSeed.map(p => p.radius)) / t6.ids.length).toFixed(4)) : 0,
  },
  impactedTests: { seeds: perSeed.length, equal: perSeed.filter(p => p.testsEqual).length, testEntries: graph.entries.filter(e => e.kind === 'test').length, median: median(perSeed.map(p => p.tests)) },
  reach: {
    equalWithoutConstructors: sameTiers(mineReach, noCtors),
    t6Strong: [...mineReach.values()].filter(v => v === 'strong').length,
    t6Weak: [...mineReach.values()].filter(v => v === 'weak').length,
    circleIrFull: full.size,
    gapNotReached: gap.length,
    gapWeakNotStrong: gapUpgraded.length,
    gapExplainedByConstructors: [...gap, ...gapUpgraded].every(id => fromCtors.has(id)),
    constructorRoots: ctorRoots.length,
  },
  perSeed,
};
const ok = result.blast.equal === result.blast.seeds && result.impactedTests.equal === result.impactedTests.seeds && result.reach.equalWithoutConstructors;
console.log(JSON.stringify({ ...result, perSeed: undefined, parity: ok ? 'PASS' : 'FAIL' }, null, 2));
if (out) writeFileSync(out, JSON.stringify({ ...result, parity: ok ? 'PASS' : 'FAIL' }, null, 2) + '\n');
process.exit(ok ? 0 : 1);
