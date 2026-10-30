/**
 * Go graph facts: stable ids, entry points (main, init, net/http, gin, echo,
 * chi, go test), call edges keyed by Go stable ids, and reach / dead code /
 * removal reach over them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildGoGraph, type GoGraph } from '../../src/navigation/index.js';
import { deadCode, removalReach } from '../../src/graph-facts/index.js';
import { deriveStableIds, stableIdsSupport } from '../../src/stable-ids/index.js';
import * as publicApi from '../../src/index.js';
import { GO_APP } from './go-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
let g: GoGraph;
let q: Map<string, string>;

beforeAll(async () => {
  g = await buildGoGraph(files(GO_APP), { modulePath: 'example.com/app' });
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
}, 60_000);

describe('Go stable ids', () => {
  it('keys functions, methods by receiver type, types and package-level names', async () => {
    expect(stableIdsSupport('go')).toBe(true);
    const ids = await deriveStableIds(GO_APP['internal/core/service.go'], 'internal/core/service.go', 'go');
    const names = ids.decls.map(d => `${d.kind} ${d.qualified_name} ${d.signature}`);
    expect(names).toEqual(expect.arrayContaining([
      'module internal/core/service ',
      'field internal/core:registry ',
      'function internal/core:init@service ()',
      'type internal/core:Service ',
      'function internal/core:NewService (Store)*Service',
      'method internal/core:Service.Find (string)(string,error)',
    ]));
    // A parameter rename or a body edit keeps the declaration id.
    const renamed = await deriveStableIds(GO_APP['internal/core/service.go'].replace('Find(key string)', 'Find(k string)').replace('ToLower(key)', 'ToLower(k)'), 'internal/core/service.go', 'go');
    const find = (f: typeof ids) => f.decls.find(d => d.name === 'Find')!;
    expect(find(renamed).id).toBe(find(ids).id);
    expect(find(renamed).body_hash).not.toBe(find(ids).body_hash);
  });
});

describe('Go entries', () => {
  it('finds main, init, routes with prefixes and tests', () => {
    const rows = g.entries.map(e => `${e.kind} ${e.certainty} ${q.get(e.id)}${e.method ? ` ${e.method} ${e.path ?? ''}` : ''}`);
    expect(rows).toEqual(expect.arrayContaining([
      'main declared cmd/server:main',
      'lifecycle declared internal/core:init@service',
      'route declared internal/web:Handler.getUser GET /users/{id}',
      'route declared internal/web:health ANY /health',
      'route declared internal/web:listItems GET /api/items/:id',
      'route declared internal/web:ping GET /v2/ping',
      'route declared internal/web:getOrder GET /orders/{id}',
      'test declared internal/core:TestOnlyTested',
      'test declared internal/core:BenchmarkFind',
    ]));
    expect(rows.some(r => r.includes('POST /api/items'))).toBe(true);
    expect(g.typeOnly.map(id => q.get(id))).toEqual(['internal/core:Store']);
    expect(g.scheme).toBe('go-graph@0.1');
  });
});

describe('Go call edges', () => {
  it('resolves package scope, imports, receivers and unknown receivers with tiers', () => {
    const edges = g.edges.map(e => `${q.get(e.from)} -> ${q.get(e.to)} [${e.tier}]`);
    expect(edges).toEqual(expect.arrayContaining([
      'cmd/server:main -> internal/core:NewService [exact]',
      'cmd/server:main -> internal/core:NewMemStore [exact]',
      'cmd/server:main -> internal/web:Register [exact]',
      'internal/core:Service.OnlyTested -> internal/core:Service.helper [exact]',
      'internal/core:Service.Find -> internal/core:MemStore.Load [polymorphic]',
      'internal/web:Handler.getUser -> internal/core:Service.Find [exact]',
      'internal/web:Handler.getUser -> internal/core:Format [exact]',
    ]));
    expect(g.unresolved.filter(u => u.reason === 'external').map(u => u.methodName)).toEqual(expect.arrayContaining(['ListenAndServe', 'ToLower']));
    expect(g.references.map(r => `${q.get(r.from)} -> ${q.get(r.to)}`)).toEqual(expect.arrayContaining([
      'internal/web:Register -> internal/web:health',
      'internal/web:Register -> internal/web:Handler.getUser',
    ]));
    // Composite literals construct their type.
    expect(g.loads.map(l => `${q.get(l.from)} -> ${q.get(l.to)}`)).toContain('internal/core:NewMemStore -> internal/core:MemStore');
    expect(g.imports.map(i => `${q.get(i.from)} -> ${q.get(i.to)}`)).toContain('cmd/server/main -> internal/web/routes');
    expect(g.sites).toBe(new Set([...g.edges, ...g.unresolved].map(e => `${e.site.file}:${e.site.line}:${e.site.col}:${e.methodName}`)).size);
  });
});

describe('Go reach and dead code', () => {
  it('gives live, may-be-live and dead verdicts and test reach', () => {
    const v = Object.fromEntries(deadCode(g).facts.map(f => [f.qualified_name, f]));
    expect(v['internal/core:NewService'].verdict).toBe('live');
    expect(v['internal/web:Register'].verdict).toBe('live');
    expect(v['internal/web:health'].verdict).toBe('live');
    expect(v['internal/core:Format'].verdict).toBe('live');
    expect(v['internal/core:init@service'].verdict).toBe('live');
    expect(v['internal/core:Service.Find'].verdict).toBe('live');
    expect(v['internal/core:MemStore.Load'].verdict).toBe('live');
    expect(v['internal/web:orphan'].verdict).toBe('dead');
    expect(v['internal/core:MemStore.Legacy'].verdict).toBe('dead');
    expect(v['internal/core:Service.Unused'].verdict).toBe('dead');
    expect(v['internal/core:Service.OnlyTested'].verdict).toBe('dead');
    expect(v['internal/core:Service.OnlyTested'].reachedByTest).toBe(true);
    expect(Object.keys(v).some(k => k.includes('TestOnlyTested'))).toBe(false);
    expect(v['internal/core:Store']).toBeUndefined();
  });

  it('marks a library package exported API as entries, and unresolved handlers as could-reach', async () => {
    const app = { ...GO_APP, 'internal/web/routes.go': GO_APP['internal/web/routes.go'].replace('func orphan() {}', 'func Wire(r chi.Router, x interface{ H() }) { r.Get("/z", mystery) }') };
    const g2 = await buildGoGraph(files(app), { libraryPackages: ['internal/core'] });
    expect(g2.unresolvedRegistrations.map(r => r.reason)).toEqual(['handler-unresolved']);
    const v = Object.fromEntries(deadCode(g2).facts.map(f => [f.qualified_name, f]));
    expect(v['internal/core:Service.Unused'].verdict).toBe('live');
    expect(v['internal/core:MemStore.Legacy'].verdict).toBe('live');
  });
});

describe('Go values of unknown type and computed callees', () => {
  it('infers methods by name, refuses too many, and marks computed callees dynamic', async () => {
    const extra = `package web

import "example.com/lib/kv"

func Use(m map[string]func()) {
	v := kv.Open()
	v.Load("k")
	m["x"]()
}
`;
    const g2 = await buildGoGraph(files({ ...GO_APP, 'internal/web/use.go': extra }), { modulePath: 'example.com/app', maxInferred: 4 });
    const q2 = new Map(g2.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
    expect(g2.edges.map(e => `${q2.get(e.from)} -> ${q2.get(e.to)} [${e.tier}]`)).toContain('internal/web:Use -> internal/core:MemStore.Load [inferred]');
    expect(g2.unresolved.map(u => `${u.methodName} ${u.reason}`)).toEqual(expect.arrayContaining(['Open external', '<computed> dynamic']));
    const g3 = await buildGoGraph(files({ ...GO_APP, 'internal/web/use.go': extra }), { modulePath: 'example.com/app', maxInferred: 0 });
    expect(g3.unresolved.some(u => u.methodName === 'Load' && u.reason === 'unknown')).toBe(true);
  });
});

describe('Go removal reach', () => {
  it('reports what a removal could still reach', async () => {
    const headApp = { ...GO_APP };
    headApp['internal/core/store.go'] = GO_APP['internal/core/store.go'].replace('func (m *MemStore) Legacy() int { return 1 }\n', '');
    headApp['internal/core/service.go'] = GO_APP['internal/core/service.go'].replace('func Format(v string) string { return v }\n', '');
    const head = await Promise.all(Object.entries(headApp).map(([path, code]) => deriveStableIds(code, path, 'go')));
    const rr = removalReach(g, head);
    const byName = Object.fromEntries(rr.removed.map(x => [x.qualified_name, x]));
    expect(byName['internal/core:MemStore.Legacy'].strong).toBeNull();
    expect(byName['internal/core:Format'].strong?.entry.kind).toBe('route');
  });
});

describe('Go graph in the public API', () => {
  it('exports the builder, the scheme and the ids', () => {
    expect(publicApi.buildGoGraph).toBe(buildGoGraph);
    expect(publicApi.GO_GRAPH_SCHEME).toBe('go-graph@0.1');
    expect(typeof publicApi.deriveGoIds).toBe('function');
  });
});
