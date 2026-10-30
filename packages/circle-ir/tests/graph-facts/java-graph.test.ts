/**
 * Java graph facts: entry points (Spring, JAX-RS, servlets, main, tests,
 * reflection), call edges from the navigation index keyed by Java stable ids,
 * and reach / dead code / removal reach over them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { deadCode, reach, removalReach } from '../../src/graph-facts/index.js';
import * as publicApi from '../../src/index.js';
import { JAVA_APP } from './java-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
let g: JavaGraph;
let q: Map<string, string>;

beforeAll(async () => {
  g = await buildJavaGraph(files(JAVA_APP), {
    serviceFiles: [{ path: 'src/main/resources/META-INF/services/app.plugins.Plugin', text: '# plugins\napp.plugins.Spi\n' }],
  });
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
}, 60_000);

describe('Java entries', () => {
  it('finds routes with prefixes, servlets, filters, beans, main, tests and reflection', () => {
    const rows = g.entries.map(e => `${e.kind} ${e.certainty} ${q.get(e.id)}${e.method ? ` ${e.method} ${e.path ?? ''}` : ''}`);
    expect(rows).toEqual(expect.arrayContaining([
      'route declared app.web:UserController.get GET /users/{id}',
      'route declared app.web:UserController.list GET /users',
      'route declared app.web:UserController.list HEAD /users/all',
      'bean declared app.web:UserController.constructor',
      'bean declared app.core:UserService',
      'route declared app.api:Health.ok GET /health',
      'route declared app.api:Health.deep GET /health/deep',
      'route declared app.servlet:Legacy.doGet GET /legacy',
      'lifecycle declared app.servlet:Legacy.init',
      'route declared app.servlet:Audit.doFilter USE ',
      'main declared app:Main.main',
      'reflection declared app.plugins:Echo',
      'reflection declared app.plugins:Spi',
      'test conventional app.core/UserServiceTest',
      'test declared app.core:UserServiceTest.tested',
    ]));
    expect(g.typeOnly.map(id => q.get(id)).sort()).toEqual(['app.core:Store', 'app.core:Store.load']);
  });
});

describe('Java call edges', () => {
  it('maps navigation targets to stable ids with their tiers', () => {
    const edges = g.edges.map(e => `${q.get(e.from)} -> ${q.get(e.to)} [${e.tier}]`);
    expect(edges).toEqual(expect.arrayContaining([
      'app.web:UserController.get -> app.core:UserService.find [exact]',
      'app.core:UserService.find -> app.core:MemStore.load [polymorphic]',
      'app.core:UserService.find -> app.core:DbStore.load [polymorphic]',
      'app.core:UserServiceTest.tested -> app.core:UserService.onlyTested [exact]',
    ]));
    expect(g.references.map(r => `${q.get(r.from)} -> ${q.get(r.to)}`)).toContain('app.core:UserService.all -> app.core:UserService.format');
    expect(g.sites).toBe(new Set([...g.edges.map(e => `${e.site.file}:${e.site.line}:${e.site.col}:${e.methodName}`), ...g.unresolved.filter(u => u.evidence === 'navigation index' || u.evidence.endsWith('not tied to a declaration')).map(u => `${u.site.file}:${u.site.line}:${u.site.col}:${u.methodName}`)]).size);
    expect(g.scheme).toBe('java-graph@0.1');
  });
});

describe('Java reach and dead code', () => {
  it('reach, dead-code verdicts and test reach', () => {
    const d = deadCode(g);
    const v = Object.fromEntries(d.facts.map(f => [f.qualified_name, f]));
    expect(v['app.core:UserService.find'].verdict).toBe('live');
    expect(v['app.core:MemStore.load'].verdict).toBe('live');
    expect(v['app.core:UserService.format'].verdict).toBe('may-be-live'); // only a method reference reaches it
    expect(v['app.core:UserService.unused'].verdict).toBe('dead');
    expect(v['app.core:MemStore.legacy'].verdict).toBe('dead');
    expect(v['app.core:UserService.onlyTested'].verdict).toBe('dead');
    expect(v['app.core:UserService.onlyTested'].reachedByTest).toBe(true);
    expect(v['app.plugins:Echo.constructor']).toBeDefined();
    // Test sources and interfaces are not reported.
    expect(Object.keys(v).some(k => k.includes('UserServiceTest'))).toBe(false);
    expect(v['app.core:Store']).toBeUndefined();
    const r = reach(g, { targets: [d.facts.find(f => f.qualified_name === 'app.core:UserService.store')?.id ?? ''] });
    // The bean entry is on the class (no constructor declared); the class creates its fields.
    expect(r.facts[0].strong?.steps.map(s => s.via)).toEqual(['entry', 'contains']);
    // A member initializes its class: a route method reaches its controller's fields through `loads`.
    const svcField = d.facts.find(f => f.qualified_name === 'app.web:UserController.service');
    expect(svcField?.verdict).toBe('live');
  });

  it('removal reach over Java', async () => {
    const head = await buildJavaGraph(files({
      ...JAVA_APP,
      'src/main/java/app/core/MemStore.java': JAVA_APP['src/main/java/app/core/MemStore.java'].replace('  void legacy() {}\n', ''),
      'src/main/java/app/core/UserService.java': JAVA_APP['src/main/java/app/core/UserService.java'].replace('  public String find(String id) { return store.load(id); }\n', ''),
    }));
    const r = removalReach(g, head.files);
    const byName = Object.fromEntries(r.removed.map(x => [x.qualified_name, x]));
    expect(byName['app.core:MemStore.legacy'].strong).toBeNull();
    expect(byName['app.core:UserService.find'].strong).not.toBeNull();
    expect(publicApi.buildJavaGraph).toBe(buildJavaGraph);
  }, 60_000);
});
