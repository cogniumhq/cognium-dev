/**
 * Python graph facts: entry points (Flask, FastAPI, Django, click, Celery,
 * pytest, unittest, __main__), call edges keyed by Python stable ids, and
 * reach / dead code / removal reach over them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildPythonGraph, type PythonGraph } from '../../src/navigation/index.js';
import { deadCode, reach, removalReach } from '../../src/graph-facts/index.js';
import { deriveStableIds } from '../../src/stable-ids/index.js';
import * as publicApi from '../../src/index.js';
import { PY_APP } from './python-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
let g: PythonGraph;
let q: Map<string, string>;

beforeAll(async () => {
  g = await buildPythonGraph(files(PY_APP));
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
}, 60_000);

describe('Python entries', () => {
  it('finds routes with prefixes, commands, tasks, tests and Django modules', () => {
    const rows = g.entries.map(e => `${e.kind} ${e.certainty} ${q.get(e.id)}${e.method ? ` ${e.method} ${e.path ?? ''}` : ''}`);
    expect(rows).toEqual(expect.arrayContaining([
      'route declared app.web:health GET /health',
      'route declared app.web:get_user GET /users/<key>',
      'route declared app.web:get_user POST /users/<key>',
      'lifecycle declared app.web:before',
      'route declared app.api:read_item GET /v1/items/{item_id}',
      'route declared app.api:echo POST /echo',
      'route declared app.views:index ANY /',
      'route declared app.views:ItemView.get GET /items/',
      'reflection conventional app.urls',
      'main declared app.cli:run',
      'main conventional app.cli',
      'listener declared app.tasks:nightly',
      'main declared app.management.commands.sync:Command.handle',
      'test declared tests.test_core:svc',
      'test declared tests.test_core:CoreTest.test_find',
      'test declared tests.test_core:CoreTest.setUp',
      'test conventional tests.test_core:test_only',
      'test conventional tests.test_core',
    ]));
    const mounted = g.entries.find(e => q.get(e.id) === 'app.web:get_user');
    expect(mounted?.registeredPath).toBe('/<key>');
    expect(mounted?.mounts).toEqual(['/users']);
    expect(g.typeOnly.map(id => q.get(id))).toEqual(expect.arrayContaining(['app.core:Store', 'app.core:Store.load', 'app.core:coerce']));
    expect(g.scheme).toBe('python-graph@0.1');
    expect(g.entryScheme).toBe('entry-index@0.1');
  });
});

describe('Python call edges', () => {
  it('resolves names, imports, self, overrides and classes with tiers', () => {
    const edges = g.edges.map(e => `${q.get(e.from)} -> ${q.get(e.to)} [${e.tier}]`);
    expect(edges).toEqual(expect.arrayContaining([
      'app.web:get_user -> app.core:make_service [exact]',
      'app.api:read_item -> app.core:helper [exact]',
      'app.cli -> app.cli:run [exact]',
      'app.core:make_service -> app.core:UserService [exact]',
      'app.core:make_service -> app.core:UserService.__init__ [exact]',
      'app.core:BaseStore.load -> app.core:BaseStore.fetch [exact]',
      'app.core:BaseStore.load -> app.core:MemStore.fetch [polymorphic]',
      'app.views:ItemView.get -> app.views:ItemView.render [exact]',
      'app.web:get_user -> app.core:UserService.find [inferred]',
    ]));
    // Framework objects and imports from outside the project are unresolved, never guessed.
    expect(edges.some(e => e.includes('ItemView.get') && e.startsWith('app.api'))).toBe(false);
    expect(g.unresolved.filter(u => u.reason === 'external').map(u => u.methodName)).toEqual(expect.arrayContaining(['Flask', 'route', 'get', 'HttpResponse']));
    expect(g.references.map(r => `${q.get(r.from)} -> ${q.get(r.to)}`)).toContain('app.core:UserService.all -> app.core:UserService.format');
    expect(g.loads.map(l => `${q.get(l.from)} -> ${q.get(l.to)}`)).toEqual(expect.arrayContaining([
      'app.core:MemStore -> app.core:BaseStore',
      'app.core:MemStore -> app.core:MemStore.__repr__',
    ]));
    expect(g.imports.map(i => `${q.get(i.from)} -> ${q.get(i.to)}`)).toContain('app.web -> app.core');
    expect(g.sites).toBe(new Set([...g.edges, ...g.unresolved].map(e => `${e.site.file}:${e.site.line}:${e.site.col}:${e.methodName}`)).size);
  });
});

describe('Python reach and dead code', () => {
  it('gives live, may-be-live and dead verdicts and test reach', () => {
    const d = deadCode(g);
    const v = Object.fromEntries(d.facts.map(f => [f.qualified_name, f]));
    expect(v['app.core:make_service'].verdict).toBe('live');
    expect(v['app.core:helper'].verdict).toBe('live');
    expect(v['app.core:UserService.__init__'].verdict).toBe('live');
    expect(v['app.core:MemStore.__repr__'].verdict).toBe('live');
    expect(v['app.views:ItemView.render'].verdict).toBe('live');
    expect(v['app.management.commands.sync:Command'].verdict).toBe('live');
    expect(v['app.core:UserService.find'].verdict).toBe('may-be-live');
    expect(v['app.core:UserService.find'].reasons).toContain('weak-path');
    expect(v['app.core:UserService.unused'].verdict).toBe('dead');
    expect(v['app.core:MemStore.legacy'].verdict).toBe('dead');
    expect(v['app.core:UserService.format'].verdict).toBe('dead');
    expect(v['app.core:UserService.only_tested'].verdict).toBe('dead');
    expect(v['app.core:UserService.only_tested'].reachedByTest).toBe(true);
    // Test files and type-only declarations are not reported.
    expect(Object.keys(v).some(k => k.startsWith('tests.'))).toBe(false);
    expect(v['app.core:Store']).toBeUndefined();
    const r = reach(g, { targets: [d.facts.find(f => f.qualified_name === 'app.core:helper')!.id] });
    expect(r.facts[0].strong?.entry.kind).toBeDefined();
  });

  it('counts dynamic calls and unresolved registrations as could-reach', async () => {
    const app = {
      ...PY_APP,
      'src/app/urls.py': PY_APP['src/app/urls.py'].replace(']', '    path("missing/", views.nowhere),\n]'),
      'src/app/cli.py': PY_APP['src/app/cli.py'] + '\n\ndef late(name):\n    return getattr(make_service(), name)()\n',
    };
    const g2 = await buildPythonGraph(files(app), { mainFiles: [] });
    expect(g2.unresolvedRegistrations.map(r => r.reason)).toEqual(['handler-unresolved']);
    expect(g2.unresolved.find(u => u.reason === 'dynamic')?.methodName).toBe('<getattr>');
    const v = Object.fromEntries(deadCode(g2).facts.map(f => [f.qualified_name, f]));
    expect(v['app.core:UserService.unused'].verdict).toBe('may-be-live');
    expect(v['app.core:UserService.unused'].reasons).toContain('unresolved-sites');
  });

  it('takes console scripts as main entries and reports unknown ones', async () => {
    const g3 = await buildPythonGraph(files(PY_APP), { consoleScripts: ['app.core:helper', 'app.nowhere:main'] });
    expect(g3.entries.some(e => e.kind === 'main' && e.framework === 'console_scripts')).toBe(true);
    expect(g3.unresolvedRegistrations.map(r => r.reason)).toContain('manifest-unresolved');
  });
});

describe('Python removal reach', () => {
  it('reports what a removal could still reach, with move candidates', async () => {
    const headApp = { ...PY_APP };
    headApp['src/app/core.py'] = PY_APP['src/app/core.py'].replace(/\ndef helper\(\):\n {4}return 3\n/, '\n').replace('    def legacy(self):\n        return 1\n', '');
    headApp['src/app/util.py'] = '\n\ndef helper():\n    return 3\n';
    const head = await Promise.all(Object.entries(headApp).map(([path, code]) => deriveStableIds(code, path, 'python')));
    const rr = removalReach(g, head);
    const byName = Object.fromEntries(rr.removed.map(x => [x.qualified_name, x]));
    expect(byName['app.core:MemStore.legacy'].strong).toBeNull();
    // A small body that moved is a candidate, not settled; the removal still reports its live path.
    expect(byName['app.core:helper'].strong?.entry.kind).toBe('route');
    expect(byName['app.core:helper'].moveCandidates?.[0]?.relation).toBe('moved');
      });
});

describe('Python graph in the public API', () => {
  it('exports the builder and scheme', () => {
    expect(publicApi.buildPythonGraph).toBe(buildPythonGraph);
    expect(publicApi.PYTHON_GRAPH_SCHEME).toBe('python-graph@0.1');
  });
});
