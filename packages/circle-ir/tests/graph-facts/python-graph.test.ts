/**
 * Python graph facts: entries (Flask, Django, Click, Celery, pytest,
 * `__main__`, pyproject scripts), call edges with tiers, and reach / dead
 * code / removal reach over them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildPythonGraph, type PythonGraph } from '../../src/navigation/index.js';
import { deadCode, removalReach } from '../../src/graph-facts/index.js';
import * as publicApi from '../../src/index.js';
import { PY_APP, PYPROJECT } from './python-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
let g: PythonGraph;
let q: Map<string, string>;

beforeAll(async () => {
  g = await buildPythonGraph(files(PY_APP), { pyprojectToml: PYPROJECT, exportRoots: ['src/shop/__init__.py'] });
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
});

describe('Python entries', () => {
  it('finds routes with blueprint prefixes and mounts, Django views, commands, tasks, tests, main and scripts', () => {
    const rows = g.entries.map(e => `${e.kind} ${e.certainty} ${q.get(e.id)}${e.method ? ` ${e.method} ${e.path}` : ''}`);
    expect(rows).toEqual(expect.arrayContaining([
      'route declared shop.app:health GET /health',
      'route declared shop.api:order GET /v1/orders/{oid}',
      'route declared shop.api:order DELETE /v1/orders/{oid}',
      'route declared shop.api:create POST /v1/orders',
      'route declared shop.views:item ANY /items/{pk}',
      'route declared shop.views:About.get GET /about',
      'main declared shop.cli:cli',
      'main declared shop.cli:sync',
      'main declared shop.cli',
      'main declared shop.cli:main',
      'listener declared shop.tasks:nightly',
      'test declared tests.test_service:svc',
      'test conventional tests.test_service:test_only',
      'test conventional tests.test_service:TestOrders.test_get',
      'test conventional tests.test_service',
      'export declared shop.service:OrderService',
    ]));
    expect(g.unresolvedRegistrations.map(u => u.evidence)).toEqual(['script shop.gone:run not found in the tree']);
  });
});

describe('Python call edges', () => {
  it('binds through imports, re-exports, self, annotations and constructors, with tiers', () => {
    const edges = g.edges.map(e => `${q.get(e.from)} -> ${q.get(e.to)} [${e.tier}]`);
    expect(edges).toEqual(expect.arrayContaining([
      'shop.api:service -> shop.service:OrderService.__init__ [exact]', // re-exported through __init__
      'shop.api:create -> shop.util:slug [exact]', // module alias
      'shop.service:OrderService.create -> shop.service:OrderService._new [exact]', // self
      'shop.service:OrderService.get -> shop.store:MemStore.load [exact]', // self.cache: MemStore
      'shop.cli:main -> shop.cli:cli [exact]',
    ]));
    // `service.get` on a module value constructed from the class.
    expect(edges).toContain('shop.api:order -> shop.service:OrderService.get [exact]');
    expect(g.references.map(r => `${q.get(r.from)} -> ${q.get(r.to)}`)).toContain('shop.service:OrderService._new -> shop.service:OrderService._key');
    expect(g.unresolved.some(u => u.methodName === 'lower' && u.reason === 'external')).toBe(false);
    expect(g.scheme).toBe('python-graph@0.1');
  });
});

describe('more Python shapes', () => {
  it('FastAPI routers and mounts, overrides, super(), parameters, lambdas, classes and unknown receivers', async () => {
    const h = await buildPythonGraph(files({
      'svc/main.py': [
        'from fastapi import FastAPI, APIRouter',
        'from svc.shapes import Shape, Square, make',
        'app = FastAPI()',
        'router = APIRouter(prefix="/shapes")',
        'app.include_router(router, prefix="/api")',
        'app.include_router(other_router)',
        '@router.get("/{sid}")',
        'def read(sid: int, shape: Shape):',
        '    area = shape.area()',
        '    sq = Square()',
        '    sq.area()',
        '    f = lambda: 1',
        '    f()',
        '    Shape.unit()',
        '    make(1)()',
        '    print(area)',
        '    return mystery.thing()',
        '@other.get("/x")',
        'def guessed(x):',
        '    x.area()',
      ].join('\n'),
      'svc/shapes.py': [
        'class Shape:',
        '    def area(self):',
        '        return 0',
        '    @staticmethod',
        '    def unit():',
        '        return 1',
        'class Square(Shape):',
        '    def area(self):',
        '        return super().area() + 1',
        'def make(n):',
        '    return lambda: n',
      ].join('\n'),
    }));
    const hq = new Map(h.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
    const rows = h.entries.map(e => `${e.kind} ${e.certainty} ${hq.get(e.id)} ${e.method} ${e.path}`);
    expect(rows).toEqual(expect.arrayContaining(['route declared svc.main:read GET /api/shapes/{sid}', 'route inferred svc.main:guessed GET /x']));
    const edges = h.edges.map(e => `${hq.get(e.to)} [${e.tier}]`);
    expect(edges).toEqual(expect.arrayContaining([
      'svc.shapes:Shape.area [polymorphic]', 'svc.shapes:Square.area [polymorphic]', // shape: Shape, Square overrides
      'svc.shapes:Square.area [exact]', // sq = Square()
      'svc.shapes:Shape.area [exact]', // super().area()
      'svc.shapes:Shape.unit [exact]',
      'svc.shapes:make [exact]',
      'svc.main:read/<lambda>@1.2.3.0.1 [exact]', // f = lambda: 1; f()
      'svc.shapes:Shape.area [inferred]', 'svc.shapes:Square.area [inferred]', // x has no class
    ]));
    expect(h.unresolved.map(u => `${u.methodName}:${u.reason}`)).toEqual(expect.arrayContaining(['print:external', 'thing:external', '<expr>:dynamic']));
    expect(h.unresolvedRegistrations.map(u => u.reason)).toEqual(['mount-unresolved']);
  });
});

describe('Python reach and dead code', () => {
  it('verdicts', () => {
    const d = deadCode(g);
    const v = Object.fromEntries(d.facts.map(f => [f.qualified_name, f]));
    expect(v['shop.service:OrderService.get'].verdict).toBe('live');
    expect(v['shop.store:MemStore.load'].verdict).toBe('live');
    expect(v['shop.service:OrderService.__repr__'].verdict).toBe('live'); // dunder: part of its class
    expect(v['shop.service:OrderService.size'].verdict).toBe('live'); // property: the class runs it
    expect(v['shop.service:OrderService._key'].verdict).toBe('may-be-live'); // passed as a value only
    expect(v['shop.service:OrderService.unused'].verdict).toBe('dead');
    expect(v['shop.util:dead_helper'].verdict).toBe('dead');
    expect(v['shop.store:MemStore.legacy'].verdict).toBe('dead');
    expect(v['shop.service:OrderService.only_tested'].verdict).toBe('dead');
    expect(v['shop.service:OrderService.only_tested'].reachedByTest).toBe(true);
    expect(Object.keys(v).some(k => k.startsWith('tests.'))).toBe(false);
  });

  it('removal reach over Python', async () => {
    const head = await buildPythonGraph(files({
      ...PY_APP,
      'src/shop/util.py': PY_APP['src/shop/util.py'].replace('def dead_helper():\n    return slug("x")\n', ''),
    }), { pyprojectToml: PYPROJECT });
    const r = removalReach(g, head.files);
    expect(r.removed.map(x => [x.qualified_name, x.strong === null])).toEqual([['shop.util:dead_helper', true]]);
    expect(publicApi.buildPythonGraph).toBe(buildPythonGraph);
  });
});
