/**
 * Django / Django REST framework routes in the Python graph: `include()`
 * prefixes (inline and across urls modules), DRF verbs, and the call-argument
 * literal of prefixed strings.
 */

import { describe, it, expect } from 'vitest';
import { buildPythonGraph, type PythonGraph } from '../../src/navigation/index.js';
import { parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { PY_DRF_INCLUDE, PY_DRF_INLINE, PY_DRF_VERBS, PY_DRF_VIEWSET } from './python-drf-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));

async function routes(app: Record<string, string>): Promise<{ g: PythonGraph; rows: string[] }> {
  const g = await buildPythonGraph(files(app));
  const q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
  const rows = g.entries.filter(e => e.kind === 'route').map(e => `${q.get(e.id)} ${e.method} ${e.path}`);
  return { g, rows };
}

describe('Django include() prefixes', () => {
  it('composes inline include([...]) lists', async () => {
    const { rows } = await routes(PY_DRF_INLINE);
    expect(rows).toEqual(expect.arrayContaining([
      'shop.views:ping ANY /api/ping/',
      'shop.views:items ANY /api/v1/items/',
    ]));
  });

  it('composes prefixes across urls modules, by dotted name and by imported module', async () => {
    const { g, rows } = await routes(PY_DRF_INCLUDE);
    expect(rows).toEqual(expect.arrayContaining([
      'shop.views:items ANY /api/v1/items/',
      'shop.views:items ANY /v2/items/',
    ]));
    // An included module is not a root: its unprefixed route is not reported.
    expect(rows).not.toContain('shop.views:items ANY /items/');
    const mounted = g.entries.find(e => e.path === '/api/v1/items/');
    expect(mounted?.registeredPath).toBe('/items/');
    expect(mounted?.mounts).toEqual(['/api/v1/']);
    // A URLconf from outside the project is neither a mount nor a handler.
    expect(g.unresolvedRegistrations).toEqual([]);
  });

  // todo (design call): DRF routers. `router.register(r"items", ItemViewSet)`
  // reached through `include(router.urls)` should give the ViewSet's actions
  // routes under the include prefix: list/create at `/api/items/`,
  // retrieve/update/partial_update/destroy at a detail path, plus `@action`
  // methods. Open: the detail path's parameter spelling (`{pk}`, `<pk>`, the
  // router's regex, `lookup_field`), `trailing_slash`, `SimpleRouter` vs
  // `DefaultRouter` (the API root view), and whether an unresolved router
  // should be an unresolved registration. Fixture: PY_DRF_ROUTER.
  it.todo('gives ViewSet actions routes through router.register + include(router.urls)');
});

describe('DRF verbs', () => {
  it('takes @api_view verbs and generic-view verbs instead of ANY', async () => {
    const { rows } = await routes(PY_DRF_VERBS);
    expect(rows).toEqual(expect.arrayContaining([
      'shop.views:items GET /items/',
      'shop.views:items POST /items/',
      'shop.views:ping GET /ping/',
      'shop.views:ItemList GET /list/',
      'shop.views:ItemList POST /list/',
      'shop.views:ItemDetail GET /detail/<int:pk>/',
      'shop.views:ItemDetail DELETE /detail/<int:pk>/',
      'shop.views:ItemDetail.destroy DELETE /detail/<int:pk>/',
    ]));
    expect(rows.filter(r => r.includes(' ANY '))).toEqual([]);
  });

  it('takes ViewSet verbs from the as_view({verb: action}) map only', async () => {
    const { rows } = await routes(PY_DRF_VIEWSET);
    const at = (path: string) => rows.filter(r => r.endsWith(` ${path}`)).sort();
    // Only POST → list is wired: list is not GET, and create gets no route.
    expect(at('/search/')).toEqual([
      'shop.views:SearchViewSet POST /search/',
      'shop.views:SearchViewSet.list POST /search/',
    ]);
    // actions= keyword; a perform_* hook takes the verbs of its wired action; destroy is not wired.
    expect(at('/items/')).toEqual([
      'shop.views:ItemViewSet GET /items/',
      'shop.views:ItemViewSet POST /items/',
      'shop.views:ItemViewSet.create POST /items/',
      'shop.views:ItemViewSet.list GET /items/',
      'shop.views:ItemViewSet.perform_create POST /items/',
    ]);
    // A custom action named by the map is a route.
    expect(at('/items/export/')).toEqual([
      'shop.views:ItemViewSet GET /items/export/',
      'shop.views:ItemViewSet.export GET /items/export/',
    ]);
  });

  it('keeps ANY for a ViewSet without an as_view() map, not verbs guessed from action names', async () => {
    const { rows } = await routes(PY_DRF_VIEWSET);
    expect(rows.filter(r => r.endsWith(' /bare/')).sort()).toEqual([
      'shop.views:BareViewSet ANY /bare/',
      'shop.views:BareViewSet.create ANY /bare/',
      'shop.views:BareViewSet.list ANY /bare/',
    ]);
  });
});

describe('Python call-argument literal', () => {
  it('drops string prefixes and triple quotes', async () => {
    const tree = await parse(`
re_path(r'^api/', include("shop.urls"))
send(b"raw", rb'\\d+', f"plain", u'text', '''doc''', "")
`, 'python');
    const lit = (name: string) => extractCalls(tree, undefined, 'python').find(c => c.method_name === name)!.arguments.map(a => a.literal);
    expect(lit('re_path')[0]).toBe('^api/');
    expect(lit('send')).toEqual(['raw', '\\d+', 'plain', 'text', 'doc', '']);
  });
});
