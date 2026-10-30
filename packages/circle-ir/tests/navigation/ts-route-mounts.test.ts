/**
 * T-EP1.2: route mounts composed into full paths, Next.js file routes and
 * React Router routes, as `entry-index@0.1` entries.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadLanguage } from '../../src/core/parser.js';
import { buildTsCallGraph, joinRoutePath, type TsCallGraph, type TsCallGraphOptions } from '../../src/navigation/index.js';

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'wasm');
beforeAll(async () => {
  await loadLanguage('tsx', join(wasmDir, 'tree-sitter-tsx.wasm'));
});

const build = (files: Record<string, string>, options: TsCallGraphOptions = {}): Promise<TsCallGraph> =>
  buildTsCallGraph(Object.entries(files).map(([path, code]) => ({ path, code, ids: { packageName: 'p' } })), options);

function routes(g: TsCallGraph): string[] {
  const q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
  return g.entries
    .filter(e => e.kind === 'route' || e.kind === 'lifecycle')
    .map(e => `${e.kind === 'lifecycle' ? 'lifecycle ' : ''}${e.method ?? ''} ${e.path ?? ''} ${q.get(e.id)}${e.surface ? ` [${e.surface}]` : ''}${e.mounts ? ` mounts=${e.mounts.join(',')} registered=${e.registeredPath}` : ''}`.trim());
}

describe('Express mounts', () => {
  it('composes app.use prefixes across files, chained routes, middleware and repeated mounts', async () => {
    const g = await build({
      'src/app.ts': [
        "import express from 'express';",
        "import users from './users';",
        "import { admin } from './admin';",
        "import { auth } from './auth';",
        'const app = express();',
        'const api = express.Router();',
        'app.use(express.json());',
        'app.use(auth);',
        "app.use('/api', api);",
        "api.use('/users', users);",
        "app.use('/admin', auth, admin);",
        "app.use('/v2', users);",
        'app.use(missing);',
      ].join('\n'),
      'src/users.ts': [
        "import { Router } from 'express';",
        'const router = Router();',
        "router.get('/:id', function show(req, res) {});",
        "router.route('/').get(list).post(create);",
        'function list(req: any, res: any) {}',
        'function create(req: any, res: any) {}',
        'export default router;',
      ].join('\n'),
      'src/admin.ts': "import express from 'express';\nexport const admin = express.Router();\nadmin.delete('/cache', () => 1);",
      'src/auth.ts': 'export function auth(req: any, res: any, next: any) { next(); }',
    });
    expect(routes(g)).toEqual([
      'DELETE /admin/cache p/admin/<anonymous>@2.0.1.1 mounts=/admin registered=/cache',
      'USE / p/auth:auth [middleware]',
      'USE /admin p/auth:auth [middleware]',
      // one entry per mount chain: /api/users and /v2
      'GET /api/users/:id p/users/show@2.0.1.1 mounts=/api,/users registered=/:id',
      'GET /v2/:id p/users/show@2.0.1.1 mounts=/v2 registered=/:id',
      'GET /api/users p/users:list mounts=/api,/users registered=/',
      'GET /v2 p/users:list mounts=/v2 registered=/',
      'POST /api/users p/users:create mounts=/api,/users registered=/',
      'POST /v2 p/users:create mounts=/v2 registered=/',
    ]);
    // `express.json()` is a factory call: silent. `missing` resolves to nothing: counted.
    expect(g.unresolvedRegistrations.map(u => [u.reason, u.evidence])).toEqual([
      ['mount-unresolved', 'use : missing is neither a known router nor a declared function'],
    ]);
  });

  it('a mount cycle terminates; an unknown receiver mounts nothing', async () => {
    const g = await build({
      'src/a.ts': [
        "import express from 'express';",
        'const a = express.Router();',
        'const b = express.Router();',
        "a.use('/b', b);",
        "b.use('/a', a);",
        "a.get('/x', () => 1);",
        "other.use('/z', a);",
      ].join('\n'),
    });
    expect(routes(g).map(r => r.split(' ').slice(0, 2).join(' '))).toEqual(['GET /b/a/x']);
  });

  it('joins paths', () => {
    expect(joinRoutePath(['/api/', '/users', ''])).toBe('/api/users');
    expect(joinRoutePath(['', '/'])).toBe('/');
  });
});

describe('Next.js file routes', () => {
  const app = {
    'web/package.json': '',
    'web/pages/index.tsx': 'export default function Home() { return <div/>; }\nexport async function getServerSideProps() { return { props: {} }; }',
    'web/pages/blog/[slug].tsx': 'const Post = () => <p/>;\nexport default Post;',
    'web/pages/api/users/[id].ts': 'export default function handler(req: any, res: any) {}',
    'web/pages/_app.tsx': 'export default function App() { return null; }',
    'web/src/app/(shop)/cart/page.tsx': 'export default function Cart() { return <div/>; }',
    'web/src/app/layout.tsx': 'export default function Root({ children }: any) { return children; }\nexport function generateMetadata() { return {}; }',
    'web/src/app/docs/[...path]/page.tsx': 'export default function Docs() { return null; }',
    'web/src/app/api/items/route.ts': 'export async function GET() {}\nexport async function POST() {}\nexport function helper() {}',
    'web/middleware.ts': 'export function middleware(req: any) {}',
    'web/lib/util.ts': 'export function u() {}',
  };
  const files = Object.fromEntries(Object.entries(app).filter(([k]) => !k.endsWith('package.json')));

  it('maps pages/, app/ and middleware when the package depends on next', async () => {
    const g = await build(files, { packages: [{ root: 'web', packageJson: JSON.stringify({ dependencies: { next: '15.0.0' } }) }] });
    expect(routes(g)).toEqual([
      'USE / p/web/middleware:middleware [middleware]',
      'lifecycle   p/web/pages/_app:App',
      'ANY /api/users/{id} p/web/pages/api/users/[id]:handler [api]',
      'GET /blog/{slug} p/web/pages/blog/[slug]:Post [page]',
      'GET / p/web/pages/index:Home [page]',
      'lifecycle  / p/web/pages/index:getServerSideProps',
      'GET /cart p/web/src/app/(shop)/cart/page:Cart [page]', // route group dropped
      'GET /api/items p/web/src/app/api/items/route:GET [api]',
      'POST /api/items p/web/src/app/api/items/route:POST [api]', // `helper` is not a method name
      'GET /docs/{path} p/web/src/app/docs/[...path]/page:Docs [page]',
      'GET / p/web/src/app/layout:Root [layout]',
      'lifecycle  / p/web/src/app/layout:generateMetadata',
    ]);
    expect(g.entries.every(e => e.kind !== 'route' || e.certainty === 'conventional')).toBe(true);
  });

  it('is off without the dependency, on with fileRouteRoots', async () => {
    const off = await build(files, { packages: [{ root: 'web', packageJson: '{}' }] });
    expect(routes(off)).toEqual([]);
    const on = await build(files, { fileRouteRoots: { next: ['web'] } });
    expect(routes(on).length).toBeGreaterThan(5);
  });
});

describe('React Router', () => {
  it('JSX routes compose with their parents; index routes take the parent path', async () => {
    const g = await build({
      'src/App.tsx': [
        "import { Routes, Route } from 'react-router-dom';",
        "import { Users, User, Home, Settings } from './pages';",
        'export const App = () => (',
        '  <Routes>',
        '    <Route path="/" element={<Home />} />',
        '    <Route path="users" element={<Users />}>',
        '      <Route path=":id" element={<User />} />',
        '      <Route index element={<Users />} />',
        '    </Route>',
        '    <Route path="/settings" Component={Settings} />',
        '    <Route path="/gone" element={<NotDeclared />} />',
        '  </Routes>',
        ');',
      ].join('\n'),
      'src/pages.tsx': 'export function Users() { return null; }\nexport function User() { return null; }\nexport function Home() { return null; }\nexport function Settings() { return null; }',
    });
    expect(routes(g)).toEqual([
      'GET / p/pages:Home [page]',
      'GET /users p/pages:Users [page]',
      'GET /users/:id p/pages:User [page]',
      'GET /users p/pages:Users [page]',
      'GET /settings p/pages:Settings [page]',
    ].filter((r, i, a) => a.indexOf(r) === i));
    expect(g.unresolvedRegistrations.map(u => u.evidence)).toEqual(['route /gone: no component tied to a declaration']);
  });

  it('route objects in router factories, with children', async () => {
    const g = await build({
      'src/router.tsx': [
        "import { createBrowserRouter } from 'react-router-dom';",
        "import { Root, Team, Teams } from './views';",
        'export const router = createBrowserRouter([',
        "  { path: '/', element: <Root />, children: [",
        "    { path: 'teams', Component: Teams, children: [{ path: ':teamId', element: <Team /> }] },",
        '  ] },',
        ']);',
      ].join('\n'),
      'src/views.tsx': 'export const Root = () => null;\nexport const Teams = () => null;\nexport const Team = () => null;',
    });
    expect(routes(g)).toEqual(['GET / p/views:Root [page]', 'GET /teams p/views:Teams [page]', 'GET /teams/:teamId p/views:Team [page]']);
  });

  it('a Route not from react-router is not a route', async () => {
    const g = await build({ 'src/x.tsx': "import { Route } from './mine';\nexport const X = () => <Route path=\"/a\" element={<X />} />;", 'src/mine.tsx': 'export const Route = (p: any) => null;' });
    expect(routes(g)).toEqual([]);
  });
});
