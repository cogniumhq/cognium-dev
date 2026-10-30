/**
 * Entry points (`entry-index@0.1`, TypeScript minimal), the reach core and
 * the dead-code answer on one small service.
 */

import { describe, it, expect } from 'vitest';
import { buildTsCallGraph, type TsCallGraph } from '../../src/navigation/index.js';
import { deadCode, reach } from '../../src/graph-facts/index.js';
import * as publicApi from '../../src/index.js';
import { PACKAGE_JSON, files } from './fixture.js';

const build = (extra: Record<string, string> = {}, exportRoots: string[] = []): Promise<TsCallGraph> =>
  buildTsCallGraph(files(extra), { packages: [{ root: '', packageJson: PACKAGE_JSON }], exportRoots });

function qnames(g: TsCallGraph): Map<string, string> {
  return new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
}

describe('entry points', () => {
  it('finds routes, decorators, exports, bin and tests with their certainty', async () => {
    const g = await build();
    const q = qnames(g);
    const rows = g.entries.map(e => `${e.kind} ${e.certainty} ${q.get(e.id)}${e.method ? ` ${e.method} ${e.path}` : ''}`);
    expect(rows).toEqual([
      'main declared svc/cli', // package.json bin, dist/ mapped back to src/
      'bean declared svc/nest:Svc.constructor', // @Injectable
      'bean declared svc/nest:GreetController.constructor', // @Controller
      'route declared svc/nest:GreetController.greet GET /greet/:name', // @Get under the controller prefix
      'export declared svc/server:app', // package.json main/exports; default export
      'route declared svc/users:listUsers GET /users', // express, handler by reference
      'route declared svc/server/<anonymous>@5.0.1.1 POST /users/:id', // inline handler
      'test conventional svc/users.test', // the test file runs
      'test conventional svc/users.test/<anonymous>@1.0.1.1/<anonymous>@1.0.0.1.1', // it(...)
      'test conventional svc/users.test/<anonymous>@1.0.1.1', // describe(...)
    ]);
    // `./package.json` in exports is not code and is skipped.
    expect(g.unresolvedRegistrations).toEqual([]);
  });

  it('a route on a receiver of unknown origin is inferred; an unresolvable handler is counted', async () => {
    const g = await build({ 'src/other.ts': "import { r } from 'somewhere';\nr.get('/x', () => 1);\nr.post('/y', makeHandler());\nmap.get('key', fallback);" });
    const inferred = g.entries.filter(e => e.file === 'src/other.ts');
    expect(inferred.map(e => [e.kind, e.certainty, e.path])).toEqual([['route', 'inferred', '/x']]);
    expect(g.unresolvedRegistrations.map(u => [u.reason, u.site.file])).toEqual([['handler-unresolved', 'src/other.ts']]);
  });

  it('manifest problems are unresolved registrations, never silent', async () => {
    const bad = await buildTsCallGraph(files(), { packages: [{ root: '', packageJson: '{nope' }] });
    expect(bad.unresolvedRegistrations.map(u => u.reason)).toEqual(['manifest-unresolved']);
    const missing = await buildTsCallGraph(files(), { packages: [{ root: '', packageJson: JSON.stringify({ main: 'dist/gone.js', bin: 'bin/x.js' }) }] });
    expect(missing.unresolvedRegistrations.map(u => u.evidence)).toEqual([
      'export path dist/gone.js not found in the tree',
      'bin bin/x.js not found in the tree',
    ]);
    const roots = await buildTsCallGraph(files(), { exportRoots: ['src/audit.ts'], mainFiles: ['src/cli.ts'] });
    const q = qnames(roots);
    expect(roots.entries.filter(e => e.kind === 'export').map(e => q.get(e.id))).toEqual(['svc/audit:audit', 'svc/audit:escaped', 'svc/audit:handlers']);
    expect(roots.entries.filter(e => e.kind === 'main').map(e => q.get(e.id))).toEqual(['svc/cli']);
  });

  it('records value references and module loads', async () => {
    const g = await build();
    const q = qnames(g);
    expect(g.references.map(r => `${q.get(r.from)} -> ${q.get(r.to)}`)).toEqual(expect.arrayContaining([
      'svc/server -> svc/users:listUsers',
      'svc/audit:handlers -> svc/audit:escaped',
    ]));
    expect(g.imports.map(i => `${q.get(i.from)} -> ${q.get(i.to)}`)).toEqual(expect.arrayContaining([
      'svc/server -> svc/users', 'svc/users -> svc/repo', 'svc/cli -> svc/users',
    ]));
    expect(g.typeOnly.map(id => q.get(id)).sort()).toEqual(['svc/repo:Store', 'svc/repo:Store.all', 'svc/types:Id', 'svc/types:Shape', 'svc/types:Shape.area', 'svc/types:ambient']);
  });
});

describe('reach', () => {
  it('gives a strong path through exact calls, contains and loads, with tiers', async () => {
    const g = await build();
    const q = qnames(g);
    const r = reach(g);
    const find = (name: string) => r.facts.find(f => f.qualified_name === name);
    const all = find('svc/repo:Repo.all');
    expect(all?.strong?.entry.kind).toBe('route');
    expect(all?.strong?.steps.map(s => `${s.via}${s.tier ? `:${s.tier}` : ''} ${q.get(s.decl)}`)).toEqual([
      'entry svc/users:listUsers',
      'call:exact svc/repo:Repo.all',
    ]);
    // `new Repo()` at module level: module -> field (contains) -> constructor-less class (call).
    expect(find('svc/repo:Repo.rows')?.strong).not.toBeNull();
    expect(find('svc/users:getUser')?.strong?.steps[0].via).toBe('entry');
  });

  it('a value reference is a weak path, and an inferred call too', async () => {
    const g = await build();
    const r = reach(g, { rootKinds: ['route', 'main', 'bean'] });
    const find = (name: string) => r.facts.find(f => f.qualified_name === name);
    const escaped = find('svc/audit:escaped');
    expect(escaped?.strong).toBeNull();
    expect(escaped?.weak?.steps.at(-1)?.via).toBe('reference');
    // `x.mystery()` in onlyByName binds by name alone; onlyByName itself is only exported.
    expect(find('svc/repo:Repo.mystery')?.strong).toBeNull();
  });

  it('unresolved sites that could reach a declaration are listed', async () => {
    const g = await build({ 'src/dyn.ts': "import { getUser } from './users';\nexport function d(o: any, k: string) { getUser('a'); o[k](); }" }, ['src/dyn.ts']);
    const r = reach(g, { rootKinds: ['export'] });
    const legacy = r.facts.find(f => f.qualified_name === 'svc/repo:Repo.legacy');
    expect(legacy?.strong).toBeNull();
    expect(legacy?.unresolved.map(u => [u.kind, u.methodName])).toContainEqual(['call', '<expr>']);
    expect(r.rootKinds).toEqual(['export']);
  });

  it('targets narrow the answer; partial files are passed through', async () => {
    const g = await build({ 'src/broken.ts': 'function x( {' });
    const id = g.files.find(f => f.file === 'src/users.ts')?.decls[1].id as string;
    const r = reach(g, { targets: [id] });
    expect(r.facts.map(f => f.id)).toEqual([id]);
    expect(r.partial).toEqual(['src/broken.ts']);
  });
});

describe('deadCode (R-EN2)', () => {
  it('verdicts, reasons and test reach', async () => {
    const g = await build();
    const d = deadCode(g);
    const v = Object.fromEntries(d.facts.map(f => [f.qualified_name, f]));
    expect(v['svc/users:listUsers'].verdict).toBe('live');
    expect(v['svc/repo:Repo.find'].verdict).toBe('live');
    // Only a test calls it: dead product code that a test reaches.
    expect(v['svc/users:unusedHelper'].verdict).toBe('dead');
    expect(v['svc/users:unusedHelper'].reachedByTest).toBe(true);
    expect(v['svc/users:unusedHelper'].test).toBeDefined();
    expect(v['svc/users:formatName'].verdict).toBe('dead');
    expect(v['svc/users:formatName'].reachedByTest).toBe(true);
    // Nothing calls it, and no unresolved site in reached code could.
    expect(v['svc/repo:Repo.legacy'].verdict).toBe('dead');
    expect(v['svc/repo:Repo.legacy'].reachedByTest).toBe(false);
    // Test files and type-only declarations are not reported.
    expect(Object.keys(v).some(k => k.startsWith('svc/users.test'))).toBe(false);
    expect(v['svc/types:Shape']).toBeUndefined();
    expect(d.summary.dead).toBeGreaterThan(0);
    expect(d.summary.reachedByTestOnly).toBeGreaterThanOrEqual(2);
  });

  it('a weak path or an unresolved site makes it may-be-live; a partial file too', async () => {
    const g = await build({ 'src/dyn.ts': "export const table = { legacy: (o: any, k: string) => o[k]() };" }, ['src/dyn.ts']);
    const d = deadCode(g, { rootKinds: ['route', 'main', 'bean', 'export'] });
    const v = Object.fromEntries(d.facts.map(f => [f.qualified_name, f]));
    expect(v['svc/repo:Repo.legacy'].verdict).toBe('may-be-live');
    expect(v['svc/repo:Repo.legacy'].reasons).toEqual(['unresolved-sites']);
    // A file that did not parse holds back only what it could reach (#1004).
    const p = deadCode(await build({ 'src/broken.ts': "import { Repo } from './repo';\nfunction x( {" }));
    const pv = Object.fromEntries(p.facts.map(f => [f.qualified_name, f]));
    expect(pv['svc/repo:Repo.legacy'].reasons).toEqual(['partial-files']);
    const q = deadCode(await build({ 'src/broken.ts': 'function x( {' }));
    const qv = Object.fromEntries(q.facts.map(f => [f.qualified_name, f]));
    expect(qv['svc/repo:Repo.legacy'].verdict).toBe('dead');
    expect(q.summary.dead).toBeGreaterThan(0);
    expect(q.partial).toEqual(['src/broken.ts']);
  });

  it('is deterministic and on the entry point', async () => {
    const a = deadCode(await build());
    const b = deadCode(await build());
    expect(b).toEqual(a);
    expect(publicApi.deadCode).toBe(deadCode);
    expect(publicApi.reach).toBe(reach);
  });
});
