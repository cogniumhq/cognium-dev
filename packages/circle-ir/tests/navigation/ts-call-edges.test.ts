/**
 * TypeScript call edges keyed by stable ids: every call site is an edge with
 * a tier or an unresolved site with a reason, never silently dropped.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadLanguage } from '../../src/core/parser.js';
import { buildTsCallGraph, type TsCallGraph, type TsSourceFile } from '../../src/navigation/index.js';
import * as publicApi from '../../src/index.js';

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'wasm');
beforeAll(async () => {
  await loadLanguage('tsx', join(wasmDir, 'tree-sitter-tsx.wasm'));
});

const opts = { packageName: 'p' };
const src = (files: Record<string, string>): TsSourceFile[] =>
  Object.entries(files).map(([path, code]) => ({ path, code, ids: opts }));

/** `from-qname -> to-qname [tier]` for every edge. */
function edges(g: TsCallGraph): string[] {
  const q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
  return g.edges.map(e => `${q.get(e.from)} -> ${q.get(e.to)} [${e.tier}]`);
}
function unresolved(g: TsCallGraph): string[] {
  return g.unresolved.map(u => `${u.methodName}: ${u.reason}`);
}
function accounted(g: TsCallGraph): void {
  const key = (s: { file: string; line: number; col: number }, n: string) => `${s.file}:${s.line}:${s.col}:${n}`;
  const seen = new Set([...g.edges.map(e => key(e.site, e.methodName)), ...g.unresolved.map(u => key(u.site, u.methodName))]);
  expect(seen.size).toBe(g.sites);
}

describe('functions and modules', () => {
  it('binds local, imported, aliased, default, namespace and re-exported functions exactly', async () => {
    const g = await buildTsCallGraph(src({
      'src/util.ts': 'export function slug(s: string) { return s.trim(); }\nexport default function main() { return slug("x"); }',
      'src/barrel.ts': "export { slug as toSlug } from './util';\nexport * from './more';",
      'src/more.ts': 'export function extra() {}',
      'src/app.ts': [
        "import main, { slug } from './util';",
        "import * as u from './util.js';",
        "import { toSlug, extra } from './barrel';",
        'function local() { return 1; }',
        'export function run() { local(); slug("a"); main(); u.slug("b"); toSlug("c"); extra(); }',
      ].join('\n'),
    }));
    expect(edges(g)).toEqual([
      'p/app:run -> p/app:local [exact]',
      'p/app:run -> p/util:slug [exact]',
      'p/app:run -> p/util:main [exact]',
      'p/app:run -> p/util:slug [exact]',
      'p/app:run -> p/util:slug [exact]',
      'p/app:run -> p/more:extra [exact]',
      'p/util:main -> p/util:slug [exact]',
    ]);
    // `s: string` — a built-in type's method.
    expect(unresolved(g)).toEqual(['trim: external']);
    accounted(g);
  });

  it('CommonJS require binds like an import; module loading is not a call', async () => {
    const g = await buildTsCallGraph(src({
      'lib/a.js': 'exports.hello = function (n) { return n; };',
      'lib/b.js': "const a = require('./a');\nconst { hello } = require('./a');\nfunction go() { a.hello(1); hello(2); }",
    }));
    expect(edges(g)).toEqual(['p/lib/b:go -> p/lib/a:hello [exact]', 'p/lib/b:go -> p/lib/a:hello [exact]']);
    expect(g.sites).toBe(2);
  });

  it('lexical scope: nested functions bind exactly, parameters and values shadow', async () => {
    const g = await buildTsCallGraph(src({
      'src/a.ts': [
        'function helper() {}',
        'export function outer(cb: () => void, helper2: any) {',
        '  const inner = () => helper();',
        '  function deep() { inner(); }',
        '  deep(); cb();',
        '  const helper = makeIt(); helper();',
        '  (() => 1)();',
        '}',
      ].join('\n'),
    }));
    expect(edges(g)).toEqual([
      'p/a:outer/deep@2.1 -> p/a:outer/inner@2.0.0.1 [exact]',
      'p/a:outer -> p/a:outer/deep@2.1 [exact]',
      'p/a:outer -> p/a:outer/<anonymous>@2.6.0.0.0 [exact]',
    ]);
    // `helper` inside `inner` is the block's `const helper`, not the module function.
    expect(unresolved(g).sort()).toEqual(['cb: dynamic', 'helper: dynamic', 'helper: dynamic', 'makeIt: external']);
  });

  it('globals and packages are external; overloads pick the body', async () => {
    const g = await buildTsCallGraph(src({
      'src/a.ts': [
        "import express from 'express';",
        'function f(a: string): string;',
        'function f(a: number): number;',
        'function f(a: any) { return a; }',
        'declare function amb(): void;',
        'export function go() { f(1); console.log(1); express(); setTimeout(go, 1); amb(); }',
      ].join('\n'),
    }));
    expect(edges(g)).toEqual(['p/a:go -> p/a:f [exact]']);
    expect(unresolved(g)).toEqual(['log: external', 'express: external', 'setTimeout: external', 'amb: external']);
  });

  it('aliases resolve non-relative imports', async () => {
    const files = src({ 'src/lib/x.ts': 'export function x() {}', 'src/a.ts': "import { x } from '@app/lib/x';\nx();" });
    expect(edges(await buildTsCallGraph(files, { moduleAliases: { '@app/': 'src/' } }))).toEqual(['p/a -> p/lib/x:x [exact]']);
    expect(unresolved(await buildTsCallGraph(files))).toEqual(['x: external']);
  });
});

describe('classes and dispatch', () => {
  const svc = {
    'src/repo.ts': [
      'export interface Store { save(x: string): void; }',
      'export class Repo implements Store { save(x: string) { this.log(x); } log(x: string) {} static make() { return new Repo(); } }',
      'export class MemRepo extends Repo { save(x: string) { super.save(x); } }',
      'export class Base { constructor(n: number) {} }',
      'export class Child extends Base { constructor() { super(1); } }',
    ].join('\n'),
    'src/svc.ts': [
      "import { Repo, Store, MemRepo, Child } from './repo';",
      'export class Svc {',
      '  private cache = new MemRepo();',
      '  constructor(private repo: Repo, private store: Store, plain: Repo) {}',
      '  run(other: MemRepo, loose) {',
      '    this.repo.save("a");',
      '    this.store.save("b");',
      '    this.cache.log("c");',
      '    other.save("d");',
      '    const r: Repo = Repo.make();',
      '    r.log("e");',
      '    new Child();',
      '    loose.save("f");',
      '    "s".trim(); const n = [1]; n.push(2);',
      '  }',
      '}',
    ].join('\n'),
  };

  it('labels exact and polymorphic by receiver type and overrides', async () => {
    const g = await buildTsCallGraph(src(svc));
    expect(edges(g)).toEqual([
      'p/repo:Repo.save -> p/repo:Repo.log [exact]',
      'p/repo:Repo.make -> p/repo:Repo [exact]',
      'p/repo:MemRepo.save -> p/repo:Repo.save [exact]',
      'p/repo:Child.constructor -> p/repo:Base.constructor [exact]',
      // A field initializer's call belongs to the field.
      'p/svc:Svc.cache -> p/repo:MemRepo [exact]',
      // Repo.save is overridden in MemRepo: open dispatch.
      'p/svc:Svc.run -> p/repo:MemRepo.save [polymorphic]',
      'p/svc:Svc.run -> p/repo:Repo.save [polymorphic]',
      // Store is an interface: every implementation in the tree.
      'p/svc:Svc.run -> p/repo:MemRepo.save [polymorphic]',
      'p/svc:Svc.run -> p/repo:Repo.save [polymorphic]',
      // log is inherited and never overridden.
      'p/svc:Svc.run -> p/repo:Repo.log [exact]',
      'p/svc:Svc.run -> p/repo:MemRepo.save [exact]',
      'p/svc:Svc.run -> p/repo:Repo.make [exact]',
      'p/svc:Svc.run -> p/repo:Repo.log [exact]',
      'p/svc:Svc.run -> p/repo:Child.constructor [exact]',
      // unknown receiver: bound by name alone.
      'p/svc:Svc.run -> p/repo:MemRepo.save [inferred]',
      'p/svc:Svc.run -> p/repo:Repo.save [inferred]',
    ].map(x => x));
    const poly = g.edges.find(e => e.tier === 'polymorphic');
    expect(poly?.via).toBeDefined();
    expect(unresolved(g)).toEqual(['trim: external', 'push: external']);
    accounted(g);
  });

  it('is deterministic regardless of input order', async () => {
    const a = await buildTsCallGraph(src(svc));
    const b = await buildTsCallGraph(src(svc).reverse());
    expect(b).toEqual(a);
  });

  it('external bases and unknown members are unresolved with reasons', async () => {
    const g = await buildTsCallGraph(src({
      'src/a.ts': [
        "import { Component } from 'react';",
        'abstract class Shape { abstract area(): number; }',
        'class W extends Component { go() { this.setState({}); super.render(); this.nope(); } }',
        'function f(s: Shape, m: Map<string, number>) { s.area(); m.get("k"); (s as any)["x"](); }',
        'class X { constructor() { super(); } }',
        'new Date();',
        'nothingNamedLikeThis.zzz();',
        'const v = factory();',
        'v.qqq();',
      ].join('\n'),
    }));
    expect(edges(g)).toEqual([]);
    expect(unresolved(g)).toEqual([
      'setState: external', 'render: external', 'nope: external',
      'area: external', 'get: external', '<expr>: dynamic',
      'super: unknown', 'Date: external', 'zzz: external', 'factory: external', 'qqq: unknown',
    ]);
    accounted(g);
  });

  it('caps inferred edges', async () => {
    const classes = Array.from({ length: 4 }, (_, i) => `class C${i} { go() {} }`).join('\n');
    const code = `${classes}\nfunction f(x: any) { x.go(); }`;
    expect((await buildTsCallGraph(src({ 'src/a.ts': code }))).edges.filter(e => e.tier === 'inferred').length).toBe(4);
    const capped = await buildTsCallGraph(src({ 'src/a.ts': code }), { maxInferred: 3 });
    expect(unresolved(capped)).toEqual(['go: unknown']);
  });
});

describe('more shapes', () => {
  it('export clauses, class expressions, namespace types, interface chains, and the reasons', async () => {
    const g = await buildTsCallGraph(src({
      'src/m.ts': [
        'function a() {}',
        'const K = class { hi() {} };',
        'export interface I0 { go(): void; }',
        'export interface I1 extends I0 {}',
        'export class Impl implements I1 { go() {} }',
        'export { a as alpha, K, a as default };',
      ].join('\n'),
      'src/n.js': "const { alpha: al } = require('./m');\nfunction dup() {}\nfunction dup() {}\nfunction z() { al(); dup(); }",
      'src/o.ts': [
        "import * as m from './m';",
        "import d, { K } from './m';",
        'class P { #secret() {} go(o: P) { this.#secret(); o.#secret(); } }',
        'const notFn = 3;',
        'export function f(i: m.I1, { a, b }: any, k = new K()) {',
        '  i.go(); d(); k.hi();',
        '  const Local = K; new Local(); new (pick())(); m.Impl(); notFn(); a(); m.go2();',
        '}',
      ].join('\n'),
    }));
    expect(edges(g)).toEqual([
      'p/n:z -> p/m:a [exact]', // destructured require with a rename
      'p/o:P.go -> p/o:P.#secret [exact]',
      'p/o:f -> p/m:K [exact]', // `new K()` in a parameter default; K is a class expression
      'p/o:f -> p/m:Impl.go [polymorphic]', // I1 extends I0; Impl implements I1
      'p/o:f -> p/m:a [exact]', // default export through an export clause
      'p/o:f -> p/m:K.hi [exact]', // receiver typed by its default value
    ]);
    expect(unresolved(g)).toEqual([
      'dup: overload-ambiguous',
      '#secret: unknown',
      'Local: dynamic',
      '(pick()): dynamic',
      'pick: external',
      'Impl: unknown', // a class called without new
      'notFn: dynamic',
      'a: dynamic', // a destructured parameter
      'go2: unknown', // the module is in the tree; the name is not
    ]);
    accounted(g);
  });
});

describe('files', () => {
  it('reports partial files, skips other languages, handles JSX and default classes', async () => {
    const g = await buildTsCallGraph(src({
      'src/broken.ts': 'function ok() {}\nok();\nfunction bad( {',
      'src/App.tsx': "import Thing from './thing';\nexport const App = () => { new Thing().go(); return <div/>; };",
      'src/thing.ts': 'export default class { go() {} }',
      'README.md': '# not code',
    }));
    expect(g.partial).toEqual(['src/broken.ts']);
    expect(g.files.map(f => f.file)).toEqual(['src/App.tsx', 'src/broken.ts', 'src/thing.ts']);
    expect(edges(g)).toEqual(expect.arrayContaining(['p/App:App -> p/thing:default [exact]', 'p/App:App -> p/thing:default.go [exact]']));
    expect(g.scheme).toBe('ts-call-edges@0.1');
  });

  it('is on the entry point', () => {
    expect(publicApi.buildTsCallGraph).toBe(buildTsCallGraph);
  });
});
