/**
 * `ids@0.1` on TypeScript/JavaScript: declaration ids follow names and
 * signatures, never positions; body ids change when, and only when, the
 * normalized body changes.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadLanguage } from '../../src/core/parser.js';
import * as publicApi from '../../src/index.js';
import {
  deriveStableIds,
  diffStableIds,
  moduleNameFor,
  stableIdsSupport,
  STABLE_ID_SCHEME,
  type StableDecl,
  type StableIdFile,
} from '../../src/stable-ids/index.js';

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'wasm');

beforeAll(async () => {
  await loadLanguage('tsx', join(wasmDir, 'tree-sitter-tsx.wasm'));
});

const ts = (code: string, file = 'src/a.ts') => deriveStableIds(code, file, 'typescript', { packageName: 'pkg' });

function find(f: StableIdFile, qname: string): StableDecl {
  const d = f.decls.find(x => x.qualified_name === qname);
  if (!d) throw new Error(`no ${qname} in ${f.decls.map(x => x.qualified_name).join(', ')}`);
  return d;
}

const BASE = `
import { db } from './db';

export function load(id: string, opts?: { cache: boolean }): Promise<User> {
  return db.get(id);
}

export class Repo<T> {
  private items: T[] = [];
  add(item: T): void { this.items.push(item); }
  get size(): number { return this.items.length; }
}

export const double = (n: number) => n * 2;
`;

describe('declarations', () => {
  it('extracts the module, functions, types, members and bindings', async () => {
    const f = await ts(BASE);
    expect(f.scheme).toBe(STABLE_ID_SCHEME);
    expect(f.module).toBe('pkg/a');
    expect(f.partial).toBe(false);
    expect(f.decls.map(d => [d.kind, d.qualified_name, d.signature])).toEqual([
      ['module', 'pkg/a', ''],
      ['function', 'pkg/a:load', '(string,{cache boolean}?):Promise<User>'],
      ['type', 'pkg/a:Repo', '<T>'],
      ['field', 'pkg/a:Repo.items', ''],
      ['method', 'pkg/a:Repo.add', '(T):void'],
      ['method', 'pkg/a:Repo.size', 'get ():number'],
      ['function', 'pkg/a:double', '(number)'],
    ]);
    const repo = find(f, 'pkg/a:Repo');
    expect(find(f, 'pkg/a:Repo.add').parent).toBe(repo.id);
    expect(repo.parent).toBe(f.decls[0].id);
    for (const d of f.decls) {
      expect(d.id).toMatch(/^[a-z2-7]{26}$/);
      expect(d.body_id).toBe(`${d.id}.${d.body_hash}`);
    }
  });

  it('is deterministic and pinned (a cross-host golden)', async () => {
    const a = await ts(BASE);
    const b = await ts(BASE);
    expect(b).toEqual(a);
    // Pinned so a change to hashing, normalization or the key layout cannot
    // land silently: ids are a persisted contract.
    expect(find(a, 'pkg/a:load').id).toMatchInlineSnapshot(`"fv5h6nc4b3b2enqo2bnddxmkn4"`);
    expect(find(a, 'pkg/a:load').body_hash).toMatchInlineSnapshot(`"d2s2eq3px2gj55hcq6lb5ufi5i"`);
  });

  it('keeps every id when other declarations move, comments change or code is reformatted', async () => {
    const before = await ts(BASE);
    const after = await ts(`
// Users.
export const double = (n: number) => n * 2

import { db } from "./db"

export class Repo<T> {
  private items: T[] = []
  /** Adds one. */
  add(item: T): void {
    this.items.push(item)
  }
  get size(): number {
    return this.items.length
  }
}

export function load(
  id: string,
  opts?: { cache: boolean },
): Promise<User> {
  return db.get(id) // read through
}
`);
    const d = diffStableIds([before], [after]);
    expect(d.added.map(x => x.qualified_name)).toEqual([]);
    expect(d.removed.map(x => x.qualified_name)).toEqual([]);
    // Only the module's own body changed: its statements are in another order.
    expect(d.body_changed.map(([b]) => b.qualified_name)).toEqual(['pkg/a']);
  });

  it('a body edit keeps the decl id, changes the body id, and leaves the container alone', async () => {
    const before = await ts(BASE);
    const after = await ts(BASE.replace('this.items.push(item);', 'this.items.unshift(item);'));
    const d = diffStableIds([before], [after]);
    expect(d.body_changed.map(([b]) => b.qualified_name)).toEqual(['pkg/a:Repo.add']);
    expect(d.unchanged.length).toBe(before.decls.length - 1);
  });

  it('adding a member changes the class body but no other id', async () => {
    const before = await ts(BASE);
    const after = await ts(BASE.replace('  get size()', '  clear(): void { this.items = []; }\n  get size()'));
    const d = diffStableIds([before], [after]);
    expect(d.added.map(x => x.qualified_name)).toEqual(['pkg/a:Repo.clear']);
    expect(d.body_changed.map(([b]) => b.qualified_name)).toEqual(['pkg/a:Repo']);
    expect(d.removed).toEqual([]);
  });

  it('a rename gives a new decl id with the same body hash', async () => {
    const before = await ts(BASE);
    const after = await ts(BASE.replace('function load(', 'function fetchUser('));
    const d = diffStableIds([before], [after]);
    expect(d.removed.map(x => x.qualified_name)).toEqual(['pkg/a:load']);
    expect(d.added.map(x => x.qualified_name)).toEqual(['pkg/a:fetchUser']);
    expect(d.added[0].body_hash).toBe(d.removed[0].body_hash);
  });

  it('parameter names never take part in the signature; types do', async () => {
    const a = find(await ts('function f(a: number, b: (e: Error) => void) {}'), 'pkg/a:f');
    const b = find(await ts('function f(x: number, y: (err: Error) => void) {}'), 'pkg/a:f');
    const c = find(await ts('function f(a: string, b: (e: Error) => void) {}'), 'pkg/a:f');
    expect(b.signature).toBe('(number,(Error)=>void)');
    expect(b.id).toBe(a.id);
    expect(b.body_hash).not.toBe(a.body_hash);
    expect(c.id).not.toBe(a.id);
  });

  it('parentheses around a lone untyped arrow parameter are formatting', async () => {
    const a = find(await ts('const f = (x) => x;'), 'pkg/a:f');
    const b = find(await ts('const f = x => x'), 'pkg/a:f');
    expect(b.body_id).toBe(a.body_id);
  });

  it('object types and unions serialize canonically', async () => {
    const a = find(await ts('function f(o: { b: string; a: number }, u: A | B) {}'), 'pkg/a:f');
    const b = find(await ts('function f(o: { a: number, b: string }, u: B | A) {}'), 'pkg/a:f');
    expect(b.id).toBe(a.id);
  });

  it('overloads differ by signature; same-signature duplicates are suffixed and flagged', async () => {
    const f = await ts(`
function over(a: string): string;
function over(a: number): number;
function over(a: any) { return a; }
function dup() {}
function dup() {}
`);
    const overs = f.decls.filter(d => d.name === 'over');
    expect(new Set(overs.map(d => d.id)).size).toBe(3);
    const dups = f.decls.filter(d => d.name === 'dup');
    expect(dups.map(d => d.qualified_name)).toEqual(['pkg/a:dup', 'pkg/a:dup#2']);
    for (const d of dups) expect(d.flags).toEqual(['unstable:duplicate']);
  });

  it('keys nested and anonymous functions under their enclosing declaration', async () => {
    const f = await ts(`
export function outer(xs: number[]) {
  const inner = (x: number) => x + 1;
  return xs.map(v => inner(v));
}
`);
    const nested = f.decls.filter(d => d.flags.includes('unstable:anonymous'));
    expect(nested.map(d => d.name)).toEqual(['inner', '<anonymous>']);
    const outer = find(f, 'pkg/a:outer');
    for (const d of nested) {
      expect(d.parent).toBe(outer.id);
      expect(d.qualified_name.startsWith('pkg/a:outer/')).toBe(true);
    }
    // A bound function is declared once, not again as its own nested value.
    expect(f.decls.filter(d => d.name === 'outer').length).toBe(1);
  });

  it('covers interfaces, aliases, enums, namespaces, default and CommonJS exports', async () => {
    const f = await ts(`
interface Opts { a: number; run(x: string): void }
type Id = string | number;
enum Color { Red, Green }
namespace NS { export function g() {} }
declare module 'm' { function h(): void; }
export default class { go() {} }
exports.legacy = function (req) { return req; };
module.exports.other = () => 1;
let counter = 0;
`, 'src/b.ts');
    const names = f.decls.map(d => `${d.kind} ${d.qualified_name}`);
    expect(names).toEqual(expect.arrayContaining([
      'type pkg/b:Opts', 'field pkg/b:Opts.a', 'method pkg/b:Opts.run',
      'type pkg/b:Id', 'type pkg/b:Color',
      'module pkg/b:NS', 'function pkg/b:NS.g',
      'module pkg/b:m', 'function pkg/b:m.h',
      'type pkg/b:default', 'method pkg/b:default.go',
      'function pkg/b:legacy', 'function pkg/b:other', 'field pkg/b:counter',
    ]));
  });

  it('keeps decorators in the member body, not the class body', async () => {
    const before = await ts('class C { @Input() name = 1; @Get() run() {} }');
    const after = await ts('class C { @Input("x") name = 1; @Get() run() {} }');
    const d = diffStableIds([before], [after]);
    expect(d.body_changed.map(([b]) => b.qualified_name)).toEqual(['pkg/a:C.name']);
  });

  it('marks a file with syntax errors partial', async () => {
    const f = await ts('function ok() {}\nfunction broken( {');
    expect(f.partial).toBe(true);
    expect(f.decls.some(d => d.name === 'ok')).toBe(true);
  });
});

describe('languages and grammars', () => {
  it('JavaScript ids differ from TypeScript ids for the same text', async () => {
    const js = await deriveStableIds('function f(a) { return a; }', 'src/a.js', 'javascript', { packageName: 'pkg' });
    const t = await ts('function f(a) { return a; }');
    expect(js.language).toBe('javascript');
    expect(find(js, 'pkg/a:f').id).not.toBe(find(t, 'pkg/a:f').id);
  });

  it('parses .tsx and .jsx with the JSX grammar; JSX whitespace is formatting', async () => {
    const a = await deriveStableIds('export const App = () => <div>\n  hi  there\n</div>;', 'src/App.tsx', 'typescript');
    const b = await deriveStableIds('export const App = () => <div>hi there</div>', 'src/App.tsx', 'tsx');
    expect(a.partial).toBe(false);
    expect(a.language).toBe('typescript');
    expect(diffStableIds([a], [b]).unchanged.length).toBe(a.decls.length);
    const j = await deriveStableIds('export const App = () => <p/>;', 'src/App.jsx', 'javascript');
    expect(j.partial).toBe(false);
    expect(j.language).toBe('javascript');
  });

  it('refuses languages outside ids@0.1', async () => {
    expect(stableIdsSupport('python')).toBe(false);
    expect(stableIdsSupport('java')).toBe(true);
    expect(stableIdsSupport('tsx')).toBe(true);
    await expect(deriveStableIds('class A: pass', 'a.py', 'python')).rejects.toThrow(/not covered/);
  });
});

describe('module names', () => {
  it('package name plus the path inside src/, extension removed', () => {
    expect(moduleNameFor('src/util/x.ts', { packageName: 'p' })).toBe('p/util/x');
    expect(moduleNameFor('packages/core/src/a.tsx', { packageName: '@s/core', packageRoot: 'packages/core/' })).toBe('@s/core/a');
    expect(moduleNameFor('lib\\b.mjs', { packageName: 'p' })).toBe('p/lib/b');
  });

  it('falls back to the repository-relative path; an explicit module wins', async () => {
    expect(moduleNameFor('./src/a.ts')).toBe('src/a');
    const f = await deriveStableIds('function f() {}', 'src/a.ts', 'typescript', { module: 'm' });
    expect(f.module).toBe('m');
    expect(f.decls[1].qualified_name).toBe('m:f');
  });

  it('a file moved inside the same package and module path keeps its ids; another module does not', async () => {
    const a = await deriveStableIds('function f() {}', 'packages/x/src/a.ts', 'typescript', { packageName: 'x', packageRoot: 'packages/x' });
    const b = await deriveStableIds('function f() {}', 'src/a.ts', 'typescript', { packageName: 'x' });
    const c = await deriveStableIds('function f() {}', 'src/b.ts', 'typescript', { packageName: 'x' });
    expect(b.decls[1].id).toBe(a.decls[1].id);
    expect(c.decls[1].id).not.toBe(a.decls[1].id);
  });

  it('keeps body tokens only on request', async () => {
    const f = await deriveStableIds('function f() { return 1; }', 'a.ts', 'typescript', { keepBodyTokens: true });
    expect(f.decls[1].body_tokens).toEqual(['function', '(', ')', '{', 'return', '1', '}']);
    expect(f.decls[1].token_count).toBe(7);
    expect((await ts('function f() {}')).decls[1].body_tokens).toBeUndefined();
  });
});

describe('entry point', () => {
  it('exports the stable-id functions as runtime values', () => {
    expect(publicApi.deriveStableIds).toBe(deriveStableIds);
    expect(typeof publicApi.assignNodeIds).toBe('function');
    expect(publicApi.STABLE_ID_SCHEME).toBe('ids@0.1');
  });
});

describe('diffStableIds', () => {
  it('rejects another scheme', () => {
    const bad = { scheme: 'ids@9', file: 'a', language: 'typescript', module: 'a', decls: [], partial: false } as unknown as StableIdFile;
    expect(() => diffStableIds([bad], [])).toThrow(/scheme/);
  });
});
