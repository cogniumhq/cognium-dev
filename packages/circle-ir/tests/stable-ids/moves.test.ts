/**
 * Moves and renames as facts: equal body hash settles, a unique name with a
 * new signature settles, similar bodies are signal, and nothing ever pairs
 * the wrong declarations.
 */

import { describe, it, expect } from 'vitest';
import {
  bodySimilarity,
  deriveStableIds,
  detectMoves,
  type StableDecl,
  type StableIdFile,
} from '../../src/stable-ids/index.js';

const ts = (code: string, file = 'src/a.ts') =>
  deriveStableIds(code, file, 'typescript', { packageName: 'pkg', keepBodyTokens: true });

const names = (ds: readonly StableDecl[]) => ds.map(d => d.qualified_name);

const LOAD = `
export function load(id: string, cache: Map<string, User>): User | undefined {
  const hit = cache.get(id);
  if (hit) return hit;
  return db.users.find(u => u.id === id);
}
`;

describe('detectMoves — settled facts', () => {
  it('a rename settles by body hash', async () => {
    const r = detectMoves([await ts(LOAD)], [await ts(LOAD.replace('function load', 'function loadUser'))], { base: 'b1', head: 'h1' });
    expect(r.moves.map(m => [m.relation, m.evidence, m.from.qualified_name, m.to.qualified_name])).toEqual([
      ['renamed', 'body-hash', 'pkg/a:load', 'pkg/a:loadUser'],
      // Its nested callback is too small to settle alone; it follows its parent.
      ['moved', 'enclosing', 'pkg/a:load/<anonymous>@3.2.0.1.0', 'pkg/a:loadUser/<anonymous>@3.2.0.1.0'],
    ]);
    expect(r.moves[0].scheme).toBe('ids@0.1');
    expect(r.moves[0].base).toBe('b1');
    expect(r.moves[0].head).toBe('h1');
    expect(r.diff.removed).toEqual([]);
    expect(r.diff.added).toEqual([]);
    expect(r.candidates).toEqual([]);
  });

  it('a declaration moved to another file is a move; the old module stays removed', async () => {
    const before = [await ts(LOAD + 'export const other = 1;\n', 'src/a.ts')];
    const after = [await ts('export const other = 1;\n', 'src/a.ts'), await ts(LOAD, 'src/users.ts')];
    const r = detectMoves(before, after);
    const load = r.moves.find(m => m.from.name === 'load');
    expect(load?.relation).toBe('moved');
    expect(load?.to.qualified_name).toBe('pkg/users:load');
    expect(names(r.diff.removed)).toEqual([]);
    // The new module is added (its body differs from the old one's).
    expect(names(r.diff.added)).toContain('pkg/users');
  });

  it('a file moved whole moves its module and every member', async () => {
    const r = detectMoves([await ts(LOAD, 'src/a.ts')], [await ts(LOAD, 'src/lib/a.ts')]);
    expect(r.moves.map(m => [m.relation, m.to.qualified_name])).toEqual(
      expect.arrayContaining([['moved', 'pkg/lib/a'], ['moved', 'pkg/lib/a:load']]),
    );
    expect(r.diff.removed).toEqual([]);
    expect(r.diff.added).toEqual([]);
  });

  it('a class rename renames the class and moves its members', async () => {
    const cls = `export class Repo {
  add(item: string): void { this.items.push(item); this.count = this.items.length; this.dirty = true; }
}
`;
    const r = detectMoves([await ts(cls)], [await ts(cls.replace('class Repo', 'class Store'))]);
    const rel = Object.fromEntries(r.moves.map(m => [m.to.qualified_name, m.relation]));
    expect(rel['pkg/a:Store']).toBe('renamed');
    expect(rel['pkg/a:Store.add']).toBe('moved');
    expect(r.moves.find(m => m.to.name === 'Store')?.evidence).toBe('members');
  });

  it('a method moved to another class and renamed is moved-renamed', async () => {
    const body = '{ const total = items.reduce((a, b) => a + b.price * b.qty, 0); return total * (1 + rate); }';
    const before = await ts(`class A { price(items: Item[], rate: number) ${body} }\nclass B {}`);
    const after = await ts(`class A {}\nclass B { total(items: Item[], rate: number) ${body} }`);
    const m = detectMoves([before], [after]).moves.find(x => x.from.name === 'price');
    expect(m?.relation).toBe('moved-renamed');
    expect(m?.to.qualified_name).toBe('pkg/a:B.total');
  });

  it('a new signature under the same name settles as signature-changed', async () => {
    const r = detectMoves([await ts(LOAD)], [await ts(LOAD.replace('id: string,', 'id: number,'))]);
    expect(r.moves.map(m => [m.relation, m.evidence, m.from.signature, m.to.signature])).toEqual([
      ['signature-changed', 'qualified-name', expect.stringContaining('string,Map'), expect.stringContaining('number,Map')],
    ]);
  });
});

describe('detectMoves — never a wrong match', () => {
  it('a member does not follow its class when its body changed too', async () => {
    const cls = 'class Repo { add(item: string): void { this.items.push(item); this.count = this.items.length; } size() { return 1; } }';
    const r = detectMoves([await ts(cls)], [await ts(cls.replace('class Repo', 'class Store').replace('return 1', 'return 2'))]);
    expect(r.moves.map(m => m.to.qualified_name).sort()).toEqual(['pkg/a:Store', 'pkg/a:Store.add']);
    expect(names(r.diff.removed)).toEqual(['pkg/a:Repo.size']);
    expect(names(r.diff.added)).toEqual(['pkg/a:Store.size']);
  });

  it('a small body equal by hash is a candidate, not a fact', async () => {
    const r = detectMoves([await ts('function a() { return 1; }')], [await ts('function b() { return 1; }')]);
    expect(r.moves).toEqual([]);
    expect(r.candidates.map(c => [c.evidence, c.from.name, c.to.name])).toEqual([['body-hash-small', 'a', 'b']]);
    expect(names(r.diff.removed)).toEqual(['pkg/a:a']);
    expect(names(r.diff.added)).toEqual(['pkg/a:b']);
  });

  it('a body shared by several declarations is ambiguous: candidates only', async () => {
    const body = '{ this.items.push(item); this.count = this.items.length; this.dirty = true; }';
    const before = await ts(`function a(item: T) ${body}\nfunction b(item: T) ${body}`);
    const after = await ts(`function c(item: T) ${body}\nfunction d(item: T) ${body}`);
    const r = detectMoves([before], [after]);
    expect(r.moves).toEqual([]);
    expect(r.candidates.filter(c => c.evidence === 'body-hash-ambiguous').length).toBe(4);
    expect(r.diff.removed.length).toBe(2);
  });

  it('large shared-body groups yield no candidates', async () => {
    const fns = (p: string) => Array.from({ length: 6 }, (_, i) => `function ${p}${i}() {}`).join('\n');
    const r = detectMoves([await ts(fns('a'))], [await ts(fns('b'))]);
    expect(r.moves).toEqual([]);
    expect(r.candidates.filter(c => c.evidence === 'body-hash-ambiguous')).toEqual([]);
  });

  it('an ambiguous body still settles by a unique name', async () => {
    const before = await ts('function f(a: number) { return; }\nfunction g(a: string) { return; }');
    const after = await ts('function f(a: boolean) { return; }\nfunction h(a: string) { return; }');
    const r = detectMoves([before], [after]);
    // g → h is a small equal-hash pair (candidate); f changed signature (fact).
    expect(r.moves.map(m => [m.relation, m.to.name])).toEqual([['signature-changed', 'f']]);
  });

  it('kinds never cross', async () => {
    const r = detectMoves([await ts('let x = 1;')], [await ts('function x() { return 1; }')]);
    expect(r.moves).toEqual([]);
  });

  it('duplicates never settle by name', async () => {
    const before = await ts('function d() { a(); }\nfunction d() { b(); }');
    const after = await ts('function d(x: number) { c(); }\nfunction d(x: number) { e(); }');
    const r = detectMoves([before], [after]);
    expect(r.moves.filter(m => m.evidence === 'qualified-name')).toEqual([]);
  });
});

describe('detectMoves — similar bodies are signal', () => {
  const v1 = `export function total(items: Item[], rate: number): number {
  let sum = 0;
  for (const it of items) { sum += it.price * it.qty; }
  if (rate > 0) { sum = sum * (1 + rate); }
  return Math.round(sum * 100) / 100;
}
`;
  const v2 = v1.replace('function total', 'function grandTotal').replace('Math.round(sum * 100) / 100', 'Math.round(sum * 100) / 100 || 0');

  it('an edited rename is a candidate with its similarity', async () => {
    const r = detectMoves([await ts(v1)], [await ts(v2)]);
    expect(r.moves).toEqual([]);
    const c = r.candidates.find(x => x.evidence === 'similar-body');
    expect(c?.from.name).toBe('total');
    expect(c?.to.name).toBe('grandTotal');
    expect(c?.relation).toBe('renamed');
    expect(c?.callers).toBe('unknown');
    expect(c?.similarity).toBeGreaterThan(0.8);
    expect(c?.similarity).toBeLessThan(1);
  });

  it('caller sets: equal keeps the candidate (after mapping settled moves), different drops it', async () => {
    const before = [await ts(v1)];
    const after = [await ts(v2)];
    const from = before[0].decls.find(d => d.name === 'total') as StableDecl;
    const to = after[0].decls.find(d => d.name === 'grandTotal') as StableDecl;
    const equal = detectMoves(before, after, {
      callersBefore: new Map([[from.id, ['c1', 'c2']]]),
      callersAfter: new Map([[to.id, ['c2', 'c1', 'c1']]]),
    });
    expect(equal.candidates.find(c => c.evidence === 'similar-body')?.callers).toBe('equal');
    const differ = detectMoves(before, after, {
      callersBefore: new Map([[from.id, ['c1']]]),
      callersAfter: new Map([[to.id, ['c9']]]),
    });
    expect(differ.candidates.filter(c => c.evidence === 'similar-body')).toEqual([]);
  });

  it('the bar is an option; without body tokens there are no similarity candidates', async () => {
    const strict = detectMoves([await ts(v1)], [await ts(v2)], { similarityBar: 0.999 });
    expect(strict.candidates.filter(c => c.evidence === 'similar-body')).toEqual([]);
    const plain = (code: string): Promise<StableIdFile> => deriveStableIds(code, 'src/a.ts', 'typescript');
    const none = detectMoves([await plain(v1)], [await plain(v2)]);
    expect(none.candidates.filter(c => c.evidence === 'similar-body')).toEqual([]);
  });

  it('is deterministic', async () => {
    const a = detectMoves([await ts(v1)], [await ts(v2)]);
    const b = detectMoves([await ts(v1)], [await ts(v2)]);
    expect(b).toEqual(a);
  });
});

describe('bodySimilarity', () => {
  it('is Dice over token bigrams', () => {
    expect(bodySimilarity(['a', 'b', 'c'], ['a', 'b', 'c'])).toBe(1);
    expect(bodySimilarity(['a', 'b', 'c'], ['x', 'y', 'z'])).toBe(0);
    expect(bodySimilarity(['a', 'b', 'c'], ['a', 'b', 'd'])).toBe(0.5);
    expect(bodySimilarity(['a'], ['a'])).toBe(1);
    expect(bodySimilarity(['a'], ['b'])).toBe(0);
    expect(bodySimilarity([], ['a', 'b'])).toBe(0);
  });
});
