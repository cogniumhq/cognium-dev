/**
 * Explicit constructor invocations (`super(…)`, `this(…)`, `outer.super(…)`) in the Java
 * graph and its `facts@1` rows. They used to produce neither a `call` nor an `unresolved`
 * row, so a superclass constructor reached only through its subclasses' constructors
 * looked uncalled, and so did every class whose only callers were subclass constructors.
 *
 * - `super(…)` binds to the superclass constructor its arguments select; a superclass
 *   outside the tree is an `external` site naming it (`java.lang.Object` when the class
 *   names none), an ambiguous choice is `overload-ambiguous`.
 * - `this(…)` binds to the sibling constructor its arguments select.
 * - The call is named as written, `super` or `this`, at the invocation's own position.
 * - An implicit `super()` (a constructor with no explicit invocation, or a class with no
 *   constructor) is not a written call site, so it adds no row: `facts@1` `call` rows are
 *   sites in the source, each with the name written there.
 * - Under `navigationTypes` only: the default IR is unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { deadCode } from '../../src/graph-facts/index.js';
import { javaGraphFactSet } from '../../src/facts/java-facts.js';
import { tableRows } from '../../src/facts/table.js';
import { FACTS_RELATIONS } from '../../src/facts/schema.js';
import { base32 } from '../../src/stable-ids/hash.js';

const file = (path: string, code: string) => ({ path, code });

const APP: Record<string, string> = {
  'src/app/Base.java': [
    'package app;',
    'public class Base {',
    '  public Base(int n) {}',
    '  public Base(String s) {}',
    '  public Base(Integer n) {}',
    '  public Base(Runnable r) {}',
    '  void unused() {}',
    '}',
    '',
  ].join('\n'),
  'src/app/Child.java': [
    'package app;',
    'public class Child extends Base {',
    '  public Child(int n) { super(n); }',
    '  public Child(String s) { super(s); }',
    '  public Child() { this(7); }',
    '  public Child(long n) { super(null); }',
    '  public Child(Runnable r) { super(new Runnable() { public void run() {} }); }',
    '  public static void main(String[] args) { new Child(); }',
    '}',
    '',
  ].join('\n'),
  'src/app/Quiet.java': [
    'package app;',
    '/** No explicit invocation: the implicit super() is not a written call site. */',
    'public class Quiet extends Plain {',
    '  public Quiet() { int x = 1; }',
    '}',
    '',
  ].join('\n'),
  'src/app/Plain.java': [
    'package app;',
    'public class Plain {',
    '  public Plain() {}',
    '}',
    '',
  ].join('\n'),
  'src/app/Outer.java': [
    'package app;',
    'public class Outer {',
    '  public class In {',
    '    public In(String s) {}',
    '  }',
    '  public static class Nested extends Base {',
    '    public Nested(String s) { super(s); }',
    '    public Nested() { this("x"); }',
    '  }',
    '  public class Sub extends In {',
    '    public Sub() { Outer.this.super("y"); }',
    '  }',
    '  Base anon() { return new Base(3) { void extra() {} }; }',
    '}',
    '',
  ].join('\n'),
  'src/app/Oops.java': [
    'package app;',
    'import java.util.AbstractList;',
    'public class Oops extends Exception {',
    '  public Oops(String m) { super(m); }',
    '}',
    '',
  ].join('\n'),
  'src/app/Lone.java': [
    'package app;',
    'public class Lone {',
    '  public Lone() { super(); }',
    '}',
    '',
  ].join('\n'),
  'src/app/Mode.java': [
    'package app;',
    'public enum Mode {',
    '  A, B(2);',
    '  private final int w;',
    '  Mode() { this(1); }',
    '  Mode(int w) { this.w = w; }',
    '}',
    '',
  ].join('\n'),
  'src/app/Pair.java': [
    'package app;',
    'public record Pair(String a, String b) {',
    '  public Pair(String a) { this(a, a); }',
    '}',
    '',
  ].join('\n'),
};

let g: JavaGraph;
/** decl id → `pkg:Type.member(signature)` */
let q: Map<string, string>;

const at = (line: number) => (x: { site: { line: number } }) => x.site.line === line;
const callsFrom = (file: string, line: number) =>
  g.edges.filter(e => e.site.file === file && e.site.line === line).map(e => `${e.methodName} -> ${q.get(e.to)} [${e.tier}]`);
const unresolvedAt = (file: string, line: number) =>
  g.unresolved.filter(u => u.site.file === file && at(line)(u)).map(u => `${u.methodName}: ${u.reason}${u.receiver ? ` ${u.receiver}` : ''}`);

beforeAll(async () => {
  await initAnalyzer();
  g = await buildJavaGraph(Object.entries(APP).map(([p, c]) => file(p, c)));
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, `${d.qualified_name}${d.kind === 'method' ? d.signature : ''}`] as const)));
}, 60_000);

describe('explicit super(…) calls', () => {
  it('bind to the superclass constructor the arguments select', () => {
    expect(callsFrom('src/app/Child.java', 3)).toEqual(['super -> app:Base.constructor(int) [exact]']);
    expect(callsFrom('src/app/Child.java', 4)).toEqual(['super -> app:Base.constructor(String) [exact]']);
  });

  it('come from the subclass constructor, at the invocation, named as written', () => {
    const e = g.edges.find(x => x.site.file === 'src/app/Child.java' && x.site.line === 3)!;
    expect(q.get(e.from)).toBe('app:Child.constructor(int)');
    expect(e.site.col).toBe('  public Child(int n) { '.length);
    expect(e.methodName).toBe('super');
  });

  it('an ambiguous choice is an overload-ambiguous site, not a pick', () => {
    expect(callsFrom('src/app/Child.java', 6)).toEqual([]);
    expect(unresolvedAt('src/app/Child.java', 6)).toEqual(['super: overload-ambiguous']);
  });

  it('an anonymous class in the arguments does not change which class is constructed', () => {
    expect(callsFrom('src/app/Child.java', 7)).toEqual(['super -> app:Base.constructor(Runnable) [exact]']);
  });

  it('a superclass outside the tree is external, naming it', () => {
    expect(callsFrom('src/app/Oops.java', 4)).toEqual([]);
    expect(unresolvedAt('src/app/Oops.java', 4)).toEqual(['super: external java.lang.Exception']);
  });

  it('a class that names no superclass calls java.lang.Object', () => {
    expect(unresolvedAt('src/app/Lone.java', 3)).toEqual(['super: external java.lang.Object']);
  });

  it('in a nested class, and qualified with an outer instance', () => {
    expect(callsFrom('src/app/Outer.java', 7)).toEqual(['super -> app:Base.constructor(String) [exact]']);
    expect(callsFrom('src/app/Outer.java', 11)).toEqual(['super -> app:Outer.In.constructor(String) [exact]']);
  });
});

describe('explicit this(…) calls', () => {
  it('bind to the sibling constructor the arguments select', () => {
    expect(callsFrom('src/app/Child.java', 5)).toEqual(['this -> app:Child.constructor(int) [exact]']);
    expect(callsFrom('src/app/Outer.java', 8)).toEqual(['this -> app:Outer.Nested.constructor(String) [exact]']);
  });

  it('in an enum and in a record (the canonical constructor is implicit: the record itself)', () => {
    expect(callsFrom('src/app/Mode.java', 5)).toEqual(['this -> app:Mode.constructor(int) [exact]']);
    expect(callsFrom('src/app/Pair.java', 3)).toEqual(['this -> app:Pair [exact]']);
  });
});

describe('what adds no row', () => {
  it('an implicit super(): no written site, no call or unresolved row', () => {
    expect(g.edges.filter(e => e.site.file === 'src/app/Quiet.java')).toEqual([]);
    expect(g.unresolved.filter(u => u.site.file === 'src/app/Quiet.java')).toEqual([]);
  });

  it('an anonymous class body: its creation is the call, bound to the constructor it selects', () => {
    expect(callsFrom('src/app/Outer.java', 13)).toEqual(['Base -> app:Base.constructor(int) [exact]']);
  });

  it('the default IR is unchanged: explicit invocations are calls only under navigationTypes', async () => {
    const plain = await analyze(APP['src/app/Child.java'], 'src/app/Child.java', 'java');
    expect(plain.calls.some(c => c.method_name === 'super' || c.method_name === 'this')).toBe(false);
    const typed = await analyze(APP['src/app/Child.java'], 'src/app/Child.java', 'java', { navigationTypes: true });
    const ctorCalls = typed.calls.filter(c => c.method_name === 'super' || c.method_name === 'this');
    expect(ctorCalls.map(c => [c.method_name, c.receiver_type, c.is_constructor, c.in_method])).toEqual([
      ['super', 'Base', true, 'Child'],
      ['super', 'Base', true, 'Child'],
      ['this', 'Child', true, 'Child'],
      ['super', 'Base', true, 'Child'],
      ['super', 'Base', true, 'Child'],
    ]);
  });
});

describe('reach and facts@1', () => {
  it('a superclass constructor reached only through subclass constructors is live', () => {
    const d = deadCode(g);
    const v = new Map(d.facts.map(f => [q.get(f.id), f.verdict]));
    // main → new Child() → this(7) → Child(int) → super(n) → Base(int)
    expect(v.get('app:Child.constructor(int)')).toBe('live');
    expect(v.get('app:Base.constructor(int)')).toBe('live');
    expect(v.get('app:Base.unused()')).toBe('dead');
  });

  it('writes call and unresolved rows for the invocations', () => {
    const inputs = Object.entries(APP).map(([path, code]) => ({ path, code, imports: [] }));
    const set = javaGraphFactSet(g, inputs);
    const calls = tableRows(FACTS_RELATIONS.call, set.relations.call)
      .map(r => [q.get(base32(r[0] as Uint8Array)), q.get(base32(r[1] as Uint8Array)), r[2], r[3]] as const)
      .filter(r => r[3] === 'super' || r[3] === 'this');
    expect(calls).toEqual(expect.arrayContaining([
      ['app:Child.constructor(int)', 'app:Base.constructor(int)', 'exact', 'super'],
      ['app:Child.constructor()', 'app:Child.constructor(int)', 'exact', 'this'],
      ['app:Outer.Sub.constructor()', 'app:Outer.In.constructor(String)', 'exact', 'super'],
    ]));
    expect(calls).toHaveLength(9);
    const unresolved = tableRows(FACTS_RELATIONS.unresolved, set.relations.unresolved)
      .filter(r => r[3] === 'super' || r[3] === 'this')
      .map(r => [r[1], r[2], r[3]]);
    expect(unresolved).toEqual(expect.arrayContaining([
      ['external', 'java.lang.Exception', 'super'],
      ['external', 'java.lang.Object', 'super'],
      ['overload-ambiguous', '', 'super'],
    ]));
    expect(unresolved).toHaveLength(3);
  });
});
