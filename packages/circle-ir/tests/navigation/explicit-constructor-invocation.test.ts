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
import { javaGraphFact2Set } from '../../src/facts/facts2.js';
import { FACTS2_RELATIONS } from '../../src/facts/schema2.js';
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

describe('an overload whose parameter types are the arguments\' own', () => {
  // `copy`'s class extends a type outside the tree, so it might be a `ResultSet`:
  // the `ResultSet` overload possibly applies. Wherever it does, `Rec` is a
  // `ResultSet` and the `Rec` overload is the more specific one, so that one runs.
  const REC = {
    'src/app/Rec.java': [
      'package app;',
      'import java.sql.ResultSet;',
      'import java.util.Properties;',
      'import lib.Persistent;',
      'public class Rec extends Persistent {',
      '  public Rec(Properties ctx, int id, String trx) {}',
      '  public Rec(Properties ctx, ResultSet rs, String trx) {}',
      '  public Rec(Properties ctx, Rec copy, String trx) {}',
      '  public Rec(Properties ctx, Rec copy) { this(ctx, copy, (String) null); }',
      '  static Rec of(Properties ctx, Rec copy) { return new Rec(ctx, copy, (String) null); }',
      '  void load(ResultSet rs) {}',
      '  void load(Rec r) {}',
      '  void reload(Rec r) { load(r); }',
      '  void loose(Sub s) { load(s); }',
      '  void nul() { load(null); }',
      '  void lam(java.util.List raw) { raw.forEach(x -> load(x)); }',
      '  void unr() { load(make()); }',
      '  void w(ResultSet r) {}',
      '  void w(Rec... rs) {}',
      '  void vw(Rec r) { w(r); }',
      '  void p(Rec a, ResultSet b) {}',
      '  void p(ResultSet a, Rec b) {}',
      '  void tie(Rec a, Rec b) { p(a, b); }',
      '  void arr(Rec[] a) {}',
      '  void arr(ResultSet[] a) {}',
      '  void ua(Rec[] xs) { arr(xs); }',
      '  void gen(Rec r) {}',
      '  <T extends ResultSet> void gen(T t) {}',
      '  void ug(Rec r) { gen(r); }',
      '  void num(Number n) {}',
      '  void num(Runnable r) {}',
      '  void un(Number n) { num(n); }',
      '  void obj(Object o) {}',
      '  void obj(Runnable r) {}',
      '  void uo(Object o) { obj(o); }',
      '}',
      'class Sub extends Rec { Sub() { super(null, 0, null); } }',
      '',
    ].join('\n'),
  };
  let r: JavaGraph;
  let rq: Map<string, string>;
  beforeAll(async () => {
    r = await buildJavaGraph(Object.entries(REC).map(([p, c]) => file(p, c)));
    rq = new Map(r.files.flatMap(f => f.decls.map(d => [d.id, `${d.qualified_name}${d.kind === 'method' ? d.signature : ''}`] as const)));
  });
  const edgesAt = (line: number) => r.edges.filter(e => e.site.line === line).map(e => `${e.methodName} -> ${rq.get(e.to)}`);
  const unresolvedAt2 = (line: number) => r.unresolved.filter(u => u.site.line === line).map(u => `${u.methodName}: ${u.reason}`);

  it('this(…), new and a method call bind to it', () => {
    expect(edgesAt(9)).toEqual(['this -> app:Rec.constructor(Properties,Rec,String)']);
    expect(edgesAt(10)).toEqual(['Rec -> app:Rec.constructor(Properties,Rec,String)']);
    expect(edgesAt(13)).toEqual(['load -> app:Rec.load(Rec)']);
  });

  it('an argument of a subtype is not its own type: still ambiguous', () => {
    expect(edgesAt(14)).toEqual([]);
    expect(unresolvedAt2(14)).toEqual(['load: overload-ambiguous']);
  });

  it('stays ambiguous where no argument decides it', () => {
    const ambiguous = (line: number, name: string) => {
      expect(r.edges.filter(e => e.site.line === line && e.methodName === name), `line ${line}`).toEqual([]);
      expect(unresolvedAt2(line).filter(u => u.startsWith(`${name}:`)), `line ${line}`).toEqual([`${name}: overload-ambiguous`]);
    };
    ambiguous(15, 'load'); // null fits both
    ambiguous(16, 'load'); // an untyped lambda parameter
    ambiguous(17, 'load'); // the result of an unresolved call
    ambiguous(20, 'w'); // a plain parameter the argument only possibly fits, against varargs
    ambiguous(23, 'p'); // each overload has the argument's own type at a different position
  });

  it('picks the own-type overload against one the argument only possibly fits', () => {
    expect(edgesAt(26)).toEqual(['arr -> app:Rec.arr(Rec[])']);
    expect(edgesAt(29)).toEqual(['gen -> app:Rec.gen(Rec)']);
    expect(edgesAt(32)).toEqual(['num -> app:Rec.num(Number)']);
    expect(edgesAt(35)).toEqual(['obj -> app:Rec.obj(Object)']);
  });
});

describe('super(…) resolves its superclass from the class\'s scope', () => {
  // A member type of an enclosing type hides a same-package or imported type
  // with the same name; the class's own members are not in scope in its own
  // `extends` clause.
  const SCOPE = {
    'src/app/Node.java': 'package app;\npublic class Node {\n  public Node(int x) {}\n}\n',
    'src/app/Tree.java': [
      'package app;',
      'public class Tree {',
      '  static class Node { Node(int x) {} }',
      '  static class Leaf extends Node { Leaf() { super(1); } }',
      '  static class Box {',
      '    static class Inner extends Node { Inner() { super(2); } }',
      '  }',
      '}',
      '',
    ].join('\n'),
    'src/app/Base.java': 'package app;\npublic class Base {\n  public static class Node { public Node(int x) {} }\n}\n',
    'src/app/Heir.java': [
      'package app;',
      'public class Heir extends Base {',
      '  static class Leaf extends Node { Leaf() { super(4); } }',
      '}',
      '',
    ].join('\n'),
    'src/app/ui/Widget.java': 'package app.ui;\npublic class Widget {\n  public Widget() {}\n}\n',
    'src/app/w/W.java': 'package app.w;\nimport org.lib.*;\npublic class W extends Widget {\n  W() { super(); }\n}\n',
    'src/app/w/W2.java': 'package app.w;\nimport app.ui.*;\npublic class W2 extends Widget {\n  W2() { super(); }\n}\n',
    'src/app/Self.java': [
      'package app;',
      'public class Self extends Node {',
      '  static class Node { Node(int x) {} }',
      '  Self() { super(5); }',
      '}',
      '',
    ].join('\n'),
  };
  let sg: JavaGraph;
  let sq: Map<string, string>;
  beforeAll(async () => {
    sg = await buildJavaGraph(Object.entries(SCOPE).map(([p, c]) => file(p, c)));
    sq = new Map(sg.files.flatMap(f => f.decls.map(d => [d.id, `${d.qualified_name}${d.kind === 'method' ? d.signature : ''}`] as const)));
  });
  const superAt = (f: string, line: number) =>
    sg.edges.filter(e => e.site.file === f && e.site.line === line && e.methodName === 'super').map(e => `super -> ${sq.get(e.to)}`);

  it('a member type of the enclosing class, not the same-package type of that name', () => {
    expect(superAt('src/app/Tree.java', 4)).toEqual(['super -> app:Tree.Node.constructor(int)']);
  });

  it('a member type of an outer enclosing class, from two levels in', () => {
    expect(superAt('src/app/Tree.java', 6)).toEqual(['super -> app:Tree.Node.constructor(int)']);
  });

  it('a member type the enclosing class inherits from a supertype in the tree', () => {
    expect(superAt('src/app/Heir.java', 3)).toEqual(['super -> app:Base.Node.constructor(int)']);
  });

  it('not the class\'s own member type: its `extends` clause is outside its body', () => {
    expect(superAt('src/app/Self.java', 4)).toEqual(['super -> app:Node.constructor(int)']);
  });

  it('not a same-named type in the tree that no import of the file names', () => {
    // `Widget` comes from `org.lib.*`, outside the tree, not from `app.ui`.
    expect(superAt('src/app/w/W.java', 4)).toEqual([]);
    expect(sg.unresolved.filter(u => u.site.file === 'src/app/w/W.java' && u.methodName === 'super').map(u => `${u.reason} ${u.receiver ?? ''}`)).toEqual(['external Widget']);
  });

  it('a type a wildcard import of the file names', () => {
    expect(superAt('src/app/w/W2.java', 4)).toEqual(['super -> app.ui:Widget.constructor()']);
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

describe('reach, facts@1 and facts@2', () => {
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

  it('writes the same rows in facts@2 (exact, not declaring; the name as written)', () => {
    const inputs = Object.entries(APP).map(([path, code]) => ({ path, code, imports: [] }));
    const set = javaGraphFact2Set(g, inputs);
    const calls = tableRows(FACTS2_RELATIONS.call, set.relations.call).filter(r => r[3] === 'super' || r[3] === 'this');
    expect(calls).toHaveLength(9);
    expect(calls.every(r => r[2] === 'exact' && r[6] === false)).toBe(true);
    const unresolved = tableRows(FACTS2_RELATIONS.unresolved, set.relations.unresolved)
      .filter(r => r[3] === 'super' || r[3] === 'this')
      .map(r => [r[1], r[2]]);
    expect(unresolved).toEqual(expect.arrayContaining([
      ['external', 'java.lang.Exception'],
      ['external', 'java.lang.Object'],
      ['overload-ambiguous', ''],
    ]));
    expect(unresolved).toHaveLength(3);
  });
});
