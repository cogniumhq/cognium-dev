/**
 * Callers of an overloaded method, and of an overridden one.
 *
 * Both were wrong in the same direction before: a symbol carried no parameter
 * types, so the callers of every overload came back as callers of one; and a
 * call that reaches a method through a supertype, or calls an override of it,
 * bound to a different declaration and was dropped. An overload is now chosen
 * the way the compiler chooses it, or reported as ambiguous with its
 * candidates — never guessed — and dispatch is answered `polymorphic` with
 * `via` saying what the site binds to.
 */

import { describe, it, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { buildNavigationIndex, type NavigationIndex } from '../../src/navigation/index.js';

async function indexOf(files: Record<string, string>): Promise<NavigationIndex> {
  await initAnalyzer();
  const entries = [];
  for (const [path, source] of Object.entries(files)) {
    entries.push({
      path,
      language: 'java' as const,
      source,
      ir: await analyze(source, path, 'java', { navigationTypes: true }),
    });
  }
  return buildNavigationIndex(entries);
}

const lines = (a: { answers: Array<{ site: { line: number } }> }): number[] => a.answers.map(x => x.site.line);

const overloads = {
  'app/Money.java': `package app;
public class Money {
  public static Money zero(Currency c) { return null; }
  public static Money zero(Currency c, int scale) { return null; }
  public static Money of(Long amount) { return null; }
  public static Money of(String amount) { return null; }
  public static Money of(Object amount) { return null; }
  public static Money pick(Long a, String b) { return null; }
  public static Money pick(String a, Long b) { return null; }
  public Money plus(Money other) { return this; }
}`,
  'app/Currency.java': `package app;
public class Currency { }`,
  'app/Caller.java': `package app;
public class Caller {
  Money a(Currency c) { return Money.zero(c); }
  Money b(Currency c) { return Money.zero(c, 2); }
  Money c(Long n) { return Money.of(n); }
  Money d() { return Money.of("12"); }
  Money e(java.util.List<String> xs) { return Money.of(xs); }
  Money f(Long n) { return Money.of(Money.zero(null).plus(null)); }
  Money g(Object o) { return Money.pick(null, null); }
  Money h(Currency c) { return Money.of(c.toString()); }
}`,
};

describe('overloads: a call binds to one overload or to none', () => {
  it('binds by arity', async () => {
    const idx = await indexOf(overloads);
    const one = idx.resolveCallers({ symbol: 'app.Money.zero(Currency)' });
    const two = idx.resolveCallers({ symbol: 'app.Money.zero(Currency,int)' });
    // `f` calls `Money.zero(null)`, which only the one-parameter overload takes.
    expect(lines(one)).toEqual([3, 8]);
    expect(lines(two)).toEqual([4]);
    expect(one.answers.every(a => a.tier === 'exact' && a.signature === '(Currency)')).toBe(true);
  });

  it('binds by argument type, phase by phase, to the most specific overload', async () => {
    const idx = await indexOf(overloads);
    expect(lines(idx.resolveCallers({ symbol: 'app.Money.of(Long)' }))).toEqual([5]);
    // A String literal fits `of(String)` and `of(Object)`; the String one is more specific.
    // `c.toString()` is a call into the JDK, so its type is unknown: not decidable.
    expect(lines(idx.resolveCallers({ symbol: 'app.Money.of(String)' }))).toEqual([6]);
    // A List fits only `of(Object)`; so does a Money, typed from the overload
    // `plus` binds to. A qualified parameter list names the same overload.
    expect(lines(idx.resolveCallers({ symbol: 'app.Money.of(java.lang.Object)' }))).toEqual([7, 8]);
    expect(lines(idx.resolveCallers({ symbol: 'app.Money.of(Object)' }))).toEqual([7, 8]);
  });

  it('reports an undecidable call as overload-ambiguous with the candidates, and does not answer it', async () => {
    const idx = await indexOf(overloads);
    const a = idx.resolveCallers({ symbol: 'app.Money.pick(Long,String)' });
    expect(a.answers).toHaveLength(0);
    expect(a.unresolved).toHaveLength(1);
    expect(a.unresolved[0].reason).toBe('overload-ambiguous');
    expect(a.unresolved[0].candidates).toEqual(['app.Money.pick(Long,String)', 'app.Money.pick(String,Long)']);

    const s = idx.resolveCallers({ symbol: 'app.Money.of(String)' });
    const amb = s.unresolved.filter(u => u.reason === 'overload-ambiguous');
    expect(amb.map(u => u.site.line)).toEqual([10]);
  });

  it('groups a query without a signature per overload, and says so', async () => {
    const idx = await indexOf(overloads);
    const a = idx.resolveCallers({ symbol: 'app.Money.zero' });
    expect(a.overloads).toEqual([
      { signature: '(Currency)', answers: 2 },
      { signature: '(Currency,int)', answers: 1 },
    ]);
    expect(a.note).toMatch(/^2 overloads; pass a signature to narrow/);
    expect(a.answers.map(x => x.signature)).toEqual(['(Currency)', '(Currency)', '(Currency,int)']);
  });

  it('answers a signature no overload has with a note, not with every overload', async () => {
    const idx = await indexOf(overloads);
    const a = idx.resolveCallers({ symbol: 'app.Money.zero(String)' });
    expect(a.answers).toHaveLength(0);
    expect(a.note).toContain('declared: app.Money.zero(Currency), app.Money.zero(Currency,int)');
  });

  it('leaves a method with one declaration exactly as it was: no signature, no note', async () => {
    const idx = await indexOf(overloads);
    const a = idx.resolveCallers({ symbol: 'app.Money.plus' });
    expect(lines(a)).toEqual([8]);
    expect(a.answers[0].signature).toBeUndefined();
    expect(a.note).toBeUndefined();
    expect(a.overloads).toBeUndefined();
  });

  it('types an argument from a generated getter, through a generic superclass', async () => {
    const idx = await indexOf({
      'app/Base.java': `package app;
import lombok.Getter;
@Getter
public abstract class Base<T extends java.io.Serializable> { private T id; }`,
      'app/Loan.java': `package app;
public class Loan extends Base<Long> { }`,
      'app/Ref.java': `package app;
public class Ref { }`,
      'app/Repo.java': `package app;
public class Repo {
  public Loan find(Long id) { return null; }
  public Loan find(Ref ref) { return null; }
}`,
      'app/Use.java': `package app;
public class Use {
  Loan a(Repo r, Loan l) { return r.find(l.getId()); }
}`,
    });
    expect(lines(idx.resolveCallers({ symbol: 'app.Repo.find(Long)' }))).toEqual([3]);
  });

  it("types a forEach lambda's parameter from the collection's element type, and nothing else", async () => {
    const idx = await indexOf({
      'app/Fmt.java': `package app;
public class Fmt {
  public static String f(Long n) { return ""; }
  public static String f(String s) { return ""; }
}`,
      'app/Use.java': `package app;
import java.util.List;
import java.util.Map;
public class Use {
  void a(List<Long> ns, List<? extends Long> ws, Map<String, Long> m) {
    ns.forEach(n -> Fmt.f(n));
    ws.forEach(w -> Fmt.f(w));
    m.forEach((k, v) -> Fmt.f(v));
  }
}`,
    });
    expect(lines(idx.resolveCallers({ symbol: 'app.Fmt.f(Long)' }))).toEqual([6]);
    // A lambda parameter typed this way also types a call made on it.
    const recv = await indexOf({
      'app/Box.java': `package app;
public class Box { public Long id() { return 1L; } }`,
      'app/Fmt.java': `package app;
public class Fmt {
  public static String f(Long n) { return ""; }
  public static String f(String s) { return ""; }
}`,
      'app/Use.java': `package app;
import java.util.List;
public class Use { void a(List<Box> bs) { bs.forEach(b -> Fmt.f(b.id())); } }`,
    });
    expect(lines(recv.resolveCallers({ symbol: 'app.Fmt.f(Long)' }))).toEqual([3]);
    const amb =idx.resolveCallers({ symbol: 'app.Fmt.f(Long)' }).unresolved.filter(u => u.reason === 'overload-ambiguous');
    expect(amb.map(u => u.site.line)).toEqual([7, 8]);
  });

  it('rules out a JDK parameter type for a project type that never names it', async () => {
    const idx = await indexOf({
      'app/Cur.java': `package app;
public class Cur implements java.io.Serializable { }`,
      'app/M.java': `package app;
import java.math.MathContext;
public class M {
  public static M zero(Cur c) { return null; }
  public static M zero(MathContext mc) { return null; }
}`,
      'app/Use.java': `package app;
public class Use { M a(Cur c) { return M.zero(c); } }`,
    });
    expect(lines(idx.resolveCallers({ symbol: 'app.M.zero(Cur)' }))).toEqual([2]);
  });

  it('chooses a constructor like any overload', async () => {
    const idx = await indexOf({
      'app/Box.java': `package app;
public class Box {
  public Box(int n) { }
  public Box(String s) { }
}`,
      'app/Use.java': `package app;
public class Use {
  Box a() { return new Box(1); }
  Box b() { return new Box("x"); }
}`,
    });
    expect(lines(idx.resolveCallers({ symbol: 'app.Box.<init>(int)' }))).toEqual([3]);
    expect(lines(idx.resolveCallers({ symbol: 'app.Box.<init>(String)' }))).toEqual([4]);
  });

  it('types a local, a parameter, a field and a loop variable from their declarations in scope', async () => {
    const idx = await indexOf({
      'app/Fmt.java': `package app;
public class Fmt {
  public static String f(Long n) { return ""; }
  public static String f(String s) { return ""; }
}`,
      'app/Use.java': `package app;
import java.util.List;
public class Use {
  private Long count;
  void a(String p) {
    Long local = 1L;
    Fmt.f(local);
    Fmt.f(p);
    Fmt.f(this.count);
    for (String s : List.of("a")) { Fmt.f(s); }
    Fmt.f(p + 1);
  }
}`,
    });
    expect(lines(idx.resolveCallers({ symbol: 'app.Fmt.f(Long)' }))).toEqual([7, 9]);
    expect(lines(idx.resolveCallers({ symbol: 'app.Fmt.f(String)' }))).toEqual([8, 10, 11]);
  });
});

const viaInterface = {
  'app/Greeter.java': `package app;
public interface Greeter { String greet(String who); }`,
  'app/Polite.java': `package app;
public class Polite implements Greeter { public String greet(String who) { return "hello " + who; } }`,
  'app/Blunt.java': `package app;
public class Blunt implements Greeter { public String greet(String who) { return "hi"; } }`,
  'app/Caller.java': `package app;
public class Caller {
  String viaInterface(Greeter g) { return g.greet("you"); }
  String viaClass(Polite p) { return p.greet("you"); }
  String viaSibling(Blunt b) { return b.greet("you"); }
}`,
};

describe('overrides: dispatch is answered, labelled, and scoped', () => {
  it('answers a call through an interface for an implementation, via the interface', async () => {
    const idx = await indexOf(viaInterface);
    const a = idx.resolveCallers({ symbol: 'app.Polite.greet' });
    expect(lines(a)).toEqual([3, 4]);
    const through = a.answers.find(x => x.site.line === 3)!;
    expect(through.tier).toBe('polymorphic');
    expect(through.target).toBe('app.Polite.greet');
    expect(through.via).toEqual({ member: 'app.Greeter.greet', relation: 'supertype' });
    // A call on a sibling implementation never lands on this one.
    expect(lines(a)).not.toContain(5);
  });

  it('answers the interface method with calls to its implementations, via each override', async () => {
    const idx = await indexOf(viaInterface);
    const a = idx.resolveCallers({ symbol: 'app.Greeter.greet' });
    expect(lines(a)).toEqual([3, 4, 5]);
    const viaPolite = a.answers.find(x => x.site.line === 4)!;
    expect(viaPolite.tier).toBe('polymorphic');
    expect(viaPolite.via).toEqual({ member: 'app.Polite.greet', relation: 'override' });
  });

  it('says in scope.excluded what dispatch it cannot see', async () => {
    const idx = await indexOf(viaInterface);
    const patterns = idx.resolveCallers({ symbol: 'app.Greeter.greet' }).scope.excluded.map(e => e.pattern);
    expect(patterns).toEqual(expect.arrayContaining(['subtypes outside the searched tree', 'reflection', 'framework dispatch']));
  });

  it('answers through an abstract class: the template method and the overrides', async () => {
    const idx = await indexOf({
      'app/Base.java': `package app;
public abstract class Base {
  public int run() { return step(1); }
  protected abstract int step(int n);
}`,
      'app/Fast.java': `package app;
public class Fast extends Base {
  protected int step(int n) { return n; }
  int again() { return step(2); }
}`,
      'app/Slow.java': `package app;
public class Slow extends Base {
  protected int step(int n) { return n * 2; }
}`,
      'app/User.java': `package app;
public class User {
  int use(Base b) { return b.step(3); }
  int direct(Slow s) { return s.step(4); }
}`,
    });
    const onBase = idx.resolveCallers({ symbol: 'app.Base.step' });
    expect(onBase.answers.map(a => `${a.site.file}:${a.site.line}`)).toEqual([
      'app/Base.java:3', 'app/Fast.java:4', 'app/User.java:3', 'app/User.java:4',
    ]);
    expect(onBase.answers.find(a => a.site.file === 'app/Fast.java')!.via?.relation).toBe('override');

    const onFast = idx.resolveCallers({ symbol: 'app.Fast.step' });
    // The template method's unqualified call, and the call on a Base receiver,
    // reach Fast.step through Base.step; the call on a Slow receiver cannot.
    expect(onFast.answers.map(a => `${a.site.file}:${a.site.line}:${a.via?.relation ?? 'direct'}`)).toEqual([
      'app/Base.java:3:supertype', 'app/Fast.java:4:direct', 'app/User.java:3:supertype',
    ]);
  });

  it('matches an override by parameter types, not by name alone', async () => {
    const idx = await indexOf({
      'app/Shape.java': `package app;
public interface Shape { void draw(String how); }`,
      'app/Square.java': `package app;
public class Square implements Shape {
  public void draw(String how) { }
  public void draw(int times) { }
}`,
      'app/Use.java': `package app;
public class Use {
  void a(Square s) { s.draw(3); }
  void b(Square s) { s.draw("x"); }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Shape.draw' });
    expect(lines(a)).toEqual([4]);
  });

  it('leaves a static or final-in-practice method with no dispatch scope', async () => {
    const idx = await indexOf(overloads);
    const patterns = idx.resolveCallers({ symbol: 'app.Money.plus' }).scope.excluded.map(e => e.pattern);
    expect(patterns).not.toContain('subtypes outside the searched tree');
  });
});

describe('extraction under navigationTypes', () => {
  it("emits an enum's methods, which the default path misses", async () => {
    const idx = await indexOf({
      'app/Kind.java': `package app;
public enum Kind {
  A, B;
  public static Kind fromInt(Integer v) { return A; }
}`,
      'app/Use.java': `package app;
public class Use { Kind k(Integer v) { return Kind.fromInt(v); } }`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Kind.fromInt' });
    expect(lines(a)).toEqual([2]);
    expect(a.answers[0].tier).toBe('exact');
  });

  it('types a varargs parameter and binds a varargs call', async () => {
    await initAnalyzer();
    const ir = await analyze(`package app;
public class V { static void log(String fmt, Object... args) { } }`, 'V.java', 'java', { navigationTypes: true });
    expect(ir.types[0].methods[0].parameters.map(p => [p.name, p.type])).toEqual([['fmt', 'String'], ['args', 'Object...']]);

    const idx = await indexOf({
      'app/V.java': `package app;
public class V {
  static void log(String fmt, Object... args) { }
  static void log(String fmt) { }
}`,
      'app/Use.java': `package app;
public class Use {
  void a() { V.log("x"); }
  void b() { V.log("x", 1, 2); }
}`,
    });
    expect(lines(idx.resolveCallers({ symbol: 'app.V.log(String,Object...)' }))).toEqual([4]);
    expect(lines(idx.resolveCallers({ symbol: 'app.V.log(String)' }))).toEqual([3]);
  });

  it('leaves the default extraction unchanged', async () => {
    await initAnalyzer();
    const src = `package app;
public enum Kind { A; static Kind of(String... xs) { return A; } }
class U { void u(String s) { Kind.of(s); } }`;
    const ir = await analyze(src, 'Kind.java', 'java');
    expect(ir.types.find(t => t.name === 'Kind')!.methods).toEqual([]);
    expect(ir.calls[0].arguments[0]).not.toHaveProperty('type');
    expect(ir.calls[0].arguments[0]).not.toHaveProperty('location');
  });
});

describe('determinism', () => {
  it('answers byte-identically on two builds', async () => {
    const a = JSON.stringify({ ...(await indexOf(overloads)).resolveCallers({ symbol: 'app.Money.of' }), timing: null });
    const b = JSON.stringify({ ...(await indexOf(overloads)).resolveCallers({ symbol: 'app.Money.of' }), timing: null });
    expect(a).toBe(b);
  });
});
