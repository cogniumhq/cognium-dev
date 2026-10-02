/**
 * What an answer says on an interface-typed receiver, and the key a consumer
 * can join an answer on.
 *
 * Both of these matter outside this package. The answers are graded against an
 * oracle that resolves a call the way a compiler does — statically, to the
 * member the receiver's *declared* type names. So on a `Greeter`-typed
 * receiver the oracle's target is `Greeter.greet`, never `Polite.greet`, and an
 * answer that named an implementation as its target would be making a claim
 * the oracle cannot support, however useful that claim is to a human.
 *
 * The join key matters because a chained expression reports several calls at
 * one line and column, so `(file, line, col)` cannot address one call. The only
 * sound key is `(file, line, methodName)`.
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

const dispatch = {
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
}`,
};

describe('an interface-typed receiver answers about the interface', () => {
  it('targets the declaring member, never an implementation', async () => {
    const idx = await indexOf(dispatch);
    const a = idx.resolveCallees({ symbol: 'app.Caller.viaInterface' });

    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].target).toBe('app.Greeter.greet');
    expect(a.answers[0].tier).toBe('polymorphic');
  });

  it('never claims `exact` with an implementation on an interface receiver', async () => {
    const idx = await indexOf(dispatch);
    for (const sym of ['app.Polite.greet', 'app.Blunt.greet']) {
      const a = idx.resolveCallers({ symbol: sym });
      const viaInterface = a.answers.filter(x => x.site.inMethod === 'viaInterface');
      expect(viaInterface).toHaveLength(0);
    }
  });

  it('puts the runnable bodies in candidates, and not the declaration', async () => {
    const idx = await indexOf(dispatch);
    const a = idx.resolveCallees({ symbol: 'app.Caller.viaInterface' });

    expect(a.answers[0].candidates?.sort()).toEqual(['app.Blunt.greet', 'app.Polite.greet']);
    // The interface's own member is the target, not a candidate: it has no body.
    expect(a.answers[0].candidates).not.toContain('app.Greeter.greet');
  });

  it('a class-typed receiver that declares the method is exact on that class', async () => {
    const idx = await indexOf(dispatch);
    const a = idx.resolveCallees({ symbol: 'app.Caller.viaClass' });

    expect(a.answers[0].target).toBe('app.Polite.greet');
    expect(a.answers[0].tier).toBe('exact');
  });
});

describe('every answer carries the name as written, so it can be joined', () => {
  it('methodName is on answers as well as on non-answers', async () => {
    const idx = await indexOf(dispatch);
    const a = idx.resolveCallees({ symbol: 'app.Caller.viaInterface' });

    expect(a.answers[0].methodName).toBe('greet');
  });

  it('methodName is the written name, which a constructor\'s target is not', async () => {
    const idx = await indexOf({
      'app/Widget.java': `package app;
public class Widget { public Widget() {} }`,
      'app/Factory.java': `package app;
public class Factory { Widget build() { return new Widget(); } }`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Widget.<init>' });

    expect(a.answers[0].target).toBe('app.Widget.<init>');
    expect(a.answers[0].methodName).toBe('Widget');
  });

  it('(file, line, methodName) separates calls that share a line and column', async () => {
    const idx = await indexOf({
      'app/Builder.java': `package app;
public class Builder {
  public static Builder of() { return new Builder(); }
  public Builder step(String s) { return this; }
  public String done() { return "x"; }
}`,
      'app/Use.java': `package app;
public class Use { String run() { return Builder.of().step("a").done(); } }`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Use.run' });

    const byCol = new Set(a.answers.map(x => `${x.site.file}:${x.site.line}:${x.site.col}`));
    const byName = new Set(a.answers.map(x => `${x.site.file}:${x.site.line}:${x.methodName}`));
    expect(a.answers.length).toBeGreaterThan(1);
    expect(byCol.size).toBeLessThan(a.answers.length);   // the col key collapses them
    expect(byName.size).toBe(a.answers.length);          // the name key does not
  });
});

describe('symbolAt — asking by line of code instead of by name', () => {
  const files = {
    'app/A.java': `package app;
public class A { public String go() { return "a"; } }`,
    'app/B.java': `package app;
public class B {
  String call() { A a = new A(); return a.go(); }
}`,
  };

  it('a callers query from a site resolves to what that line calls', async () => {
    const idx = await indexOf(files);
    expect(idx.symbolAt('app/B.java', 3, 'go', 'callers')).toBe('app.A.go');
  });

  it('a callees query from a site resolves to the method holding the line', async () => {
    const idx = await indexOf(files);
    expect(idx.symbolAt('app/B.java', 3, 'go', 'callees')).toBe('app.B.call');
  });

  it('separates calls a column cannot, in a chained expression', async () => {
    const idx = await indexOf({
      'app/Builder.java': `package app;
public class Builder {
  public static Builder of() { return new Builder(); }
  public Builder step(String s) { return this; }
  public String done() { return "x"; }
}`,
      'app/Use.java': `package app;
public class Use { String run() { return Builder.of().step("a").done(); } }`,
    });
    expect(idx.symbolAt('app/Use.java', 2, 'done', 'callers')).toBe('app.Builder.done');
    expect(idx.symbolAt('app/Use.java', 2, 'step', 'callers')).toBe('app.Builder.step');
    expect(idx.symbolAt('app/Use.java', 2, 'of', 'callers')).toBe('app.Builder.of');
  });

  it('answers nothing when the same name appears twice on one line', async () => {
    // The key cannot separate them, and picking one would be a guess
    // presented as an answer.
    const idx = await indexOf({
      'app/A.java': `package app;
public class A { public String go() { return "a"; } }`,
      'app/Twice.java': `package app;
public class Twice { String run() { A a = new A(); return a.go() + a.go(); } }`,
    });
    expect(idx.symbolAt('app/Twice.java', 2, 'go', 'callers')).toBeUndefined();
  });

  it('answers nothing for a file or a name that is not there', async () => {
    const idx = await indexOf(files);
    expect(idx.symbolAt('app/Nope.java', 1, 'go', 'callers')).toBeUndefined();
    expect(idx.symbolAt('app/B.java', 3, 'absent', 'callers')).toBeUndefined();
  });
});

describe('`exact` requires a body — a target that is a shape is never exact', () => {
  /**
   * Found by the evaluation side, from the other direction: their static
   * oracles were naming a *binding* — a variable, a parameter, a property, an
   * element of an array of callables — as though it were the function that
   * would run, on 15 of 1,500 labels, and both of their hosts agreed on every
   * one, so two-host stability never caught it. Two-host agreement proves
   * agreement; it cannot prove correctness.
   *
   * The same class exists here wherever a declaration has no body. An
   * interface member without `default`, or a method marked `abstract`, names
   * nothing that can run: what runs is an implementation, or a lambda this
   * index cannot see as a type at all. The target stays the declaring member,
   * which is what a static resolver answers — only the tier may not say
   * `exact`, and `candidates` must not list a body that does not exist.
   */
  it('an interface implemented only by a lambda is not exact', async () => {
    const idx = await indexOf({
      'app/Handler.java': `package app;
public interface Handler { String run(String s); }`,
      'app/Use.java': `package app;
public class Use {
  private final Handler h = s -> s;
  String go() { return h.run("a"); }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Use.go' });
    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].target).toBe('app.Handler.run');
    expect(a.answers[0].tier).toBe('polymorphic');
    expect(a.answers[0].candidates).toEqual([]);
    expect(a.answers[0].evidence).toContain('without a body');
  });

  it('an abstract method nothing overrides is not exact, and is not its own candidate', async () => {
    const idx = await indexOf({
      'app/Base.java': `package app;
public abstract class Base { public abstract String step(); }`,
      'app/Use.java': `package app;
public class Use { String go(Base b) { return b.step(); } }`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Use.go' });
    expect(a.answers[0].tier).toBe('polymorphic');
    // Listing `Base.step` here would name a body that does not exist.
    expect(a.answers[0].candidates).toEqual([]);
  });

  it('a `default` interface method DOES have a body, so it is exact', async () => {
    const idx = await indexOf({
      'app/Greet.java': `package app;
public interface Greet {
  String name();
  default String hello() { return "hi"; }
}`,
      'app/Use.java': `package app;
public class Use {
  private final Greet g = () -> "n";
  String viaDefault() { return g.hello(); }
  String viaAbstract() { return g.name(); }
}`,
    });
    const viaDefault = idx.resolveCallees({ symbol: 'app.Use.viaDefault' }).answers[0];
    const viaAbstract = idx.resolveCallees({ symbol: 'app.Use.viaAbstract' }).answers[0];
    expect(viaDefault.tier).toBe('exact');
    expect(viaAbstract.tier).toBe('polymorphic');
  });

  it('an overridden abstract method lists only the overriding bodies', async () => {
    const idx = await indexOf({
      'app/Base.java': `package app;
public abstract class Base { public abstract String step(); }`,
      'app/Real.java': `package app;
public class Real extends Base { public String step() { return "r"; } }`,
      'app/Use.java': `package app;
public class Use { String go(Base b) { return b.step(); } }`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Use.go' });
    expect(a.answers[0].tier).toBe('polymorphic');
    expect(a.answers[0].candidates).toEqual(['app.Real.step']);
  });

  it('a JDK functional interface is external, not an exact answer about ours', async () => {
    const idx = await indexOf({
      'app/Use.java': `package app;
import java.util.function.Function;
public class Use {
  private final Function<String,String> fn = x -> x;
  String go() { return fn.apply("a"); }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Use.go' });
    expect(a.answers).toHaveLength(0);
    expect(a.unresolved.find((u) => u.methodName === 'apply')?.reason).toBe('external');
  });

  it('a concrete class method with no subtype is still exact', async () => {
    const idx = await indexOf({
      'app/Solid.java': `package app;
public class Solid { public String run() { return "s"; } }`,
      'app/Use.java': `package app;
public class Use { String go(Solid s) { return s.run(); } }`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Use.go' });
    expect(a.answers[0].tier).toBe('exact');
    expect(a.answers[0].evidence).toContain('has a body');
  });
});
