/**
 * Every tier transition, and every reason in the vocabulary.
 *
 * The tier is the product: an answer labelled `exact` is a promise that the
 * receiver's static type was known and the target was unique in it, and the
 * only way to keep that promise honest is to pin each boundary with a test
 * that fails if an answer drifts up a tier.
 *
 * `inferred` has its own group at the end. It is a permanent floor: it is never
 * promoted, and it is never produced when a receiver type *is* known and
 * disagrees — that case is the one a name-only search gets wrong, 78 times out
 * of 147 on a real repository.
 */

import { describe, it, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { buildNavigationIndex, type NavigationIndex } from '../../src/navigation/index.js';

async function indexOf(
  files: Record<string, string>,
  opts: Parameters<typeof buildNavigationIndex>[1] = {},
): Promise<NavigationIndex> {
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
  return buildNavigationIndex(entries, opts);
}

describe('tier — exact', () => {
  it('a known receiver type with one method of that name is exact', async () => {
    const idx = await indexOf({
      'app/Service.java': `package app;
public class Service { public String run() { return "x"; } }`,
      'app/Caller.java': `package app;
public class Caller {
  private final Service svc = new Service();
  String go() { return svc.run(); }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Service.run' });
    expect(a.answers.map(x => x.tier)).toEqual(['exact']);
    expect(a.answers[0].candidates).toBeUndefined();
  });

  it('an unqualified call inside the declaring type is exact, not inferred', async () => {
    const idx = await indexOf({
      'app/Solo.java': `package app;
public class Solo {
  String helper() { return "h"; }
  String go() { return helper(); }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Solo.helper' });
    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].tier).toBe('exact');
  });

  it('a method inherited from a project supertype is exact on the supertype', async () => {
    const idx = await indexOf({
      'app/Base.java': `package app;
public class Base { public String shared() { return "s"; } }`,
      'app/Child.java': `package app;
public class Child extends Base {}`,
      'app/Use.java': `package app;
public class Use {
  private final Child c = new Child();
  String go() { return c.shared(); }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Base.shared' });
    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].tier).toBe('exact');
  });
});

describe('tier — polymorphic', () => {
  it('an interface receiver with implementors is polymorphic, with every candidate', async () => {
    const idx = await indexOf({
      'app/Shape.java': `package app;
public interface Shape { String draw(); }`,
      'app/Circle.java': `package app;
public class Circle implements Shape { public String draw() { return "o"; } }`,
      'app/Square.java': `package app;
public class Square implements Shape { public String draw() { return "[]"; } }`,
      'app/Canvas.java': `package app;
public class Canvas {
  String paint(Shape s) { return s.draw(); }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Shape.draw' });
    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].tier).toBe('polymorphic');
    expect(a.answers[0].candidates?.sort()).toEqual(['app.Circle.draw', 'app.Square.draw']);
  });

  it('a class with two overriding subtypes is polymorphic, not exact', async () => {
    const idx = await indexOf({
      'app/Animal.java': `package app;
public class Animal { public String speak() { return "..."; } }`,
      'app/Dog.java': `package app;
public class Dog extends Animal { public String speak() { return "woof"; } }`,
      'app/Cat.java': `package app;
public class Cat extends Animal { public String speak() { return "meow"; } }`,
      'app/Zoo.java': `package app;
public class Zoo { String all(Animal a) { return a.speak(); } }`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Animal.speak' });
    expect(a.answers[0].tier).toBe('polymorphic');
    expect(a.answers[0].candidates).toHaveLength(3);
  });
});

describe('tier — inferred is a floor', () => {
  it('a receiver with no known type binds by name alone, labelled inferred', async () => {
    const idx = await indexOf({
      'app/Target.java': `package app;
public class Target { public String onlyOne() { return "x"; } }`,
      'app/Murky.java': `package app;
public class Murky {
  String go(java.util.List<?> xs) { return xs.get(0).toString() + mystery().onlyOne(); }
  Object mystery() { return null; }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.Target.onlyOne' });
    expect(a.answers.every(x => x.tier === 'inferred')).toBe(true);
    expect(a.answers[0]?.evidence).toContain('name alone');
  });

  it('a KNOWN receiver type that lacks the method yields NO answer, never inferred', async () => {
    // This is the 78-of-147 case. `Other` is a project type, its type is known,
    // and it has no `equals` of its own — so a name-only bind to
    // `app.User.equals` would be a contradiction, not a weak answer.
    const idx = await indexOf({
      'app/User.java': `package app;
public class User { public boolean equals(Object o) { return true; } }`,
      'app/Other.java': `package app;
public class Other { public String name() { return "n"; } }`,
      'app/Compare.java': `package app;
public class Compare {
  private final Other other = new Other();
  boolean go() { return other.equals("x"); }
}`,
    });
    const a = idx.resolveCallers({ symbol: 'app.User.equals' });
    expect(a.answers).toHaveLength(0);
    expect(a.unresolved).toHaveLength(1);
    expect(a.unresolved[0].site.file).toBe('app/Compare.java');
  });

  it('an ambiguous name is not inferred either — two owners is not evidence', async () => {
    const idx = await indexOf({
      'app/A.java': `package app;
public class A { public String ping() { return "a"; } }`,
      'app/B.java': `package app;
public class B { public String ping() { return "b"; } }`,
      'app/Caller.java': `package app;
public class Caller { String go(Object o) { return mystery().ping(); } Object mystery() { return null; } }`,
    });
    const a = idx.resolveCallers({ symbol: 'app.A.ping' });
    expect(a.answers).toHaveLength(0);
  });

  it('tiers can be filtered out of an answer without changing the scope', async () => {
    const idx = await indexOf({
      'app/Target.java': `package app;
public class Target { public String onlyOne() { return "x"; } }`,
      'app/Murky.java': `package app;
public class Murky { String go() { return mystery().onlyOne(); } Object mystery() { return null; } }`,
    });
    const all = idx.resolveCallers({ symbol: 'app.Target.onlyOne' });
    const exactOnly = idx.resolveCallers({ symbol: 'app.Target.onlyOne' }, { tiers: ['exact'] });
    expect(all.answers.length).toBeGreaterThan(0);
    expect(exactOnly.answers).toHaveLength(0);
    expect(exactOnly.scope.searched.files).toBe(all.scope.searched.files);
  });
});

describe('unresolved — every reason comes from the source, not from a default', () => {
  it('external: the target is declared in no indexed file', async () => {
    const idx = await indexOf({
      'app/Uses.java': `package app;
import java.util.ArrayList;
public class Uses {
  int go() { ArrayList<String> xs = new ArrayList<>(); return xs.size(); }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Uses.go' });
    const sizeCall = a.unresolved.find(u => u.methodName === 'size');
    expect(sizeCall?.reason).toBe('external');
  });

  it('dynamic: a reflective receiver', async () => {
    const idx = await indexOf({
      'app/Refl.java': `package app;
public class Refl {
  Object go(Class<?> c) throws Exception { return c.getDeclaredMethod("x"); }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Refl.go' });
    expect(a.unresolved.find(u => u.methodName === 'getDeclaredMethod')?.reason).toBe('dynamic');
  });

  it('generated: a Lombok accessor that exists only after annotation processing', async () => {
    const idx = await indexOf({
      'app/Bean.java': `package app;
import lombok.Getter;
@Getter
public class Bean { private String title; }`,
      'app/Read.java': `package app;
public class Read {
  private final Bean bean = new Bean();
  String go() { return bean.getTitle(); }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Read.go' });
    expect(a.unresolved.find(u => u.methodName === 'getTitle')?.reason).toBe('generated');
  });

  it('generated: a field-level @Getter on a project supertype', async () => {
    const idx = await indexOf({
      'app/Base.java': `package app;
import lombok.Getter;
public abstract class Base { @Getter private String user = "u"; }`,
      'app/Child.java': `package app;
public class Child extends Base { String go() { return getUser(); } }`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Child.go' });
    expect(a.unresolved.find(u => u.methodName === 'getUser')?.reason).toBe('generated');
  });

  it('unknown: the target is in the tree and could not be bound', async () => {
    // A field access mid-chain is deliberately not walked, so the receiver
    // stays untyped while the target plainly is ours. That is `unknown`, and
    // calling it `external` would be a lie about the denominator.
    const idx = await indexOf({
      'app/Holder.java': `package app;
public class Holder { public Inner inner = new Inner(); }`,
      'app/Inner.java': `package app;
public class Inner { public String reach() { return "r"; } public String reach(int n) { return "r"; } }`,
      'app/Other.java': `package app;
public class Other { public String reach() { return "o"; } }`,
      'app/Walk.java': `package app;
public class Walk {
  String go(Holder h) { return h.inner.reach(); }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Walk.go' });
    const reach = a.unresolved.find(u => u.methodName === 'reach');
    expect(reach?.reason).toBe('unknown');
  });

  it('parse-error: a partial parse outranks every other reason', async () => {
    // `mystery` is declared nowhere, so on a clean file this would be
    // `external`. It is not, because the file has an ERROR node: the region
    // tree-sitter could not read might well declare it, and claiming the
    // target is outside the tree would be a statement about source nobody
    // read. A wholly unparseable file yields no calls to reason about at all,
    // so the fixture has to be one that parses in part — which is also the
    // shape that actually occurs, in a half-saved buffer.
    const idx = await indexOf({
      'app/Partial.java': `package app;
public class Partial {
  String go() { return mystery(); }
  String broken() { int x = ; }
}`,
    });
    const a = idx.resolveCallees({ symbol: 'app.Partial.go' });
    expect(a.unresolved).toHaveLength(1);
    expect(a.unresolved[0].methodName).toBe('mystery');
    expect(a.unresolved[0].reason).toBe('parse-error');
  });
});

describe('the answer always states its denominator', () => {
  const files = {
    'app/A.java': `package app;
public class A { public String go() { return "a"; } }`,
    'app/B.java': `package app;
public class B { String call() { A a = new A(); return a.go(); } }`,
  };

  it('scope.searched counts the files and names the languages', async () => {
    const idx = await indexOf(files);
    const a = idx.resolveCallers({ symbol: 'app.A.go' });
    expect(a.scope.searched).toEqual({ files: 2, languages: ['java'] });
  });

  it('scope.excluded carries what was left out, with the reason', async () => {
    const idx = await indexOf(files, {
      excluded: [{ pattern: '**/generated/**', reason: 'build output' }],
    });
    const a = idx.resolveCallers({ symbol: 'app.A.go' });
    expect(a.scope.excluded).toEqual([{ pattern: '**/generated/**', reason: 'build output' }]);
  });

  it('a truncated answer says so, with the real total', async () => {
    const callers: Record<string, string> = {
      'app/A.java': files['app/A.java'],
    };
    for (let i = 0; i < 5; i++) {
      callers[`app/C${i}.java`] = `package app;
public class C${i} { String call() { A a = new A(); return a.go(); } }`;
    }
    const idx = await indexOf(callers);
    const a = idx.resolveCallers({ symbol: 'app.A.go' }, { limit: 2 });
    expect(a.answers).toHaveLength(2);
    expect(a.truncated).toEqual({ returned: 2, total: 5 });
  });

  it('timing is reported on every answer', async () => {
    const idx = await indexOf(files);
    const a = idx.resolveCallers({ symbol: 'app.A.go' });
    expect(a.timing.indexMs).toBeGreaterThanOrEqual(0);
    expect(a.timing.queryMs).toBeGreaterThanOrEqual(0);
    expect(a.timing.parseMs).toBe(0);
  });
});

describe('the site shape, and what a site cannot do', () => {
  it('a site carries the pack\'s four fields', async () => {
    const idx = await indexOf({
      'app/A.java': `package app;
public class A { public String go() { return "a"; } }`,
      'app/B.java': `package app;
public class B { String call() { A a = new A(); return a.go(); } }`,
    });
    const a = idx.resolveCallers({ symbol: 'app.A.go' });
    const site = a.answers[0].site;
    expect(Object.keys(site).sort()).toEqual(['col', 'file', 'inMethod', 'line', 'text']);
    // the called name belongs to the answer, not to the site
    expect(a.answers[0].methodName).toBe('go');
    expect(site.file).toBe('app/B.java');
    expect(site.line).toBe(2);
    expect(typeof site.col).toBe('number');
    expect(site.text).toContain('a.go()');
  });

  it('a chained expression puts several calls at one line and column', async () => {
    // Which is why a (file, line, col) triple cannot address one call, and why
    // a site query that lands on such a triple answers nothing rather than
    // picking one of them.
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
    const done = idx.resolveCallers({ symbol: 'app.Builder.done' }).answers[0];
    const step = idx.resolveCallers({ symbol: 'app.Builder.step' }).answers[0];
    expect(done.site.line).toBe(step.site.line);
    expect(done.site.col).toBe(step.site.col);

    const bySite = idx.resolveCallers({ site: done.site });
    expect(bySite.answers).toHaveLength(0);
  });

  it('a site query resolves when the site names exactly one call', async () => {
    const idx = await indexOf({
      'app/A.java': `package app;
public class A { public String go() { return "a"; } }`,
      'app/B.java': `package app;
public class B {
  String one() { A a = new A(); return a.go(); }
  String two() { A a = new A(); return a.go(); }
}`,
    });
    const first = idx.resolveCallers({ symbol: 'app.A.go' }).answers[0];
    const bySite = idx.resolveCallers({ site: first.site });
    expect(bySite.query.kind).toBe('callers');
    expect(bySite.answers).toHaveLength(2);
  });
});

describe('the cache is keyed by content, and off by default', () => {
  const files = {
    'app/A.java': `package app;
public class A { public String go() { return "a"; } }`,
    'app/B.java': `package app;
public class B { String call() { A a = new A(); return a.go(); } }`,
  };

  it('two builds over the same content give the same answer', async () => {
    const first = await indexOf(files, { cache: true });
    const second = await indexOf(files, { cache: true });
    const strip = (x: unknown): string =>
      JSON.stringify(x, (k, v) => (k === 'timing' ? undefined : v));
    expect(strip(second.resolveCallers({ symbol: 'app.A.go' })))
      .toBe(strip(first.resolveCallers({ symbol: 'app.A.go' })));
  });

  it('changed content is re-indexed, not served from the cache', async () => {
    await indexOf(files, { cache: true });
    const edited = {
      ...files,
      'app/B.java': `package app;
public class B {
  String call() { A a = new A(); return a.go(); }
  String callAgain() { A a = new A(); return a.go(); }
}`,
    };
    const after = await indexOf(edited, { cache: true });
    expect(after.resolveCallers({ symbol: 'app.A.go' }).answers).toHaveLength(2);
  });
});

describe('`analyze` without the flag is unchanged', () => {
  it('a record yields no type at all, as before', async () => {
    await initAnalyzer();
    const src = `package app;
public record Config(String host) { public String url(String p) { return host + p; } }`;
    const plain = await analyze(src, 'app/Config.java', 'java');
    const withFlag = await analyze(src, 'app/Config.java', 'java', { navigationTypes: true });
    expect(plain.types).toHaveLength(0);
    expect(withFlag.types).toHaveLength(1);
    expect(withFlag.types[0].is_record).toBe(true);
    expect(withFlag.types[0].methods.map(m => m.name).sort()).toEqual(['host', 'url']);
  });

  it('a nested type carries no enclosing_type without the flag', async () => {
    await initAnalyzer();
    const src = `package app;
public class Outer { public static class Inner { public void m() {} } }`;
    const plain = await analyze(src, 'app/Outer.java', 'java');
    const withFlag = await analyze(src, 'app/Outer.java', 'java', { navigationTypes: true });
    expect(plain.types.find(t => t.name === 'Inner')?.enclosing_type).toBeUndefined();
    expect(withFlag.types.find(t => t.name === 'Inner')?.enclosing_type).toBe('Outer');
  });
});
