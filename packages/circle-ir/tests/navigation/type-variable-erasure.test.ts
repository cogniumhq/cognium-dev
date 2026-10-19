/**
 * Callers of a method declared with a type variable.
 *
 * `MapUtils.getNumber(Map, K)` is `getNumber(java.util.Map, java.lang.Object)`
 * to the compiler, to javadoc's `{@link}` and to every bytecode-level tool: a
 * type variable erases to its leftmost bound, else `Object`, and a
 * parameterized type to its raw type. A query naming the method that way got
 * no overload and no callers. A parameter list may now name a type variable
 * either way, and overload selection reads a type variable as its erasure —
 * certain where the compiler infers it from the arguments, possible where the
 * receiver fixes it.
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

type Answer = Awaited<ReturnType<NavigationIndex['resolveCallers']>>;
const sites = (a: Answer): string[] => a.answers.map(x => `${x.site.file.split('/').pop()}:${x.site.line}`);
const callers = (idx: NavigationIndex, symbol: string): string[] => sites(idx.resolveCallers({ symbol }));

const generic = {
  'app/Box.java': `package app;
public class Box<E> {
  public void put(E e) { }
  public void put(E e, int times) { }
  public void add(E e) { }
  public void add(Number n) { }
  public class Slot {
    public void take(E e) { }
    void self() { take(null); }
  }
}`,
  'app/Util.java': `package app;
import java.util.Map;
public class Util {
  public static <T> void f(T t) { }
  public static void f(int a, int b) { }
  public static <K, V, M extends Map<K, V>> M invert(Map<? extends V, ? extends K> in, M out) { return out; }
  public static <T extends Comparable<T>> T max(T a, T b) { return a; }
  public static int max(int a, int b) { return a; }
  public static <T> void put(T t) { }
  public static void put(String s) { }
  public static void put(Number n) { }
  @SafeVarargs public static <T> void all(T... xs) { }
  public static <N extends Number> double sum(N[] xs) { return 0; }
  static <U extends Comparable<U>, W extends U> void chain(W w) { }
}`,
  'app/Caller.java': `package app;
import java.util.HashMap;
import java.util.Map;
public class Caller {
  void boxes(Box<String> b, Box<Integer> n) {
    b.put("x");
    b.put("y", 2);
    n.add(5);
  }
  void utils(Map<String, Integer> m, Object o) {
    Util.f("x");
    Util.f(1, 2);
    Util.invert(m, new HashMap<Integer, String>());
    Util.max("a", "b");
    Util.max(1, 2);
    Util.put("s");
    Util.put(5L);
    Util.put(o.hashCode() > 0 ? o : null);
    Util.all("a", "b");
    Util.sum(new Integer[0]);
  }
}`,
};

describe('a parameter list names a type variable as written or by its erasure', () => {
  it('a type parameter of the class erases to Object', async () => {
    const idx = await indexOf(generic);
    for (const sym of ['app.Box.put(E)', 'app.Box.put(Object)', 'app.Box.put(java.lang.Object)']) {
      expect(callers(idx, sym)).toEqual(['Caller.java:6']);
    }
    expect(callers(idx, 'app.Box.put(java.lang.Object,int)')).toEqual(['Caller.java:7']);
  });

  it('a type parameter of the method erases to Object; a parameterized bound to its raw type', async () => {
    const idx = await indexOf(generic);
    expect(callers(idx, 'app.Util.f(Object)')).toEqual(['Caller.java:11']);
    expect(callers(idx, 'app.Util.f(T)')).toEqual(['Caller.java:11']);
    for (const sym of ['app.Util.invert(Map,M)', 'app.Util.invert(Map,Map)', 'app.Util.invert(java.util.Map,java.util.Map)']) {
      expect(callers(idx, sym)).toEqual(['Caller.java:13']);
    }
  });

  it('a bounded type variable erases to its leftmost bound, not to Object', async () => {
    const idx = await indexOf(generic);
    expect(callers(idx, 'app.Util.max(Comparable,Comparable)')).toEqual(['Caller.java:14']);
    expect(callers(idx, 'app.Util.max(java.lang.Comparable,java.lang.Comparable)')).toEqual(['Caller.java:14']);
    expect(callers(idx, 'app.Util.max(T,T)')).toEqual(['Caller.java:14']);
    expect(callers(idx, 'app.Util.max(int,int)')).toEqual(['Caller.java:15']);
    const wrong = idx.resolveCallers({ symbol: 'app.Util.max(Object,Object)' });
    expect(wrong.answers).toEqual([]);
    // A signature shows a type variable as its erasure, the spelling javadoc and bytecode use.
    expect(wrong.note).toContain('declared: app.Util.max(Comparable,Comparable), app.Util.max(int,int)');
    // `W extends U extends Comparable<U>`: a bound that is itself a variable is erased in turn.
    expect(idx.resolveCallers({ symbol: 'app.Util.chain(Comparable)' }).note).toBeUndefined();
  });

  it('an enclosing type\'s type parameter, arrays and varargs', async () => {
    const idx = await indexOf(generic);
    expect(callers(idx, 'app.Box.Slot.take(Object)')).toEqual(['Box.java:9']);
    expect(callers(idx, 'app.Util.all(Object...)')).toEqual(['Caller.java:19']);
    expect(callers(idx, 'app.Util.sum(Number[])')).toEqual(['Caller.java:20']);
    expect(callers(idx, 'app.Util.sum(Object[])')).toEqual([]);
  });

  it('is deterministic', async () => {
    const a = JSON.stringify((await indexOf(generic)).resolveCallers({ symbol: 'app.Util.put(Object)' }).answers);
    const b = JSON.stringify((await indexOf(generic)).resolveCallers({ symbol: 'app.Util.put(Object)' }).answers);
    expect(a).toBe(b);
  });
});

describe('overload selection reads a type variable as its erasure', () => {
  it('a method type variable is inferred: the most specific overload wins', async () => {
    const idx = await indexOf(generic);
    // "s" fits put(T) and put(String); put(String) is more specific.
    expect(callers(idx, 'app.Util.put(String)')).toEqual(['Caller.java:16']);
    // 5L boxes to Long, which fits put(T) and put(Number); put(Number) is more specific.
    expect(callers(idx, 'app.Util.put(Number)')).toEqual(['Caller.java:17']);
    // A bounded variable rules out what its bound does: "a" is no int, 1 is.
    expect(callers(idx, 'app.Util.f(int,int)')).toEqual(['Caller.java:12']);
  });

  it('more than one overload fitting is still ambiguous, never a guess', async () => {
    const idx = await indexOf(generic);
    const any = idx.resolveCallers({ symbol: 'app.Util.put(T)' });
    expect(sites(any)).toEqual([]);
    const amb = any.unresolved.filter(u => u.reason === 'overload-ambiguous');
    expect(amb.map(u => u.site.line)).toEqual([18]);
    expect(amb[0].candidates).toEqual(['app.Util.put(Object)', 'app.Util.put(String)', 'app.Util.put(Number)']);
  });

  it('a class type variable is fixed by the receiver, so it only rules out', async () => {
    // `Box<Integer>.add(5)` is add(E) to the compiler — Integer is more
    // specific than Number — but without the receiver's type argument, E is
    // only known to be some reference type.
    const idx = await indexOf(generic);
    const r = idx.resolveCallers({ symbol: 'app.Box.add(Number)' });
    expect(sites(r)).toEqual([]);
    expect(r.unresolved.filter(u => u.reason === 'overload-ambiguous').map(u => u.site.line)).toEqual([8]);
  });
});

const bridged = {
  'app/Fn.java': `package app;
public interface Fn<T, R> {
  R apply(T t);
}`,
  'app/Upper.java': `package app;
public class Upper implements Fn<String, String> {
  public String apply(String s) { return s.toUpperCase(); }
}`,
  'app/Use.java': `package app;
public class Use {
  String a(Fn<String, String> f) { return f.apply("x"); }
  String b(Upper u) { return u.apply("y"); }
}`,
};

describe('a generic interface implemented with a concrete type', () => {
  it('the interface method is named by its erasure; the implementation by its own types', async () => {
    const idx = await indexOf(bridged);
    for (const sym of ['app.Fn.apply(Object)', 'app.Fn.apply(T)', 'app.Fn.apply']) {
      const r = idx.resolveCallers({ symbol: sym });
      // A call through an interface with an implementation is `polymorphic`;
      // so is a call to the implementation, labelled with what it overrides.
      expect(sites(r)).toEqual(['Use.java:3', 'Use.java:4']);
      expect(r.answers.map(a => a.tier)).toEqual(['polymorphic', 'polymorphic']);
      expect(r.answers[1].via).toEqual({ member: 'app.Upper.apply', relation: 'override' });
    }
    const impl = idx.resolveCallers({ symbol: 'app.Upper.apply(String)' });
    expect(sites(impl)).toEqual(['Use.java:3', 'Use.java:4']);
    expect(impl.answers.map(a => a.tier)).toEqual(['polymorphic', 'exact']);
    expect(impl.answers[0].via).toEqual({ member: 'app.Fn.apply', relation: 'supertype' });
  });

  it('the compiler\'s bridge method is not a declaration: no answer, and the note names what is declared', async () => {
    const idx = await indexOf(bridged);
    const r = idx.resolveCallers({ symbol: 'app.Upper.apply(java.lang.Object)' });
    expect(r.answers).toEqual([]);
    expect(r.note).toContain('declared: app.Upper.apply(String)');
  });
});

const hashed = {
  'app/Base.java': `package app;
public class Base<K, V> {
  protected void addMapping(int index, int hash, K key, V value) { }
  public void put(K key, V value) { addMapping(0, 0, key, value); }
}`,
  'app/Lru.java': `package app;
public class Lru<K, V> extends Base<K, V> {
  @Override
  protected void addMapping(int index, int hash, K key, V value) {
    super.addMapping(index, hash, key, value);
  }
}`,
};

describe('an override in a generic subclass', () => {
  it('the erased query finds the dispatched call and the super call; the super call is exact', async () => {
    const idx = await indexOf(hashed);
    for (const sym of ['app.Base.addMapping(int,int,java.lang.Object,java.lang.Object)', 'app.Base.addMapping(int,int,K,V)']) {
      const r = idx.resolveCallers({ symbol: sym });
      expect(sites(r)).toEqual(['Base.java:4', 'Lru.java:5']);
      // `addMapping(…)` inside Base may land on Lru's override; `super.addMapping(…)` cannot.
      expect(r.answers.map(a => a.tier)).toEqual(['polymorphic', 'exact']);
    }
  });
});

describe('a method the type only inherits from outside the tree', () => {
  it('says so instead of answering "no callers" silently', async () => {
    const idx = await indexOf({
      'app/Cursor.java': `package app;
public interface Cursor { Object key(); }`,
      'app/ListCursor.java': `package app;
public class ListCursor implements Cursor {
  public Object key() { return null; }
  @Override public String toString() { return "Cursor[]"; }
}`,
      'app/Log.java': `package app;
public class Log {
  String a(Cursor c) { return "at " + c; }
}`,
    });
    const r = idx.resolveCallers({ symbol: 'app.Cursor.toString()' });
    expect(r.answers).toEqual([]);
    expect(r.note).toContain('app.Cursor declares no method toString');
    expect(r.note).toContain('java.lang.Object');
    expect(idx.resolveCallers({ symbol: 'app.Cursor.key()' }).note).toBeUndefined();
  });
});

const selfCalls = {
  'app/Transformed.java': `package app;
import java.util.Collection;
public class Transformed<E> {
  protected E transform(E object) { return object; }
  protected Collection<E> transform(Collection<? extends E> coll) { return null; }
  boolean add(E object) { return transform(object) != null; }
  boolean addAll(Collection<? extends E> coll) { return this.transform(coll) != null; }
}`,
  'app/TransformedBag.java': `package app;
public class TransformedBag<E> extends Transformed<E> {
  boolean add(E object, int n) { return transform(object) != null; }
}`,
  'app/Strings.java': `package app;
import java.util.List;
public class Strings extends Transformed<String> {
  void a(List<String> xs) { transform("s"); transform(xs); }
}`,
  'app/Copy.java': `package app;
import java.util.function.Consumer;
import java.util.function.Predicate;
public class Copy {
  static <T extends Consumer<?>> T[] copy(T... consumers) { return consumers; }
  static <T extends Predicate<?>> T[] copy(T... predicates) { return predicates; }
  static <T> void one(T t) { pick(t); }
  static void pick(Object o) { }
  static void pick(String s) { }
}`,
};

describe('a call on the enclosing type sees the declaring type\'s variables as it fills them', () => {
  it('a generic class calling its own overloads: only the variable itself fits E', async () => {
    const idx = await indexOf(selfCalls);
    expect(callers(idx, 'app.Transformed.transform(Object)')).toEqual(['Strings.java:4', 'Transformed.java:6', 'TransformedBag.java:3']);
    expect(callers(idx, 'app.Transformed.transform(Collection)')).toEqual(['Strings.java:4', 'Transformed.java:7']);
  });

  it('a subclass that fills the variable with a concrete type', async () => {
    const idx = await indexOf(selfCalls);
    // `Strings extends Transformed<String>`: transform("s") is transform(E = String); a List is a Collection.
    expect(callers(idx, 'app.Transformed.transform(E)')).toContain('Strings.java:4');
    const coll = idx.resolveCallers({ symbol: 'app.Transformed.transform(java.util.Collection)' });
    expect(sites(coll)).toEqual(['Strings.java:4', 'Transformed.java:7']);
  });

  it('an argument typed by the calling method\'s own variable has that variable\'s supertypes', async () => {
    const idx = await indexOf(selfCalls);
    // `t` is a T, which is an Object and not a String.
    expect(callers(idx, 'app.Copy.pick(Object)')).toEqual(['Copy.java:7']);
    expect(callers(idx, 'app.Copy.pick(String)')).toEqual([]);
  });

  it('overloads differing only in a bound are told apart by their erased signatures', async () => {
    const idx = await indexOf(selfCalls);
    const r = idx.resolveCallers({ symbol: 'app.Copy.copy' });
    expect(r.overloads?.map(o => o.signature)).toEqual(['(Consumer...)', '(Predicate...)']);
    expect(idx.resolveCallers({ symbol: 'app.Copy.copy(java.util.function.Predicate...)' }).note).toBeUndefined();
  });
});
