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
