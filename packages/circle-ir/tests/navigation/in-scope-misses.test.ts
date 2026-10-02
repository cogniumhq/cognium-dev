/**
 * The four shapes where the target is inside the searched tree and the
 * resolver answers nothing.
 *
 * These come from an audit of every call site in a 405-file Java repository
 * that `CrossFileResolver.resolveCall` leaves unanswered: of 8,015 such sites,
 * 7,246 are genuinely outside the tree (JDK, framework, test library) and the
 * non-answer is correct. 455 are not — the target is declared in the tree and
 * the resolver fails to bind it — and they fall into exactly four shapes:
 *
 *   | shape                        | sites | why it fails today                      |
 *   |------------------------------|-------|-----------------------------------------|
 *   | a `record` receiver          |   182 | the Java extractor emits no type at all |
 *   | a chained / fluent receiver  |   161 | the receiver is an expression, not a name |
 *   | a project type's constructor |    89 | there is no constructor path            |
 *   | a nested type's static import|    23 | the import's FQN and the symbol's differ |
 *
 * Each test below is one shape, reduced to the smallest Java that reproduces
 * it. They are the measurement the navigation API's coverage is judged by, so
 * they assert the *tier* as well as the target: a name-only guess that happens
 * to hit the right method is not a pass.
 */

import { describe, it, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { buildNavigationIndex } from '../../src/navigation/index.js';
import type { NavigationIndex } from '../../src/navigation/index.js';

/** Analyze a set of in-memory Java files and build a navigation index over them. */
async function indexOf(files: Record<string, string>): Promise<NavigationIndex> {
  await initAnalyzer();
  const entries = [];
  for (const [path, source] of Object.entries(files)) {
    entries.push({
      path,
      language: 'java' as const,
      ir: await analyze(source, path, 'java', { navigationTypes: true }),
    });
  }
  return buildNavigationIndex(entries);
}

describe('navigation — a `record` receiver (182 of 455 in-scope misses)', () => {
  const files = {
    'app/Config.java': `package app;
public record Config(String host) {
  public String url(String path) { return host + path; }
}`,
    'app/Main.java': `package app;
public class Main {
  private final Config cfg = new Config("h");
  String go() { return cfg.url("/a"); }
}`,
  };

  it('finds the caller of a method declared on a record, at the exact tier', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallers({ symbol: 'app.Config.url' });

    expect(answer.answers).toHaveLength(1);
    expect(answer.answers[0].tier).toBe('exact');
    expect(answer.answers[0].target).toBe('app.Config.url');
    expect(answer.answers[0].site.file).toBe('app/Main.java');
    expect(answer.answers[0].site.line).toBe(4);
  });

  it('declares the record itself as searched, not excluded', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallers({ symbol: 'app.Config.url' });

    expect(answer.scope.searched.files).toBe(2);
    expect(answer.scope.searched.languages).toEqual(['java']);
    expect(answer.unresolved).toHaveLength(0);
  });
});

describe('navigation — a chained / fluent receiver (161 of 455)', () => {
  const files = {
    'app/Builder.java': `package app;
public class Builder {
  public static Builder of() { return new Builder(); }
  public Builder step(String s) { return this; }
  public String done() { return "x"; }
}`,
    'app/Use.java': `package app;
public class Use {
  String run() { return Builder.of().step("a").done(); }
}`,
  };

  it('types a receiver that is an expression, by walking the chain\'s return types', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallers({ symbol: 'app.Builder.done' });

    expect(answer.answers).toHaveLength(1);
    expect(answer.answers[0].tier).toBe('exact');
    expect(answer.answers[0].target).toBe('app.Builder.done');
    expect(answer.answers[0].site.file).toBe('app/Use.java');
  });

  it('carries the chain it walked as the answer\'s evidence', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallers({ symbol: 'app.Builder.done' });

    expect(answer.answers[0].evidence).toContain('Builder');
  });
});

describe('navigation — a project type\'s constructor (89 of 455)', () => {
  const files = {
    'app/Widget.java': `package app;
public class Widget {
  public Widget() {}
}`,
    'app/Factory.java': `package app;
public class Factory {
  Widget build() { return new Widget(); }
}`,
  };

  it('finds the `new` site as a caller of the constructor, at the exact tier', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallers({ symbol: 'app.Widget.<init>' });

    expect(answer.answers).toHaveLength(1);
    expect(answer.answers[0].tier).toBe('exact');
    expect(answer.answers[0].target).toBe('app.Widget.<init>');
    expect(answer.answers[0].site.file).toBe('app/Factory.java');
    expect(answer.answers[0].site.line).toBe(3);
  });

  it('reports the constructor among a method\'s callees', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallees({ symbol: 'app.Factory.build' });

    const targets = answer.answers.map(a => a.target);
    expect(targets).toContain('app.Widget.<init>');
  });
});

describe('navigation — a nested type\'s statically imported factory (23 of 455)', () => {
  const files = {
    'app/Outer.java': `package app;
public class Outer {
  public static class Inner {
    public static Inner make(String s) { return new Inner(); }
  }
}`,
    'app/Client.java': `package app;
import static app.Outer.Inner.make;
public class Client {
  Object go() { return make("x"); }
}`,
  };

  it('binds the static import to the nested type\'s method, at the exact tier', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallers({ symbol: 'app.Outer.Inner.make' });

    expect(answer.answers).toHaveLength(1);
    expect(answer.answers[0].tier).toBe('exact');
    expect(answer.answers[0].target).toBe('app.Outer.Inner.make');
    expect(answer.answers[0].site.file).toBe('app/Client.java');
  });

  it('gives the nested type an enclosing-qualified FQN', async () => {
    const idx = await indexOf(files);
    const answer = idx.resolveCallees({ symbol: 'app.Client.go' });

    expect(answer.answers.map(a => a.target)).toContain('app.Outer.Inner.make');
  });
});
