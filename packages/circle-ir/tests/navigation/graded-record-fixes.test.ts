/**
 * The two resolver bugs the first graded record found.
 *
 * Both are contract failures, not coverage gaps — they are the two things a
 * record can catch that a unit test written by the author of the code will
 * not, because each is a case where the answer was *confident* and wrong
 * rather than missing.
 *
 *   1. `:denominator-stated` — the answer reported four languages searched
 *      while resolving one. A count is not a result without the set it was
 *      measured over, and naming a language this index cannot resolve makes
 *      the set a fiction.
 *   2. `:inferred-labelled` — an implicit-receiver call to a body-less
 *      abstract member was labelled `exact`. Phase 2 required a body for an
 *      `exact` answer, but only on the path where a receiver was written; a
 *      call with no receiver at all skipped the check entirely.
 *
 * Written before the fixes, and both failed when written.
 */

import { describe, it, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { buildNavigationIndex, type NavigationIndex } from '../../src/navigation/index.js';
import type { SupportedLanguage } from '../../src/core/parser.js';

async function indexOf(
  files: Record<string, [SupportedLanguage, string]>,
  opts: Parameters<typeof buildNavigationIndex>[1] = {},
): Promise<NavigationIndex> {
  await initAnalyzer();
  const entries = [];
  for (const [path, [language, source]] of Object.entries(files)) {
    entries.push({
      path,
      language,
      source,
      ir: await analyze(source, path, language, { navigationTypes: true }),
    });
  }
  return buildNavigationIndex(entries, opts);
}

const JAVA_ONLY = {
  'app/A.java': ['java', `package app;
public class A { public String go() { return "a"; } }`],
  'app/B.java': ['java', `package app;
public class B { String call() { A a = new A(); return a.go(); } }`],
} as Record<string, [SupportedLanguage, string]>;

const MIXED = {
  ...JAVA_ONLY,
  'web/app.ts': ['typescript', `export function hello(n: string) { return greet(n); }
function greet(n: string) { return "hi " + n; }`],
  'web/util.js': ['javascript', `function helper() { return 1; }  helper();`],
  'tools/run.py': ['python', `def main():
    return helper()
def helper():
    return 2`],
} as Record<string, [SupportedLanguage, string]>;

describe('denominator-stated — the scope names only what was searched', () => {
  it('reports one language, not every language handed to it', async () => {
    const idx = await indexOf(MIXED);
    const a = idx.resolveCallers({ symbol: 'app.A.go' });

    // Four languages were handed in; one is resolved. Saying four were
    // searched is the deviation.
    expect(a.scope.searched.languages).toEqual(['java']);
  });

  it('counts only the files it can actually answer about', async () => {
    const idx = await indexOf(MIXED);
    const a = idx.resolveCallers({ symbol: 'app.A.go' });

    // Two of the five files are Java. A caller dividing answers by files
    // searched is entitled to a denominator that can produce answers.
    expect(a.scope.searched.files).toBe(2);
  });

  it('declines the other languages by name, with the vocabulary reason', async () => {
    const idx = await indexOf(MIXED);
    const a = idx.resolveCallers({ symbol: 'app.A.go' });

    const declined = a.scope.excluded.filter((e) => e.reason.startsWith('unsupported-language'));
    expect(declined.map((e) => e.pattern).sort()).toEqual(['javascript', 'python', 'typescript']);
    for (const e of declined) expect(e.reason).toContain('java');
  });

  it('says nothing about other languages when it was given none', async () => {
    const idx = await indexOf(JAVA_ONLY);
    const a = idx.resolveCallers({ symbol: 'app.A.go' });

    expect(a.scope.searched).toEqual({ files: 2, languages: ['java'] });
    expect(a.scope.excluded.filter((e) => e.reason.startsWith('unsupported-language'))).toEqual([]);
  });

  it('keeps a caller-supplied exclusion alongside the declined languages', async () => {
    const idx = await indexOf(MIXED, {
      excluded: [{ pattern: '**/generated/**', reason: 'build output' }],
    });
    const a = idx.resolveCallers({ symbol: 'app.A.go' });

    expect(a.scope.excluded).toEqual(
      expect.arrayContaining([{ pattern: '**/generated/**', reason: 'build output' }]),
    );
    expect(a.scope.excluded.length).toBe(4);
  });

  it('does not answer, or claim to have searched, inside a declined language', async () => {
    const idx = await indexOf(MIXED);
    // `greet` is declared and called in the TypeScript file. The index must
    // not bind it — answering about a language it declined would make the
    // decline a lie in the other direction.
    const a = idx.resolveCallers({ symbol: 'greet' });
    expect(a.answers).toHaveLength(0);
  });
});

describe('inferred-labelled — a body is required on every path to `exact`', () => {
  // The shape the record found: an abstract class calling its own abstract
  // member with no receiver written. What runs is a subclass's body, never
  // the member named here.
  const LESSON = {
    'app/Lesson.java': ['java', `package app;
public abstract class Lesson {
  public abstract String getTitle();
  public String describe() { return "lesson: " + getTitle(); }
}`],
    'app/Real.java': ['java', `package app;
public class Real extends Lesson { public String getTitle() { return "r"; } }`],
  } as Record<string, [SupportedLanguage, string]>;

  it('an implicit-receiver call to an abstract member is not exact', async () => {
    const idx = await indexOf(LESSON);
    const a = idx.resolveCallers({ symbol: 'app.Lesson.getTitle' });

    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].target).toBe('app.Lesson.getTitle');
    expect(a.answers[0].tier).toBe('polymorphic');
    expect(a.answers[0].candidates).toEqual(['app.Real.getTitle']);
  });

  it('a `this.`-receiver call to an abstract member is not exact either', async () => {
    const idx = await indexOf({
      'app/Lesson.java': ['java', `package app;
public abstract class Lesson {
  public abstract String getTitle();
  public String describe() { return "lesson: " + this.getTitle(); }
}`],
      'app/Real.java': LESSON['app/Real.java'],
    } as Record<string, [SupportedLanguage, string]>);
    const a = idx.resolveCallers({ symbol: 'app.Lesson.getTitle' });

    expect(a.answers[0].tier).toBe('polymorphic');
  });

  it('an implicit-receiver call to a member WITH a body is still exact', async () => {
    const idx = await indexOf({
      'app/Solo.java': ['java', `package app;
public class Solo {
  String helper() { return "h"; }
  String go() { return helper(); }
}`],
    } as Record<string, [SupportedLanguage, string]>);
    const a = idx.resolveCallers({ symbol: 'app.Solo.helper' });

    expect(a.answers).toHaveLength(1);
    expect(a.answers[0].tier).toBe('exact');
  });

  it('a statically imported member that is abstract is not exact', async () => {
    // The third path to a target with no receiver written: a static import.
    // An interface member reached that way has no body either.
    const idx = await indexOf({
      'app/Spec.java': ['java', `package app;
public interface Spec { String shape(); }`],
      'app/Client.java': ['java', `package app;
public class Client {
  String go(Spec s) { return s.shape(); }
}`],
    } as Record<string, [SupportedLanguage, string]>);
    const a = idx.resolveCallers({ symbol: 'app.Spec.shape' });

    expect(a.answers[0].tier).toBe('polymorphic');
    expect(a.answers[0].candidates).toEqual([]);
  });
});
