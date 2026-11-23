/**
 * cognium-dev#1195 — `foreignTypeOf` qualifies implicit `java.lang` receivers on external sites.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { buildJavaGraph } from '../../src/navigation/index.js';

const file = (path: string, code: string) => ({ path, code });

describe('cognium-dev#1195 — foreignTypeOf java.lang qualification', () => {
  beforeAll(async () => {
    await import('../../src/analyzer.js').then((m) => m.initAnalyzer());
  });

  it('reports java.lang.String and java.lang.Object on external JDK instance calls', async () => {
    const g = await buildJavaGraph([
      file(
        'src/app/UseJdk.java',
        [
          'package app;',
          'public class UseJdk {',
          '  void m(String s, Object o) {',
          '    s.substring(0);',
          '    o.toString();',
          '  }',
          '}',
          '',
        ].join('\n'),
      ),
    ]);

    const receivers = g.unresolved
      .filter((u) => u.site.file === 'src/app/UseJdk.java' && u.reason === 'external')
      .map((u) => `${u.methodName}:${u.receiver ?? ''}`)
      .sort();

    expect(receivers).toEqual(['substring:java.lang.String', 'toString:java.lang.Object']);
  });
});
