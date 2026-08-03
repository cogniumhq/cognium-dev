/**
 * Micronaut / Quarkus annotation source coverage (framework-coverage expansion).
 *
 * Micronaut reuses several Spring/JAX-RS annotation names (@Body, @Header,
 * @CookieValue, @PathVariable) already covered; these tests exercise the
 * framework-specific ones that were missing:
 *   - Micronaut: @QueryValue, @Part, @RequestBean
 *   - Quarkus / RESTEasy Reactive: @RestQuery, @RestPath, @RestHeader,
 *     @RestForm, @RestCookie, @RestMatrix
 *   - JAX-RS params the registry lacked: @CookieParam, @MatrixParam, @BeanParam
 *
 * IMPORTANT: assert on the *source type*, not merely on a flow existing. Any
 * Java method parameter that reaches a sink is already seeded as a low-
 * confidence `interprocedural_param` source, so a flow appears even for an
 * unrecognised annotation. The precise `http_*` source these annotations
 * produce is what proves the registration fired — the negative test pins that
 * distinction.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('Micronaut / Quarkus annotation sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = (annotation: string) =>
    [
      'public class UserController {',
      `  public void find(@${annotation} String name) throws Exception {`,
      '    Statement stmt = conn.createStatement();',
      '    stmt.executeQuery("SELECT * FROM users WHERE name = \'" + name + "\'");',
      '  }',
      '}',
    ].join('\n');

  // annotation -> the taint source type it must register
  const cases: Array<[string, string]> = [
    ['QueryValue', 'http_param'],
    ['Part', 'http_body'],
    ['RequestBean', 'http_body'],
    ['RestQuery', 'http_param'],
    ['RestPath', 'http_path'],
    ['RestHeader', 'http_header'],
    ['RestForm', 'http_param'],
    ['RestCookie', 'http_cookie'],
    ['RestMatrix', 'http_param'],
    ['CookieParam', 'http_cookie'],
    ['MatrixParam', 'http_param'],
    ['BeanParam', 'http_body'],
  ];

  for (const [ann, expectedType] of cases) {
    it(`@${ann} registers a ${expectedType} source (and flows to the SQL sink)`, async () => {
      const r = await analyze(controller(ann), 'UserController.java', 'java');
      expect(r.taint.sources.some((s) => s.type === expectedType)).toBe(true);
      expect((r.taint.flows ?? []).some((f) => f.sink_type === 'sql_injection')).toBe(true);
    });
  }

  it('an unrecognised annotation registers NO http_* source (only the interprocedural fallback)', async () => {
    const r = await analyze(controller('NotASourceAnno'), 'UserController.java', 'java');
    expect(r.taint.sources.some((s) => s.type.startsWith('http_'))).toBe(false);
    // The fallback still produces a flow — proving the http_* assertions above
    // are what distinguish the registered annotations, not flow existence.
    expect(r.taint.sources.some((s) => s.type === 'interprocedural_param')).toBe(true);
  });
});
