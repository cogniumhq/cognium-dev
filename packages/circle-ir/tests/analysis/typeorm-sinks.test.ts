/**
 * TypeORM QueryBuilder raw-fragment sink coverage (framework-coverage expansion).
 *
 * TypeORM's QueryBuilder exposes `andWhere` / `orWhere` / `andHaving` /
 * `orHaving`, each taking a raw SQL fragment. Concatenating user input into
 * that fragment is CWE-89. The pattern is classless + JS/TS-scoped: the names
 * are TypeORM-idiomatic, and the chained-builder receiver
 * (`repo.createQueryBuilder('u').andWhere(...)`) is a factory call rather than
 * a class-named variable, so class matching cannot reach it.
 *
 * Precision is inherent to the taint flow, not the pattern: parameterised use
 * (`:name` placeholders + a params object) keeps input out of the string
 * literal, so a flow fires only on concatenation.
 *
 * TypeORM's raw `.query(sql)` escape hatch is intentionally NOT re-registered
 * here — the classless `query` sink in the JS plugin already covers it. The
 * first test locks that pre-existing coverage; the rest exercise the new
 * fragment sinks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('TypeORM raw-SQL sinks (CWE-89)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sqlFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection');

  it('raw .query() with concatenated input flows (pre-existing coverage lock)', async () => {
    const code = [
      'app.get("/u", (req, res) => {',
      '  const id = req.params.id;',
      '  dataSource.query("SELECT * FROM users WHERE id = " + id);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'server.ts', 'typescript');
    expect(sqlFlows(r).length).toBeGreaterThan(0);
  });

  it('chained createQueryBuilder().andWhere(raw) flows', async () => {
    const code = [
      'app.get("/u", (req, res) => {',
      '  const name = req.query.name;',
      '  userRepository',
      '    .createQueryBuilder("u")',
      '    .andWhere("u.name = \'" + name + "\'")',
      '    .getMany();',
      '});',
    ].join('\n');
    const r = await analyze(code, 'server.ts', 'typescript');
    expect(r.taint.sinks.some((s) => s.method === 'andWhere' && s.type === 'sql_injection')).toBe(true);
    expect(sqlFlows(r).length).toBeGreaterThan(0);
  });

  it('orHaving(raw) flows', async () => {
    const code = [
      'app.get("/u", (req, res) => {',
      '  const min = req.query.min;',
      '  qb.orHaving("SUM(u.credits) > " + min);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'server.ts', 'typescript');
    expect(sqlFlows(r).length).toBeGreaterThan(0);
  });

  it('parameterised andWhere (:name placeholder) does NOT flow', async () => {
    const code = [
      'app.get("/u", (req, res) => {',
      '  const name = req.query.name;',
      '  userRepository',
      '    .createQueryBuilder("u")',
      '    .andWhere("u.name = :name", { name })',
      '    .getMany();',
      '});',
    ].join('\n');
    const r = await analyze(code, 'server.ts', 'typescript');
    // The SQL string is a constant literal; user input reaches the sink only
    // through the params object, which parameterisation neutralises.
    expect(sqlFlows(r).length).toBe(0);
  });

  it('the fragment sinks are JS/TS-scoped — a Java andWhere is unaffected', async () => {
    const code = [
      'public class Svc {',
      '  void run(String name) {',
      '    qb.andWhere("u.name = \'" + name + "\'");',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Svc.java', 'java');
    expect(sqlFlows(r).length).toBe(0);
  });
});
