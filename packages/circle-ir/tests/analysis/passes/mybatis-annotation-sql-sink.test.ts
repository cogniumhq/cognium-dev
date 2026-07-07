/**
 * cognium-dev #241 Java — MyBatis annotation-string SQL injection.
 *
 * Verifies that `MyBatisAnnotationSqlSinkPass` (3.156.0) emits synthetic
 * `sql_injection` sinks on Mapper interface method call sites when the
 * mapper method's `@Select` / `@Update` / `@Insert` / `@Delete` annotation
 * contains raw `${varname}` interpolation. `#{name}` binding is safe and
 * must NOT produce a sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countSqlSinks = (r: any) =>
  ((r.taint?.sinks ?? []) as any[]).filter(
    (s) => s.type === 'sql_injection',
  ).length;

const hasSqlSinkAtLine = (r: any, line: number) =>
  ((r.taint?.sinks ?? []) as any[]).some(
    (s) => s.type === 'sql_injection' && s.line === line,
  );

describe('#241 Java — MyBatis @Select/@Update/... ${} SQLi sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const mapperImports = [
    'package com.example;',
    'import org.apache.ibatis.annotations.Select;',
    'import org.apache.ibatis.annotations.Update;',
    'import org.apache.ibatis.annotations.Insert;',
    'import org.apache.ibatis.annotations.Delete;',
    'import org.apache.ibatis.annotations.SelectProvider;',
    'import org.apache.ibatis.annotations.Param;',
  ].join('\n');

  it('TP — @Select with ${name} and @Param("name") fires sql_injection at call site', async () => {
    const mapperCode = [
      mapperImports,
      'public interface UserMapper {',
      '  @Select("SELECT * FROM users WHERE name = \'${name}\'")',
      '  Object findByName(@Param("name") String name);',
      '}',
      'class Caller {',
      '  Object doIt(UserMapper mapper, String userInput) {',
      '    return mapper.findByName(userInput);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(mapperCode, 'UserMapper.java', 'java');
    expect(countSqlSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('TP — @Update with ${id} + @Param("id") fires sql_injection at call site', async () => {
    const code = [
      mapperImports,
      'public interface RoleMapper {',
      '  @Update("UPDATE users SET role = ? WHERE id = ${id}")',
      '  int updateRole(@Param("id") long id, @Param("role") String role);',
      '}',
      'class Caller {',
      '  int run(RoleMapper mapper, long id, String role) {',
      '    return mapper.updateRole(id, role);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'RoleMapper.java', 'java');
    expect(countSqlSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('TP — mixed #{safe} and ${bad}: sink emitted on ${bad} arg only', async () => {
    const code = [
      mapperImports,
      'public interface MixedMapper {',
      '  @Select("SELECT * FROM t WHERE a = #{safe} AND b = \'${bad}\'")',
      '  Object findMixed(@Param("safe") String safe, @Param("bad") String bad);',
      '}',
      'class Caller {',
      '  Object run(MixedMapper mapper, String s, String b) {',
      '    return mapper.findMixed(s, b);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'MixedMapper.java', 'java');
    expect(countSqlSinks(r)).toBeGreaterThanOrEqual(1);
    // The synthetic sink argPositions should target the `bad` param (index 1)
    const sqlSinks = ((r.taint?.sinks ?? []) as any[]).filter(
      (s) => s.type === 'sql_injection',
    );
    const argPositions = sqlSinks.flatMap((s) => s.argPositions ?? []);
    expect(argPositions).toContain(1);
    expect(argPositions).not.toContain(0);
  });

  it('TP — positional ${param1} (no @Param) targets first arg', async () => {
    const code = [
      mapperImports,
      'public interface PosMapper {',
      '  @Select("SELECT * FROM t WHERE x = \'${param1}\'")',
      '  Object findPositional(String x);',
      '}',
      'class Caller {',
      '  Object run(PosMapper mapper, String s) { return mapper.findPositional(s); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'PosMapper.java', 'java');
    expect(countSqlSinks(r)).toBeGreaterThanOrEqual(1);
    const sqlSinks = ((r.taint?.sinks ?? []) as any[]).filter(
      (s) => s.type === 'sql_injection',
    );
    const argPositions = sqlSinks.flatMap((s) => s.argPositions ?? []);
    expect(argPositions).toContain(0);
  });

  it('TP — multiple ${x} refs to same param collapse to a single arg position', async () => {
    const code = [
      mapperImports,
      'public interface DupMapper {',
      '  @Select("SELECT * FROM t WHERE a = \'${x}\' OR b = \'${x}\'")',
      '  Object findDup(@Param("x") String x);',
      '}',
      'class Caller {',
      '  Object run(DupMapper mapper, String s) { return mapper.findDup(s); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'DupMapper.java', 'java');
    const sqlSinks = ((r.taint?.sinks ?? []) as any[]).filter(
      (s) => s.type === 'sql_injection',
    );
    expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    // Each sink's argPositions must contain 0 exactly once (no duplication).
    for (const s of sqlSinks) {
      const zeroCount = (s.argPositions ?? []).filter(
        (p: number) => p === 0,
      ).length;
      expect(zeroCount).toBeLessThanOrEqual(1);
    }
  });

  it('TP — @Delete with ${id} and @Param("id")', async () => {
    const code = [
      mapperImports,
      'public interface DelMapper {',
      '  @Delete("DELETE FROM users WHERE id = ${id}")',
      '  int deleteUser(@Param("id") long id);',
      '}',
      'class Caller {',
      '  int run(DelMapper mapper, long i) { return mapper.deleteUser(i); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'DelMapper.java', 'java');
    expect(countSqlSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN — @Select with only #{name} binding: no sink emitted', async () => {
    const code = [
      mapperImports,
      'public interface SafeMapper {',
      '  @Select("SELECT * FROM t WHERE name = #{name}")',
      '  Object findSafe(@Param("name") String name);',
      '}',
      'class Caller {',
      '  Object run(SafeMapper mapper, String s) { return mapper.findSafe(s); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'SafeMapper.java', 'java');
    // The pass must not add any synthetic sql_injection sink. Other passes
    // (mybatis_mapper_call discovery marker) are not `sql_injection` so
    // countSqlSinks stays 0.
    const sqlSinks = ((r.taint?.sinks ?? []) as any[]).filter(
      (s) => s.type === 'sql_injection' && s.method === 'findSafe',
    );
    expect(sqlSinks.length).toBe(0);
  });

  it('TN — non-MyBatis @Select annotation (no MyBatis import): no sink', async () => {
    const code = [
      'package com.example;',
      // NOT a MyBatis import — some other library's @Select.
      'import io.reactor.core.publisher.Select;',
      'public interface FakeMapper {',
      '  @Select("SELECT * FROM t WHERE name = \'${name}\'")',
      '  Object findByName(String name);',
      '}',
      'class Caller {',
      '  Object run(FakeMapper mapper, String s) { return mapper.findByName(s); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'FakeMapper.java', 'java');
    const sqlSinks = ((r.taint?.sinks ?? []) as any[]).filter(
      (s) => s.type === 'sql_injection' && s.method === 'findByName',
    );
    expect(sqlSinks.length).toBe(0);
  });

  it('TN — non-Java file: pass short-circuits (no MyBatis semantics elsewhere)', async () => {
    // No .java file → the pass returns { annotatedMethodCount: 0,
    // addedSinkCount: 0 } without inspecting types. Regressed on any
    // language other than Java, this test would either throw or produce
    // spurious sinks.
    const py = 'def f():\n    return 1\n';
    const r = await analyze(py, 'f.py', 'python');
    const mybatisSinks = ((r.taint?.sinks ?? []) as any[]).filter(
      (s) => s.class && /Mapper/.test(s.class),
    );
    expect(mybatisSinks.length).toBe(0);
  });

  it('recall — @Insert with ${table} (identifier interpolation) fires', async () => {
    const code = [
      mapperImports,
      'public interface DynTableMapper {',
      '  @Insert("INSERT INTO ${table} (name) VALUES (\'x\')")',
      '  int insertRow(@Param("table") String table);',
      '}',
      'class Caller {',
      '  int run(DynTableMapper mapper, String t) { return mapper.insertRow(t); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'DynTableMapper.java', 'java');
    expect(countSqlSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('kill switch — disabledPasses:["mybatis-annotation-sql-sink"] suppresses sinks', async () => {
    const code = [
      mapperImports,
      'public interface UserMapper {',
      '  @Select("SELECT * FROM users WHERE name = \'${name}\'")',
      '  Object findByName(@Param("name") String name);',
      '}',
      'class Caller {',
      '  Object doIt(UserMapper mapper, String s) { return mapper.findByName(s); }',
      '}',
    ].join('\n');
    // Baseline: fires with pass enabled.
    const rOn = await analyze(code, 'UserMapper.java', 'java');
    expect(countSqlSinks(rOn)).toBeGreaterThanOrEqual(1);
    // Kill switch: pass disabled → no synthetic `sql_injection` sink for
    // `findByName`. Other sinks (unrelated) may still fire.
    const rOff = await analyze(code, 'UserMapper.java', 'java', {
      disabledPasses: ['mybatis-annotation-sql-sink'],
    });
    const findByNameSinks = ((rOff.taint?.sinks ?? []) as any[]).filter(
      (s) => s.type === 'sql_injection' && s.method === 'findByName',
    );
    expect(findByNameSinks.length).toBe(0);
  });
});
