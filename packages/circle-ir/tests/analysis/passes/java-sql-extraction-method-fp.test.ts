/**
 * Sprint 47 — cognium-dev #177.
 *
 * Java `sql_injection` (CWE-89) fires inside SQL-codegen utility methods
 * whose signature shape is "AST/builder type in, String out": methods like
 * `getInsertSql(Insert stmt)`, `toSqlInsert(InsertStatement stmt)`, or
 * `extractQueryString(QueryAST ast)`. These methods *generate* SQL from
 * a parsed builder/AST input — they don't execute user-supplied SQL.
 *
 * Stage 14 in `sink-filter-pass.ts` suppresses `sql_injection` sinks when
 * the enclosing method (looked up from `ir.types[].methods[]` by line
 * range) satisfies all three:
 *   1. return type ∈ {String, CharSequence, Optional<String>}
 *   2. method name matches `^get*Sql*` / `^extract*Sql*` / `^to*Sql*` /
 *      `*Statement*ToString$` / `*Query*String$`
 *   3. the *primary* parameter type is NOT `String`/`CharSequence` (i.e.
 *      input is a builder/AST/Statement type)
 *
 * Recall: real `executeQuery(String tainted)` and string-in/string-out
 * helpers remain unsuppressed.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const sqlInjectionSinks = (
  arr: Array<{ type?: string; line?: number; method?: string }> | undefined,
) => (arr ?? []).filter((s) => s.type === 'sql_injection');

describe('cognium-dev #177 — SQL extraction codegen methods', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP — getInsertSql(InsertStatement stmt): String — suppressed
  // --------------------------------------------------------------------------
  it('getInsertSql(InsertStatement) returns String — no sql_injection sink', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
public class Codegen {
  public String getInsertSql(InsertStatement stmt, Connection conn) throws Exception {
    String sql = "INSERT INTO " + stmt.tableName() + " VALUES (" + stmt.values() + ")";
    Statement st = conn.createStatement();
    st.executeQuery(sql);
    return sql;
  }
}`;
    const r = await analyze(code, 'Codegen.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 2. FP — toSqlSelect(Select ast): String — suppressed
  // --------------------------------------------------------------------------
  it('toSqlSelect(Select) returns String — no sql_injection sink', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
public class Renderer {
  public String toSqlSelect(Select ast, Connection conn) throws Exception {
    String sql = "SELECT " + ast.columns() + " FROM " + ast.from();
    Statement st = conn.createStatement();
    st.executeQuery(sql);
    return sql;
  }
}`;
    const r = await analyze(code, 'Renderer.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 3. FP — extractQueryString(QueryAST ast): String — suppressed
  // --------------------------------------------------------------------------
  it('extractSqlString(QueryAST) returns String — no sql_injection sink', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
public class Extractor {
  public String extractSqlString(QueryAST ast, Connection conn) throws Exception {
    String sql = "SELECT " + ast.body();
    Statement st = conn.createStatement();
    st.executeQuery(sql);
    return sql;
  }
}`;
    const r = await analyze(code, 'Extractor.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 4. Recall — same shape but FIRST param IS String — gate fails, sink fires.
  // --------------------------------------------------------------------------
  it('recall: getInsertSql(String tainted) — sink still fires (String input fails gate)', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
public class BadCodegen {
  public String getInsertSql(String tableName, Connection conn) throws Exception {
    String sql = "INSERT INTO " + tableName + " VALUES (1)";
    Statement st = conn.createStatement();
    st.executeQuery(sql);
    return sql;
  }
  public void run(HttpServletRequest req, Connection conn) throws Exception {
    String name = req.getParameter("tbl");
    getInsertSql(name, conn);
  }
}`;
    const r = await analyze(code, 'BadCodegen.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 5. Recall — same name shape but return type is `void` — gate fails, fires.
  // --------------------------------------------------------------------------
  it('recall: runUnsafe (no SQL-extract name, returns void) — sink still fires', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
public class Runner {
  public void runUnsafe(HttpServletRequest req, Connection conn) throws Exception {
    String name = req.getParameter("name");
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement st = conn.createStatement();
    st.executeQuery(sql);
  }
}`;
    const r = await analyze(code, 'Runner.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 6. Recall — extract* method name but String → String shape — fires
  // --------------------------------------------------------------------------
  it('recall: extractQueryString(String tainted) — sink still fires (String input fails gate)', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
public class Bad {
  public String extractQueryString(String userInput, Connection conn) throws Exception {
    String sql = "SELECT * FROM t WHERE col = '" + userInput + "'";
    Statement st = conn.createStatement();
    st.executeQuery(sql);
    return sql;
  }
  public void caller(HttpServletRequest req, Connection conn) throws Exception {
    extractQueryString(req.getParameter("x"), conn);
  }
}`;
    const r = await analyze(code, 'Bad.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });
});
