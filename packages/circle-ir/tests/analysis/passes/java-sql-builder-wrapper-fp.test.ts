/**
 * Sprint 47 — cognium-dev #163.
 *
 * Java `sql_injection` (CWE-89) fires inside SQL dialect / builder / quoter
 * classes whose entire purpose is to produce SQL fragments by concatenating
 * already-quoted identifiers. The quoting/wrapping itself is the
 * sanitization step — flagging the resulting concat as SQL injection is a
 * false positive at the SQL-builder library-API boundary.
 *
 * Stage 13 in `sink-filter-pass.ts` suppresses `sql_injection` sinks when:
 *   - the enclosing class name matches
 *     `*Dialect`/`*SqlBuilder`/`*Quoter`/`*Wrapper`/`*SqlGenerator`/`*QueryBuilder`, AND
 *   - a `.wrap(`/`.quote(`/`.escape(`/`.identifier(` wrapper call appears
 *     within ±10 lines of the sink.
 *
 * Recall: real `sql_injection` sinks in business classes (e.g.
 * `UserService.findByName`) remain unaffected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const sqlInjectionSinks = (
  arr: Array<{ type?: string; line?: number; method?: string }> | undefined,
) => (arr ?? []).filter((s) => s.type === 'sql_injection');

describe('cognium-dev #163 — SQL builder/dialect wrapper output', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP — PostgresDialect uses quoter.wrap(col) into concat — suppressed
  // --------------------------------------------------------------------------
  it('PostgresDialect.build with quoter.wrap(col) concat — no sql_injection sink', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
public class PostgresDialect {
  public void build(Connection conn, String col, Quoter quoter) throws Exception {
    String quoted = quoter.wrap(col);
    String sql = "SELECT " + quoted + " FROM t";
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;
    const r = await analyze(code, 'PostgresDialect.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 2. FP — *SqlBuilder class with .quote() in concat — suppressed
  // --------------------------------------------------------------------------
  it('UserSqlBuilder.build with q.quote(name) concat — no sql_injection sink', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
public class UserSqlBuilder {
  public void build(Connection conn, String name, Quoter q) throws Exception {
    String safe = q.quote(name);
    String sql = "SELECT * FROM users WHERE name = " + safe;
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;
    const r = await analyze(code, 'UserSqlBuilder.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 3. FP — *Quoter class with .identifier() wrapper — suppressed
  // --------------------------------------------------------------------------
  it('IdentifierQuoter.escapeAndRun with .identifier() concat — no sql_injection sink', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
public class IdentifierQuoter {
  public void escapeAndRun(Connection conn, String tbl, Quoter q) throws Exception {
    String safe = q.identifier(tbl);
    String sql = "SELECT * FROM " + safe;
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;
    const r = await analyze(code, 'IdentifierQuoter.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 4. Recall — non-builder class with raw user input concat — fires
  // --------------------------------------------------------------------------
  it('recall: UserService.findByName with raw user input concat — fires', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
public class UserService {
  public void findByName(Connection conn, HttpServletRequest req) throws Exception {
    String name = req.getParameter("name");
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;
    const r = await analyze(code, 'UserService.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 5. Recall — class name matches *Dialect but NO wrapper call near sink — fires
  // --------------------------------------------------------------------------
  it('recall: *Dialect class with raw concat (no .wrap/.quote call) — still fires', async () => {
    const code = `
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
public class BadDialect {
  public void build(Connection conn, HttpServletRequest req) throws Exception {
    String name = req.getParameter("name");
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}`;
    const r = await analyze(code, 'BadDialect.java', 'java');
    expect(sqlInjectionSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });
});
