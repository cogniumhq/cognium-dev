/**
 * Sprint 45 — cognium-dev #157.
 *
 * `sql_injection` (CWE-89) sink reported on a `throw new SQLException(...)`
 * line. A `throw` statement is structurally never a runtime sink — it
 * constructs the exception object then unwinds the stack. No SQL, no
 * command exec, no XSS, no path I/O happens.
 *
 * Stage 12 in `sink-filter-pass.ts` drops any sink whose own line matches
 * `^\s*throw\s+new\s+\w+(?:Exception|Error)\b`. Sink-type-agnostic; a
 * real sink on any other line of the same method continues to fire.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countByType = (
  arr: Array<{ type?: string; line?: number }> | undefined,
  t: string,
) => (arr ?? []).filter((s) => s.type === t).length;

const sinksByTypeAtLine = (
  arr: Array<{ type?: string; line?: number }> | undefined,
  t: string,
  line: number,
) => (arr ?? []).filter((s) => s.type === t && s.line === line).length;

const anySinkAtLine = (
  arr: Array<{ line?: number }> | undefined,
  line: number,
) => (arr ?? []).filter((s) => s.line === line).length;

describe('cognium-dev #157 — throw-statement is never a runtime sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP #157 — standalone `throw new SQLException(...)` line
  // --------------------------------------------------------------------------
  it('throw new SQLException("Empty where provided!") — no sql_injection sink on throw line', async () => {
    const code = `import java.sql.SQLException;

public class DialectRunner {
  public int update(String where) throws SQLException {
    if (where == null || where.isEmpty()) {
      throw new SQLException("Empty where provided!");
    }
    return 0;
  }
}
`;
    const r = await analyze(code, 'DialectRunner.java', 'java');
    // Throw is on line 6 (1-based after the import block).
    expect(sinksByTypeAtLine(r.taint?.sinks, 'sql_injection', 6)).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 2. FP (general) — `throw new IOException(...)` line
  // --------------------------------------------------------------------------
  it('throw new IOException("bad path") — no path_traversal sink on throw line', async () => {
    const code = `import java.io.IOException;

public class Loader {
  public void load(String path) throws IOException {
    if (path == null) {
      throw new IOException("bad path");
    }
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(sinksByTypeAtLine(r.taint?.sinks, 'path_traversal', 6)).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 3. FP (general) — `throw new RuntimeException(...)` line, no sinks at all
  // --------------------------------------------------------------------------
  it('throw new RuntimeException(msg) — no sinks of any type on throw line', async () => {
    const code = `public class Util {
  public void check(String msg) {
    if (msg == null) {
      throw new RuntimeException("bad");
    }
  }
}
`;
    const r = await analyze(code, 'Util.java', 'java');
    expect(anySinkAtLine(r.taint?.sinks, 4)).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 4. Recall — real `stmt.execute(tainted)` line still fires even when a
  //             `throw new SQLException(...)` lives elsewhere in same method
  // --------------------------------------------------------------------------
  it('recall: real stmt.execute(tainted) still fires alongside throw', async () => {
    const code = `import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Repo {
  public void run(Connection conn, HttpServletRequest req) throws SQLException {
    String name = req.getParameter("name");
    if (name == null) {
      throw new SQLException("name required");
    }
    Statement stmt = conn.createStatement();
    stmt.execute("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
`;
    const r = await analyze(code, 'Repo.java', 'java');
    // At least one sql_injection sink overall (on the execute line).
    expect(countByType(r.taint?.sinks, 'sql_injection')).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 5. Mixed (DialectRunner-shape) — sink appears on executeQuery line,
  //                                  NOT on throw line
  // --------------------------------------------------------------------------
  it('mixed: sink reported on executeQuery line, not on throw line', async () => {
    const code = `import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class DialectRunner {
  public void run(Connection conn, HttpServletRequest req) throws SQLException {
    String sql = req.getParameter("sql");
    if (sql == null) {
      throw new SQLException("Empty sql provided!");
    }
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
  }
}
`;
    const r = await analyze(code, 'DialectRunner.java', 'java');
    // Throw line (10) — 0 sql_injection sinks.
    expect(sinksByTypeAtLine(r.taint?.sinks, 'sql_injection', 10)).toBe(0);
    // executeQuery line (13) — at least 1 sql_injection sink expected.
    expect(sinksByTypeAtLine(r.taint?.sinks, 'sql_injection', 13)).toBeGreaterThanOrEqual(1);
  });
});
