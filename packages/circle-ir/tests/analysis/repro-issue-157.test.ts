import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #157 (reopen v3.107.0) — Stage 12 throw-statement
 * suppression must NOT swallow a real sink that shares a line with
 * an earlier throw statement.
 *
 * Original 3.103.0 ship dropped sinks whose line matched
 *   /^\s*throw\s+new\s+\w+(?:Exception|Error)\b/
 * (no end-of-line anchor). That regex incorrectly matched a compound
 * line like
 *   throw new SQLException("x"); stmt.executeQuery(sql);
 * where the throw is the first statement but a real sink follows.
 *
 * Fix: anchor the regex to the end of the line — the throw must
 * terminate the line (only trailing whitespace or comment allowed).
 */
describe('cognium-dev #157 — Stage 12 throw suppression precision', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('compound line — throw followed by real sql sink must still fire', async () => {
    const code = `
package com.demo.libapi;

import java.sql.Statement;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

public class SqlExceptionUserTp {
    public void h(HttpServletRequest req, Statement stmt) throws SQLException {
        String user = req.getParameter("u");
        String sql = "SELECT * FROM users WHERE name='" + user + "'";
        if (user == null) throw new SQLException("null"); stmt.executeQuery(sql);
    }
}
`;
    const ir = await analyze(code, 'SqlExceptionUserTp.java', 'java');
    const sinks = (ir.taint.sinks ?? []).filter(
      s => s.type === 'sql_injection',
    );
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('pure throw line — Stage 12 still drops it', async () => {
    // Baseline: a line whose only statement is a throw of a known
    // Exception subclass must still be dropped as a non-sink.
    const code = `
package com.demo.libapi;

import java.sql.SQLException;

public class DialectRunner {
    public void run(String x) throws SQLException {
        throw new SQLException("bad dialect: " + x);
    }
}
`;
    const ir = await analyze(code, 'DialectRunner.java', 'java');
    const sinks = (ir.taint.sinks ?? []).filter(
      s => s.type === 'sql_injection',
    );
    expect(sinks.length).toBe(0);
  });

  it('throw with trailing comment — Stage 12 still drops it', async () => {
    const code = `
package com.demo.libapi;

import java.sql.SQLException;

public class DialectRunnerC {
    public void run(String x) throws SQLException {
        throw new SQLException("bad: " + x); // fatal
    }
}
`;
    const ir = await analyze(code, 'DialectRunnerC.java', 'java');
    const sinks = (ir.taint.sinks ?? []).filter(
      s => s.type === 'sql_injection',
    );
    expect(sinks.length).toBe(0);
  });

  it('throw then sql sink on next line — real sink still fires', async () => {
    // Multi-line variant: throw on one line, executeQuery on the
    // next. The Stage 12 gate is per-line, so this shape has always
    // been safe. Locked as a recall guard.
    const code = `
package com.demo.libapi;

import java.sql.Statement;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

public class MultilineThrowSql {
    public void h(HttpServletRequest req, Statement stmt) throws SQLException {
        String user = req.getParameter("u");
        String sql = "SELECT * FROM users WHERE name='" + user + "'";
        if (user == null) {
            throw new SQLException("null user");
        }
        stmt.executeQuery(sql);
    }
}
`;
    const ir = await analyze(code, 'MultilineThrowSql.java', 'java');
    const sinks = (ir.taint.sinks ?? []).filter(
      s => s.type === 'sql_injection',
    );
    expect(sinks.length).toBeGreaterThan(0);
  });
});
