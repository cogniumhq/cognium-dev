/**
 * Tests for JdbcTemplate query-family `safe_if_string_literal_at` gating.
 *
 * The Spring JdbcTemplate `query`, `queryForObject`, `queryForList`,
 * `queryForMap`, `queryForRowSet`, `update`, `execute` and `batchUpdate`
 * methods accept a compile-time SQL string literal at arg[0]. The `?`
 * placeholders in that literal are bound by the driver — the parameters
 * cannot be interpolated into the SQL string, so a literal SQL is not a
 * taint sink. Non-literal SQL (variable / concat / `String.format`)
 * remains a sink.
 *
 * Closes cognium-dev#233 (SQL family, JdbcTemplate).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';

async function sqlSinksFor(code: string) {
  const tree = await parse(code, 'java');
  const calls = extractCalls(tree);
  const types = extractTypes(tree);
  const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');
  return taint.sinks.filter((s) => s.type === 'sql_injection');
}

describe('JdbcTemplate safe_if_string_literal_at (#233)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('JdbcTemplate.query("SELECT * FROM u WHERE id = ?", rm, id) is NOT a sink', async () => {
    const code = `
public class Svc {
  public void run(JdbcTemplate jdbc, RowMapper rm, long id) {
    jdbc.query("SELECT * FROM users WHERE id = ?", rm, id);
  }
}
`;
    const sinks = await sqlSinksFor(code);
    expect(sinks.find((s) => s.method === 'query')).toBeUndefined();
  });

  it('JdbcTemplate.query(variable) IS a sink (non-literal SQL)', async () => {
    const code = `
public class Svc {
  public void run(JdbcTemplate jdbc, RowMapper rm, String sql) {
    jdbc.query(sql, rm);
  }
}
`;
    const sinks = await sqlSinksFor(code);
    expect(sinks.find((s) => s.method === 'query')).toBeDefined();
  });

  it('JdbcTemplate.queryForObject("SELECT ... WHERE id=?", int.class, id) is NOT a sink', async () => {
    const code = `
public class Svc {
  public Integer run(JdbcTemplate jdbc, long id) {
    return jdbc.queryForObject("SELECT age FROM users WHERE id=?", Integer.class, id);
  }
}
`;
    const sinks = await sqlSinksFor(code);
    expect(sinks.find((s) => s.method === 'queryForObject')).toBeUndefined();
  });

  it('JdbcTemplate.update(String.format(...)) IS a sink (format is not a literal)', async () => {
    const code = `
public class Svc {
  public void run(JdbcTemplate jdbc, String uid) {
    jdbc.update(String.format("DELETE FROM users WHERE id=%s", uid));
  }
}
`;
    const sinks = await sqlSinksFor(code);
    expect(sinks.find((s) => s.method === 'update')).toBeDefined();
  });

  it('JdbcTemplate.batchUpdate("UPDATE u SET n=? WHERE id=?", args) is NOT a sink', async () => {
    const code = `
public class Svc {
  public void run(JdbcTemplate jdbc, java.util.List<Object[]> args) {
    jdbc.batchUpdate("UPDATE users SET name=? WHERE id=?", args);
  }
}
`;
    const sinks = await sqlSinksFor(code);
    expect(sinks.find((s) => s.method === 'batchUpdate')).toBeUndefined();
  });

  it('Statement.executeQuery("SELECT 1") IS still a sink (no safe gate on Statement)', async () => {
    const code = `
public class Svc {
  public void run(java.sql.Statement stmt) throws Exception {
    stmt.executeQuery("SELECT 1 FROM DUAL");
  }
}
`;
    const sinks = await sqlSinksFor(code);
    // Statement.executeQuery has no safe_if_string_literal_at — literal or not,
    // it is emitted; only downstream taint filtering decides finding severity.
    expect(sinks.find((s) => s.method === 'executeQuery')).toBeDefined();
  });
});
