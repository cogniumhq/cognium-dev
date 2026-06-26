/**
 * Tests for cognium-dev #191 / FP-77 — Java `sql_injection` (CWE-89)
 * FP suppression on regex-allowlist-quoter wrappers (Stage 15 in
 * `sink-filter-pass.ts`).
 *
 * Generalises Stage 13 (#163): Stage 13 only suppressed inside
 * `*Dialect` / `*SqlBuilder` / `*Quoter` / `*QueryBuilder` classes.
 * Stage 15 drops the class-name gate and instead recognises the
 * pattern: SQL string assembled from string literals + in-file
 * method calls (no bare-variable concat) WITH a `?` placeholder
 * for value binding AND at least one of the method calls invokes a
 * method whose body validates its argument via an inline
 * `String.matches("strict-anchored-regex")` + `throw` guard.
 *
 * Recall locks (bare-variable concat, no `?` placeholder, no
 * regex-allowlist guard) continue to fire `sql_injection`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countSqlSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'sql_injection').length;
const countSqlFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'sql_injection').length;

describe('cognium-dev #191 / FP-77 — Java sql_injection regex-allowlist-quoter FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP suppression — regex-allowlist quoter + `?` placeholder
  // -------------------------------------------------------------------------

  it('issue #191 / FP-77 repro — SafeSqlIdentifierQuote.run: no sql_injection sink/flow', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeSqlIdentifierQuote {
    private static String quoteIdent(String id) {
        if (!id.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("bad identifier: " + id);
        }
        return "\`" + id + "\`";
    }
    public ResultSet run(Connection conn, String col, String val) throws Exception {
        String sql = "SELECT * FROM users WHERE " + quoteIdent(col) + " = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, val);
        return ps.executeQuery();
    }
}
`;
    const r = await analyze(code, 'SafeSqlIdentifierQuote.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBe(0);
    expect(countSqlFlows(r.taint?.flows)).toBe(0);
  });

  it('FP — character-class regex `[A-Za-z][A-Za-z0-9]*` allowlist is recognised', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class IdentifierWrapper {
    private String safeName(String name) {
        if (!name.matches("[A-Za-z][A-Za-z0-9]*")) {
            throw new RuntimeException("invalid name");
        }
        return name;
    }
    public PreparedStatement build(Connection conn, String col, String val) throws Exception {
        String sql = "SELECT " + safeName(col) + " FROM t WHERE id = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, val);
        return ps;
    }
}
`;
    const r = await analyze(code, 'IdentifierWrapper.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP — multi-fragment SQL with two `?` placeholders + quoter call', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class TwoBindQuery {
    private static String quoteCol(String c) {
        if (!c.matches("[a-z_]+")) throw new IllegalArgumentException();
        return "\`" + c + "\`";
    }
    public PreparedStatement build(Connection conn, String col, String v1, String v2) throws Exception {
        String sql = "SELECT * FROM users WHERE " + quoteCol(col) + " = ? AND status = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, v1);
        ps.setString(2, v2);
        return ps;
    }
}
`;
    const r = await analyze(code, 'TwoBindQuery.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks — non-safe shapes continue to fire
  // -------------------------------------------------------------------------

  it('Recall — bare-variable concat (no quoter): sql_injection fires', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class UnsafeSql {
    public PreparedStatement run(Connection conn, String userInput) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
        return conn.prepareStatement(sql);
    }
}
`;
    const r = await analyze(code, 'UnsafeSql.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — quoter call but NO `?` placeholder (value also concatenated): fires', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class NoPlaceholder {
    private static String quoteIdent(String id) {
        if (!id.matches("[A-Za-z_]+")) throw new IllegalArgumentException();
        return id;
    }
    public PreparedStatement run(Connection conn, String col, String val) throws Exception {
        String sql = "SELECT * FROM users WHERE " + quoteIdent(col) + " = " + val;
        return conn.prepareStatement(sql);
    }
}
`;
    const r = await analyze(code, 'NoPlaceholder.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — wrapper method with NO regex-allowlist guard: fires', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class NoGuard {
    private static String quoteIdent(String id) { return "\`" + id + "\`"; }
    public PreparedStatement run(Connection conn, String col, String val) throws Exception {
        String sql = "SELECT * FROM users WHERE " + quoteIdent(col) + " = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, val);
        return ps;
    }
}
`;
    const r = await analyze(code, 'NoGuard.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — wrapper method with WILDCARD regex `.+` (not strict-anchored): fires', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class WildcardGuard {
    private static String quoteIdent(String id) {
        if (!id.matches(".+")) throw new IllegalArgumentException();
        return "\`" + id + "\`";
    }
    public PreparedStatement run(Connection conn, String col, String val) throws Exception {
        String sql = "SELECT * FROM users WHERE " + quoteIdent(col) + " = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, val);
        return ps;
    }
}
`;
    const r = await analyze(code, 'WildcardGuard.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // #214 — inline `prepareStatement(concat)` form (Sprint 51 extension)
  // -------------------------------------------------------------------------

  it('issue #214 — inline prepareStatement(concat) with regex-allowlist quoter is suppressed', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeSqlIdentifierQuoteInline {
    private static String quoteIdent(String id) {
        if (!id.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("bad identifier: " + id);
        }
        return "\`" + id + "\`";
    }
    public ResultSet run(Connection c, String column, String value) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM items WHERE " + quoteIdent(column) + " = ?");
        ps.setString(1, value);
        return ps.executeQuery();
    }
}
`;
    const r = await analyze(code, 'SafeSqlIdentifierQuoteInline.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBe(0);
    expect(countSqlFlows(r.taint?.flows)).toBe(0);
  });

  it('Recall — inline prepareStatement(concat) with bare-variable concat (no quoter): fires', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class InlineBareVar {
    public PreparedStatement run(Connection c, String column, String value) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM items WHERE " + column + " = ?");
        ps.setString(1, value);
        return ps;
    }
}
`;
    const r = await analyze(code, 'InlineBareVar.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — inline prepareStatement(concat) with quoter but NO ? placeholder: fires', async () => {
    const code = `import java.sql.Connection;
import java.sql.PreparedStatement;

public class InlineNoPlaceholder {
    private static String quoteIdent(String id) {
        if (!id.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("bad identifier: " + id);
        }
        return "\`" + id + "\`";
    }
    public PreparedStatement run(Connection c, String column, String value) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM items WHERE " + quoteIdent(column) + " = " + value);
        return ps;
    }
}
`;
    const r = await analyze(code, 'InlineNoPlaceholder.java', 'java');
    expect(countSqlSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });
});
