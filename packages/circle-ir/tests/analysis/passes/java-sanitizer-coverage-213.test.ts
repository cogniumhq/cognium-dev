/**
 * Tests for cognium-dev #213 — seventh slice: Java sanitizer parity.
 *
 * Prior coverage was PreparedStatement.setString/setInt/setLong + a
 * handful of encoder methods. This slice fills the JDBC 4.x setter
 * surface (setDate, setBigDecimal, setObject, setBytes, setBlob, …)
 * plus common third-party libraries: Guava HtmlEscapers, Apache
 * Commons Text escapes (escapeJson / escapeEcmaScript / escapeXml11 /
 * escapeCsv / escapeXsi), OWASP HTML sanitizer PolicyFactory, and
 * Java 8+ Base64.getEncoder().encodeToString + MessageDigest.digest.
 *
 * Base64/Hex encoders + MessageDigest also get bare-alias entries
 * because Java IR rarely resolves the type of a call-expression
 * receiver like `Base64.getEncoder()`.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 seventh slice — Java sanitizer parity', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasSqlFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).some(f => f.sink_type === 'sql_injection');

  const hasSanitizerAtMethod = (r: Awaited<ReturnType<typeof analyze>>, method: string) =>
    (r.taint.sanitizers ?? []).some(s => s.method?.includes(method));

  // ── PreparedStatement setter parity ───────────────────────────────────

  it('PreparedStatement.setObject binds safely (sql_injection sanitizer)', async () => {
    const code = `import java.sql.*;
public class T {
  Connection c;
  public void h(Object o) throws SQLException {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE x = ?");
    ps.setObject(1, o);
    ps.executeQuery();
  }
}`;
    const r = await analyze(code, 'T.java', 'java');
    expect(hasSqlFlow(r)).toBe(false);
    expect(hasSanitizerAtMethod(r, 'setObject')).toBe(true);
  });

  it('PreparedStatement.setDate binds safely', async () => {
    const code = `import java.sql.*;
public class T {
  Connection c;
  public void h(java.sql.Date d) throws SQLException {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE d = ?");
    ps.setDate(1, d);
    ps.executeQuery();
  }
}`;
    const r = await analyze(code, 'D.java', 'java');
    expect(hasSanitizerAtMethod(r, 'setDate')).toBe(true);
  });

  it('PreparedStatement.setBigDecimal binds safely', async () => {
    const code = `import java.sql.*;
import java.math.BigDecimal;
public class T {
  Connection c;
  public void h(BigDecimal bd) throws SQLException {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE x = ?");
    ps.setBigDecimal(1, bd);
    ps.executeQuery();
  }
}`;
    const r = await analyze(code, 'B.java', 'java');
    expect(hasSanitizerAtMethod(r, 'setBigDecimal')).toBe(true);
  });

  it('PreparedStatement.setBytes / setBlob / setTimestamp bind safely', async () => {
    // Cover a handful of the less-common setters in one file to lock the
    // broader parity claim without proliferating tests.
    const code = `import java.sql.*;
import java.io.InputStream;
public class T {
  Connection c;
  public void h(byte[] b, InputStream in, Timestamp ts) throws SQLException {
    PreparedStatement ps = c.prepareStatement("INSERT INTO t VALUES (?, ?, ?)");
    ps.setBytes(1, b);
    ps.setBlob(2, in);
    ps.setTimestamp(3, ts);
    ps.executeUpdate();
  }
}`;
    const r = await analyze(code, 'Bytes.java', 'java');
    expect(hasSanitizerAtMethod(r, 'setBytes')).toBe(true);
    expect(hasSanitizerAtMethod(r, 'setBlob')).toBe(true);
    expect(hasSanitizerAtMethod(r, 'setTimestamp')).toBe(true);
  });

  // ── Third-party library sanitizers ───────────────────────────────────

  it('Apache Commons Text `escapeJson` sanitizes', async () => {
    const code = `import org.apache.commons.text.StringEscapeUtils;
import javax.servlet.http.*;
public class T {
  public void h(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String val = req.getParameter("val");
    String safe = StringEscapeUtils.escapeJson(val);
    res.getWriter().println("{\\"v\\":\\"" + safe + "\\"}");
  }
}`;
    const r = await analyze(code, 'J.java', 'java');
    expect(hasSanitizerAtMethod(r, 'escapeJson')).toBe(true);
  });

  it('Guava HtmlEscapers.htmlEscaper().escape sanitizes', async () => {
    const code = `import com.google.common.html.HtmlEscapers;
import javax.servlet.http.*;
public class T {
  public void h(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String name = req.getParameter("name");
    String safe = HtmlEscapers.htmlEscaper().escape(name);
    res.getWriter().println("<h1>" + safe + "</h1>");
  }
}`;
    const r = await analyze(code, 'G.java', 'java');
    expect(hasSanitizerAtMethod(r, 'escape')).toBe(true);
  });

  // ── Base64 / encoder chain (bare method needed because receiver is a call) ─

  it('Base64.getEncoder().encodeToString sanitizes downstream string sinks', async () => {
    const code = `import java.util.Base64;
import java.sql.*;
public class T {
  Connection c;
  public void h(byte[] input) throws SQLException {
    String enc = Base64.getEncoder().encodeToString(input);
    Statement s = c.createStatement();
    s.executeQuery("SELECT * FROM t WHERE b = '" + enc + "'");
  }
}`;
    const r = await analyze(code, 'B64.java', 'java');
    expect(hasSqlFlow(r)).toBe(false);
    expect(hasSanitizerAtMethod(r, 'encodeToString')).toBe(true);
  });
});
