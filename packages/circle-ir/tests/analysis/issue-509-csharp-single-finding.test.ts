/**
 * #509 — one C# SQL injection emitted TWO findings, because both the command
 * constructor and the execute call are registered sinks and the same source
 * pairs with each:
 *
 *   var cmd = new SqlCommand(q, conn);   // sink: method 'SqlCommand'
 *   cmd.ExecuteReader();                 // sink: class  'SqlCommand'
 *
 * That is 2x inflation on C# SQL true positives and 2x verification spend.
 * #302 stated the intent ("one finding, at the Execute* call") but the dedup
 * in `generateFindings` groups by (sink.line, type), so two different lines
 * survived as two findings.
 *
 * The constructor is suppressed in BOTH emission paths — the source x sink
 * pairing loop and the #372 flow-derived loop — because the taint layer proves
 * a flow to each sink and the flow loop would otherwise re-emit it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const sqli = async (code: string, lang = 'csharp', file = 'X.cs') => {
  const r = await analyze(code, file, lang);
  const t = r.taint ?? ({} as NonNullable<typeof r.taint>);
  return generateFindings(
    t.sources ?? [], t.sinks ?? [], r.dfg, file, code, lang,
    t.sanitizers ?? [], r.types ?? [], t.flows ?? [],
  ).filter(f => f.type === 'sql_injection');
};

describe('#509 one C# SQL injection yields one finding', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reports once, at the Execute* call, not also at the constructor', async () => {
    const found = await sqli(`using System.Data.SqlClient;
public class A { public void Run(string input, SqlConnection conn) {
  var q = "SELECT * FROM u WHERE id=" + input;
  var cmd = new SqlCommand(q, conn);
  cmd.ExecuteReader();
} }`);
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(5);
  });

  it('still reports the constructor when nothing is executed on it', async () => {
    // No execute sink exists, so the constructor is the only sink and must
    // still be reported — the suppression is conditional, not blanket.
    const found = await sqli(`using System.Data.SqlClient;
public class B { public void Run(string input, SqlConnection conn) {
  var cmd = new SqlCommand("SELECT " + input, conn);
} }`);
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(3);
  });

  it('leaves Java untouched', async () => {
    const found = await sqli(`import java.sql.*;
public class C { public void run(javax.servlet.http.HttpServletRequest req, Connection conn) throws Exception {
  String id = req.getParameter("id");
  Statement s = conn.createStatement();
  s.executeQuery("SELECT " + id);
} }`, 'java', 'C.java');
    expect(found).toHaveLength(1);
  });
});
