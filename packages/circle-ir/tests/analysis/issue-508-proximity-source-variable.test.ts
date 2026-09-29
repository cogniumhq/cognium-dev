/**
 * #508 — `findTaintPath`'s proximity fallback accepted ANY variable defined
 * within one line of the source that was also used within one line of the
 * sink, without checking the variable had anything to do with the source.
 *
 * On the C# ADO.NET shape the variable carrying the verdict was `conn` — the
 * SqlConnection — so every method with a `string` parameter and an execute
 * call reported CWE-89 with `taint.flows = 0`. It fired with the parameter in
 * a DIFFERENT method too, because `pathExists` short-circuits the #361 method
 * scoping in the caller.
 *
 * The pair is now accepted only when the shared variable is the source's own.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const findingsFor = async (code: string, file: string, lang: string) => {
  const ir = await analyze(code, file, lang);
  const t = ir.taint ?? ({} as NonNullable<typeof ir.taint>);
  return {
    flows: t.flows ?? [],
    findings: generateFindings(
      t.sources ?? [], t.sinks ?? [], ir.dfg, file, code, lang,
      t.sanitizers ?? [], ir.types ?? [], t.flows ?? [],
    ),
  };
};

describe('#508 proximity fallback requires the source own variable', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not pair a string param in another method with an ADO.NET sink', async () => {
    const code = `using System.Data.SqlClient;
public class E5 { static SqlConnection conn;
  public void Handle(string input) { System.Console.WriteLine(input); }
  public void Query() {
    var cmd = new SqlCommand("SELECT * FROM u", conn);
    cmd.ExecuteReader();
} }`;
    const { flows, findings } = await findingsFor(code, 'E5.cs', 'csharp');
    expect(flows).toHaveLength(0);
    expect(findings.filter(f => f.type === 'sql_injection')).toHaveLength(0);
  });

  it('still reports a genuine C# SQL injection', async () => {
    const code = `using System.Data.SqlClient;
public class D5 { static SqlConnection conn;
  public void Run(string input) {
  var cmd = new SqlCommand($"SELECT * FROM u WHERE id={input}", conn);
  cmd.ExecuteReader();
} }`;
    const { flows, findings } = await findingsFor(code, 'D5.cs', 'csharp');
    expect(flows.length).toBeGreaterThan(0);
    expect(findings.some(f => f.type === 'sql_injection')).toBe(true);
  });

  it('keeps a same-variable proximity pairing (the fallback still works)', async () => {
    const code = `import java.sql.*;
public class C {
  public void run(javax.servlet.http.HttpServletRequest req, Connection conn) throws Exception {
    String id = req.getParameter("id");
    conn.createStatement().executeQuery("SELECT * FROM u WHERE id=" + id);
  }
}`;
    const { findings } = await findingsFor(code, 'C.java', 'java');
    expect(findings.some(f => f.type === 'sql_injection')).toBe(true);
  });
});
