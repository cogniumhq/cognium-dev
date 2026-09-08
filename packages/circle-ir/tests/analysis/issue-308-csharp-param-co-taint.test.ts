/**
 * cognium-dev #308 (from cognium-ai#326 Child C / cognium-ai#289).
 *
 * `findInitialTaint` seeded every DFG definition on the source's line. For an
 * `interprocedural_param` source that is the whole signature line, so a
 * non-taintable neighbour (`SqlConnection conn`) declared beside `string input`
 * was co-tainted, `new SqlCommand(constSql, conn)` carried it into `cmd`, and
 * `cmd.ExecuteReader()` fired CWE-89 on a fully parameterised query.
 *
 * Locks: the parameterised shape is silent; concat shapes still fire; a second
 * taintable string parameter on the same line keeps its own taint.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const sqli = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');

describe('#308 C#: parameterised ADO.NET beside a SqlConnection parameter', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('AddWithValue + constant CommandText does NOT fire sql_injection', async () => {
    const code = [
      'using System.Data.SqlClient;',
      'public class P {',
      '  public void Safe(string input, SqlConnection conn) {',
      '    var cmd = new SqlCommand("SELECT * FROM u WHERE id=@id", conn);',
      '    cmd.Parameters.AddWithValue("@id", input);',
      '    cmd.ExecuteReader();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'P.cs', 'csharp');
    expect(sqli(r)).toEqual([]);
  });

  it('concatenated CommandText beside the same parameters STILL fires (recall)', async () => {
    const code = [
      'using System.Data.SqlClient;',
      'public class P {',
      '  public void Bad(string input, SqlConnection conn) {',
      '    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + input, conn);',
      '    cmd.ExecuteReader();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'P.cs', 'csharp');
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('a second taintable string parameter on the signature line keeps its own taint', async () => {
    const code = [
      'using System.Data.SqlClient;',
      'public class P {',
      '  public void Both(string input, string tableName, SqlConnection conn) {',
      '    var q = "SELECT * FROM " + tableName;',
      '    var cmd = new SqlCommand(q, conn);',
      '    cmd.ExecuteReader();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'P.cs', 'csharp');
    expect(sqli(r).some(f => f.sink_line === 5 || f.sink_line === 6)).toBe(true);
  });

  it('Java control: a Connection parameter beside a String parameter is not co-tainted', async () => {
    const code = [
      'import java.sql.*;',
      'public class A {',
      '  public void safe(String input, Connection conn) throws Exception {',
      '    PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id=?");',
      '    ps.setString(1, input);',
      '    ps.executeQuery();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'A.java', 'java');
    expect(sqli(r)).toEqual([]);
  });
});
