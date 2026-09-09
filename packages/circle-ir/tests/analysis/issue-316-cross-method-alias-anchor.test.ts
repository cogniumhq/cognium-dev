/**
 * cognium-dev #316 (from cognium-ai#326 Child C, found while fixing #308).
 *
 * `buildJavaTaintedVars` derives tainted aliases by name across the whole file,
 * and each alias was pushed into the expression-scan source list as a copy of
 * the globally earliest source — inheriting that source's `in_method`. So a
 * `cmd` tainted by an assignment in method Bad matched `cmd.ExecuteReader()`
 * in an unrelated, earlier method Safe. Aliases are now anchored to the
 * earliest source inside the method enclosing the derived assignment and
 * stamped with that method, so they can only reach sinks in their own method.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

describe('#316 derived aliases do not leak across methods', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('C#: a later tainted `cmd` in Bad does not make Safe.cmd.ExecuteReader() fire', async () => {
    const code = [
      'using System.Data.SqlClient;',
      'public class P {',
      '  public void Safe(string input, SqlConnection conn) {',
      '    var cmd = new SqlCommand("SELECT * FROM u WHERE id=@id", conn);',
      '    cmd.Parameters.AddWithValue("@id", input);',
      '    cmd.ExecuteReader();',
      '  }',
      '  public void Bad(string input, SqlConnection conn) {',
      '    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + input, conn);',
      '    cmd.ExecuteReader();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'P.cs', 'csharp');
    const sqli = flows(r, 'sql_injection');
    expect(sqli.some(f => f.sink_line === 6)).toBe(false);   // Safe stays silent
    expect(sqli.some(f => f.sink_line === 10)).toBe(true);   // Bad still fires
  });

  it('C#: a tainted assignment with no sink in another method does not taint a same-named var', async () => {
    const code = [
      'using System.Data.SqlClient;',
      'public class P {',
      '  public void Safe(string input, SqlConnection conn) {',
      '    var cmd = new SqlCommand("SELECT * FROM u WHERE id=@id", conn);',
      '    cmd.Parameters.AddWithValue("@id", input);',
      '    cmd.ExecuteReader();',
      '  }',
      '  public void Other(string input) {',
      '    var cmd = "SELECT * FROM u WHERE id=" + input;',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'P.cs', 'csharp');
    expect(flows(r, 'sql_injection')).toEqual([]);
  });

  it('Java: the same-method derived alias flow is preserved (recall)', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class A extends HttpServlet {',
      '  public void unsafe(HttpServletRequest request) throws Exception {',
      '    String arg = request.getParameter("q");',
      '    String cmd = "echo " + arg;',
      '    Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});',
      '  }',
      '  public void other(HttpServletRequest request) throws Exception {',
      '    String cmd = "ls";',
      '    Runtime.getRuntime().exec(cmd);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'A.java', 'java');
    const cmdi = flows(r, 'command_injection');
    expect(cmdi.some(f => f.sink_line === 6)).toBe(true);
    expect(cmdi.some(f => f.sink_line === 10)).toBe(false);
  });
});
