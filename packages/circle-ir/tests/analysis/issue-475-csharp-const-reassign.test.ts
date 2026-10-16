/**
 * cognium-dev #475 — C#: reassigning a tainted local to a constant clears taint.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const PROBE = `using System.Data.SqlClient;
public class e287_constctl {
    static SqlConnection conn;
    public void Run(string input) {
        var v = input; v = "const";
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;

beforeAll(async () => {
  await initAnalyzer();
});

describe('#475 C# literal reassignment kills taint', () => {
  it('same-line var + literal reassignment stays clean', async () => {
    const ir = await analyze(PROBE, 'e287_constctl.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql).toHaveLength(0);
  });

  it('split across lines: literal on the next line stays clean', async () => {
    const code = PROBE.replace('var v = input; v = "const";', 'var v = input;\n        v = "const";');
    const ir = await analyze(code, 'e287_split.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql).toHaveLength(0);
  });

  it('no literal overwrite: still reports', async () => {
    const code = PROBE.replace('v = "const"', 'v = input');
    const ir = await analyze(code, 'e287_tp.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });
});
