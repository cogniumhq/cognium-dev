/**
 * cognium-dev #475 — C#: reassigning a tainted local to a constant clears taint.
 *
 * The kill must target variables that carry THIS flow's taint only. An unrelated
 * literal reassignment between source and sink must not drop a real finding;
 * a conditional literal assign must not kill when another path stays tainted;
 * a re-taint after a literal (`v = "const"; v = input;`) must still report.
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

  it('unrelated literal reassignment between source and sink still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_unrelated {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        string label = "a";
        label = "b";
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'e287_unrelated.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('unrelated var w literal reassignment still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_unrelated_w {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        var w = "x";
        w = "y";
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'e287_unrelated_w.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('conditional literal reassign does not kill when path still tainted', async () => {
    const code = `using System.Data.SqlClient;
public class e287_cond {
    static SqlConnection conn;
    public void Run(string input, bool c)
    {
        var v = input;
        if (c) v = "const";
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'e287_cond.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('braced conditional literal reassign does not kill', async () => {
    const code = `using System.Data.SqlClient;
public class e287_cond_brace {
    static SqlConnection conn;
    public void Run(string input, bool c)
    {
        var v = input;
        if (c)
        {
            v = "const";
        }
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'e287_cond_brace.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('literal reset after value copied into query still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_reset_after_copy {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        v = "safe";
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('compound += re-taint after literal still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_compound {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        v = "const";
        v += input;
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('literal in multi-line for body does not kill', async () => {
    const code = `using System.Data.SqlClient;
public class e287_for {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        for (int i = 0; i < input.Length; i++)
        {
            v = "const";
        }
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('literal in multi-line while body does not kill', async () => {
    const code = `using System.Data.SqlClient;
public class e287_while {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        while (input.Length > 100)
        {
            v = "const";
            break;
        }
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('re-taint after literal still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_retain {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        v = "const";
        v = input;
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'e287_retain.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });
});
