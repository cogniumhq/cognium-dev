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

  it('reset of v after q copied v still reports through q', async () => {
    const code = `using System.Data.SqlClient;
public class e287_q_copy {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        var q = "SELECT * FROM u WHERE id=" + v;
        v = "safe";
        var cmd = new SqlCommand(q, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('reset of a after v copied a still reports through v', async () => {
    const code = `using System.Data.SqlClient;
public class e287_a_copy {
    static SqlConnection conn;
    public void Run(string input)
    {
        var a = input;
        var v = a;
        a = "const";
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('literal reset after value copied into SqlCommand still reports (cmd.ExecuteNonQuery sink)', async () => {
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

  it('ref argument re-taint after literal still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_ref {
    static SqlConnection conn;
    static void Append(ref string v, string input) { v += input; }
    public void Run(string input)
    {
        var v = input;
        v = "const";
        Append(ref v, input);
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('out argument re-taint after literal still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_out {
    static SqlConnection conn;
    static void CopyOut(string input, out string v) { v = input; }
    public void Run(string input)
    {
        var v = input;
        v = "const";
        CopyOut(input, out v);
        var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + v, conn);
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

  it('literal table name beside tainted input still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_table {
    static SqlConnection conn;
    public void Run(string input)
    {
        string table = "users";
        var q = "SELECT * FROM " + table + " WHERE id=" + input;
        var cmd = new SqlCommand(q, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('literal table in SqlCommand argument beside tainted v still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_table_inline {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        string table = "users";
        var cmd = new SqlCommand("SELECT * FROM " + table + " WHERE id=" + v, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('string.Format with literal table and tainted input still reports', async () => {
    const code = `using System.Data.SqlClient;
public class e287_format {
    static SqlConnection conn;
    public void Run(string input)
    {
        var t = "users";
        var q = string.Format("SELECT * FROM {0} WHERE id={1}", t, input);
        var cmd = new SqlCommand(q, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });

  it('query rewritten to literal after building from v stays clean', async () => {
    const code = `using System.Data.SqlClient;
public class e287_q_reset {
    static SqlConnection conn;
    public void Run(string input)
    {
        var v = input;
        var q = "SELECT * FROM u WHERE id=" + v;
        q = "SELECT 1";
        var cmd = new SqlCommand(q, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
    const ir = await analyze(code, 'UserController.cs', 'csharp');
    const sql = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sql).toHaveLength(0);
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
