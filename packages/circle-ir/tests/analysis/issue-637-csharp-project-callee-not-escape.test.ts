/**
 * C# project gate (#637): a call that resolves to a method of another project
 * file is not an `external_taint_escape`. The cross-file path (or its absence
 * after the callee-reach check) is what reports, so `analyzeProject` agrees
 * with a single-file analysis of the same code. An unresolved call keeps the
 * escape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

type F = { filePath: string; code: string };

const run = async (files: F[]) => {
  const pa = await analyzeProject(files.map(f => ({ ...f, language: 'csharp' as const })), {});
  const escapes: string[] = [];
  const sinks: string[] = [];
  for (const fa of pa.files) {
    for (const f of fa.analysis.taint.flows ?? []) {
      if (f.sink_type === 'external_taint_escape') escapes.push(`${fa.file}:${f.sink_line}`);
    }
    for (const s of fa.analysis.taint.sinks ?? []) {
      if (s.type === 'external_taint_escape') sinks.push(`${fa.file}:${s.line}`);
    }
  }
  const paths = pa.taint_paths.map(p => `${p.sink.type}@${p.source.file}:${p.source.line}->${p.sink.file}:${p.sink.line}`);
  return { pa, escapes, sinks, paths };
};

const callerA = `using System.Web;
public class A
{
    public void Bad(HttpRequest req)
    {
        string data = req.QueryString["name"];
        B.BadSink(data);
    }
    public void GoodB2G(HttpRequest req)
    {
        string data = req.QueryString["name"];
        B.GoodB2GSink(data);
    }
}
`;

const calleeB = `using System.Data.SqlClient;
public class B
{
    public static void BadSink(string data)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name='" + data + "'", conn);
            cmd.ExecuteReader();
        }
    }
    public static void GoodB2GSink(string data)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name=@name", conn);
            cmd.Parameters.AddWithValue("@name", data);
            cmd.ExecuteReader();
        }
    }
}
`;

describe('C# in-project callee is not an external_taint_escape (#637)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('issue fixture: no escape at A.cs:7 / A.cs:12; the vulnerable callee still reports', async () => {
    const r = await run([{ filePath: 'A.cs', code: callerA }, { filePath: 'B.cs', code: calleeB }]);
    expect(r.escapes).toEqual([]);
    expect(r.sinks).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('external_taint_escape'))).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('sql_injection@A.cs:6->B.cs:'))).not.toEqual([]);
    // the parameterised callee is not reached from A.cs:11
    expect(r.paths.filter(p => p.includes('A.cs:11'))).toEqual([]);
  });

  it('the same code in one file reports no escape either (modes agree)', async () => {
    const single = callerA.replace('using System.Web;\n', '') + calleeB;
    const ir = await analyze('using System.Web;\n' + single, 'Both.cs', 'csharp');
    expect((ir.taint.flows ?? []).filter(f => f.sink_type === 'external_taint_escape')).toEqual([]);
  });

  it('renamed variant: parameterised callee in another namespace-less class reports nothing', async () => {
    const caller = `using System.Web;
public class Lookup
{
    public void Find(HttpRequest request)
    {
        string who = request.QueryString["who"];
        Repo.Fetch(who);
    }
}
`;
    const callee = `using System.Data.SqlClient;
public class Repo
{
    public static void Fetch(string who)
    {
        using (var c = new SqlConnection("cs"))
        {
            var q = new SqlCommand("select 1 where n=@n", c);
            q.Parameters.AddWithValue("@n", who);
            q.ExecuteScalar();
        }
    }
}
`;
    const r = await run([{ filePath: 'Lookup.cs', code: caller }, { filePath: 'Repo.cs', code: callee }]);
    expect(r.escapes).toEqual([]);
    expect(r.paths).toEqual([]);
    expect(r.pa.cross_file_calls.some(c => c.to.file === 'Repo.cs')).toBe(true);
  });

  it('an unresolved external call keeps the escape', async () => {
    const caller = `using System.Web;
public class A
{
    public void Run(HttpRequest req)
    {
        string data = req.QueryString["name"];
        Vendor.Sdk.Forward(data);
    }
}
`;
    const r = await run([{ filePath: 'A.cs', code: caller }, { filePath: 'B.cs', code: calleeB }]);
    expect(r.escapes).toContain('A.cs:7');
  });

  it('a call whose name matches nothing in the project keeps the escape even with another file present', async () => {
    const caller = `using System.Web;
public class A
{
    public void Run(HttpRequest req)
    {
        string data = req.QueryString["name"];
        B.NotDeclaredAnywhere(data);
    }
}
`;
    const r = await run([{ filePath: 'A.cs', code: caller }, { filePath: 'B.cs', code: calleeB }]);
    expect(r.escapes).toContain('A.cs:7');
  });
});
