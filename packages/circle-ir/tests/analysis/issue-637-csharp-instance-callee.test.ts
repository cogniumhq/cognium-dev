/**
 * C# project gate (#637, instance-call slice): instance calls resolve through the
 * receiver's declared or created type so the callee-reach / escape gate applies.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

type F = { filePath: string; code: string };

const run = async (files: F[]) => {
  const pa = await analyzeProject(files.map(f => ({ ...f, language: 'csharp' as const })), {});
  const escapes: string[] = [];
  const sqlAt: string[] = [];
  for (const fa of pa.files) {
    for (const s of fa.analysis.taint.sinks ?? []) {
      if (s.type === 'external_taint_escape') escapes.push(`${fa.file}:${s.line}`);
      if (s.type === 'sql_injection') sqlAt.push(`${fa.file}:${s.line}`);
    }
    for (const f of fa.analysis.taint.flows ?? []) {
      if (f.sink_type === 'external_taint_escape') escapes.push(`${fa.file}:${f.sink_line}`);
      if (f.sink_type === 'sql_injection') sqlAt.push(`${fa.file}:${f.sink_line}`);
    }
  }
  const paths = pa.taint_paths.map(p => `${p.sink.type}@${p.source.file}:${p.source.line}->${p.sink.file}:${p.sink.line}`);
  return { escapes, sqlAt, paths };
};

const entry = `using System.Web;
public class Entry
{
    public void Raw(HttpRequest req)
    {
        string data = req.QueryString["name"];
        var worker = new Lookup();
        worker.FindRaw(data);
    }
    public void Bound(HttpRequest req)
    {
        string data = req.QueryString["name"];
        new Lookup().Find(data);
    }
}
`;

const lookup = `using System.Data.SqlClient;
public class Lookup
{
    public void Find(string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name=@name", conn);
            cmd.Parameters.AddWithValue("@name", v);
            cmd.ExecuteReader();
        }
    }
    public void FindRaw(string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name='" + v + "'", conn);
            cmd.ExecuteReader();
        }
    }
}
`;

const plain = `public class Plain
{
    public void Find(string v)
    {
        System.Console.WriteLine(v);
    }
}
`;

const iface = `public interface ILookup
{
    void Find(string v);
}
`;

describe('C# instance callee resolves through receiver type (#637)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('issue fixture: no escape at instance calls; sql_injection only for FindRaw', async () => {
    const r = await run([
      { filePath: 'Entry.cs', code: entry },
      { filePath: 'Lookup.cs', code: lookup },
    ]);
    expect(r.escapes).toEqual([]);
    const sqlFromEntry = [...r.paths, ...r.sqlAt.map(l => `sql_injection@${l}`)].filter(
      p => p.includes('sql_injection') && p.includes('Entry.cs'),
    );
    expect(sqlFromEntry.some(p => p.includes('Entry.cs:7') || p.includes('Entry.cs:6'))).toBe(true);
    expect(sqlFromEntry.filter(p => p.includes('Entry.cs:12') || p.includes('Entry.cs:11'))).toEqual([]);
  });

  it('negative: Plain.Find keeps external_taint_escape', async () => {
    const code = `using System.Web;
public class Entry
{
    public void Raw(HttpRequest req)
    {
        string data = req.QueryString["name"];
        var p = new Plain();
        p.Find(data);
    }
}
`;
    const r = await run([
      { filePath: 'Entry.cs', code },
      { filePath: 'Plain.cs', code: plain },
    ]);
    expect(r.escapes.length).toBeGreaterThan(0);
  });

  it('negative: interface-typed local stays polymorphic (escape kept)', async () => {
    const code = `using System.Web;
public class Entry
{
    public void Bound(HttpRequest req)
    {
        string data = req.QueryString["name"];
        ILookup l = new Lookup();
        l.Find(data);
    }
}
`;
    const r = await run([
      { filePath: 'Entry.cs', code },
      { filePath: 'Lookup.cs', code: lookup },
      { filePath: 'ILookup.cs', code: iface },
    ]);
    expect(r.escapes.length).toBeGreaterThan(0);
  });

  it('negative: same-named method in another class does not steal resolution', async () => {
    const other = `using System.Data.SqlClient;
public class Other
{
    public void Find(string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name='" + v + "'", conn);
            cmd.ExecuteReader();
        }
    }
}
`;
    const code = `using System.Web;
public class Entry
{
    public void Bound(HttpRequest req)
    {
        string data = req.QueryString["name"];
        var worker = new Lookup();
        worker.Find(data);
    }
}
`;
    const r = await run([
      { filePath: 'Entry.cs', code },
      { filePath: 'Lookup.cs', code: lookup },
      { filePath: 'Other.cs', code: other },
    ]);
    expect(r.escapes).toEqual([]);
    expect(r.paths.filter(p => p.includes('Other.cs'))).toEqual([]);
  });
});
